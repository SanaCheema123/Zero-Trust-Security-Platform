"""Self-contained OAuth 2.0 authorization server.

Implements the standard authorization-code flow (RFC 6749) with optional
PKCE (RFC 7636) and a built-in HTML login form, so the whole flow can be
exercised without any external provider:

  1. GET /oauth/authorize?client_id=..&redirect_uri=..&response_type=code
     -> HTML login form (password + TOTP when MFA is enabled)
  2. POST /oauth/authorize (form submit) -> 302 to redirect_uri?code=..&state=..
  3. POST /oauth/token (client_secret) -> { access_token, token_type }

A demo client is created by the seed script.
"""

import hashlib
import html
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.security import OAuthAuthorizationCode, OAuthClient
from app.models.user import User
from app.security.auth import create_access_token, verify_password
from app.security.mfa import verify_totp
from app.services.alerts import create_security_event

router = APIRouter(
    prefix="/oauth",
    tags=["OAuth 2.0"],
)

CODE_TTL_MINUTES = 10


def _form(
    error: str = "",
    username: str = "",
    mfa: bool = False,
    client_name: str = "",
    **params,
):
    hidden = "".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(str(v))}">'
        for k, v in params.items()
    )
    mfa_field = (
        '<div class="field"><label>TOTP code (MFA)</label>'
        '<input type="text" name="totp" autocomplete="one-time-code"></div>'
        if mfa else ""
    )
    error_html = (
        f'<div class="error">{html.escape(error)}</div>' if error else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in - ZeroTrust Platform</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
          background: #0b1220; color: #e5e7eb; display: flex;
          align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
  .card {{ background: #111a2e; border: 1px solid #263350; border-radius: 12px;
          padding: 32px; width: 340px; box-shadow: 0 10px 30px rgba(0,0,0,.4); }}
  h1 {{ font-size: 18px; margin: 0 0 4px; }}
  .sub {{ color: #93a4c8; font-size: 13px; margin-bottom: 20px; }}
  .field {{ margin-bottom: 14px; }}
  label {{ display: block; font-size: 12px; color: #93a4c8; margin-bottom: 6px; }}
  input {{ width: 100%; box-sizing: border-box; padding: 10px; border-radius: 8px;
          border: 1px solid #2c3a5c; background: #0d1526; color: #e5e7eb; }}
  button {{ width: 100%; padding: 11px; border: 0; border-radius: 8px;
           background: #2563eb; color: white; font-size: 14px; cursor: pointer; }}
  button:hover {{ background: #1d4ed8; }}
  .error {{ background: #3b1d24; border: 1px solid #7f2d3a; color: #fca5a5;
           padding: 8px 10px; border-radius: 8px; font-size: 13px; margin-bottom: 14px; }}
  .brand {{ color: #38bdf8; font-weight: 600; }}
</style></head><body>
<div class="card">
  <h1><span class="brand">ZeroTrust</span> Platform</h1>
  <div class="sub">Authorize <b>{html.escape(client_name)}</b> to access your account</div>
  {error_html}
  <form method="post" action="/oauth/authorize">{hidden}
    <div class="field"><label>Username</label>
      <input type="text" name="username" value="{html.escape(username)}" required autofocus></div>
    <div class="field"><label>Password</label>
      <input type="password" name="password" required></div>
    {mfa_field}
    <button type="submit">Authorize</button>
  </form>
</div></body></html>"""


def _valid_redirect(client: OAuthClient, redirect_uri: str) -> bool:
    uris = client.redirect_uris or []
    return redirect_uri in uris or (not uris and redirect_uri)


@router.get("/authorize", response_class=HTMLResponse)
def authorize_form(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "",
    db: Session = Depends(get_db),
):
    client = db.query(OAuthClient).filter(
        OAuthClient.client_id == client_id,
        OAuthClient.is_active.is_(True),
    ).first()

    if not client:
        return HTMLResponse(_form(error="Unknown OAuth client", client_name="unknown",
                                  client_id=client_id, redirect_uri=redirect_uri,
                                  response_type=response_type, state=state), status_code=400)
    if not _valid_redirect(client, redirect_uri):
        return HTMLResponse(_form(error="Invalid redirect_uri", client_name=client.name,
                                  client_id=client_id, redirect_uri=redirect_uri,
                                  response_type=response_type, state=state), status_code=400)
    if response_type != "code":
        return HTMLResponse(_form(error="Only response_type=code is supported",
                                  client_name=client.name, client_id=client_id,
                                  redirect_uri=redirect_uri, response_type=response_type,
                                  state=state), status_code=400)

    return HTMLResponse(_form(
        client_name=client.name,
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    ))


@router.post("/authorize")
def authorize_submit(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    response_type: str = Form("code"),
    state: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form(""),
    username: str = Form(...),
    password: str = Form(...),
    totp: str = Form(""),
    db: Session = Depends(get_db),
):
    client = db.query(OAuthClient).filter(
        OAuthClient.client_id == client_id,
        OAuthClient.is_active.is_(True),
    ).first()

    base_params = {
        "client_id": client_id, "redirect_uri": redirect_uri,
        "response_type": response_type, "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }

    if not client:
        return HTMLResponse(_form(error="Unknown OAuth client", username=username,
                                  client_name="unknown", **base_params), status_code=400)
    if not _valid_redirect(client, redirect_uri):
        return HTMLResponse(_form(error="Invalid redirect_uri", username=username,
                                  client_name=client.name, **base_params), status_code=400)

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        return HTMLResponse(_form(error="Invalid username or password", username=username,
                                  client_name=client.name, **base_params), status_code=401)

    # MFA check: if enabled, a valid TOTP code is required to authorize
    if user.mfa_enabled:
        if not verify_totp(user.mfa_secret, totp):
            return HTMLResponse(_form(
                error="TOTP code required / invalid",
                username=username, mfa=True,
                client_name=client.name, **base_params,
            ), status_code=401)

    if code_challenge and code_challenge_method not in ("S256", "plain"):
        return HTMLResponse(_form(error="Unsupported code_challenge_method",
                                  username=username, client_name=client.name,
                                  **base_params), status_code=400)

    code = secrets.token_urlsafe(48)
    db.add(OAuthAuthorizationCode(
        code=code,
        client_id=client.client_id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        scope="read write",
        code_challenge=code_challenge or None,
        code_challenge_method=code_challenge_method or None,
        expires_at=datetime.utcnow() + timedelta(minutes=CODE_TTL_MINUTES),
    ))
    db.commit()

    redirect = (
        f"{redirect_uri}?{urlencode({'code': code, 'state': state})}"
        if state
        else f"{redirect_uri}?code={code}"
    )
    return RedirectResponse(redirect, status_code=302)


@router.post("/token")
def token_endpoint(
    grant_type: str = Form(...),
    code: str = Form(""),
    redirect_uri: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    code_verifier: str = Form(""),
    db: Session = Depends(get_db),
):
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="unsupported_grant_type")

    auth_code = db.query(OAuthAuthorizationCode).filter(
        OAuthAuthorizationCode.code == code
    ).first()

    if not auth_code or auth_code.is_used or auth_code.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="invalid_grant")

    client = db.query(OAuthClient).filter(
        OAuthClient.client_id == auth_code.client_id,
        OAuthClient.is_active.is_(True),
    ).first()
    if not client:
        raise HTTPException(status_code=400, detail="invalid_client")

    if client_id and client_id != client.client_id:
        raise HTTPException(status_code=400, detail="invalid_client")
    if client_secret != client.client_secret:
        raise HTTPException(status_code=400, detail="invalid_client")
    if redirect_uri and redirect_uri != auth_code.redirect_uri:
        raise HTTPException(status_code=400, detail="invalid_grant")

    # PKCE verification (RFC 7636)
    if auth_code.code_challenge:
        if not code_verifier:
            raise HTTPException(status_code=400, detail="invalid_request")
        if auth_code.code_challenge_method == "S256":
            digest = hashlib.sha256(code_verifier.encode()).digest()
            if _b64url(digest) != auth_code.code_challenge:
                raise HTTPException(status_code=400, detail="invalid_grant")
        elif code_verifier != auth_code.code_challenge:
            raise HTTPException(status_code=400, detail="invalid_grant")

    auth_code.is_used = True
    db.commit()

    user = db.query(User).filter(User.id == auth_code.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="invalid_grant")

    access_token = create_access_token({"sub": str(user.id), "oauth": True})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": auth_code.scope,
    }


def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@router.get("/clients")
def list_clients(db: Session = Depends(get_db)):
    """Public client registry (no secrets) used by the frontend SSO button."""
    clients = db.query(OAuthClient).filter(OAuthClient.is_active.is_(True)).all()
    return [
        {
            "client_id": c.client_id,
            "name": c.name,
            "redirect_uris": c.redirect_uris,
            "pkce_supported": True,
        }
        for c in clients
    ]