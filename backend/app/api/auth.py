from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.security import LoginAttempt, SecurityEvent
from app.models.user import User
from app.security.audit import write_audit_log
from app.security.auth import (
    create_access_token,
    verify_password,
)
from app.security.dependencies import (
    get_client_ip,
    get_client_user_agent,
    get_current_user,
)
from app.security.mfa import (
    create_mfa_token,
    decode_mfa_token,
    generate_mfa_secret,
    generate_otp_uri,
    verify_totp,
)
from app.services.alerts import create_security_event

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


class LoginForm:
    """Username/password login form.

    Deliberately *not* ``OAuth2PasswordRequestForm``: Swagger UI submits an
    empty ``grant_type`` field, which fails that form's ``pattern='password'``
    validation and returns a confusing 422. The login handler never uses
    ``grant_type`` anyway; the Authorize dialog's ``grant_type=password``
    post is simply ignored as an undeclared extra form field.
    """

    def __init__(
        self,
        *,
        username: str = Form(...),
        password: str = Form(...),
    ):
        self.username = username
        self.password = password

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
SUSPICIOUS_IPS = {"45.155.205.233", "185.220.101.34", "91.219.236.105"}


def _record_login_attempt(
    db: Session,
    *,
    username: str,
    user_id=None,
    ip_address=None,
    user_agent=None,
    success: bool,
    mfa_required: bool = False,
    mfa_success=None,
    reason=None,
):
    attempt = LoginAttempt(
        username=username,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
        mfa_required=mfa_required,
        mfa_success=mfa_success,
        reason=reason,
    )
    db.add(attempt)
    db.commit()


def _raise_unauthorized(detail: str):
    raise HTTPException(status_code=401, detail=detail)


@router.post("/login")
def login(
    request: Request,
    form_data: LoginForm = Depends(),
    db: Session = Depends(get_db),
):
    ip = get_client_ip(request)
    user_agent = get_client_user_agent(request)

    user = db.query(User).filter(
        User.username == form_data.username
    ).first()

    # --- lockout check --------------------------------------------------
    if user and user.locked_until and user.locked_until > datetime.utcnow():
        _record_login_attempt(
            db, username=form_data.username, user_id=user.id,
            ip_address=ip, user_agent=user_agent,
            success=False, reason="account_locked",
        )
        _raise_unauthorized("Account temporarily locked due to repeated failures")

    # --- credential check ------------------------------------------------
    if not user or not verify_password(form_data.password, user.password_hash):
        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= MAX_FAILED_LOGINS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                user.failed_login_count = 0
                db.commit()
                create_security_event(
                    db,
                    event_type="account_lockout",
                    description=(
                        f"Account '{user.username}' locked after "
                        f"{MAX_FAILED_LOGINS} failed login attempts"
                    ),
                    severity="HIGH",
                    user_id=user.id,
                    source_ip=ip,
                    risk_score=70.0,
                )
                write_audit_log(
                    db, user_id=user.id, username=user.username,
                    action="login.lockout", resource_type="user",
                    resource_id=user.id, ip_address=ip, user_agent=user_agent,
                )
            else:
                db.commit()
        _record_login_attempt(
            db, username=form_data.username, user_id=user.id if user else None,
            ip_address=ip, user_agent=user_agent,
            success=False, reason="invalid_credentials",
        )
        _raise_unauthorized("Invalid username or password")

    # --- suspicious login detection ---------------------------------------
    suspicious_reason = None
    if ip in SUSPICIOUS_IPS:
        suspicious_reason = "login_from_known_malicious_ip"
    elif user.last_login_ip and user.last_login_ip != ip:
        suspicious_reason = "login_from_new_ip"

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    user.last_login_ip = ip
    db.commit()

    if suspicious_reason:
        create_security_event(
            db,
            event_type="suspicious_login",
            description=(
                f"Suspicious login for '{user.username}' from {ip} "
                f"({suspicious_reason})"
            ),
            severity="MEDIUM",
            user_id=user.id,
            source_ip=ip,
            risk_score=55.0,
            event_metadata={"reason": suspicious_reason, "user_agent": user_agent},
        )
        _record_login_attempt(
            db, username=user.username, user_id=user.id,
            ip_address=ip, user_agent=user_agent,
            success=True, reason=suspicious_reason,
        )

    # --- MFA gate ----------------------------------------------------------
    if user.mfa_enabled:
        mfa_token = create_mfa_token(user.id)
        _record_login_attempt(
            db, username=user.username, user_id=user.id,
            ip_address=ip, user_agent=user_agent,
            success=False, mfa_required=True, reason="mfa_pending",
        )
        return {
            "mfa_required": True,
            "mfa_token": mfa_token,
            "detail": "TOTP code required",
        }

    token = create_access_token({"sub": str(user.id)})
    _record_login_attempt(
        db, username=user.username, user_id=user.id,
        ip_address=ip, user_agent=user_agent,
        success=True,
    )
    write_audit_log(
        db, user_id=user.id, username=user.username,
        action="login.success", resource_type="user",
        resource_id=user.id, ip_address=ip, user_agent=user_agent,
    )
    return {"access_token": token, "token_type": "bearer", "mfa_required": False}


@router.post("/login/mfa")
def verify_mfa(
    request: Request,
    mfa_token: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = get_client_ip(request)
    user_agent = get_client_user_agent(request)

    payload = decode_mfa_token(mfa_token)
    if not payload:
        _raise_unauthorized("MFA session expired, please log in again")

    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user or not user.mfa_enabled:
        _raise_unauthorized("MFA is not enabled for this account")

    if not verify_totp(user.mfa_secret, code):
        _record_login_attempt(
            db, username=user.username, user_id=user.id,
            ip_address=ip, user_agent=user_agent,
            success=False, mfa_required=True, mfa_success=False,
            reason="invalid_totp",
        )
        create_security_event(
            db,
            event_type="mfa_failure",
            description=f"Invalid TOTP code for '{user.username}' from {ip}",
            severity="MEDIUM",
            user_id=user.id,
            source_ip=ip,
            risk_score=50.0,
        )
        _raise_unauthorized("Invalid authentication code")

    token = create_access_token({"sub": str(user.id)})
    _record_login_attempt(
        db, username=user.username, user_id=user.id,
        ip_address=ip, user_agent=user_agent,
        success=True, mfa_required=True, mfa_success=True,
    )
    write_audit_log(
        db, user_id=user.id, username=user.username,
        action="login.success_mfa", resource_type="user",
        resource_id=user.id, ip_address=ip, user_agent=user_agent,
    )
    return {"access_token": token, "token_type": "bearer", "mfa_required": False}


@router.post("/mfa/enroll")
def enroll_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a TOTP secret for the current user (not yet activated)."""
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled")

    secret = generate_mfa_secret()
    # Store the pending secret directly so the next call activates it
    current_user.mfa_secret = secret
    db.commit()

    return {
        "secret": secret,
        "otpauth_uri": generate_otp_uri(secret, current_user.username),
        "issuer": "ZeroTrust Platform",
    }


@router.post("/mfa/activate")
def activate_mfa(
    request: Request,
    code: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Confirm a TOTP code and enable MFA for the current user."""
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled")
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="Call /auth/mfa/enroll first")

    if not verify_totp(current_user.mfa_secret, code):
        raise HTTPException(status_code=400, detail="Invalid verification code")

    current_user.mfa_enabled = True
    db.commit()

    write_audit_log(
        db, user_id=current_user.id, username=current_user.username,
        action="mfa.enabled", resource_type="user",
        resource_id=current_user.id,
        ip_address=get_client_ip(request), user_agent=get_client_user_agent(request),
    )
    return {"detail": "MFA enabled", "mfa_enabled": True}


@router.post("/mfa/disable")
def disable_mfa(
    request: Request,
    code: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    if not verify_totp(current_user.mfa_secret, code):
        raise HTTPException(status_code=400, detail="Invalid authentication code")

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.commit()

    write_audit_log(
        db, user_id=current_user.id, username=current_user.username,
        action="mfa.disabled", resource_type="user",
        resource_id=current_user.id,
        ip_address=get_client_ip(request), user_agent=get_client_user_agent(request),
    )
    return {"detail": "MFA disabled", "mfa_enabled": False}