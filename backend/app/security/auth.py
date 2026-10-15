from datetime import datetime, timedelta, timezone
import os

import bcrypt
from jose import JWTError, jwt


SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "dev-only-change-this-secret-key"
)

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# Token types
TOKEN_ACCESS = "access"
TOKEN_MFA = "mfa"


def _secret_bytes(password: str) -> bytes:
    # bcrypt only uses the first 72 bytes; truncate explicitly so long
    # passwords hash/verify consistently instead of raising.
    return password.encode("utf-8")[:72]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        _secret_bytes(password),
        bcrypt.gensalt(),
    ).decode("utf-8")


def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:
    try:
        return bcrypt.checkpw(
            _secret_bytes(plain_password),
            hashed_password.encode("utf-8"),
        )
    except ValueError:
        return False


def create_access_token(data: dict) -> str:
    return _create_token(data, TOKEN_ACCESS, ACCESS_TOKEN_EXPIRE_MINUTES)


def create_temp_token(user_id: int, minutes: int = 5) -> str:
    """Short-lived token used between authentication steps (e.g. MFA)."""
    return _create_token({"sub": str(user_id)}, TOKEN_MFA, minutes)


def _create_token(data: dict, token_type: str, expire_minutes: int) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expire_minutes
    )
    payload.update({
        "exp": expire,
        "type": token_type,
    })
    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def decode_access_token(token: str) -> dict | None:
    return _decode(token, TOKEN_ACCESS)


def decode_temp_token(token: str) -> dict | None:
    return _decode(token, TOKEN_MFA)


def _decode(token: str, expected_type: str) -> dict | None:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        if payload.get("type") != expected_type:
            return None
        return payload
    except JWTError:
        return None