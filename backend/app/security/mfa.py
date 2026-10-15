import secrets

import pyotp

from app.security.auth import (
    create_temp_token,
    decode_temp_token,
)

ISSUER = "ZeroTrust Platform"


def generate_mfa_secret() -> str:
    """Generate a new TOTP secret (base32)."""
    return pyotp.random_base32()


def generate_otp_uri(secret: str, username: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=ISSUER,
    )


def verify_totp(secret: str, code: str) -> bool:
    if not secret:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def create_mfa_token(user_id: int) -> str:
    """Short-lived token proving the password step succeeded."""
    return create_temp_token(user_id, minutes=5)


def decode_mfa_token(token: str):
    return decode_temp_token(token)