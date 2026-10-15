from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.user import User
from app.security.auth import decode_access_token
from app.security.rbac import can_read, can_write


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login"
)


def get_client_ip(request: Request) -> str:
    # Respect X-Forwarded-For when behind a proxy (nginx)
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_client_user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:255]


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    payload = decode_access_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token"
        )

    user = db.query(User).filter(
        User.id == int(user_id)
    ).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="User not found or inactive"
        )

    return user


def role_names(user: User):
    return [role.name for role in user.roles]


def require_read(capability: str):
    """Dependency factory: allow access if the user can read the capability."""

    def checker(current_user: User = Depends(get_current_user)):
        if not can_read(current_user.roles, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: requires read access to '{capability}'"
            )
        return current_user

    return checker


def require_write(capability: str):
    """Dependency factory: allow access if the user can write the capability."""

    def checker(current_user: User = Depends(get_current_user)):
        if not can_write(current_user.roles, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: requires write access to '{capability}'"
            )
        return current_user

    return checker