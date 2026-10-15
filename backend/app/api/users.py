from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.user import Role, User
from app.security.audit import write_audit_log
from app.security.auth import hash_password
from app.security.dependencies import (
    get_client_ip,
    get_client_user_agent,
    get_current_user,
    require_write,
)
from app.security.rbac import ASSIGNABLE_ROLES

router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "viewer"


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    password: str | None = None
    role: str | None = None
    is_active: bool | None = None


def _user_dict(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "roles": [role.name for role in user.roles],
    }


@router.get("/me")
def get_me(
    current_user: User = Depends(get_current_user),
):
    return _user_dict(current_user)


@router.get("")
def list_users(
    current_user: User = Depends(require_write("users")),
    db: Session = Depends(get_db),
):
    users = db.query(User).all()
    return [_user_dict(u) for u in users]


@router.post("", status_code=201)
def create_user(
    request: Request,
    payload: UserCreate,
    current_user: User = Depends(require_write("users")),
    db: Session = Depends(get_db),
):
    if payload.role not in ASSIGNABLE_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role: {payload.role}")

    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    role = db.query(Role).filter(Role.name == payload.role).first()
    if not role:
        role = Role(name=payload.role)
        db.add(role)

    user = User(
        username=payload.username,
        email=str(payload.email),
        password_hash=hash_password(payload.password),
    )
    user.roles.append(role)
    db.add(user)
    db.commit()
    db.refresh(user)

    write_audit_log(
        db, user_id=current_user.id, username=current_user.username,
        action="user.create", resource_type="user", resource_id=user.id,
        ip_address=get_client_ip(request), user_agent=get_client_user_agent(request),
        details={"username": user.username, "role": payload.role},
    )
    return _user_dict(user)


@router.patch("/{user_id}")
def update_user(
    request: Request,
    user_id: int,
    payload: UserUpdate,
    current_user: User = Depends(require_write("users")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Only admins may deactivate accounts / change roles of other users
    admin = any(role.name == "admin" for role in current_user.roles)
    if user.id != current_user.id and not admin:
        raise HTTPException(status_code=403, detail="Only admins can modify other users")

    if payload.email is not None:
        user.email = str(payload.email)
    if payload.password:
        user.password_hash = hash_password(payload.password)
    if payload.role is not None:
        if payload.role not in ASSIGNABLE_ROLES:
            raise HTTPException(status_code=400, detail=f"Invalid role: {payload.role}")
        role = db.query(Role).filter(Role.name == payload.role).first()
        if not role:
            role = Role(name=payload.role)
            db.add(role)
        user.roles = [role]
    if payload.is_active is not None:
        user.is_active = payload.is_active

    db.commit()
    db.refresh(user)

    write_audit_log(
        db, user_id=current_user.id, username=current_user.username,
        action="user.update", resource_type="user", resource_id=user.id,
        ip_address=get_client_ip(request), user_agent=get_client_user_agent(request),
        details=payload.model_dump(exclude_none=True),
    )
    return _user_dict(user)