"""
Role-based access control.

Roles are hierarchical: each role inherits the permissions of the role
below it, plus its own. This keeps permission checks simple and explicit.
"""

ROLE_HIERARCHY = {
    "viewer": 0,
    "operator": 1,
    "security_analyst": 2,
    "admin": 3,
}

# Permission levels per capability (0 = none, 1 = read, 2 = read+write)
PERMISSIONS = {
    "dashboard": {"viewer": 1, "operator": 2, "security_analyst": 2, "admin": 2},
    "network": {"viewer": 1, "operator": 2, "security_analyst": 2, "admin": 2},
    "devices": {"viewer": 1, "operator": 2, "security_analyst": 2, "admin": 2},
    "servers": {"viewer": 1, "operator": 2, "security_analyst": 2, "admin": 2},
    "incidents": {"viewer": 1, "operator": 2, "security_analyst": 2, "admin": 2},
    "audit": {"viewer": 0, "operator": 1, "security_analyst": 2, "admin": 2},
    "reports": {"viewer": 1, "operator": 1, "security_analyst": 2, "admin": 2},
    "users": {"viewer": 0, "operator": 0, "security_analyst": 0, "admin": 2},
    "ml": {"viewer": 0, "operator": 0, "security_analyst": 2, "admin": 2},
    "search": {"viewer": 1, "operator": 1, "security_analyst": 2, "admin": 2},
}

# Roles that can be assigned when creating/editing users
ASSIGNABLE_ROLES = ["viewer", "operator", "security_analyst", "admin"]


def role_level(role_name: str) -> int:
    return ROLE_HIERARCHY.get(role_name, 0)


def user_level(roles) -> int:
    """Highest hierarchy level across a user's roles."""
    levels = [role_level(r.name if hasattr(r, "name") else r) for r in roles]
    return max(levels) if levels else 0


def can_read(user_roles, capability: str) -> bool:
    return PERMISSIONS.get(capability, {}).get(
        _effective_role(user_roles), 0
    ) >= 1


def can_write(user_roles, capability: str) -> bool:
    return PERMISSIONS.get(capability, {}).get(
        _effective_role(user_roles), 0
    ) >= 2


def _effective_role(user_roles) -> str:
    """Map a user's roles to the single highest permission role name."""
    level = user_level(user_roles)
    for name, lvl in sorted(ROLE_HIERARCHY.items(), key=lambda kv: kv[1], reverse=True):
        if lvl <= level:
            return name
    return "viewer"