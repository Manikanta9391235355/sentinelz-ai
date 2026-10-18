from enum import Enum
from typing import List, Set
from fastapi import HTTPException, status

class UserRole(str, Enum):
    SECURITY_ADMIN = "security_admin"
    SECURITY_ANALYST = "security_analyst"
    VIEWER = "viewer"

class Permission(str, Enum):
    # Viewer Permissions
    VIEW_DASHBOARD_METRICS = "view:dashboard_metrics"
    VIEW_HEALTH_STATUS = "view:health_status"
    VIEW_OWN_PROFILE = "view:own_profile"
    
    # Analyst Permissions
    VIEW_SECURITY_EVENTS = "view:security_events"
    INGEST_SECURITY_EVENTS = "ingest:security_events"
    VIEW_THREAT_FINDINGS = "view:threat_findings"
    INVESTIGATE_FINDING = "investigate:finding"
    USE_PRIVACY_SHIELD = "use:privacy_shield"
    VIEW_PRIVACY_STATS = "view:privacy_stats"
    VIEW_LIMITED_AUDIT = "view:limited_audit"
    
    # Administrator Permissions
    MANAGE_USERS = "manage:users"
    ASSIGN_ROLES = "assign:roles"
    CONFIGURE_DETECTION = "configure:detection"
    VIEW_FULL_AUDIT_TRAIL = "view:full_audit_trail"
    SYSTEM_RESEED = "system:reseed"

ROLE_PERMISSIONS: dict[UserRole, Set[Permission]] = {
    UserRole.VIEWER: {
        Permission.VIEW_DASHBOARD_METRICS,
        Permission.VIEW_HEALTH_STATUS,
        Permission.VIEW_OWN_PROFILE,
    },
    UserRole.SECURITY_ANALYST: {
        Permission.VIEW_DASHBOARD_METRICS,
        Permission.VIEW_HEALTH_STATUS,
        Permission.VIEW_OWN_PROFILE,
        Permission.VIEW_SECURITY_EVENTS,
        Permission.INGEST_SECURITY_EVENTS,
        Permission.VIEW_THREAT_FINDINGS,
        Permission.INVESTIGATE_FINDING,
        Permission.USE_PRIVACY_SHIELD,
        Permission.VIEW_PRIVACY_STATS,
        Permission.VIEW_LIMITED_AUDIT,
    },
    UserRole.SECURITY_ADMIN: {
        Permission.VIEW_DASHBOARD_METRICS,
        Permission.VIEW_HEALTH_STATUS,
        Permission.VIEW_OWN_PROFILE,
        Permission.VIEW_SECURITY_EVENTS,
        Permission.INGEST_SECURITY_EVENTS,
        Permission.VIEW_THREAT_FINDINGS,
        Permission.INVESTIGATE_FINDING,
        Permission.USE_PRIVACY_SHIELD,
        Permission.VIEW_PRIVACY_STATS,
        Permission.VIEW_LIMITED_AUDIT,
        Permission.MANAGE_USERS,
        Permission.ASSIGN_ROLES,
        Permission.CONFIGURE_DETECTION,
        Permission.VIEW_FULL_AUDIT_TRAIL,
        Permission.SYSTEM_RESEED,
    }
}

def has_permission(role_str: str, permission: Permission) -> bool:
    """Checks if a given role possesses a specific permission."""
    try:
        role = UserRole(role_str)
        return permission in ROLE_PERMISSIONS.get(role, set())
    except (ValueError, TypeError):
        return False

def verify_role_access(user_role: str, allowed_roles: List[UserRole]) -> None:
    """
    Enforces that user role belongs to the allowed roles list.
    Throws 403 Forbidden on failure.
    """
    try:
        current = UserRole(user_role)
        if current not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Role '{user_role}' lacks required authorization."
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Invalid or unrecognized role."
        )
