from typing import Optional, List
from fastapi import Depends, HTTPException, status, Header, Request
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.core.security import validate_token
from backend.app.core.rbac import UserRole, verify_role_access
from backend.app.models.all_models import User

def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Extracts and validates bearer token from Authorization header or cookie.
    Denies access by default if token is missing, expired, or invalid.
    """
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1].strip()
    elif "sentinelz_token" in request.cookies:
        token = request.cookies.get("sentinelz_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session = validate_token(token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please re-authenticate.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == session["user_id"], User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists or is inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

def require_roles(allowed_roles: List[UserRole]):
    """
    Dependency factory to strictly enforce server-side RBAC on endpoints.
    """
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        verify_role_access(current_user.role, allowed_roles)
        return current_user
    return role_checker

# Predefined role dependencies
require_admin = require_roles([UserRole.SECURITY_ADMIN])
require_analyst_or_admin = require_roles([UserRole.SECURITY_ADMIN, UserRole.SECURITY_ANALYST])
require_any_authenticated = require_roles([UserRole.SECURITY_ADMIN, UserRole.SECURITY_ANALYST, UserRole.VIEWER])
