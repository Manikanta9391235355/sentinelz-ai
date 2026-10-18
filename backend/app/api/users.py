from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.all_models import User
from backend.app.schemas.all_schemas import UserResponse, UserRoleUpdate
from backend.app.api.deps import require_admin
from backend.app.services.audit_logger import audit_logger

router = APIRouter(prefix="/users", tags=["Identity & Role Administration"])

@router.get("", response_model=List[UserResponse])
def list_users(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Lists system identities and role assignments.
    Restricted to Security Administrators.
    """
    users = db.query(User).order_by(User.id).all()
    return [UserResponse.model_validate(u) for u in users]

@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Updates a user's role assignment.
    Restricted to Security Administrators.
    Appends an immutable audit log record to document the administrative authorization change.
    """
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found.")

    old_role = target_user.role
    target_user.role = payload.role
    db.commit()
    db.refresh(target_user)

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_logger.log(
        db=db,
        actor_id=current_user.email,
        actor_role=current_user.role,
        action="USER_ROLE_CHANGE",
        target_type="USER",
        target_id=str(target_user.id),
        outcome="SUCCESS",
        client_ip=client_ip,
        context_metadata={
            "target_email": target_user.email,
            "old_role": old_role,
            "new_role": payload.role,
            "authorized_by": current_user.email
        }
    )

    return UserResponse.model_validate(target_user)
