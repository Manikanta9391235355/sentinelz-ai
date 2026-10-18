from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.all_models import User
from backend.app.schemas.all_schemas import LoginRequest, LoginResponse, UserResponse
from backend.app.core.security import verify_password, create_access_token, revoke_token
from backend.app.api.deps import get_current_user
from backend.app.services.audit_logger import audit_logger
from backend.app.services.seeder import DEMO_USERS

router = APIRouter(prefix="/auth", tags=["Authentication & Identity"])

@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Authenticates a user with email and password using salted PBKDF2-HMAC-SHA256.
    Generates a cryptographically secure session token and logs the outcome in audit trail.
    """
    user = db.query(User).filter(User.email == payload.email).first()
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not user or not verify_password(payload.password, user.hashed_password, user.salt):
        # Record failed auth audit event
        audit_logger.log(
            db=db,
            actor_id=payload.email,
            actor_role="unauthenticated",
            action="AUTH_LOGIN",
            target_type="USER",
            target_id=payload.email,
            outcome="FAILURE",
            client_ip=client_ip,
            context_metadata={"reason": "INVALID_CREDENTIALS"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Authentication failed.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Contact a Security Administrator."
        )

    token = create_access_token(user.id, user.role)

    # Set secure cookie
    response.set_cookie(
        key="sentinelz_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False, # Set True in production HTTPS
        max_age=86400
    )

    # Record success in audit trail
    audit_logger.log(
        db=db,
        actor_id=user.email,
        actor_role=user.role,
        action="AUTH_LOGIN",
        target_type="USER",
        target_id=str(user.id),
        outcome="SUCCESS",
        client_ip=client_ip,
        context_metadata={"auth_method": "pbkdf2_hmac_sha256"}
    )

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Returns the authenticated identity profile and active role."""
    return UserResponse.model_validate(current_user)

@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Terminates session, revokes bearer token, and records logout."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.split("Bearer ")[1].strip() if "Bearer " in auth_header else request.cookies.get("sentinelz_token")
    if token:
        revoke_token(token)

    response.delete_cookie("sentinelz_token")

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_logger.log(
        db=db,
        actor_id=current_user.email,
        actor_role=current_user.role,
        action="AUTH_LOGOUT",
        target_type="USER",
        target_id=str(current_user.id),
        outcome="SUCCESS",
        client_ip=client_ip
    )

    return {"status": "logged_out", "message": "Session terminated successfully."}

@router.get("/demo-accounts")
def get_demo_accounts():
    """Lists standard demo accounts for evaluation."""
    return [
        {
            "email": u["email"],
            "full_name": u["full_name"],
            "role": u["role"],
            "password": u["password"],
            "description": "Administrator with full user, rule, and system configuration control" if u["role"] == "security_admin" else (
                "SOC Analyst with threat investigation, privacy shield, and event ingestion rights" if u["role"] == "security_analyst" else
                "Auditor/Viewer with read-only aggregate dashboard view"
            )
        }
        for u in DEMO_USERS
    ]

@router.post("/demo-switch", response_model=LoginResponse)
def demo_switch_role(
    role: str,
    response: Response,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Convenience endpoint for datathon evaluators to effortlessly switch active persona
    (security_admin, security_analyst, or viewer) to test RBAC enforcement live.
    """
    valid_roles = ["security_admin", "security_analyst", "viewer"]
    if role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid demo role. Choose from {valid_roles}")

    target_user = db.query(User).filter(User.role == role).first()
    if not target_user:
        raise HTTPException(status_code=404, detail=f"Demo user for role '{role}' not found. Reseed database.")

    token = create_access_token(target_user.id, target_user.role)

    response.set_cookie(
        key="sentinelz_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=86400
    )

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_logger.log(
        db=db,
        actor_id=target_user.email,
        actor_role=target_user.role,
        action="AUTH_DEMO_SWITCH",
        target_type="USER",
        target_id=str(target_user.id),
        outcome="SUCCESS",
        client_ip=client_ip,
        context_metadata={"switched_to_role": role}
    )

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(target_user)
    )
