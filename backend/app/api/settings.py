from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.all_models import DetectionRuleConfig, User
from backend.app.schemas.all_schemas import DetectionRuleConfigResponse, DetectionRuleConfigUpdate
from backend.app.api.deps import require_admin
from backend.app.services.seeder import seed_database
from backend.app.services.audit_logger import audit_logger

router = APIRouter(prefix="/settings", tags=["Detection Rules & System Configuration"])

@router.get("/detection-rules", response_model=List[DetectionRuleConfigResponse])
def get_detection_rules(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Returns active detection rules, thresholds, and sliding window parameters.
    Restricted to Security Administrators.
    """
    rules = db.query(DetectionRuleConfig).all()
    return [DetectionRuleConfigResponse.model_validate(r) for r in rules]

@router.patch("/detection-rules/{rule_id}", response_model=DetectionRuleConfigResponse)
def update_detection_rule(
    rule_id: str,
    payload: DetectionRuleConfigUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Updates detection rule sensitivity, threshold count, and time window parameters.
    Restricted to Security Administrators.
    Appends an immutable audit log record.
    """
    rule = db.query(DetectionRuleConfig).filter(DetectionRuleConfig.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found.")

    changes = {}
    if payload.is_enabled is not None:
        changes["is_enabled"] = payload.is_enabled
        rule.is_enabled = payload.is_enabled
    if payload.threshold_count is not None:
        changes["threshold_count"] = payload.threshold_count
        rule.threshold_count = payload.threshold_count
    if payload.window_seconds is not None:
        changes["window_seconds"] = payload.window_seconds
        rule.window_seconds = payload.window_seconds
    if payload.base_weight is not None:
        changes["base_weight"] = payload.base_weight
        rule.base_weight = payload.base_weight

    rule.updated_at = datetime.utcnow()
    rule.updated_by = current_user.email
    db.commit()
    db.refresh(rule)

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_logger.log(
        db=db,
        actor_id=current_user.email,
        actor_role=current_user.role,
        action="CONFIG_CHANGE",
        target_type="CONFIG",
        target_id=rule.rule_id,
        outcome="SUCCESS",
        client_ip=client_ip,
        context_metadata={"changes": changes}
    )

    return DetectionRuleConfigResponse.model_validate(rule)

@router.post("/reseed-demo")
def reseed_demo_data(
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Re-initializes all synthetic events, demo findings, and audit log state.
    Restricted to Security Administrators.
    """
    result = seed_database(db, force=True)

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_logger.log(
        db=db,
        actor_id=current_user.email,
        actor_role=current_user.role,
        action="DEMO_RESEED",
        target_type="SYSTEM",
        target_id="sentinelz_db",
        outcome="SUCCESS",
        client_ip=client_ip,
        context_metadata=result
    )

    return result
