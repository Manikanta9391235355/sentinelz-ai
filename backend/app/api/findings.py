import json
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc
from backend.app.database import get_db
from backend.app.models.all_models import ThreatFinding, User
from backend.app.schemas.all_schemas import ThreatFindingResponse, ThreatFindingStatusUpdate
from backend.app.api.deps import require_analyst_or_admin
from backend.app.services.audit_logger import audit_logger

router = APIRouter(prefix="/findings", tags=["Threat Findings & Incident Investigation"])

def _format_finding(f: ThreatFinding) -> dict:
    try:
        evidence = json.loads(f.evidence) if isinstance(f.evidence, str) else f.evidence
    except Exception:
        evidence = {}

    try:
        steps = json.loads(f.recommended_steps) if isinstance(f.recommended_steps, str) else f.recommended_steps
    except Exception:
        steps = []

    try:
        events = json.loads(f.related_event_ids) if isinstance(f.related_event_ids, str) else f.related_event_ids
    except Exception:
        events = []

    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "risk_score": f.risk_score,
        "detection_method": f.detection_method,
        "rule_id": f.rule_id,
        "explanation": f.explanation,
        "evidence": evidence,
        "recommended_steps": steps,
        "related_event_ids": events,
        "affected_identity": f.affected_identity,
        "status": f.status,
        "created_at": f.created_at,
        "updated_at": f.updated_at,
        "resolved_by": f.resolved_by,
        "resolution_notes": f.resolution_notes
    }

@router.get("", response_model=List[ThreatFindingResponse])
def list_threat_findings(
    severity: Optional[str] = Query(None, description="Filter: LOW, MEDIUM, HIGH, CRITICAL"),
    status: Optional[str] = Query(None, description="Filter: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE"),
    rule_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Lists threat findings with explainable severity, risk scores, and evidence.
    Restricted to Security Analysts and Administrators.
    """
    query = db.query(ThreatFinding)
    if severity:
        query = query.filter(ThreatFinding.severity == severity.upper())
    if status:
        query = query.filter(ThreatFinding.status == status.upper())
    if rule_id:
        query = query.filter(ThreatFinding.rule_id == rule_id)

    findings = query.order_by(desc(ThreatFinding.risk_score), desc(ThreatFinding.created_at)).offset(offset).limit(limit).all()
    return [_format_finding(f) for f in findings]

@router.get("/{finding_id}", response_model=ThreatFindingResponse)
def get_threat_finding_details(
    finding_id: str,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Returns granular threat finding details, timeline evidence, and recommended investigation steps.
    """
    finding = db.query(ThreatFinding).filter(ThreatFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Threat finding '{finding_id}' not found.")
    return _format_finding(finding)

@router.patch("/{finding_id}/status", response_model=ThreatFindingResponse)
def update_threat_finding_status(
    finding_id: str,
    payload: ThreatFindingStatusUpdate,
    request: Request,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Updates the investigation status of a security finding (e.g. from OPEN to INVESTIGATING or RESOLVED).
    Appends an immutable audit log record to document the analyst's disposition.
    """
    finding = db.query(ThreatFinding).filter(ThreatFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Threat finding '{finding_id}' not found.")

    old_status = finding.status
    finding.status = payload.status
    finding.updated_at = datetime.utcnow()
    finding.resolved_by = current_user.email
    if payload.resolution_notes:
        finding.resolution_notes = payload.resolution_notes

    db.commit()
    db.refresh(finding)

    # Record status change in audit trail
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_logger.log(
        db=db,
        actor_id=current_user.email,
        actor_role=current_user.role,
        action="FINDING_STATUS_CHANGE",
        target_type="FINDING",
        target_id=finding.id,
        outcome="SUCCESS",
        client_ip=client_ip,
        context_metadata={
            "old_status": old_status,
            "new_status": payload.status,
            "rule_id": finding.rule_id,
            "risk_score": finding.risk_score,
            "analyst": current_user.email
        }
    )

    return _format_finding(finding)
