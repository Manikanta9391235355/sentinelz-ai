import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc
from backend.app.database import get_db
from backend.app.models.all_models import SecurityEvent, User
from backend.app.schemas.all_schemas import SecurityEventCreate, SecurityEventResponse
from backend.app.api.deps import require_analyst_or_admin, require_any_authenticated
from backend.app.services.threat_engine import threat_engine
from backend.app.services.audit_logger import audit_logger

router = APIRouter(prefix="/events", tags=["Security Event Ingestion & Telemetry"])

@router.post("/ingest", response_model=SecurityEventResponse)
def ingest_security_event(
    payload: SecurityEventCreate,
    request: Request,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Ingests a single validated security event into SentinelZ AI.
    Immediately evaluates event against explainable detection rules, updates sliding state,
    and logs the ingestion action in the audit trail.
    """
    event_id = payload.id or f"evt_{uuid.uuid4().hex[:12]}"
    
    # Check duplicate ID
    if db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first():
        raise HTTPException(status_code=400, detail=f"Event with ID '{event_id}' already exists.")

    import json
    new_event = SecurityEvent(
        id=event_id,
        timestamp=payload.timestamp or datetime.utcnow(),
        user_id=payload.user_id,
        user_role=payload.user_role,
        source_ip=payload.source_ip,
        resource=payload.resource,
        requested_action=payload.requested_action,
        resource_classification=payload.resource_classification,
        access_decision=payload.access_decision,
        auth_result=payload.auth_result,
        context_metadata=json.dumps(payload.context_metadata or {}),
        is_synthetic=payload.is_synthetic,
        created_at=datetime.utcnow()
    )
    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    # Evaluate in real-time through threat detection engine
    new_findings = threat_engine.analyze_event(db, new_event)

    # Record in audit trail
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_logger.log(
        db=db,
        actor_id=current_user.email,
        actor_role=current_user.role,
        action="EVENT_INGESTED",
        target_type="EVENT",
        target_id=new_event.id,
        outcome="SUCCESS",
        client_ip=client_ip,
        context_metadata={
            "resource": new_event.resource,
            "decision": new_event.access_decision,
            "generated_findings_count": len(new_findings)
        }
    )

    # Build response with parsed context metadata
    resp_dict = {
        "id": new_event.id,
        "timestamp": new_event.timestamp,
        "user_id": new_event.user_id,
        "user_role": new_event.user_role,
        "source_ip": new_event.source_ip,
        "resource": new_event.resource,
        "requested_action": new_event.requested_action,
        "resource_classification": new_event.resource_classification,
        "access_decision": new_event.access_decision,
        "auth_result": new_event.auth_result,
        "context_metadata": json.loads(new_event.context_metadata),
        "is_synthetic": new_event.is_synthetic,
        "created_at": new_event.created_at
    }
    return resp_dict

@router.get("", response_model=List[SecurityEventResponse])
def list_security_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = Query(None, description="Filter: ALLOW or DENY"),
    classification: Optional[str] = Query(None, description="Filter: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED_HIGH_VALUE"),
    user_id: Optional[str] = Query(None),
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Lists security events with filtering, sorting, and pagination."""
    query = db.query(SecurityEvent)
    if decision:
        query = query.filter(SecurityEvent.access_decision == decision.upper())
    if classification:
        query = query.filter(SecurityEvent.resource_classification == classification.upper())
    if user_id:
        query = query.filter(SecurityEvent.user_id.ilike(f"%{user_id}%"))

    events = query.order_by(desc(SecurityEvent.timestamp)).offset(offset).limit(limit).all()

    import json
    results = []
    for ev in events:
        try:
            meta = json.loads(ev.context_metadata)
        except Exception:
            meta = {}
        results.append({
            "id": ev.id,
            "timestamp": ev.timestamp,
            "user_id": ev.user_id,
            "user_role": ev.user_role,
            "source_ip": ev.source_ip,
            "resource": ev.resource,
            "requested_action": ev.requested_action,
            "resource_classification": ev.resource_classification,
            "access_decision": ev.access_decision,
            "auth_result": ev.auth_result,
            "context_metadata": meta,
            "is_synthetic": ev.is_synthetic,
            "created_at": ev.created_at
        })
    return results

@router.get("/{event_id}", response_model=SecurityEventResponse)
def get_security_event_details(
    event_id: str,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Retrieves full details of a specific security event."""
    ev = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail=f"Security event '{event_id}' not found.")

    import json
    try:
        meta = json.loads(ev.context_metadata)
    except Exception:
        meta = {}

    return {
        "id": ev.id,
        "timestamp": ev.timestamp,
        "user_id": ev.user_id,
        "user_role": ev.user_role,
        "source_ip": ev.source_ip,
        "resource": ev.resource,
        "requested_action": ev.requested_action,
        "resource_classification": ev.resource_classification,
        "access_decision": ev.access_decision,
        "auth_result": ev.auth_result,
        "context_metadata": meta,
        "is_synthetic": ev.is_synthetic,
        "created_at": ev.created_at
    }
