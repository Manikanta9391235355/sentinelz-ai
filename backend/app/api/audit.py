import json
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from backend.app.database import get_db
from backend.app.models.all_models import AuditRecord, User
from backend.app.schemas.all_schemas import AuditRecordResponse
from backend.app.api.deps import require_admin, require_analyst_or_admin

router = APIRouter(prefix="/audit", tags=["Audit Trail & Governance"])

@router.get("", response_model=List[AuditRecordResponse])
def list_audit_trail(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    actor_id: Optional[str] = Query(None),
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Returns immutable, append-only security audit trail records.
    Contains cryptographic correlation IDs, actor roles, target entities, and outcomes.
    Sensitive credentials and raw text are strictly omitted at ingestion time.
    """
    query = db.query(AuditRecord)
    if action:
        query = query.filter(AuditRecord.action == action.upper())
    if outcome:
        query = query.filter(AuditRecord.outcome == outcome.upper())
    if actor_id:
        query = query.filter(AuditRecord.actor_id.ilike(f"%{actor_id}%"))

    records = query.order_by(desc(AuditRecord.timestamp)).offset(offset).limit(limit).all()

    formatted = []
    for r in records:
        try:
            meta = json.loads(r.context_metadata)
        except Exception:
            meta = {}

        formatted.append({
            "id": r.id,
            "timestamp": r.timestamp,
            "actor_id": r.actor_id,
            "actor_role": r.actor_role,
            "action": r.action,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "outcome": r.outcome,
            "request_id": r.request_id,
            "client_ip": r.client_ip,
            "context_metadata": meta,
            "created_at": r.created_at
        })

    return formatted
