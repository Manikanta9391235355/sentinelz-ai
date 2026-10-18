import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from backend.app.database import get_db
from backend.app.models.all_models import (
    SecurityEvent, ThreatFinding, AuditRecord, PrivacyRedactionLog, User
)
from backend.app.schemas.all_schemas import (
    DashboardMetricsResponse, SeverityDistribution, EventTrendPoint,
    ThreatFindingResponse, AuditRecordResponse
)
from backend.app.api.deps import require_any_authenticated
from backend.app.api.findings import _format_finding

router = APIRouter(prefix="/metrics", tags=["Security Operations Metrics"])

@router.get("/dashboard", response_model=DashboardMetricsResponse)
def get_dashboard_metrics(
    current_user: User = Depends(require_any_authenticated),
    db: Session = Depends(get_db)
):
    """
    Computes live, aggregate security operations telemetry from persisted records.
    Accessible to all authenticated personas (Viewer, Analyst, Administrator).
    """
    total_events = db.query(SecurityEvent).count()
    
    # High risk events: findings with risk_score >= 60.0
    high_risk_findings = db.query(ThreatFinding).filter(ThreatFinding.risk_score >= 60.0).count()
    
    # Events requiring investigation: OPEN findings
    open_findings = db.query(ThreatFinding).filter(ThreatFinding.status == "OPEN").count()
    
    # Unauthorized access attempts: DENY decisions
    unauthorized_attempts = db.query(SecurityEvent).filter(SecurityEvent.access_decision == "DENY").count()
    
    # Redaction count from privacy logs
    privacy_logs = db.query(PrivacyRedactionLog).all()
    sensitive_data_redactions = sum(l.entities_redacted_count for l in privacy_logs)

    # Severity distribution of findings
    crit_count = db.query(ThreatFinding).filter(ThreatFinding.severity == "CRITICAL").count()
    high_count = db.query(ThreatFinding).filter(ThreatFinding.severity == "HIGH").count()
    med_count = db.query(ThreatFinding).filter(ThreatFinding.severity == "MEDIUM").count()
    low_count = db.query(ThreatFinding).filter(ThreatFinding.severity == "LOW").count()

    # Event volume trend (aggregate into 6 time slices across recent hours)
    now = datetime.utcnow()
    trend_points = []
    for h in range(5, -1, -1):
        window_start = now - timedelta(hours=h+1)
        window_end = now - timedelta(hours=h)
        label = window_start.strftime("%H:%M")

        ev_count = db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.timestamp < window_end
        ).count()

        denied_c = db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.timestamp < window_end,
            SecurityEvent.access_decision == "DENY"
        ).count()

        find_c = db.query(ThreatFinding).filter(
            ThreatFinding.created_at >= window_start,
            ThreatFinding.created_at < window_end
        ).count()

        trend_points.append(EventTrendPoint(
            time_label=label,
            event_count=ev_count,
            anomaly_count=find_c,
            denied_count=denied_c
        ))

    # Recent findings
    recent_find_records = db.query(ThreatFinding).order_by(
        desc(ThreatFinding.created_at)
    ).limit(5).all()
    recent_findings = [_format_finding(f) for f in recent_find_records]

    # Recent audit events
    recent_audit_records = db.query(AuditRecord).order_by(
        desc(AuditRecord.timestamp)
    ).limit(6).all()
    recent_audit = []
    for a in recent_audit_records:
        try:
            meta = json.loads(a.context_metadata)
        except Exception:
            meta = {}
        recent_audit.append({
            "id": a.id,
            "timestamp": a.timestamp,
            "actor_id": a.actor_id,
            "actor_role": a.actor_role,
            "action": a.action,
            "target_type": a.target_type,
            "target_id": a.target_id,
            "outcome": a.outcome,
            "request_id": a.request_id,
            "client_ip": a.client_ip,
            "context_metadata": meta,
            "created_at": a.created_at
        })

    return {
        "total_events": total_events,
        "high_risk_events": high_risk_findings,
        "events_requiring_investigation": open_findings,
        "unauthorized_access_attempts": unauthorized_attempts,
        "sensitive_data_redactions": sensitive_data_redactions,
        "open_findings_count": open_findings,
        "severity_distribution": SeverityDistribution(
            critical=crit_count,
            high=high_count,
            medium=med_count,
            low=low_count
        ),
        "event_volume_trend": trend_points,
        "recent_findings": recent_findings,
        "recent_audit": recent_audit,
        "demo_mode_active": True
    }
