import pytest
from backend.app.models.all_models import AuditRecord

def test_audit_created_on_login_and_no_credentials_leaked(client, db_session):
    """
    Verifies that authentication creates an audit record
    and that plain password or token is NEVER recorded in context_metadata.
    """
    initial_count = db_session.query(AuditRecord).count()

    res = client.post(
        "/api/auth/login",
        json={"email": "analyst@sentinelz.local", "password": "SentinelAnalyst#2026"}
    )
    assert res.status_code == 200

    latest_audit = db_session.query(AuditRecord).order_by(AuditRecord.id.desc()).first()
    assert latest_audit is not None
    assert latest_audit.action == "AUTH_LOGIN"
    assert latest_audit.outcome == "SUCCESS"
    assert latest_audit.actor_id == "analyst@sentinelz.local"

    # CRITICAL: Verify context metadata contains NO passwords, secrets, or tokens
    meta_str = latest_audit.context_metadata.lower()
    assert "sentinelanalyst#2026" not in meta_str
    assert "password" not in meta_str or "[redacted" in meta_str

def test_audit_created_on_finding_status_change(client, analyst_headers, db_session):
    """
    Verifies that changing a finding's status records an audit entry with the analyst's ID.
    """
    # Create or fetch a finding
    from backend.app.models.all_models import ThreatFinding
    finding = db_session.query(ThreatFinding).first()
    assert finding is not None

    res = client.patch(
        f"/api/findings/{finding.id}/status",
        json={"status": "INVESTIGATING", "resolution_notes": "Triage in progress by Marcus Chen"},
        headers=analyst_headers
    )
    assert res.status_code == 200

    latest_audit = db_session.query(AuditRecord).order_by(AuditRecord.id.desc()).first()
    assert latest_audit.action == "FINDING_STATUS_CHANGE"
    assert latest_audit.target_id == finding.id
    assert latest_audit.outcome == "SUCCESS"
    assert "INVESTIGATING" in latest_audit.context_metadata
