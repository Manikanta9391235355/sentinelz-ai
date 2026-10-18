import pytest
from datetime import datetime, timedelta
from backend.app.models.all_models import SecurityEvent, ThreatFinding
from backend.app.services.threat_engine import threat_engine

def test_high_value_unauthorized_detection(db_session):
    """
    Scenario: Unauthorized attempt on RESTRICTED_HIGH_VALUE asset
    must trigger an immediate CRITICAL / HIGH severity finding.
    """
    event = SecurityEvent(
        id="test_evt_hvu_01",
        timestamp=datetime.utcnow(),
        user_id="u_untrusted_ext",
        user_role="external",
        source_ip="198.51.100.99",
        resource="mainframes/z16-hsm/crypto-keys/master-aes256",
        requested_action="READ",
        resource_classification="RESTRICTED_HIGH_VALUE",
        access_decision="DENY",
        auth_result="N/A",
        context_metadata="{}",
        is_synthetic=True,
        created_at=datetime.utcnow()
    )
    db_session.add(event)
    db_session.commit()

    findings = threat_engine.analyze_event(db_session, event)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "HIGH_VALUE_UNAUTHORIZED"
    assert f.severity in ("CRITICAL", "HIGH")
    assert f.risk_score >= 80.0
    assert "mainframes/z16-hsm" in f.explanation
    assert f.affected_identity == "u_untrusted_ext"

def test_brute_force_detection(db_session):
    """
    Scenario: Multiple failed authentications in sliding window (>= 3)
    must trigger BRUTE_FORCE_AUTH finding.
    """
    now = datetime.utcnow()
    user_target = "u_brute_victim_01"
    ip = "192.0.2.77"

    for i in range(3):
        evt = SecurityEvent(
            id=f"test_bfa_evt_{i}",
            timestamp=now - timedelta(seconds=60 - (i * 15)),
            user_id=user_target,
            user_role="unauthenticated",
            source_ip=ip,
            resource="api/v1/auth/login",
            requested_action="AUTHENTICATE",
            resource_classification="INTERNAL",
            access_decision="DENY",
            auth_result="FAILURE",
            context_metadata="{}",
            is_synthetic=True,
            created_at=now - timedelta(seconds=60 - (i * 15))
        )
        db_session.add(evt)
        db_session.commit()
        findings = threat_engine.analyze_event(db_session, evt)

    # After the 3rd failed attempt, BRUTE_FORCE_AUTH finding must be triggered
    assert len(findings) >= 1
    bfa_finding = next((f for f in findings if f.rule_id == "BRUTE_FORCE_AUTH"), None)
    assert bfa_finding is not None
    assert bfa_finding.affected_identity == user_target
    assert bfa_finding.risk_score >= 50.0

def test_privilege_mismatch_detection(db_session):
    """
    Scenario: User with 'viewer' role requesting ADMIN_DELETE or RESTRICTED resource
    must trigger PRIVILEGE_MISMATCH.
    """
    event = SecurityEvent(
        id="test_prm_evt_01",
        timestamp=datetime.utcnow(),
        user_id="u_audit_viewer_temp",
        user_role="viewer",
        source_ip="10.0.0.15",
        resource="db/admin/purge-logs",
        requested_action="ADMIN_DELETE",
        resource_classification="RESTRICTED_HIGH_VALUE",
        access_decision="DENY",
        auth_result="N/A",
        context_metadata="{}",
        is_synthetic=True,
        created_at=datetime.utcnow()
    )
    db_session.add(event)
    db_session.commit()

    findings = threat_engine.analyze_event(db_session, event)
    prm_finding = next((f for f in findings if f.rule_id == "PRIVILEGE_MISMATCH"), None)
    assert prm_finding is not None
    assert prm_finding.affected_identity == "u_audit_viewer_temp"
    assert "ADMIN_DELETE" in prm_finding.explanation

def test_recon_probing_detection(db_session):
    """
    Scenario: Successive denials across 3 distinct resources triggers RECON_PROBING.
    """
    now = datetime.utcnow()
    actor = "u_recon_scanner"
    ip = "203.0.113.55"
    targets = ["/api/v1/secret-a", "/api/v1/secret-b", "/api/v1/secret-c"]

    findings = []
    for idx, target in enumerate(targets):
        evt = SecurityEvent(
            id=f"test_rcn_evt_{idx}",
            timestamp=now - timedelta(seconds=30 - (idx * 5)),
            user_id=actor,
            user_role="external",
            source_ip=ip,
            resource=target,
            requested_action="READ",
            resource_classification="CONFIDENTIAL",
            access_decision="DENY",
            auth_result="N/A",
            context_metadata="{}",
            is_synthetic=True,
            created_at=now - timedelta(seconds=30 - (idx * 5))
        )
        db_session.add(evt)
        db_session.commit()
        findings = threat_engine.analyze_event(db_session, evt)

    rcn_finding = next((f for f in findings if f.rule_id == "RECON_PROBING"), None)
    assert rcn_finding is not None
    assert rcn_finding.affected_identity == actor

def test_risk_score_boundaries():
    """
    Verifies that the deterministic risk scoring formula stays strictly
    within bounds [0.0, 100.0] even under extreme values.
    """
    low_score = threat_engine.compute_risk_score(base_weight=0.0, event_count=0, classification="PUBLIC", has_denials=False)
    assert 0.0 <= low_score <= 100.0

    high_score = threat_engine.compute_risk_score(base_weight=90.0, event_count=50, classification="RESTRICTED_HIGH_VALUE", has_denials=True)
    assert high_score == 100.0
    assert 0.0 <= high_score <= 100.0
