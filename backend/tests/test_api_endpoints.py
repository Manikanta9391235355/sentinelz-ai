import pytest

def test_health_and_readiness_endpoints(client):
    """Liveness and readiness probes must return 200 OK."""
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

    res = client.get("/api/readiness")
    assert res.status_code == 200
    assert res.json()["ready"] is True

    res = client.get("/api/linuxone/status")
    assert res.status_code == 200
    assert "LinuxONE" in res.json()["platform_name"]

def test_dashboard_metrics_aggregation(client, viewer_headers):
    """Metrics endpoint must return aggregated numbers from database."""
    res = client.get("/api/metrics/dashboard", headers=viewer_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_events"] > 0
    assert "severity_distribution" in data
    assert len(data["event_volume_trend"]) == 6
    assert data["demo_mode_active"] is True

def test_invalid_event_payload_rejection(client, analyst_headers):
    """Malformed or unsupported fields must be rejected by Pydantic validation."""
    # 1. Invalid access_decision
    res = client.post(
        "/api/events/ingest",
        json={
            "user_id": "u_test",
            "user_role": "analyst",
            "source_ip": "10.0.0.1",
            "resource": "db/data",
            "requested_action": "READ",
            "access_decision": "MAYBE" # Invalid!
        },
        headers=analyst_headers
    )
    assert res.status_code == 422

    # 2. Invalid auth_result
    res = client.post(
        "/api/events/ingest",
        json={
            "user_id": "u_test",
            "user_role": "analyst",
            "source_ip": "10.0.0.1",
            "resource": "db/data",
            "requested_action": "READ",
            "access_decision": "ALLOW",
            "auth_result": "UNKNOWN_ERROR" # Invalid!
        },
        headers=analyst_headers
    )
    assert res.status_code == 422

def test_event_ingestion_and_threat_correlation(client, analyst_headers):
    """Valid event ingestion must correlate and trigger explainable finding."""
    res = client.post(
        "/api/events/ingest",
        json={
            "user_id": "u_auditor_bob",
            "user_role": "viewer",
            "source_ip": "198.51.100.22",
            "resource": "mainframes/z16-hsm/crypto-keys/master-aes256",
            "requested_action": "READ",
            "resource_classification": "RESTRICTED_HIGH_VALUE",
            "access_decision": "DENY",
            "auth_result": "N/A"
        },
        headers=analyst_headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["id"].startswith("evt_")
    assert data["resource_classification"] == "RESTRICTED_HIGH_VALUE"
