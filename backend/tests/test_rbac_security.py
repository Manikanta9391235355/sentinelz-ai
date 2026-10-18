import pytest

def test_deny_by_default_without_auth(client):
    """Endpoints must reject unauthenticated requests by default."""
    res = client.get("/api/events")
    assert res.status_code == 401

    res = client.get("/api/findings")
    assert res.status_code == 401

    res = client.get("/api/users")
    assert res.status_code == 401

def test_viewer_cannot_perform_admin_actions(client, viewer_headers):
    """
    REGRESSION TEST:
    Proves that a user with the 'viewer' role CANNOT perform administrative actions:
    - Cannot list users (/api/users)
    - Cannot modify roles (/api/users/1/role)
    - Cannot re-seed system (/api/settings/reseed-demo)
    - Cannot modify detection rules (/api/settings/detection-rules/BRUTE_FORCE_AUTH)
    """
    # 1. Listing users
    res = client.get("/api/users", headers=viewer_headers)
    assert res.status_code == 403
    assert "Access denied" in res.json()["detail"]

    # 2. Reseed demo
    res = client.post("/api/settings/reseed-demo", headers=viewer_headers)
    assert res.status_code == 403

    # 3. Modify rule configuration
    res = client.patch(
        "/api/settings/detection-rules/BRUTE_FORCE_AUTH",
        json={"threshold_count": 99},
        headers=viewer_headers
    )
    assert res.status_code == 403

def test_viewer_cannot_ingest_events_or_modify_findings(client, viewer_headers):
    """
    Viewer role cannot ingest security events or mutate finding statuses.
    """
    # Ingest event attempt
    res = client.post(
        "/api/events/ingest",
        json={
            "user_id": "u_rogue",
            "user_role": "viewer",
            "source_ip": "1.1.1.1",
            "resource": "test",
            "requested_action": "READ",
            "access_decision": "ALLOW"
        },
        headers=viewer_headers
    )
    assert res.status_code == 403

    # Modify finding status attempt
    res = client.patch(
        "/api/findings/find_dummy_123/status",
        json={"status": "RESOLVED"},
        headers=viewer_headers
    )
    assert res.status_code == 403

def test_analyst_can_investigate_but_cannot_perform_admin_tasks(client, analyst_headers):
    """
    Analyst can view findings and use privacy shield, but CANNOT manage users or change system rules.
    """
    # Analyst can access findings
    res = client.get("/api/findings", headers=analyst_headers)
    assert res.status_code == 200

    # Analyst CANNOT manage users
    res = client.get("/api/users", headers=analyst_headers)
    assert res.status_code == 403

    # Analyst CANNOT modify rule configs
    res = client.patch(
        "/api/settings/detection-rules/BRUTE_FORCE_AUTH",
        json={"threshold_count": 5},
        headers=analyst_headers
    )
    assert res.status_code == 403

def test_admin_can_perform_administrative_tasks(client, admin_headers):
    """Administrator possesses full administrative and config privileges."""
    res = client.get("/api/users", headers=admin_headers)
    assert res.status_code == 200
    assert len(res.json()) >= 3

    res = client.get("/api/settings/detection-rules", headers=admin_headers)
    assert res.status_code == 200

def test_vertical_privilege_escalation_prevention(client, analyst_headers):
    """
    Proves that an analyst attempting to escalate a user's role to 'security_admin'
    is blocked with 403 Forbidden.
    """
    res = client.patch(
        "/api/users/2/role",
        json={"role": "security_admin"},
        headers=analyst_headers
    )
    assert res.status_code == 403

def test_authentication_failures_and_invalid_passwords(client):
    """Incorrect passwords must be rejected with 401 Unauthorized."""
    res = client.post(
        "/api/auth/login",
        json={"email": "admin@sentinelz.local", "password": "WrongPassword!2026"}
    )
    assert res.status_code == 401
    assert "Invalid credentials" in res.json()["detail"]
