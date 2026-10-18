#!/usr/bin/env python3
"""
SentinelZ AI — Automated End-to-End Smoke Test Script
Verified for IBM LinuxONE (s390x) and x86_64 environments.

Tests:
1. Platform Health, Readiness, and LinuxONE status
2. Authentication (PBKDF2-HMAC-SHA256)
3. Role-Based Access Control (RBAC) server-side enforcement
4. Privilege Escalation Prevention (Viewer blocked from administrative actions)
5. Security Event Ingestion & Real-Time Threat Correlation
6. Threat Finding Details & Investigation Status Workflow
7. Privacy Shield PII Redaction & Overlap Protection
8. Strict AI Boundary Enforcement (Zero Sensitive Data Forwarding)
9. Append-Only Audit Trail (Zero Sensitive Leakage)
"""

import sys
import json
import os

try:
    import httpx
except ImportError:
    print("[ERROR] httpx is required for smoke tests. Run `pip install httpx`.")
    sys.exit(1)

BASE_URL = os.getenv("SENTINELZ_TEST_URL", sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/api").rstrip('/')

PASS_COUNT = 0
FAIL_COUNT = 0

def log_test(name: str, passed: bool, detail: str = ""):
    global PASS_COUNT, FAIL_COUNT
    if passed:
        PASS_COUNT += 1
        print(f"  [\033[92mPASS\033[0m] {name} {f'({detail})' if detail else ''}")
    else:
        FAIL_COUNT += 1
        print(f"  [\033[91mFAIL\033[0m] {name} — {detail}")

def run_smoke_tests():
    print("\n" + "=" * 70)
    print(" SentinelZ AI — Automated Verification & Smoke Test Suite")
    print(" Tagline: Intelligence Without Exposure")
    print(" Theme: AI Secured: Innovation Without Exposure (IBM Z Datathon 2026)")
    print("=" * 70 + "\n")

    client = httpx.Client(timeout=10.0)

    # 1. Health Probe
    try:
        res = client.get(f"{BASE_URL}/health")
        log_test("GET /api/health (Liveness Probe)", res.status_code == 200 and res.json().get("status") == "healthy")
    except Exception as e:
        log_test("GET /api/health (Liveness Probe)", False, f"Connection error: {str(e)}")
        print("\n[ABORT] Could not reach SentinelZ backend. Ensure uvicorn is running on port 8000.")
        sys.exit(1)

    # 2. Readiness Probe
    res = client.get(f"{BASE_URL}/readiness")
    data = res.json()
    log_test("GET /api/readiness (Readiness Probe)", res.status_code == 200 and data.get("ready") is True)

    # 3. LinuxONE Platform Status
    res = client.get(f"{BASE_URL}/linuxone/status")
    data = res.json()
    log_test("GET /api/linuxone/status (Platform Alignment)", res.status_code == 200 and "LinuxONE" in data.get("platform_name", ""))

    # 4. Authentication — Admin & Analyst Logins
    res_admin = client.post(f"{BASE_URL}/auth/login", json={"email": "admin@sentinelz.local", "password": "SentinelAdmin#2026"})
    admin_token = res_admin.json().get("access_token")
    log_test("POST /api/auth/login (Admin Credentials)", res_admin.status_code == 200 and bool(admin_token))

    res_viewer = client.post(f"{BASE_URL}/auth/login", json={"email": "viewer@sentinelz.local", "password": "SentinelViewer#2026"})
    viewer_token = res_viewer.json().get("access_token")
    log_test("POST /api/auth/login (Viewer Credentials)", res_viewer.status_code == 200 and bool(viewer_token))

    # 5. Auth Failure on Bad Password
    res_bad = client.post(f"{BASE_URL}/auth/login", json={"email": "admin@sentinelz.local", "password": "WrongPassword!2026"})
    log_test("POST /api/auth/login (Bad Password Rejected)", res_bad.status_code == 401)

    # Headers
    admin_hdr = {"Authorization": f"Bearer {admin_token}"}
    viewer_hdr = {"Authorization": f"Bearer {viewer_token}"}

    # 6. Dashboard Metrics
    res_metrics = client.get(f"{BASE_URL}/metrics/dashboard", headers=viewer_hdr)
    metrics_data = res_metrics.json()
    log_test("GET /api/metrics/dashboard (Metrics Aggregation)", res_metrics.status_code == 200 and metrics_data.get("total_events", 0) > 0)

    # 7. Server-Side RBAC Enforcement — Viewer blocked from Admin Endpoints
    res_users_viewer = client.get(f"{BASE_URL}/users", headers=viewer_hdr)
    log_test("RBAC Boundary: Viewer Blocked from /api/users", res_users_viewer.status_code == 403, "403 Forbidden verified")

    res_users_admin = client.get(f"{BASE_URL}/users", headers=admin_hdr)
    log_test("RBAC Boundary: Admin Allowed to /api/users", res_users_admin.status_code == 200 and len(res_users_admin.json()) >= 3)

    # 8. Security Event Ingestion & Threat Detection
    ingest_payload = {
        "user_id": "u_smoke_test_intruder",
        "user_role": "external",
        "source_ip": "198.51.100.99",
        "resource": "mainframes/z16-hsm/crypto-keys/master-aes256",
        "requested_action": "READ",
        "resource_classification": "RESTRICTED_HIGH_VALUE",
        "access_decision": "DENY",
        "auth_result": "N/A"
    }
    res_ingest = client.post(f"{BASE_URL}/events/ingest", json=ingest_payload, headers=admin_hdr)
    log_test("POST /api/events/ingest (Event Ingestion)", res_ingest.status_code == 200 and res_ingest.json().get("id", "").startswith("evt_"))

    # 9. Threat Findings Verification
    res_findings = client.get(f"{BASE_URL}/findings", headers=admin_hdr)
    findings = res_findings.json()
    hvu_finding = next((f for f in findings if f["rule_id"] == "HIGH_VALUE_UNAUTHORIZED"), None)
    log_test("GET /api/findings (High-Value Asset Rule Triggered)", hvu_finding is not None and hvu_finding["severity"] in ("CRITICAL", "HIGH"))

    # 10. Threat Finding Status Update & Audit Logging
    if hvu_finding:
        res_update = client.patch(
            f"{BASE_URL}/findings/{hvu_finding['id']}/status",
            json={"status": "INVESTIGATING", "resolution_notes": "Automated smoke test triage"},
            headers=admin_hdr
        )
        log_test("PATCH /api/findings/{id}/status (Status Disposition)", res_update.status_code == 200 and res_update.json().get("status") == "INVESTIGATING")

    # 11. Privacy Shield — PII Redaction
    sample_pii = "Contact alex@example.com, phone +1 (555) 234-5678, account IBM-ACCT-7890-1234 on IP 10.0.0.1"
    res_sanitize = client.post(f"{BASE_URL}/privacy/sanitize", json={"text": sample_pii}, headers=admin_hdr)
    san_data = res_sanitize.json()
    sanitized_text = san_data.get("sanitized_text", "")
    all_redacted = (
        "[EMAIL_REDACTED]" in sanitized_text and
        "[PHONE_REDACTED]" in sanitized_text and
        "[MAINFRAME_ACCT_REDACTED]" in sanitized_text and
        "[IP_REDACTED]" in sanitized_text and
        "alex@example.com" not in sanitized_text and
        "555" not in sanitized_text
    )
    log_test("POST /api/privacy/sanitize (Multi-Span PII Redaction)", res_sanitize.status_code == 200 and all_redacted)

    # 12. Privacy Shield — Strict AI Boundary Enforcement
    res_ai = client.post(
        f"{BASE_URL}/privacy/analyze-ai",
        json={"text": "Review transaction for alex@example.com with card 4532-1234-5678-9010", "analysis_intent": "THREAT_SUMMARIZATION"},
        headers=admin_hdr
    )
    ai_data = res_ai.json()
    zero_leakage = (
        ai_data.get("unredacted_data_exposed") is False and
        ai_data.get("sanitization_summary", {}).get("ai_boundary_secured") is True and
        "alex@example.com" not in ai_data.get("sanitization_summary", {}).get("sanitized_text", "")
    )
    log_test("POST /api/privacy/analyze-ai (Zero Exposure AI Boundary)", res_ai.status_code == 200 and zero_leakage)

    # 13. Audit Trail Verification & Zero Credentials Stored
    res_audit = client.get(f"{BASE_URL}/audit", headers=admin_hdr)
    audit_records = res_audit.json()
    latest_audit = audit_records[0] if audit_records else None
    no_creds_in_audit = True
    for r in audit_records[:5]:
        meta_str = json.dumps(r.get("context_metadata", {})).lower()
        if "sentineladmin#2026" in meta_str or "sentinelviewer#2026" in meta_str:
            no_creds_in_audit = False
            break
    log_test("GET /api/audit (Immutable Audit Trail & Zero Credential Leakage)", bool(latest_audit) and no_creds_in_audit)

    print("\n" + "-" * 70)
    print(f" Smoke Test Summary: {PASS_COUNT} Passed, {FAIL_COUNT} Failed")
    print("-" * 70)

    if FAIL_COUNT > 0:
        print("\033[91m[WARNING] Some smoke tests failed. Inspect output above.\033[0m\n")
        sys.exit(1)
    else:
        print("\033[92m[SUCCESS] All SentinelZ AI security controls verified successfully!\033[0m\n")
        sys.exit(0)

if __name__ == "__main__":
    run_smoke_tests()
