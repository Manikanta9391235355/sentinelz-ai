#!/usr/bin/env python3
"""
SentinelZ AI — Live Telemetry & Threat Simulator
Simulates a realistic SOC event stream for live demonstration during the IBM Z Datathon 2026.
"""

import sys
import os
import time
import random
import argparse
from datetime import datetime

try:
    import httpx
except ImportError:
    print("[ERROR] httpx is required for simulation. Run `pip install httpx`.")
    sys.exit(1)

BASE_URL = "http://localhost:8000/api"

# Synthetic entities adhere to RFC 5737 and simulated identifiers
SYNTHETIC_USERS = [
    {"id": "usr-jchen", "role": "security_analyst", "ip": "198.51.100.12"},
    {"id": "usr-mpatel", "role": "security_admin", "ip": "198.51.100.15"},
    {"id": "usr-drossi", "role": "viewer", "ip": "198.51.100.22"},
    {"id": "usr-external-contractor", "role": "viewer", "ip": "203.0.113.89"},
    {"id": "svc-batch-loader", "role": "viewer", "ip": "198.51.100.100"},
]

NORMAL_ACTIONS = [
    ("AUTHENTICATE", "/api/v1/auth/session", "INTERNAL", "ALLOW", "SUCCESS"),
    ("READ", "/soc/telemetry", "INTERNAL", "ALLOW", "SUCCESS"),
    ("READ", "/data/anonymized-telemetry-v1", "CONFIDENTIAL", "ALLOW", "SUCCESS"),
    ("READ", "/reports/daily-compliance.pdf", "INTERNAL", "ALLOW", "SUCCESS"),
    ("READ", "/soc/audit-stream", "CONFIDENTIAL", "ALLOW", "SUCCESS"),
    ("READ", "/platform/lpar/health", "INTERNAL", "ALLOW", "SUCCESS"),
]

THREAT_SCENARIOS = [
    {
        "name": "High-Value Asset Probing",
        "events": [
            {
                "user_id": "usr-drossi",
                "user_role": "viewer",
                "source_ip": "198.51.100.22",
                "resource": "/secure/hsm/linuxone-master-key",
                "requested_action": "READ",
                "resource_classification": "RESTRICTED_HIGH_VALUE",
                "access_decision": "DENY",
                "auth_result": "SUCCESS",
                "context_metadata": {"threat_note": "Unprivileged viewer requested export of master HSM key"}
            }
        ]
    },
    {
        "name": "Brute Force Authentication Burst",
        "events": [
            {
                "user_id": "usr-unknown-probe",
                "user_role": "viewer",
                "source_ip": "203.0.113.144",
                "resource": "/api/v1/admin/login",
                "requested_action": "AUTHENTICATE",
                "resource_classification": "INTERNAL",
                "access_decision": "DENY",
                "auth_result": "FAILURE",
                "context_metadata": {"attempt": i + 1, "failure_reason": "INVALID_PASSWORD_HASH"}
            }
            for i in range(5)
        ]
    },
    {
        "name": "Privilege Mismatch Violation",
        "events": [
            {
                "user_id": "usr-external-contractor",
                "user_role": "viewer",
                "source_ip": "203.0.113.89",
                "resource": "/admin/rbac/roles/reassign",
                "requested_action": "ADMIN_DELETE",
                "resource_classification": "RESTRICTED_HIGH_VALUE",
                "access_decision": "DENY",
                "auth_result": "SUCCESS",
                "context_metadata": {"threat_note": "Attempted administrative mutation by viewer account"}
            }
        ]
    },
    {
        "name": "Reconnaissance Port & Resource Scanning",
        "events": [
            {
                "user_id": "usr-scanner-probe",
                "user_role": "viewer",
                "source_ip": "203.0.113.200",
                "resource": f"/api/v1/internal/endpoint_{k}",
                "requested_action": "READ",
                "resource_classification": "INTERNAL",
                "access_decision": "DENY",
                "auth_result": "FAILURE",
                "context_metadata": {"probe_index": k}
            }
            for k in range(5)
        ]
    }
]

def authenticate(client: httpx.Client) -> str:
    res = client.post(
        f"{BASE_URL}/auth/login",
        json={"email": "analyst@sentinelz.local", "password": "SentinelAnalyst#2026"}
    )
    if res.status_code != 200:
        raise RuntimeError(f"Authentication failed with status {res.status_code}: {res.text}")
    return res.json()["access_token"]

def send_event(client: httpx.Client, token: str, event_data: dict):
    headers = {"Authorization": f"Bearer {token}"}
    res = client.post(f"{BASE_URL}/events/ingest", json=event_data, headers=headers)
    return res

def main():
    global BASE_URL
    parser = argparse.ArgumentParser(description="SentinelZ AI Telemetry Simulator")
    parser.add_argument("--url", default=os.getenv("SENTINELZ_TARGET_URL", BASE_URL), help="Target API URL")
    parser.add_argument("--count", type=int, default=15, help="Number of telemetry cycles to simulate")
    parser.add_argument("--interval", type=float, default=1.5, help="Seconds between telemetry emissions")
    parser.add_argument("--inject-threats", action="store_true", default=True, help="Inject realistic threat scenarios")
    args = parser.parse_args()

    BASE_URL = args.url.rstrip('/')

    print("\n" + "=" * 70)
    print(" SentinelZ AI — Real-Time Telemetry & Threat Simulator")
    print(" Tagline: Intelligence Without Exposure")
    print(f" Target API: {BASE_URL}")
    print(f" Cycles: {args.count} | Interval: {args.interval}s")
    print("=" * 70 + "\n")

    client = httpx.Client(timeout=10.0)

    try:
        token = authenticate(client)
        print("[AUTH] Successfully authenticated as Security Analyst (analyst@sentinelz.local)\n")
    except Exception as e:
        print(f"[ERROR] Could not connect or authenticate with SentinelZ backend: {e}")
        print("Ensure backend is running on http://127.0.0.1:8000")
        sys.exit(1)

    cycle = 0
    while cycle < args.count:
        cycle += 1
        now_str = datetime.now().strftime("%H:%M:%S")

        # Every 4th cycle, inject an explainable threat scenario
        if args.inject_threats and (cycle % 4 == 0):
            scenario = random.choice(THREAT_SCENARIOS)
            print(f"\033[93m[{now_str}] [INJECTING SCENARIO]\033[0m {scenario['name']} ({len(scenario['events'])} events)...")
            
            for ev in scenario["events"]:
                resp = send_event(client, token, ev)
                if resp.status_code == 200:
                    data = resp.json()
                    ev_id = data.get("id", "N/A")
                    # Check if a threat finding was generated for this event
                    headers = {"Authorization": f"Bearer {token}"}
                    findings_resp = client.get(f"{BASE_URL}/findings?limit=5", headers=headers)
                    new_findings = []
                    if findings_resp.status_code == 200:
                        for f in findings_resp.json():
                            if ev_id in f.get("related_event_ids", []):
                                new_findings.append(f)
                    
                    if new_findings:
                        for f in new_findings:
                            sev = f.get("severity", "MEDIUM")
                            score = f.get("risk_score", 0)
                            rule = f.get("detection_method", "RULE")
                            print(f"  [THREAT DETECTED] Rule: {rule} | Severity: {sev} | Risk Score: {score}/100")
                            print(f"     Title: {f.get('title')}")
                            print(f"     Explanation: {f.get('explanation')[:85]}...")
                    else:
                        print(f"  -> Event {ev_id}: Ingested (Sliding correlation window active)")
                time.sleep(0.3)
        else:
            # Emit normal synthetic SOC telemetry
            u = random.choice(SYNTHETIC_USERS)
            action, res_acc, sens, dec, auth = random.choice(NORMAL_ACTIONS)
            ev = {
                "user_id": u["id"],
                "user_role": u["role"],
                "source_ip": u["ip"],
                "resource": res_acc,
                "requested_action": action,
                "resource_classification": sens,
                "access_decision": dec,
                "auth_result": auth,
                "context_metadata": {"cycle": cycle, "platform": "IBM LinuxONE s390x"}
            }
            resp = send_event(client, token, ev)
            if resp.status_code == 200:
                data = resp.json()
                print(f"[{now_str}] [TELEMETRY #{cycle:02d}] User: {u['id']:<20} Action: {action:<14} Decision: \033[92m{dec}\033[0m")
            else:
                print(f"[{now_str}] [ERROR] Ingestion returned {resp.status_code}: {resp.text}")

        time.sleep(args.interval)

    print("\n" + "=" * 70)
    print(" Simulation completed. Check the SOC dashboard at http://localhost:3000")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()
