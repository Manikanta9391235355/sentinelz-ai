import json
import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from backend.app.models.all_models import (
    User, SecurityEvent, ThreatFinding, AuditRecord, DetectionRuleConfig
)
from backend.app.core.security import hash_password
from backend.app.services.threat_engine import threat_engine

DEMO_USERS = [
    {
        "email": "admin@sentinelz.local",
        "username": "sec_admin",
        "full_name": "Dr. Eleanor Vance (CISO / Admin)",
        "password": "SentinelAdmin#2026",
        "role": "security_admin"
    },
    {
        "email": "analyst@sentinelz.local",
        "username": "sec_analyst",
        "full_name": "Marcus Chen (Lead SOC Analyst)",
        "password": "SentinelAnalyst#2026",
        "role": "security_analyst"
    },
    {
        "email": "viewer@sentinelz.local",
        "username": "compliance_viewer",
        "full_name": "Amina Al-Mansoor (Audit & Compliance)",
        "password": "SentinelViewer#2026",
        "role": "viewer"
    }
]

def seed_database(db: Session, force: bool = False):
    """
    Populates database with initial users, rules, and realistic synthetic security events.
    """
    user_count = db.query(User).count()
    if user_count > 0 and not force:
        return {"status": "already_seeded", "user_count": user_count}

    # 1. Reset tables if forced
    if force:
        db.query(ThreatFinding).delete()
        db.query(SecurityEvent).delete()
        db.query(AuditRecord).delete()
        db.query(DetectionRuleConfig).delete()
        db.query(User).delete()
        db.commit()

    # 2. Seed Demo Users
    for u in DEMO_USERS:
        pwd_hash, salt = hash_password(u["password"])
        user = User(
            email=u["email"],
            username=u["username"],
            full_name=u["full_name"],
            hashed_password=pwd_hash,
            salt=salt,
            role=u["role"],
            is_active=True,
            created_at=datetime.utcnow() - timedelta(days=10)
        )
        db.add(user)
    db.commit()

    # 3. Seed Detection Rules
    for rule_id, rule_info in threat_engine.DEFAULT_RULES.items():
        rule_cfg = DetectionRuleConfig(
            rule_id=rule_id,
            name=rule_info["name"],
            description=rule_info["description"],
            severity=rule_info["severity"],
            base_weight=rule_info["base_weight"],
            threshold_count=rule_info["threshold_count"],
            window_seconds=rule_info["window_seconds"],
            is_enabled=True,
            updated_at=datetime.utcnow(),
            updated_by="system_seeder"
        )
        db.add(rule_cfg)
    db.commit()

    # 4. Generate Realistic Synthetic Security Events
    now = datetime.utcnow()
    synthetic_events = []

    # Scenario 1: Normal authorized traffic (Baseline)
    normal_users = [
        ("u_ops_jordan", "operator", "10.142.1.24", "db/reporting/daily-sync", "READ", "INTERNAL"),
        ("u_dev_priya", "developer", "10.142.2.18", "git/repo/microservices", "READ", "INTERNAL"),
        ("u_dba_samuel", "sysadmin", "10.142.0.12", "mainframes/z16-db2/subsys-a", "READ", "CONFIDENTIAL"),
        ("u_ops_jordan", "operator", "10.142.1.24", "api/v1/metrics/cluster", "READ", "PUBLIC"),
        ("u_billing_kai", "analyst", "10.142.4.50", "apps/billing/invoices", "READ", "CONFIDENTIAL"),
    ]
    for i in range(25):
        usr, role, ip, res, act, cls = normal_users[i % len(normal_users)]
        offset_mins = 180 - (i * 7)
        synthetic_events.append(SecurityEvent(
            id=f"evt_norm_{1000 + i}",
            timestamp=now - timedelta(minutes=offset_mins),
            user_id=usr,
            user_role=role,
            source_ip=ip,
            resource=res,
            requested_action=act,
            resource_classification=cls,
            access_decision="ALLOW",
            auth_result="SUCCESS",
            context_metadata=json.dumps({"session_duration_s": 240 + i, "client": "LinuxONE-Client-Agent/3.2"}),
            is_synthetic=True,
            created_at=now - timedelta(minutes=offset_mins)
        ))

    # Scenario 2: Brute force authentication attempt (Synthetic Actor `u_threat_external`)
    # 4 consecutive failures from IP 198.51.100.77 within 2 minutes
    for j in range(4):
        offset_seconds = 120 - (j * 25)
        synthetic_events.append(SecurityEvent(
            id=f"evt_bfa_{2000 + j}",
            timestamp=now - timedelta(minutes=25, seconds=offset_seconds),
            user_id="u_threat_external",
            user_role="external",
            source_ip="198.51.100.77",
            resource="api/v1/auth/login",
            requested_action="AUTHENTICATE",
            resource_classification="INTERNAL",
            access_decision="DENY",
            auth_result="FAILURE",
            context_metadata=json.dumps({"failure_reason": "INVALID_CREDENTIALS", "attempt_number": j + 1}),
            is_synthetic=True,
            created_at=now - timedelta(minutes=25, seconds=offset_seconds)
        ))

    # Scenario 3: High-Value Mainframe Asset Unauthorized Access
    # Contractor trying to access IBM z16 Crypto Express HSM keys
    synthetic_events.append(SecurityEvent(
        id="evt_hvu_3001",
        timestamp=now - timedelta(minutes=15),
        user_id="u_contractor_dev",
        user_role="contractor",
        source_ip="192.0.2.144",
        resource="mainframes/z16-hsm/crypto-keys/master-aes256",
        requested_action="READ",
        resource_classification="RESTRICTED_HIGH_VALUE",
        access_decision="DENY",
        auth_result="N/A",
        context_metadata=json.dumps({"reason": "INSUFFICIENT_SECURITY_CLEARANCE", "hsm_module": "CryptoExpress8S"}),
        is_synthetic=True,
        created_at=now - timedelta(minutes=15)
    ))

    # Scenario 4: Privilege Mismatch
    # Viewer role attempting ADMIN_DELETE on core audit ledger
    synthetic_events.append(SecurityEvent(
        id="evt_prm_4001",
        timestamp=now - timedelta(minutes=8),
        user_id="u_compliance_guest",
        user_role="viewer",
        source_ip="10.142.8.99",
        resource="mainframes/linuxone/ledger/audit-trail",
        requested_action="ADMIN_DELETE",
        resource_classification="RESTRICTED_HIGH_VALUE",
        access_decision="DENY",
        auth_result="N/A",
        context_metadata=json.dumps({"reason": "IMMUTABLE_AUDIT_VIOLATION"}),
        is_synthetic=True,
        created_at=now - timedelta(minutes=8)
    ))

    # Scenario 5: Reconnaissance Denials across multiple endpoints
    recon_targets = ["api/v1/admin/secrets", "api/v1/users/export", "db/core/credentials"]
    for k, target in enumerate(recon_targets):
        synthetic_events.append(SecurityEvent(
            id=f"evt_rcn_{5000 + k}",
            timestamp=now - timedelta(minutes=4, seconds=45 - (k * 15)),
            user_id="u_recon_probe",
            user_role="unauthenticated",
            source_ip="203.0.113.88",
            resource=target,
            requested_action="READ",
            resource_classification="RESTRICTED_HIGH_VALUE",
            access_decision="DENY",
            auth_result="N/A",
            context_metadata=json.dumps({"http_status": 403, "probe_signature": "automated_scan"}),
            is_synthetic=True,
            created_at=now - timedelta(minutes=4, seconds=45 - (k * 15))
        ))

    # Scenario 6: Rate Anomaly (Burst of 12 requests in 30 seconds)
    for m in range(12):
        synthetic_events.append(SecurityEvent(
            id=f"evt_rte_{6000 + m}",
            timestamp=now - timedelta(seconds=60 - (m * 2)),
            user_id="u_service_scraper",
            user_role="operator",
            source_ip="10.142.3.44",
            resource="api/v1/customers/records",
            requested_action="READ",
            resource_classification="CONFIDENTIAL",
            access_decision="ALLOW",
            auth_result="SUCCESS",
            context_metadata=json.dumps({"batch_id": f"b_{m}"}),
            is_synthetic=True,
            created_at=now - timedelta(seconds=60 - (m * 2))
        ))

    for ev in synthetic_events:
        db.add(ev)
    db.commit()

    # 5. Process events through Threat Engine to produce initial findings
    for ev in synthetic_events:
        threat_engine.analyze_event(db, ev)

    # 6. Seed Initial Audit Log Entries
    audit_samples = [
        ("admin@sentinelz.local", "security_admin", "AUTH_LOGIN", "USER", "admin@sentinelz.local", "SUCCESS", "Initial administrative session established"),
        ("analyst@sentinelz.local", "security_analyst", "AUTH_LOGIN", "USER", "analyst@sentinelz.local", "SUCCESS", "SOC shift rotation login"),
        ("u_threat_external", "unauthenticated", "AUTH_FAILURE", "USER", "u_threat_external", "FAILURE", "Failed password verification (4x threshold)"),
        ("system_seeder", "system", "EVENT_INGESTED", "EVENT", "evt_batch_initial", "SUCCESS", "Generated 46 realistic synthetic security events"),
        ("admin@sentinelz.local", "security_admin", "CONFIG_CHANGE", "CONFIG", "BRUTE_FORCE_AUTH", "SUCCESS", "Verified sliding window parameters (300s)")
    ]
    for act, role, action, target_type, target_id, outcome, notes in audit_samples:
        record = AuditRecord(
            timestamp=now - timedelta(minutes=30),
            actor_id=act,
            actor_role=role,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            request_id=f"req_{uuid.uuid4().hex[:10]}",
            client_ip="127.0.0.1",
            context_metadata=json.dumps({"notes": notes}),
            created_at=now - timedelta(minutes=30)
        )
        db.add(record)
    db.commit()

    return {
        "status": "seeded_successfully",
        "users": len(DEMO_USERS),
        "events": len(synthetic_events),
        "findings": db.query(ThreatFinding).count(),
        "audit_records": db.query(AuditRecord).count()
    }
