import json
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.app.models.all_models import SecurityEvent, ThreatFinding, DetectionRuleConfig

# Optional Scikit-Learn Anomaly Detection (graceful fallback if unavailable)
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

class ThreatDetectionEngine:
    """
    Explainable threat detection engine for SentinelZ AI.
    Evaluates newly ingested events against sliding-window state and rule configurations.
    
    Distinguishes:
    - Observed Facts (the raw security telemetry events)
    - Rule-based Findings (deterministic correlation matches)
    - Statistical Anomaly Scores (baseline deviations without attributing intent)
    - Confirmed Incidents (human analyst affirmed after investigation)
    """

    DEFAULT_RULES = {
        "BRUTE_FORCE_AUTH": {
            "name": "Repeated Authentication Failures",
            "description": "Multiple failed authentication attempts within a short sliding window.",
            "severity": "HIGH",
            "base_weight": 45.0,
            "threshold_count": 3,
            "window_seconds": 300,
        },
        "PRIVILEGE_MISMATCH": {
            "name": "Resource Access Role Mismatch",
            "description": "User role authorization is insufficient for the requested action or classification.",
            "severity": "MEDIUM",
            "base_weight": 35.0,
            "threshold_count": 1,
            "window_seconds": 60,
        },
        "RATE_ANOMALY": {
            "name": "High-Velocity Resource Access Burst",
            "description": "Unusually rapid volume of resource requests exceeding operational thresholds.",
            "severity": "MEDIUM",
            "base_weight": 30.0,
            "threshold_count": 10,
            "window_seconds": 60,
        },
        "HIGH_VALUE_UNAUTHORIZED": {
            "name": "Unauthorized Attempt on High-Value Mainframe/Security Asset",
            "description": "Explicit access denial on a restricted high-value cryptographic or mainframe resource.",
            "severity": "CRITICAL",
            "base_weight": 55.0,
            "threshold_count": 1,
            "window_seconds": 60,
        },
        "RECON_PROBING": {
            "name": "Multi-Resource Denial Reconnaissance",
            "description": "Successive denied requests across multiple distinct resources indicating port/path scanning.",
            "severity": "HIGH",
            "base_weight": 40.0,
            "threshold_count": 3,
            "window_seconds": 180,
        },
        "ANOMALY_BASELINE_DEVIATION": {
            "name": "Statistical Behavior Deviation",
            "description": "Observed request characteristics diverge significantly from synthetic baseline norms.",
            "severity": "LOW",
            "base_weight": 25.0,
            "threshold_count": 1,
            "window_seconds": 3600,
        }
    }

    def compute_risk_score(self, base_weight: float, event_count: int, classification: str, has_denials: bool) -> float:
        """
        Deterministic Risk Score Formula:
        Risk = min(100.0, BaseWeight + (EventCount * 3.5) + ClassificationBonus + DenialPenalty)
        """
        class_bonus = {
            "RESTRICTED_HIGH_VALUE": 25.0,
            "CONFIDENTIAL": 15.0,
            "INTERNAL": 5.0,
            "PUBLIC": 0.0
        }.get(classification, 5.0)

        denial_penalty = 10.0 if has_denials else 0.0
        calculated = base_weight + (event_count * 3.5) + class_bonus + denial_penalty
        return round(min(100.0, max(5.0, calculated)), 1)

    def determine_severity(self, risk_score: float) -> str:
        if risk_score >= 80.0:
            return "CRITICAL"
        elif risk_score >= 60.0:
            return "HIGH"
        elif risk_score >= 40.0:
            return "MEDIUM"
        else:
            return "LOW"

    def analyze_event(self, db: Session, event: SecurityEvent) -> List[ThreatFinding]:
        """
        Evaluates a newly ingested security event against all detection rules and sliding history.
        Returns any newly generated ThreatFinding instances (persisted in DB).
        """
        new_findings: List[ThreatFinding] = []

        # 1. Rule: HIGH_VALUE_UNAUTHORIZED
        # Unauthorized access attempt against RESTRICTED_HIGH_VALUE resource
        if event.resource_classification == "RESTRICTED_HIGH_VALUE" and event.access_decision == "DENY":
            risk = self.compute_risk_score(
                base_weight=self.DEFAULT_RULES["HIGH_VALUE_UNAUTHORIZED"]["base_weight"],
                event_count=1,
                classification=event.resource_classification,
                has_denials=True
            )
            finding_id = f"find_hvu_{uuid.uuid4().hex[:8]}"
            explanation = (
                f"Observed denied access attempt by user '{event.user_id}' ({event.user_role}) "
                f"targeting high-value asset '{event.resource}' classified as {event.resource_classification}. "
                f"Mainframe cryptographic and ledger boundaries require heightened scrutiny."
            )
            evidence = {
                "actor": event.user_id,
                "user_role": event.user_role,
                "source_ip": event.source_ip,
                "resource": event.resource,
                "requested_action": event.requested_action,
                "access_decision": event.access_decision,
                "classification": event.resource_classification,
                "timestamp": event.timestamp.isoformat()
            }
            steps = [
                f"Verify identity '{event.user_id}' against corporate IAM directory.",
                f"Check recent network logs for IP '{event.source_ip}' across mainframe partitions.",
                "Review Crypto Express HSM or sensitive keystore access attempts.",
                "Contact user supervisor to establish legitimate business need before taking action."
            ]
            finding = ThreatFinding(
                id=finding_id,
                title="Unauthorized Access Attempt on High-Value Mainframe Asset",
                severity=self.determine_severity(risk),
                risk_score=risk,
                detection_method="RULE_BASED",
                rule_id="HIGH_VALUE_UNAUTHORIZED",
                explanation=explanation,
                evidence=json.dumps(evidence),
                recommended_steps=json.dumps(steps),
                related_event_ids=json.dumps([event.id]),
                affected_identity=event.user_id,
                status="OPEN",
                created_at=datetime.utcnow()
            )
            db.add(finding)
            new_findings.append(finding)

        # 2. Rule: BRUTE_FORCE_AUTH
        # Check sliding window for failed auths by this user or IP
        if event.auth_result == "FAILURE":
            window_start = event.timestamp - timedelta(seconds=self.DEFAULT_RULES["BRUTE_FORCE_AUTH"]["window_seconds"])
            failed_events = db.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= window_start,
                SecurityEvent.auth_result == "FAILURE",
                (SecurityEvent.user_id == event.user_id) | (SecurityEvent.source_ip == event.source_ip)
            ).all()

            if len(failed_events) >= self.DEFAULT_RULES["BRUTE_FORCE_AUTH"]["threshold_count"]:
                # Check if an open finding already exists for this identity in the last 15 mins to prevent alert storms
                recent_cutoff = datetime.utcnow() - timedelta(minutes=15)
                existing = db.query(ThreatFinding).filter(
                    ThreatFinding.rule_id == "BRUTE_FORCE_AUTH",
                    ThreatFinding.affected_identity == event.user_id,
                    ThreatFinding.created_at >= recent_cutoff,
                    ThreatFinding.status == "OPEN"
                ).first()

                if not existing:
                    risk = self.compute_risk_score(
                        base_weight=self.DEFAULT_RULES["BRUTE_FORCE_AUTH"]["base_weight"],
                        event_count=len(failed_events),
                        classification=event.resource_classification,
                        has_denials=True
                    )
                    evidence_events = [e.id for e in failed_events]
                    explanation = (
                        f"Detected {len(failed_events)} consecutive failed authentication attempts "
                        f"for user '{event.user_id}' originating from source IP '{event.source_ip}' "
                        f"within a 5-minute sliding window."
                    )
                    evidence = {
                        "user_id": event.user_id,
                        "source_ip": event.source_ip,
                        "failed_attempt_count": len(failed_events),
                        "first_attempt": failed_events[0].timestamp.isoformat(),
                        "latest_attempt": event.timestamp.isoformat(),
                    }
                    steps = [
                        f"Inspect source IP '{event.source_ip}' for geographical anomalies or VPN exit nodes.",
                        f"Evaluate whether MFA challenges were triggered or bypassed.",
                        "Check for password-spraying patterns across sibling synthetic accounts.",
                        "Notify account owner via out-of-band channel if credential stuffing is suspected."
                    ]
                    finding = ThreatFinding(
                        id=f"find_bfa_{uuid.uuid4().hex[:8]}",
                        title="Multiple Authentication Failures (Potential Credential Stuffing)",
                        severity=self.determine_severity(risk),
                        risk_score=risk,
                        detection_method="RULE_BASED",
                        rule_id="BRUTE_FORCE_AUTH",
                        explanation=explanation,
                        evidence=json.dumps(evidence),
                        recommended_steps=json.dumps(steps),
                        related_event_ids=json.dumps(evidence_events),
                        affected_identity=event.user_id,
                        status="OPEN",
                        created_at=datetime.utcnow()
                    )
                    db.add(finding)
                    new_findings.append(finding)

        # 3. Rule: PRIVILEGE_MISMATCH
        # User role is viewer / contractor but requesting ADMIN_DELETE or access to RESTRICTED resources
        if (event.user_role in ("viewer", "contractor", "operator") and 
            (event.requested_action in ("ADMIN_DELETE", "EXECUTE", "WRITE_KEYS") or 
             event.resource_classification == "RESTRICTED_HIGH_VALUE")):
            risk = self.compute_risk_score(
                base_weight=self.DEFAULT_RULES["PRIVILEGE_MISMATCH"]["base_weight"],
                event_count=1,
                classification=event.resource_classification,
                has_denials=(event.access_decision == "DENY")
            )
            explanation = (
                f"Identity '{event.user_id}' assigned role '{event.user_role}' initiated a "
                f"privileged '{event.requested_action}' request on '{event.resource}', which exceeds standard role boundaries."
            )
            evidence = {
                "user_id": event.user_id,
                "role": event.user_role,
                "action": event.requested_action,
                "resource": event.resource,
                "decision": event.access_decision,
            }
            steps = [
                f"Verify role assignment for '{event.user_id}' in Identity & Access configuration.",
                "Determine if recent role downgrade was properly synchronized across services.",
                "Review API gateway logs for unauthorized token scope tampering."
            ]
            finding = ThreatFinding(
                id=f"find_prm_{uuid.uuid4().hex[:8]}",
                title="Privileged Action Requested by Incompatible Role",
                severity=self.determine_severity(risk),
                risk_score=risk,
                detection_method="RULE_BASED",
                rule_id="PRIVILEGE_MISMATCH",
                explanation=explanation,
                evidence=json.dumps(evidence),
                recommended_steps=json.dumps(steps),
                related_event_ids=json.dumps([event.id]),
                affected_identity=event.user_id,
                status="OPEN",
                created_at=datetime.utcnow()
            )
            db.add(finding)
            new_findings.append(finding)

        # 4. Rule: RECON_PROBING
        # Successive denied requests against multiple distinct resources in sliding window
        if event.access_decision == "DENY":
            recon_window = event.timestamp - timedelta(seconds=self.DEFAULT_RULES["RECON_PROBING"]["window_seconds"])
            denied_events = db.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= recon_window,
                SecurityEvent.access_decision == "DENY",
                (SecurityEvent.user_id == event.user_id) | (SecurityEvent.source_ip == event.source_ip)
            ).all()

            distinct_resources = set(e.resource for e in denied_events)
            if len(distinct_resources) >= self.DEFAULT_RULES["RECON_PROBING"]["threshold_count"]:
                recent_cutoff = datetime.utcnow() - timedelta(minutes=15)
                existing = db.query(ThreatFinding).filter(
                    ThreatFinding.rule_id == "RECON_PROBING",
                    ThreatFinding.affected_identity == event.user_id,
                    ThreatFinding.created_at >= recent_cutoff,
                    ThreatFinding.status == "OPEN"
                ).first()

                if not existing:
                    risk = self.compute_risk_score(
                        base_weight=self.DEFAULT_RULES["RECON_PROBING"]["base_weight"],
                        event_count=len(denied_events),
                        classification="INTERNAL",
                        has_denials=True
                    )
                    explanation = (
                        f"Observed {len(denied_events)} denied requests targeting {len(distinct_resources)} "
                        f"distinct resources within a 3-minute window from source '{event.source_ip}'. "
                        f"Characteristic of endpoint reconnaissance or privilege discovery scanning."
                    )
                    evidence = {
                        "source_ip": event.source_ip,
                        "user_id": event.user_id,
                        "distinct_resources_targeted": list(distinct_resources),
                        "denied_count": len(denied_events)
                    }
                    steps = [
                        f"Review perimeter firewall and reverse proxy logs for '{event.source_ip}'.",
                        "Evaluate whether automated vulnerability scanning tools were employed.",
                        "Check whether non-existent endpoints were polled in error or malice."
                    ]
                    finding = ThreatFinding(
                        id=f"find_rcn_{uuid.uuid4().hex[:8]}",
                        title="Multi-Resource Denial Pattern (Reconnaissance Activity)",
                        severity=self.determine_severity(risk),
                        risk_score=risk,
                        detection_method="RULE_BASED",
                        rule_id="RECON_PROBING",
                        explanation=explanation,
                        evidence=json.dumps(evidence),
                        recommended_steps=json.dumps(steps),
                        related_event_ids=json.dumps([e.id for e in denied_events]),
                        affected_identity=event.user_id,
                        status="OPEN",
                        created_at=datetime.utcnow()
                    )
                    db.add(finding)
                    new_findings.append(finding)

        # 5. Rule: RATE_ANOMALY
        # Rapid surge in requests (>10 events within 60s for single identity)
        rate_window = event.timestamp - timedelta(seconds=self.DEFAULT_RULES["RATE_ANOMALY"]["window_seconds"])
        recent_events = db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= rate_window,
            SecurityEvent.user_id == event.user_id
        ).all()

        if len(recent_events) >= self.DEFAULT_RULES["RATE_ANOMALY"]["threshold_count"]:
            recent_cutoff = datetime.utcnow() - timedelta(minutes=15)
            existing = db.query(ThreatFinding).filter(
                ThreatFinding.rule_id == "RATE_ANOMALY",
                ThreatFinding.affected_identity == event.user_id,
                ThreatFinding.created_at >= recent_cutoff,
                ThreatFinding.status == "OPEN"
            ).first()

            if not existing:
                risk = self.compute_risk_score(
                    base_weight=self.DEFAULT_RULES["RATE_ANOMALY"]["base_weight"],
                    event_count=len(recent_events),
                    classification=event.resource_classification,
                    has_denials=False
                )
                explanation = (
                    f"Identity '{event.user_id}' generated {len(recent_events)} requests in under 60 seconds, "
                    f"exceeding normal human interaction velocity. Possible scraping or script automation."
                )
                evidence = {
                    "user_id": event.user_id,
                    "event_count_in_window": len(recent_events),
                    "window_seconds": 60,
                    "sample_resource": event.resource
                }
                steps = [
                    "Inspect API client user-agent strings for script signatures.",
                    "Verify if automated batch processing job was pre-scheduled.",
                    "Throttle client session to prevent service degradation."
                ]
                finding = ThreatFinding(
                    id=f"find_rte_{uuid.uuid4().hex[:8]}",
                    title="High-Velocity Request Rate Exceeded Baseline",
                    severity=self.determine_severity(risk),
                    risk_score=risk,
                    detection_method="STATISTICAL_ANOMALY",
                    rule_id="RATE_ANOMALY",
                    explanation=explanation,
                    evidence=json.dumps(evidence),
                    recommended_steps=json.dumps(steps),
                    related_event_ids=json.dumps([e.id for e in recent_events]),
                    affected_identity=event.user_id,
                    status="OPEN",
                    created_at=datetime.utcnow()
                )
                db.add(finding)
                new_findings.append(finding)

        if new_findings:
            db.commit()

        return new_findings

threat_engine = ThreatDetectionEngine()
