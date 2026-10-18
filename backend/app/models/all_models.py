from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, Text
from backend.app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(150), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    salt = Column(String(64), nullable=False)
    role = Column(String(50), nullable=False, default="viewer")
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    user_id = Column(String(100), index=True, nullable=False)
    user_role = Column(String(50), nullable=False)
    source_ip = Column(String(50), index=True, nullable=False)
    resource = Column(String(255), index=True, nullable=False)
    requested_action = Column(String(50), nullable=False)
    resource_classification = Column(String(50), nullable=False)
    access_decision = Column(String(20), nullable=False)  # ALLOW, DENY
    auth_result = Column(String(20), nullable=False)      # SUCCESS, FAILURE, N/A
    context_metadata = Column(Text, default="{}", nullable=False)
    is_synthetic = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class ThreatFinding(Base):
    __tablename__ = "threat_findings"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, nullable=False)                # 0.0 to 100.0
    detection_method = Column(String(50), nullable=False)     # RULE_BASED, STATISTICAL_ANOMALY, HYBRID
    rule_id = Column(String(100), index=True, nullable=False)
    explanation = Column(Text, nullable=False)
    evidence = Column(Text, default="{}", nullable=False)              # JSON string
    recommended_steps = Column(Text, default="[]", nullable=False)     # JSON string
    related_event_ids = Column(Text, default="[]", nullable=False)     # JSON string
    affected_identity = Column(String(100), index=True, nullable=False)
    status = Column(String(30), default="OPEN", index=True, nullable=False) # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    resolved_by = Column(String(100), nullable=True)
    resolution_notes = Column(Text, nullable=True)

class AuditRecord(Base):
    __tablename__ = "audit_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    actor_id = Column(String(100), index=True, nullable=False)
    actor_role = Column(String(50), nullable=False)
    action = Column(String(100), index=True, nullable=False)
    target_type = Column(String(50), nullable=False)
    target_id = Column(String(100), nullable=True)
    outcome = Column(String(20), nullable=False)  # SUCCESS, DENIED, FAILURE
    request_id = Column(String(64), nullable=False)
    client_ip = Column(String(50), nullable=False)
    context_metadata = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class PrivacyRedactionLog(Base):
    __tablename__ = "privacy_redaction_logs"

    id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    actor_id = Column(String(100), index=True, nullable=False)
    original_char_count = Column(Integer, nullable=False)
    sanitized_char_count = Column(Integer, nullable=False)
    entities_redacted_count = Column(Integer, nullable=False)
    detected_entity_types = Column(Text, default="{}", nullable=False)  # JSON string
    ai_provider_called = Column(Boolean, default=False, nullable=False)
    ai_provider_type = Column(String(50), default="none", nullable=False)
    latency_ms = Column(Float, default=0.0, nullable=False)

class DetectionRuleConfig(Base):
    __tablename__ = "detection_rule_configs"

    rule_id = Column(String(100), primary_key=True, index=True)
    name = Column(String(150), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    base_weight = Column(Float, nullable=False)
    threshold_count = Column(Integer, nullable=False)
    window_seconds = Column(Integer, nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_by = Column(String(100), default="system", nullable=False)
