from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator, ConfigDict

# --- Authentication & Users ---
class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=6, max_length=128)

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    username: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class UserRoleUpdate(BaseModel):
    role: str = Field(..., description="Target role: security_admin, security_analyst, viewer")

    @field_validator("role")
    def validate_role(cls, v):
        valid = ["security_admin", "security_analyst", "viewer"]
        if v not in valid:
            raise ValueError(f"Role must be one of {valid}")
        return v

# --- Security Events ---
class SecurityEventCreate(BaseModel):
    id: Optional[str] = Field(None, max_length=64, description="Optional custom event ID, auto-generated if omitted")
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow)
    user_id: str = Field(..., min_length=1, max_length=100)
    user_role: str = Field(..., min_length=1, max_length=50)
    source_ip: str = Field(..., min_length=1, max_length=50)
    resource: str = Field(..., min_length=1, max_length=255)
    requested_action: str = Field(..., description="Action: READ, WRITE, EXECUTE, AUTHENTICATE, ADMIN_DELETE")
    resource_classification: str = Field("INTERNAL", description="Classification: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED_HIGH_VALUE")
    access_decision: str = Field(..., description="Decision: ALLOW, DENY")
    auth_result: str = Field("N/A", description="Auth outcome: SUCCESS, FAILURE, N/A")
    context_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    is_synthetic: bool = True

    @field_validator("access_decision")
    def validate_decision(cls, v):
        valid = ["ALLOW", "DENY"]
        if v.upper() not in valid:
            raise ValueError(f"access_decision must be one of {valid}")
        return v.upper()

    @field_validator("auth_result")
    def validate_auth(cls, v):
        valid = ["SUCCESS", "FAILURE", "N/A"]
        if v.upper() not in valid:
            raise ValueError(f"auth_result must be one of {valid}")
        return v.upper()

class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    user_id: str
    user_role: str
    source_ip: str
    resource: str
    requested_action: str
    resource_classification: str
    access_decision: str
    auth_result: str
    context_metadata: Dict[str, Any]
    is_synthetic: bool
    created_at: datetime

# --- Threat Findings ---
class ThreatFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    severity: str
    risk_score: float
    detection_method: str
    rule_id: str
    explanation: str
    evidence: Dict[str, Any]
    recommended_steps: List[str]
    related_event_ids: List[str]
    affected_identity: str
    status: str
    created_at: datetime
    updated_at: datetime
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None

class ThreatFindingStatusUpdate(BaseModel):
    status: str = Field(..., description="New status: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    resolution_notes: Optional[str] = Field(None, max_length=1000)

    @field_validator("status")
    def validate_status(cls, v):
        valid = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
        if v.upper() not in valid:
            raise ValueError(f"status must be one of {valid}")
        return v.upper()

# --- Privacy Shield ---
class RedactionEntityItem(BaseModel):
    entity_type: str
    placeholder: str
    start: int
    end: int
    char_length: int

class PrivacySanitizeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="Raw input text to sanitize")
    custom_patterns: Optional[List[str]] = Field(default_factory=list, description="Optional extra regex or keyword patterns to redact")
    enable_account_masking: bool = True
    enable_network_masking: bool = True

class PrivacySanitizeResponse(BaseModel):
    original_char_count: int
    sanitized_char_count: int
    sanitized_text: str
    redacted_items_count: int
    detected_entities_summary: Dict[str, int]
    redacted_spans: List[RedactionEntityItem]
    transformation_preview: str
    execution_time_ms: float
    ai_boundary_secured: bool = True

class PrivacyAIAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="Raw text that MUST pass through Privacy Shield before AI ingestion")
    analysis_intent: str = Field("THREAT_SUMMARIZATION", description="Intent: THREAT_SUMMARIZATION, ANOMALY_EXPLANATION, REMEDIATION_ADVICE")
    custom_patterns: Optional[List[str]] = Field(default_factory=list)

class PrivacyAIAnalysisResponse(BaseModel):
    sanitization_summary: PrivacySanitizeResponse
    ai_analysis_result: str
    ai_provider: str
    model_name: str
    disclaimer: str
    external_call_executed: bool
    unredacted_data_exposed: bool = False  # Must ALWAYS be False

# --- Audit Records ---
class AuditRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    actor_id: str
    actor_role: str
    action: str
    target_type: str
    target_id: Optional[str]
    outcome: str
    request_id: str
    client_ip: str
    context_metadata: Dict[str, Any]
    created_at: datetime

# --- Dashboard Metrics ---
class MetricCard(BaseModel):
    label: str
    value: int | float | str
    change: str
    severity: str

class EventTrendPoint(BaseModel):
    time_label: str
    event_count: int
    anomaly_count: int
    denied_count: int

class SeverityDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int

class DashboardMetricsResponse(BaseModel):
    total_events: int
    high_risk_events: int
    events_requiring_investigation: int
    unauthorized_access_attempts: int
    sensitive_data_redactions: int
    open_findings_count: int
    severity_distribution: SeverityDistribution
    event_volume_trend: List[EventTrendPoint]
    recent_findings: List[ThreatFindingResponse]
    recent_audit: List[AuditRecordResponse]
    demo_mode_active: bool = True

# --- Detection Config ---
class DetectionRuleConfigResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rule_id: str
    name: str
    description: str
    severity: str
    base_weight: float
    threshold_count: int
    window_seconds: int
    is_enabled: bool
    updated_at: datetime
    updated_by: str

class DetectionRuleConfigUpdate(BaseModel):
    is_enabled: Optional[bool] = None
    threshold_count: Optional[int] = Field(None, ge=1, le=1000)
    window_seconds: Optional[int] = Field(None, ge=5, le=86400)
    base_weight: Optional[float] = Field(None, ge=0.0, le=100.0)

# --- Health & LinuxONE ---
class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    app: str
    version: str
    database: str

class ReadinessResponse(BaseModel):
    ready: bool
    database_connected: bool
    threat_engine_active: bool
    privacy_shield_active: bool
    ai_provider_configured: bool
    ai_provider_mode: str

class LinuxOneStatusResponse(BaseModel):
    platform_name: str
    architecture: str
    pervasive_encryption_compatible: bool
    cpacf_hardware_acceleration: str
    secure_execution_ready: bool
    container_ready: bool
    audit_append_only_enforced: bool
    zero_sensitive_leakage_guarantee: str
