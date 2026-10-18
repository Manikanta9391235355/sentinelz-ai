export type UserRole = 'security_admin' | 'security_analyst' | 'viewer';

export interface User {
  id: number;
  email: string;
  username: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export type AccessDecision = 'ALLOW' | 'DENY';
export type ResourceClassification = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED_HIGH_VALUE';
export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type FindingStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  user_id: string;
  user_role: string;
  source_ip: string;
  resource: string;
  requested_action: string;
  resource_classification: ResourceClassification;
  access_decision: AccessDecision;
  auth_result: 'SUCCESS' | 'FAILURE' | 'N/A';
  context_metadata: Record<string, any>;
  is_synthetic: boolean;
  created_at: string;
}

export interface ThreatFinding {
  id: string;
  title: string;
  severity: SeverityLevel;
  risk_score: number;
  detection_method: string;
  rule_id: string;
  explanation: string;
  evidence: Record<string, any>;
  recommended_steps: string[];
  related_event_ids: string[];
  affected_identity: string;
  status: FindingStatus;
  created_at: string;
  updated_at: string;
  resolved_by?: string | null;
  resolution_notes?: string | null;
}

export interface AuditRecord {
  id: number;
  timestamp: string;
  actor_id: string;
  actor_role: string;
  action: string;
  target_type: string;
  target_id: string | null;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILURE';
  request_id: string;
  client_ip: string;
  context_metadata: Record<string, any>;
  created_at: string;
}

export interface RedactionSpan {
  entity_type: string;
  placeholder: string;
  start: number;
  end: number;
  char_length: number;
}

export interface PrivacySanitizeResponse {
  original_char_count: number;
  sanitized_char_count: number;
  sanitized_text: string;
  redacted_items_count: number;
  detected_entities_summary: Record<string, number>;
  redacted_spans: RedactionSpan[];
  transformation_preview: string;
  execution_time_ms: number;
  ai_boundary_secured: boolean;
}

export interface PrivacyAIAnalysisResponse {
  sanitization_summary: PrivacySanitizeResponse;
  ai_analysis_result: string;
  ai_provider: string;
  model_name: string;
  disclaimer: string;
  external_call_executed: boolean;
  unredacted_data_exposed: boolean;
}

export interface EventTrendPoint {
  time_label: string;
  event_count: number;
  anomaly_count: number;
  denied_count: number;
}

export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DashboardMetrics {
  total_events: number;
  high_risk_events: number;
  events_requiring_investigation: number;
  unauthorized_access_attempts: number;
  sensitive_data_redactions: number;
  open_findings_count: number;
  severity_distribution: SeverityDistribution;
  event_volume_trend: EventTrendPoint[];
  recent_findings: ThreatFinding[];
  recent_audit: AuditRecord[];
  demo_mode_active: boolean;
}

export interface DetectionRuleConfig {
  rule_id: string;
  name: string;
  description: string;
  severity: SeverityLevel;
  base_weight: number;
  threshold_count: number;
  window_seconds: number;
  is_enabled: boolean;
  updated_at: string;
  updated_by: string;
}

export interface LinuxOneStatus {
  platform_name: string;
  architecture: string;
  pervasive_encryption_compatible: boolean;
  cpacf_hardware_acceleration: string;
  secure_execution_ready: boolean;
  container_ready: boolean;
  audit_append_only_enforced: boolean;
  zero_sensitive_leakage_guarantee: string;
}
