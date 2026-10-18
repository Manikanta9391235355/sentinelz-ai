import {
  User,
  DashboardMetrics,
  SecurityEvent,
  ThreatFinding,
  AuditRecord,
  PrivacySanitizeResponse,
  PrivacyAIAnalysisResponse,
  DetectionRuleConfig,
  LinuxOneStatus,
  UserRole,
} from '@/types/sentinelz';

function getApiBase(): string {
  // In browser, always use relative path '/api' so requests naturally route
  // to the current origin (e.g., http://148.100.98.222/api) via Nginx or Next.js rewrites
  if (typeof window !== 'undefined') {
    return '/api';
  }
  // During SSR execution on the server:
  return process.env.INTERNAL_API_URL || 'http://127.0.0.1:8000/api';
}

class ApiClient {
  private token: string | null = null;

  constructor() {
    if (typeof window !== 'undefined') {
      this.token = sessionStorage.getItem('sentinelz_token');
    }
  }

  setToken(token: string | null) {
    this.token = token;
    if (typeof window !== 'undefined') {
      if (token) {
        sessionStorage.setItem('sentinelz_token', token);
      } else {
        sessionStorage.removeItem('sentinelz_token');
      }
    }
  }

  getToken(): string | null {
    if (!this.token && typeof window !== 'undefined') {
      this.token = sessionStorage.getItem('sentinelz_token');
    }
    return this.token;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const apiBase = getApiBase();
    const url = `${apiBase}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    let token = this.getToken();

    // Auto-acquire default demo session if no token is present and not an explicit auth action
    if (!token && typeof window !== 'undefined' && !endpoint.startsWith('/auth/')) {
      try {
        const authRes = await fetch(`${apiBase}/auth/demo-switch?role=security_analyst`, {
          method: 'POST',
        });
        if (authRes.ok) {
          const authData = await authRes.json();
          if (authData.access_token) {
            this.setToken(authData.access_token);
            token = authData.access_token;
          }
        }
      } catch (err) {
        console.warn('Initial demo session negotiation skipped:', err);
      }
    }

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    let res: Response;
    try {
      res = await fetch(url, {
        ...options,
        headers,
      });
    } catch (fetchErr: any) {
      throw new Error(`Cannot reach SentinelZ security API at ${url}. ${fetchErr.message || ''}`);
    }

    // Auto-retry on 401 with fresh demo analyst token for seamless evaluation
    if (res.status === 401 && typeof window !== 'undefined' && !endpoint.startsWith('/auth/')) {
      try {
        const authRes = await fetch(`${apiBase}/auth/demo-switch?role=security_analyst`, {
          method: 'POST',
        });
        if (authRes.ok) {
          const authData = await authRes.json();
          if (authData.access_token) {
            this.setToken(authData.access_token);
            headers['Authorization'] = `Bearer ${authData.access_token}`;
            const retryRes = await fetch(url, { ...options, headers });
            if (retryRes.ok) {
              return retryRes.json();
            }
          }
        }
      } catch {
        // Fall through to standard error handling
      }
    }

    if (!res.ok) {
      let errorDetail = `Request failed with status ${res.status}`;
      try {
        const errorJson = await res.json();
        if (errorJson.detail) {
          errorDetail = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
        }
      } catch {
        const text = await res.text().catch(() => '');
        if (text) errorDetail = text;
      }
      throw new Error(errorDetail);
    }

    return res.json();
  }

  // Auth & Roles
  async login(email: string, password: string): Promise<{ access_token: string; user: User }> {
    const data = await this.request<{ access_token: string; user: User }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    this.setToken(data.access_token);
    return data;
  }

  async getCurrentUser(): Promise<User> {
    return this.request<User>('/auth/me');
  }

  async logout(): Promise<void> {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.setToken(null);
    }
  }

  async switchDemoRole(role: UserRole): Promise<{ access_token: string; user: User }> {
    const data = await this.request<{ access_token: string; user: User }>(`/auth/demo-switch?role=${role}`, {
      method: 'POST',
    });
    this.setToken(data.access_token);
    return data;
  }

  async getDemoAccounts(): Promise<any[]> {
    return this.request<any[]>('/auth/demo-accounts');
  }

  // Dashboard Metrics
  async getDashboardMetrics(): Promise<DashboardMetrics> {
    return this.request<DashboardMetrics>('/metrics/dashboard');
  }

  // Security Events
  async getEvents(params: { limit?: number; offset?: number; decision?: string; classification?: string; user_id?: string } = {}): Promise<SecurityEvent[]> {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', params.limit.toString());
    if (params.offset) query.set('offset', params.offset.toString());
    if (params.decision) query.set('decision', params.decision);
    if (params.classification) query.set('classification', params.classification);
    if (params.user_id) query.set('user_id', params.user_id);
    return this.request<SecurityEvent[]>(`/events?${query.toString()}`);
  }

  async ingestEvent(event: Partial<SecurityEvent>): Promise<SecurityEvent> {
    return this.request<SecurityEvent>('/events/ingest', {
      method: 'POST',
      body: JSON.stringify(event),
    });
  }

  async getEventById(id: string): Promise<SecurityEvent> {
    return this.request<SecurityEvent>(`/events/${id}`);
  }

  // Threat Findings
  async getFindings(params: { severity?: string; status?: string; rule_id?: string } = {}): Promise<ThreatFinding[]> {
    const query = new URLSearchParams();
    if (params.severity) query.set('severity', params.severity);
    if (params.status) query.set('status', params.status);
    if (params.rule_id) query.set('rule_id', params.rule_id);
    return this.request<ThreatFinding[]>(`/findings?${query.toString()}`);
  }

  async getFindingById(id: string): Promise<ThreatFinding> {
    return this.request<ThreatFinding>(`/findings/${id}`);
  }

  async updateFindingStatus(id: string, status: string, notes?: string): Promise<ThreatFinding> {
    return this.request<ThreatFinding>(`/findings/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, resolution_notes: notes }),
    });
  }

  // Privacy Shield
  async sanitizeText(text: string, customPatterns: string[] = []): Promise<PrivacySanitizeResponse> {
    return this.request<PrivacySanitizeResponse>('/privacy/sanitize', {
      method: 'POST',
      body: JSON.stringify({ text, custom_patterns: customPatterns }),
    });
  }

  async analyzeWithAI(text: string, intent = 'THREAT_SUMMARIZATION', customPatterns: string[] = []): Promise<PrivacyAIAnalysisResponse> {
    return this.request<PrivacyAIAnalysisResponse>('/privacy/analyze-ai', {
      method: 'POST',
      body: JSON.stringify({ text, analysis_intent: intent, custom_patterns: customPatterns }),
    });
  }

  async getPrivacyStats(): Promise<any> {
    return this.request<any>('/privacy/stats');
  }

  // Identity & Access
  async getUsers(): Promise<User[]> {
    return this.request<User[]>('/users');
  }

  async updateUserRole(userId: number, role: UserRole): Promise<User> {
    return this.request<User>(`/users/${userId}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
  }

  // Audit Trail
  async getAuditTrail(params: { limit?: number; offset?: number; action?: string; outcome?: string; actor_id?: string } = {}): Promise<AuditRecord[]> {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', params.limit.toString());
    if (params.offset) query.set('offset', params.offset.toString());
    if (params.action) query.set('action', params.action);
    if (params.outcome) query.set('outcome', params.outcome);
    if (params.actor_id) query.set('actor_id', params.actor_id);
    return this.request<AuditRecord[]>(`/audit?${query.toString()}`);
  }

  // Detection Settings
  async getDetectionRules(): Promise<DetectionRuleConfig[]> {
    return this.request<DetectionRuleConfig[]>('/settings/detection-rules');
  }

  async updateDetectionRule(ruleId: string, updates: Partial<DetectionRuleConfig>): Promise<DetectionRuleConfig> {
    return this.request<DetectionRuleConfig>(`/settings/detection-rules/${ruleId}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  }

  async reseedDemo(): Promise<any> {
    return this.request<any>('/settings/reseed-demo', {
      method: 'POST',
    });
  }

  // Health & LinuxONE
  async getHealth(): Promise<{ status: string; app: string; version: string; database: string }> {
    return this.request('/health');
  }

  async getLinuxOneStatus(): Promise<LinuxOneStatus> {
    return this.request<LinuxOneStatus>('/linuxone/status');
  }
}

export const api = new ApiClient();
