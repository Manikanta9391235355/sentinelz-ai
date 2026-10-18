# SentinelZ AI — System Architecture Specification
**Platform:** SentinelZ AI — Privacy-First AI Security & Threat Detection Platform  
**Tagline:** *Intelligence Without Exposure*  
**Theme:** IBM Z Datathon 2026 — *AI Secured: Innovation Without Exposure*  

---

## 1. Executive Architecture Overview

SentinelZ AI is designed for enterprise Security Operations Centers (SOCs) handling sensitive customer records, financial ledgers, and critical infrastructure (e.g., hybrid IBM zSystems and LinuxONE mainframes). 

The platform enables security analysts to ingest high-velocity security events, detect sophisticated threat patterns through explainable deterministic rules, and run AI-assisted threat summaries **without exposing personally identifiable information (PII) or confidential infrastructure tokens to external models or unvetted processes**.

```mermaid
flowchart TD
    subgraph ClientLayer ["Client Layer (SOC Analysts & Auditors)"]
        UI["Next.js 16 Web Dashboard\n(Dark SOC Aesthetic / Recharts)"]
        CLI["Admin CLI & Automated\nSmoke Test Scripts"]
    end

    subgraph APILayer ["FastAPI Enforcement & Gateway Layer"]
        SizeCheck["Request Size Limiter\n(1MB Payload DoS Guard)"]
        AuthRBAC["Server-Side RBAC Guard\n(PBKDF2-HMAC-SHA256 / Bearer Auth)"]
    end

    subgraph CoreEngines ["SentinelZ Core Processing Engines"]
        ThreatEngine["Explainable Threat Engine\n(Sliding-Window Correlation)"]
        PrivacyShield["Privacy Shield Redaction Engine\n(Non-Overlapping Token Replacement)"]
        AuditEngine["Append-Only Audit Engine\n(Zero Credential Leakage)"]
    end

    subgraph AIInferenceLayer ["AI Security Inference Boundary"]
        LocalAI["Local Deterministic Inference\n(Default: Zero Network Egress)"]
        ExternalAI["External AI Provider (Optional)\n(Guaranteed: Sanitized Only)"]
    end

    subgraph StorageLayer ["Persistence Layer"]
        DB[("SQLAlchemy Schema\nSQLite / PostgreSQL / IBM Db2")]
    end

    subgraph IBMZPlatform ["Target Hardware Platform: IBM LinuxONE (s390x)"]
        CPACF["CPACF Hardware Acceleration"]
        TEE["IBM Secure Execution for Linux"]
        HSM["Crypto Express 8S HSM (FIPS 140-3 L4)"]
    end

    UI --> SizeCheck
    CLI --> SizeCheck
    SizeCheck --> AuthRBAC
    AuthRBAC --> ThreatEngine
    AuthRBAC --> PrivacyShield
    AuthRBAC --> AuditEngine

    ThreatEngine --> DB
    AuditEngine --> DB
    PrivacyShield --> LocalAI
    PrivacyShield -. Optional Sanitized Only .-> ExternalAI

    DB -. Supported Deployment .-> IBMZPlatform
```

---

## 2. Core Architectural Subsystems

### 2.1 Threat Detection Engine Flow
The Threat Detection Engine processes incoming security events in real-time, cross-referencing recent sliding-window state to generate explainable security findings.

```mermaid
sequenceDiagram
    autonumber
    actor Client as Ingestion Source / Analyst
    participant API as Events API (/events/ingest)
    participant Engine as ThreatDetectionEngine
    participant DB as Security Database
    participant Audit as AuditLogger

    Client->>API: POST /api/events/ingest (Validated Payload)
    API->>API: Validate Schema & Permissions (Require Analyst/Admin)
    API->>DB: Persist SecurityEvent
    API->>Engine: analyze_event(db, new_event)
    
    alt Event violates High-Value Asset Rule
        Engine->>Engine: Match RESTRICTED_HIGH_VALUE + DENY
        Engine->>DB: Create ThreatFinding (CRITICAL, Risk: 80-100)
    else Repeated Auth Failures
        Engine->>DB: Query Sliding Window (300s, failed attempts >= 3)
        Engine->>DB: Create ThreatFinding (BRUTE_FORCE_AUTH, Risk: 60-85)
    else Privilege Mismatch
        Engine->>Engine: Verify Role Authorization vs Action/Classification
        Engine->>DB: Create ThreatFinding (PRIVILEGE_MISMATCH, Risk: 50-70)
    else Reconnaissance Probing
        Engine->>DB: Query Distinct Denials across >=3 resources in 180s
        Engine->>DB: Create ThreatFinding (RECON_PROBING, Risk: 60-80)
    end

    API->>Audit: Append EVENT_INGESTED record
    API-->>Client: 200 OK (Event ID + Correlated Findings)
```

#### Deterministic Risk Scoring Formula
$$\text{RiskScore} = \min\left(100.0, \text{BaseRuleWeight} + (\text{EventCount} \times 3.5) + \text{ClassificationBonus} + \text{DenialPenalty}\right)$$

- **Base Weights:**
  - `HIGH_VALUE_UNAUTHORIZED`: 55.0
  - `BRUTE_FORCE_AUTH`: 45.0
  - `RECON_PROBING`: 40.0
  - `PRIVILEGE_MISMATCH`: 35.0
  - `RATE_ANOMALY`: 30.0
- **Classification Bonuses:**
  - `RESTRICTED_HIGH_VALUE`: +25.0
  - `CONFIDENTIAL`: +15.0
  - `INTERNAL`: +5.0
- **Denial Penalty:** +10.0 if access was rejected.

---

### 2.2 Privacy Shield Boundary & Data Flow
The Privacy Shield acts as a non-negotiable gateway between raw telemetry and AI models.

```mermaid
flowchart LR
    RawInput["Raw Security Text\n(Contains PII: email, phone, account, IP)"]
    RegexTokenizer["Multi-Pattern Entity Tokenizer\n(Pre-compiled RFC & Mainframe Regexes)"]
    SpanResolver["Non-Overlapping Span Resolver\n(Length & Offset Priority Sorting)"]
    Sanitizer["Token Substitution Engine\n(Replaces with Typed Placeholders)"]
    SanitizedOutput["Sanitized Text Output\n([EMAIL_REDACTED], [MAINFRAME_ACCT_REDACTED])"]
    
    LocalInference["Local Security Model\n(Zero External Egress)"]
    ExternalCloud["External AI Model (Optional)\n(API Key Required; Sanitized Only)"]

    RawInput --> RegexTokenizer
    RegexTokenizer --> SpanResolver
    SpanResolver --> Sanitizer
    Sanitizer --> SanitizedOutput
    SanitizedOutput --> LocalInference
    SanitizedOutput -. Optional Egress .-> ExternalCloud
```

#### Span Overlap Protection Algorithm
To prevent text corruption when multiple recognizers match overlapping character ranges (e.g., an account string adjacent to an IP or a phone number containing digits resembling a credit card):
1. Matches are harvested as `MatchedSpan(entity_type, placeholder, start, end, matched_text)`.
2. Spans are sorted by `start` ascending, and by `length` descending.
3. A single-pass pruning filter checks `span.start >= last_end`; overlapping sub-spans are deterministically discarded.
4. Token substitutions are executed from **highest character offset to lowest** (`reverse=True`), preserving byte indices for preceding substrings.

---

### 2.3 Role-Based Access Control (RBAC) Architecture
All protected endpoints enforce server-side dependency injection (`require_roles`):

```mermaid
classDiagram
    class UserRole {
        <<enumeration>>
        SECURITY_ADMIN
        SECURITY_ANALYST
        VIEWER
    }

    class ViewerPermissions {
        +view_dashboard_metrics()
        +view_health_status()
        +view_own_profile()
    }

    class AnalystPermissions {
        +view_security_events()
        +ingest_security_events()
        +view_threat_findings()
        +investigate_finding()
        +use_privacy_shield()
        +view_privacy_stats()
        +view_limited_audit()
    }

    class AdminPermissions {
        +manage_users()
        +assign_roles()
        +configure_detection_rules()
        +view_full_audit_trail()
        +system_reseed()
    }

    UserRole <|-- ViewerPermissions
    ViewerPermissions <|-- AnalystPermissions
    AnalystPermissions <|-- AdminPermissions
```

---

### 2.4 Immutable Audit Trail Architecture
1. **Append-Only Behavior:** The API provides only `POST` and `GET` verbs for audit records. No `UPDATE` or `DELETE` endpoints exist in the application.
2. **Zero-Leakage Sanitization:** The `AuditLoggerService.sanitize_metadata()` method recursively scans context payloads and replaces any key matching forbidden tokens (`password`, `token`, `secret`, `key`, `raw_text`, `unredacted`) with `[REDACTED_SECURITY_CONTROL]`.
3. **Correlation Tracking:** Every operational request receives an immutable correlation ID (`req_<uuid>`), enabling end-to-end tracing across services.

---

## 3. IBM Z / LinuxONE Architectural Alignment

### 3.1 Software Compatibility
- **Runtimes:** Python 3.11–3.14 (neutral architecture, no x86 C-extension constraints) and Node.js LTS (v20–v24).
- **Zero Binary Lock-in:** The backend uses standard Python library cryptography (`hashlib.pbkdf2_hmac` with SHA-256 and `secrets.token_hex`), avoiding third-party compiled wheels (such as older `bcrypt` versions) that can experience build failures on `s390x`.
- **Database Abstraction:** Built on SQLAlchemy 2.0 with standard SQL types, easily connecting to local SQLite in development and enterprise **IBM Db2** or **PostgreSQL** on IBM LinuxONE.

### 3.2 Platform Security Capabilities vs Application Controls

| Layer | SentinelZ Application Control (Implemented) | IBM LinuxONE Platform Capability (Deployment Target) |
| :--- | :--- | :--- |
| **Data in Transit** | TLS 1.3 termination, strict CORS headers | **CPACF Acceleration:** Hardware-accelerated AES/SHA on z15/z16 cores |
| **Data at Rest** | Typed PII placeholder redaction, zero plaintext secrets | **Pervasive Encryption:** Transparent full-disk and dataset encryption |
| **Compute Boundary** | In-memory session validation, server-side RBAC | **IBM Secure Execution for Linux:** TEE enclaves protecting against host snooping |
| **Key Storage** | Architecture-neutral PBKDF2 with 100k rounds | **Crypto Express 8S HSM:** FIPS 140-3 Level 4 tamper-resistant cryptographic keys |
| **Auditing** | Append-only SQLite/PostgreSQL audit tables with correlation IDs | **IBM z/OS SMF / Linux on Z auditd:** Immutable hardware-clocked audit logs |
