# SentinelZ AI — Security Policy & Controls Documentation

**Platform:** SentinelZ AI — Privacy-First AI Security & Threat Detection Platform  
**Tagline:** *Intelligence Without Exposure*  
**Theme:** IBM Z Datathon 2026 — *AI Secured: Innovation Without Exposure*

---

## 1. Security Architecture & Threat Model

SentinelZ AI treats security as an implementation requirement, not an afterthought. The system's threat model evaluates potential attack vectors across the ingestion, threat detection, privacy sanitization, and administrative boundaries.

### 1.1 STRIDE Threat Assessment

| Threat Category | Potential Attack Vector | Implemented SentinelZ Countermeasure |
| :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates a SOC analyst or administrator. | Salted PBKDF2-HMAC-SHA256 password hashing (100k rounds) + opaque cryptographically random session bearer tokens with constant-time verification. |
| **Tampering** | Malicious actor modifies finding dispositions or alters audit entries. | Append-only database design. Zero update/delete API routes for audit logs. Finding mutations require authenticated analyst identity and record an immediate immutable audit trail entry. |
| **Repudiation** | An analyst denies updating a finding or executing a demo reseed. | Every state mutation records actor email, client IP, timestamp, and a unique correlation ID (`req_<uuid>`). |
| **Information Disclosure** | Sensitive PII (emails, phone numbers, mainframe account IDs, SSNs) is leaked to an external AI model or in logs. | Dedicated Privacy Shield boundary replaces sensitive patterns with typed placeholders *before* persistence or AI dispatch. Strict metadata scrubbing ensures passwords and tokens are never logged. |
| **Denial of Service** | Oversized payloads overwhelm the ingestion endpoint or memory buffer. | Global FastAPI request size middleware rejects payloads exceeding 1MB (`413 Request Entity Too Large`). Ingestion batches capped at 100 events. |
| **Elevation of Privilege** | A Viewer attempts to perform admin actions or alter their role via payload. | Server-side dependency injection enforces role authorization (`require_roles`). Role assignment in request payloads is discarded; role changes require `security_admin` token. |

---

## 2. Implemented Security Controls

### 2.1 Cryptographic Controls
- **Password Storage:** Standard PBKDF2-HMAC-SHA256 with 100,000 iterations and a unique cryptographically random 16-byte salt per user (`secrets.token_hex(16)`).
- **Constant-Time Comparison:** Password hashes are verified using `hmac.compare_digest` to prevent timing attacks.
- **Session Tokens:** Generated via `secrets.token_urlsafe(32)` providing 256 bits of entropy.

### 2.2 Server-Enforced Role-Based Access Control (RBAC)
- **Deny by Default:** Unauthenticated requests receive HTTP 401 Unauthorized. Requests with insufficient role permissions receive HTTP 403 Forbidden.
- **Three Discrete Personas:**
  1. `security_admin`: Complete administrative control, role assignment, detection rule parameter tuning, and database re-seeding.
  2. `security_analyst`: Event telemetry inspection, manual event ingestion, finding investigation, status triage, and privacy shield execution.
  3. `viewer`: Read-only access to aggregate dashboard metrics and platform health. Explicitly blocked from viewing restricted finding details, updating statuses, or accessing administrative routes.

### 2.3 Privacy Shield Redaction Boundary
- **Multi-Span Regex Engine:** Identifies emails, international/domestic phone numbers, IBM Mainframe Account numbers (`IBM-ACCT-XXXX-XXXX`), generic account numbers, SSNs, and IP addresses.
- **Overlap Protection:** Sorts detected entities by character span offset and length, discarding overlapping sub-matches before executing reverse-order replacement to ensure text integrity.
- **Strict Boundary Check:** The external AI provider wrapper asserts that no unredacted email or phone number pattern exists in the prompt before network dispatch.
- **Default Offline Stance:** External AI is disabled by default (`SENTINELZ_AI_ENABLED=false`). The system runs deterministic local analysis without outbound network transmission.

### 2.4 Immutable Audit Logging
- **Append-Only:** No endpoint exists to modify or delete audit entries.
- **Credential Scrubbing:** `AuditLoggerService.sanitize_metadata()` recursively strips keys containing `password`, `token`, `secret`, `key`, `raw_text`, or `unredacted`.

---

## 3. Known Limitations & Prototype Scope

1. **Pattern-Based Redaction Limits:** Regex and pattern matching are highly effective for structured tokens (emails, credit cards, standard account IDs). However, pattern matching cannot reliably identify unstructured or indirect semantic disclosures (e.g., *"the CEO who stepped down in March"*). Human-in-the-loop review is mandatory.
2. **Prototype Session Store:** In this prototype, session tokens are stored in an in-memory dictionary. For multi-node production deployment on IBM LinuxONE, sessions should be backed by Redis or an enterprise Db2 session table.
3. **Hardware-Backed Encryption:** While SentinelZ AI is designed to run on IBM LinuxONE, hardware cryptographic acceleration (CPACF), IBM Secure Execution enclaves, and Crypto Express HSM integrations require infrastructure-level setup on an active LinuxONE LPAR.

---

## 4. Responsible Disclosure

For security vulnerabilities or questions, contact the SentinelZ AI security team via the repository issue tracker with the `security` label or via email at `security@sentinelz.local`.
