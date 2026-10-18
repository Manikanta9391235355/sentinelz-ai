# SentinelZ AI — IBM Z Datathon 2026 Submission

**Project Title:** SentinelZ AI — Privacy-First AI Security & Threat Detection Platform  
**Tagline:** *Intelligence Without Exposure*  
**Datathon Track & Theme:** *AI Secured: Innovation Without Exposure*  
**Target Platform:** IBM LinuxONE / Linux on IBM Z (`s390x`)  

---

## 1. Problem Statement

Enterprise Security Operations Centers (SOCs) monitoring hybrid cloud and mainframe workloads face a critical tension between **intelligence and exposure**:
- SOC analysts increasingly leverage AI models to summarize complex incidents, evaluate threat signals, and correlate access anomalies.
- However, standard security telemetry contains sensitive corporate and customer data: email addresses, phone numbers, core mainframe account numbers, internal IP topologies, and privileged identifiers.
- Transmitting raw telemetry to external LLM providers or unvetted internal models risks regulatory non-compliance (GDPR, HIPAA, PCI-DSS), confidential data leakage, and sovereign infrastructure exposure.
- Furthermore, many modern AI security tools rely on opaque black-box scoring, creating alert fatigue and making forensic auditability difficult.

---

## 2. Proposed Solution: SentinelZ AI

**SentinelZ AI** is a functional, demonstrable security and threat detection platform built on the principle of **Intelligence Without Exposure**:
1. **Explainable Threat Detection:** Detects suspicious behavior (brute force authentication bursts, privilege mismatches, high-velocity scraping, reconnaissance probing, and unauthorized mainframe asset access) using deterministic, human-auditable scoring formulas.
2. **Dedicated Privacy Shield:** A multi-span redaction engine that automatically intercepts sensitive tokens (emails, phones, IBM mainframe accounts, national IDs, and configurable project codewords), replaces them with typed placeholders (`[EMAIL_REDACTED]`, `[MAINFRAME_ACCT_REDACTED]`), and verifies that unredacted data **never crosses the AI boundary**.
3. **Local-First AI Execution:** Defaults to a deterministic local inference engine with zero outbound network egress. If an external model is configured, the system strictly enforces the privacy boundary on the backend before dispatch.
4. **Server-Enforced RBAC:** Implements strict three-tier role-based access control (Security Administrator, Security Analyst, Viewer) with deny-by-default logic and horizontal/vertical escalation defenses.
5. **Immutable Governance Audit Trail:** Records all security-critical operations with cryptographic correlation IDs and automated scrubbing of passwords, tokens, and raw payloads.
6. **IBM LinuxONE Architecture Readiness:** Designed with architecture-neutral Python and web technologies, ready for deployment on IBM LinuxONE Community Cloud with documented alignment to CPACF, Pervasive Encryption, and IBM Secure Execution.

---

## 3. Key Innovations

1. **Non-Overlapping Token Span Resolution:** An algorithm that sorts detected regex spans by offset and length, pruning overlapping sub-matches and executing substitutions in reverse order to ensure text structure is never corrupted or double-replaced.
2. **Deterministic Risk Scoring:** A transparent risk scoring formula that combines base rule weights, event frequency, asset sensitivity classification, and denial penalties into a 0–100 score, avoiding uncalibrated pseudo-probabilities.
3. **Clear Distinction of Knowledge:** SentinelZ strictly distinguishes observed facts (raw telemetry) from rule-based correlations, statistical anomaly scores, and analyst-verified incidents. An alert is never prematurely labeled a "confirmed cyberattack."
4. **Failsafe AI Fallback:** Works 100% offline with zero cloud API keys or subscriptions required.

---

## 4. Technology Stack

- **Frontend:** Next.js 16 (App Router, Turbopack), React 19, TypeScript, Tailwind CSS 4, Lucide React, Recharts.
- **Backend:** Python 3.14 / 3.11+, FastAPI, Pydantic v2 (Strict validation), SQLAlchemy 2.0 ORM.
- **Security & Crypto:** Standard library PBKDF2-HMAC-SHA256 (100k iterations, 16-byte random salt), constant-time HMAC comparison, cryptographic token generators.
- **Data Persistence:** SQLite for local prototyping, architectured for enterprise PostgreSQL or IBM Db2.
- **Quality Assurance:** Comprehensive Pytest test suite (24 deterministic unit & integration tests covering security boundaries, RBAC, PII redaction, and threat rules).

---

## 5. IBM LinuxONE & IBM Z Alignment

SentinelZ AI is architectured to maximize the security strengths of the IBM LinuxONE enterprise platform:
- **Architecture Neutrality:** Contains zero x86-locked binary dependencies. Python and Node.js run natively on Linux on IBM Z (`s390x`).
- **Hardware Cryptography (CPACF):** LinuxONE CPACF hardware instructions accelerate the SHA-256 and AES operations utilized in SentinelZ session management and hashing.
- **Pervasive Encryption:** The database and log storage seamlessly benefit from LinuxONE dataset and filesystem-level encryption without modifying application code.
- **IBM Secure Execution for Linux:** SentinelZ AI's containerized backend can be deployed inside an IBM Secure Execution confidential computing enclave, shielding tenant data from host administrators.

---

## 6. Testing & Evaluation Summary

| Test Domain | Tests Executed | Status | Key Assertions Verified |
| :--- | :---: | :---: | :--- |
| **Threat Detection Rules** | 5 | **PASS** | High-value asset denial triggers CRITICAL alert; 3x auth failures trigger BRUTE_FORCE; privilege mismatches and recon scans flagged. |
| **Privacy Shield** | 5 | **PASS** | Email, phone, mainframe account, card, and SSN masked; span overlap protection verified; zero unredacted PII leaks to AI. |
| **RBAC Security** | 7 | **PASS** | Deny by default; Viewer blocked from `/users` and `/settings`; role escalation blocked; invalid credentials rejected. |
| **Audit Logging** | 2 | **PASS** | Logins and finding status changes audited; passwords and tokens stripped from metadata. |
| **Platform Health & API** | 5 | **PASS** | Liveness probe `/health`, readiness probe `/readiness`, LinuxONE status, metrics aggregation, payload validation. |
| **Total Automated Tests** | **24** | **100% PASS** | Zero failures across entire suite. |

---

## 7. Social Impact & Ethics

In an era of rapid AI adoption, organizations often inadvertently feed proprietary, sovereign, or customer data into external commercial models. SentinelZ AI demonstrates how enterprises can innovate responsibly by establishing an impenetrable privacy boundary—proving that **advanced AI security intelligence does not require exposing sensitive human or infrastructure data**.

---

## 8. Future Roadmap

- Integration with IBM watsonx.governance for automated model risk monitoring.
- Native PKCS#11 driver integration for IBM Crypto Express 8S HSM hardware key storage.
- Streaming telemetry ingestion via Apache Kafka / IBM Event Streams.
