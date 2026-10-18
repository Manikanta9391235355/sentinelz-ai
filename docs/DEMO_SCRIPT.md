# SentinelZ AI — 5-Minute Datathon Demonstration Script

**Platform:** SentinelZ AI — Privacy-First AI Security & Threat Detection Platform  
**Datathon Track:** IBM Z Datathon 2026 — *AI Secured: Innovation Without Exposure*  
**Duration:** ~5 minutes  

---

## Preparation & Prerequisites

1. Start the FastAPI backend:
   ```bash
   python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
   ```
2. Start the Next.js frontend:
   ```bash
   npm run dev
   ```
3. Open your browser to `http://localhost:3000`.

---

## Step-by-Step Demonstration Walkthrough

### Minute 1: The Vision & Executive Overview
- **Screen:** `/` (Security Operations Center Overview)
- **Action:**
  1. Point out the live telemetry metrics: Total Security Events, High-Risk Findings, Under Investigation, Denied Access, and PII Shielded tokens.
  2. Highlight the **Event Volume & Anomaly Distribution** chart (Recharts) showing live temporal correlation.
  3. Show the **Severity Distribution** bar chart (Critical, High, Medium, Low).
- **Narrative:**
  > *"Welcome to SentinelZ AI. Our mission is 'Intelligence Without Exposure' for the IBM Z Datathon 2026. Enterprise SOCs monitoring mainframe and hybrid infrastructure need AI-assisted threat analytics, but they cannot afford to leak customer PII, mainframe account numbers, or internal network topologies. SentinelZ solves this by pairing explainable deterministic threat rules with an impenetrable Privacy Shield."*

---

### Minute 2: Security Event Telemetry & Threat Ingestion
- **Screen:** `/events` (Security Event Telemetry Stream)
- **Action:**
  1. Observe the live stream of synthetic security events simulating mainframe ledger queries, crypto HSM accesses, and baseline operator actions.
  2. Click **"Ingest Security Event"**.
  3. Click the preset template **"High-Value Mainframe Asset Probe"** (targets `mainframes/z16-hsm/crypto-keys/master-aes256` with decision `DENY`).
  4. Click **"Submit Event to Engine"**.
- **Expected Result:**
  - Event is immediately ingested and evaluated in real-time.
  - An explainable Threat Finding is generated instantly with risk score &ge; 80 (CRITICAL).

---

### Minute 3: Explainable Threat Findings & Incident Investigation
- **Screen:** `/findings` & `/findings/[id]`
- **Action:**
  1. Navigate to `/findings`. Notice the newly generated finding: *"Unauthorized Access Attempt on High-Value Mainframe Asset"*.
  2. Click **"Investigate Finding"**.
  3. Point out the **Detection Explanation** and **Calculated Risk Score** (transparent deterministic formula).
  4. Highlight the **Recommended Non-Destructive Next Steps**:
     > *"Notice that SentinelZ recommends verification actions for the human analyst rather than executing destructive automated bans."*
  5. In the **Analyst Investigation Disposition** card, change the status from `OPEN` to `INVESTIGATING`, add notes, and click **"Commit Status Disposition"**.
- **Expected Result:**
  - Status updates to `INVESTIGATING` with a success confirmation.
  - An immutable audit trail entry is created in the background.

---

### Minute 4: The Privacy Shield in Action
- **Screen:** `/privacy` (Privacy Shield — Dedicated PII Boundary)
- **Action:**
  1. Click the preset scenario **"Customer Incident (Mainframe & Email)"**.
     - Raw text contains: `alex@example.com`, `IBM-ACCT-98F1-44B2`, `+1 (555) 234-5678`, and IP `192.168.1.105`.
  2. Under configurable keywords, type `PROJECT_TITAN` and click **"Add Token"**.
  3. Click **"Shield & Analyze (AI Safe)"**.
- **Expected Result:**
  - The Privacy Shield's non-overlapping span engine replaces all entities with typed placeholders:
    `[EMAIL_REDACTED]`, `[MAINFRAME_ACCT_REDACTED]`, `[PHONE_REDACTED]`, `[IP_REDACTED]`.
  - The transformation card confirms: **Boundary Status: SECURED**; latency: <5ms.
  - The local privacy-preserving security model generates an assessment of the sanitized tokens.
  - Point out: **Zero external network egress occurred.**

---

### Minute 5: Server-Enforced RBAC & IBM LinuxONE Alignment
- **Screen:** `/identity` and `/health`
- **Action:**
  1. In the sidebar's **Datathon RBAC Switcher**, click **Viewer**.
  2. Notice the immediate boundary response: The User Identity Administration table is disabled with a server-enforced warning.
  3. Go to `/events` and notice the **"Ingest Security Event"** button is disabled with an RBAC notice.
  4. Switch back to **Admin** to show instant restoration of privileges.
  5. Navigate to `/audit` to verify that all operations (logins, finding status triage, event ingestion, and privacy shield runs) were appended with correlation IDs, with passwords and tokens scrubbed.
  6. Navigate to `/health` to showcase the **IBM Z / LinuxONE Security Alignment** section, highlighting CPACF acceleration, Pervasive Encryption, and IBM Secure Execution.
- **Concluding Statement:**
  > *"SentinelZ AI delivers demonstrable security analytics, strict PII privacy boundaries, server-enforced RBAC, and architecture-neutral execution ready for IBM LinuxONE. Thank you!"*
