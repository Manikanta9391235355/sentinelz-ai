# SentinelZ AI — Production Deployment & Operations Guide
## Live Deployment on IBM LinuxONE Community Cloud (s390x)

> **Application:** SentinelZ AI — Privacy-First AI Security & Threat Detection Platform  
> **Tagline:** *Intelligence Without Exposure*  
> **Datathon Track:** *IBM Z Datathon 2026 — AI Secured: Innovation Without Exposure*  
> **Server Public IP:** `148.100.98.222`  
> **Public Web URL:** [http://148.100.98.222](http://148.100.98.222)  
> **Operating System:** Ubuntu 24.04.5 LTS (Noble Numbat) on Linux on IBM Z / LinuxONE (`s390x`)  
> **VM Profile:** `AI_LAB` (3 vCPUs, 8 GB RAM, 50 GB Root Disk)

---

## 1. Deployed Production Architecture

```
Internet / Datathon Reviewer
           │
           ▼ (HTTP Port 80 - Publicly Allowed via iptables)
   ┌──────────────────────────────────────────────┐
   │       Nginx 1.24 Reverse Proxy (Port 80)     │
   └───────────────┬──────────────────────┬───────┘
                   │                      │
       (Reverse Proxy: /)       (Reverse Proxy: /api/)
                   │                      │
                   ▼                      ▼
    ┌───────────────────────────┐  ┌───────────────────────────┐
    │  Next.js 16 SOC Frontend  │  │  FastAPI Security Core    │
    │  Port 3000 (127.0.0.1)    │  │  Port 8000 (127.0.0.1)    │
    │  Systemd Service          │  │  Systemd Service          │
    └───────────────────────────┘  └─────────────┬─────────────┘
                                                 │
                                                 ▼
                                   ┌───────────────────────────┐
                                   │  SQLite 3 Database Store  │
                                   │  /opt/sentinelz-ai/       │
                                   │  sentinelz.db             │
                                   └───────────────────────────┘
```

### Security Isolation
- **No Direct Internal Exposure:** Both the Next.js frontend (`127.0.0.1:3000`) and FastAPI backend (`127.0.0.1:8000`) listen **strictly on localhost loopback**.
- **Database Privacy:** The SQLite database file (`/opt/sentinelz-ai/sentinelz.db`) is stored locally with application-only read/write permissions.
- **Single Public Port:** Only port 80 (HTTP) is routed through Nginx. Port 22 (SSH) is restricted to key-based authentication (`linux1`).

---

## 2. Server Specifications & Verified Dependencies

| Component | Detected & Verified Specification |
| :--- | :--- |
| **Architecture** | `s390x` (64-bit IBM System/390 architecture) |
| **Kernel** | `6.8.0-147-generic #147-Ubuntu SMP s390x` |
| **Node.js** | `v20.18.0` LTS (official 64-bit s390x binary) |
| **npm** | `10.8.2` |
| **Python** | `Python 3.12.3` |
| **Web Server** | `nginx/1.24.0` |
| **Database** | SQLite 3 via SQLAlchemy 2.0 ORM |

---

## 3. Systemd Services & Process Management

Both components are managed as standard Linux systemd services with auto-restart on failure and boot startup enabled:

| Service Name | Description | Executable / Command | Status |
| :--- | :--- | :--- | :--- |
| `sentinelz-backend.service` | FastAPI Security Analytics Engine | `/opt/sentinelz-ai/.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000` | `active (running)` |
| `sentinelz-frontend.service` | Next.js SOC Web Application | `/usr/local/bin/node /opt/sentinelz-ai/node_modules/.bin/next start -p 3000 -H 127.0.0.1` | `active (running)` |
| `nginx.service` | Public HTTP Reverse Proxy | `/usr/sbin/nginx` (Port 80) | `active (running)` |

### Operational Management Commands

```bash
# Check service health and status
sudo systemctl status sentinelz-backend
sudo systemctl status sentinelz-frontend
sudo systemctl status nginx

# Restart services
sudo systemctl restart sentinelz-backend
sudo systemctl restart sentinelz-frontend
sudo systemctl restart nginx

# View real-time application logs
sudo journalctl -u sentinelz-backend -f
sudo journalctl -u sentinelz-frontend -f
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

---

## 4. Live Verification & Health Check Endpoints

| Endpoint | Target URL | Expected HTTP Code | Verified Output |
| :--- | :--- | :--- | :--- |
| **Public SOC UI** | [http://148.100.98.222](http://148.100.98.222) | `200 OK` | Next.js 16 SOC Dashboard with live telemetry |
| **Liveness Probe** | [http://148.100.98.222/api/health](http://148.100.98.222/api/health) | `200 OK` | `{"status":"healthy","database":"connected"}` |
| **Readiness Probe** | [http://148.100.98.222/api/readiness](http://148.100.98.222/api/readiness) | `200 OK` | `{"status":"ready","database":"connected"}` |
| **LinuxONE Status** | [http://148.100.98.222/api/linuxone/status](http://148.100.98.222/api/linuxone/status) | `200 OK` | CPACF, s390x, Pervasive Encryption status |
| **API Documentation** | [http://148.100.98.222/api/docs](http://148.100.98.222/api/docs) | `200 OK` | Interactive Swagger / OpenAPI 3.0 Sandbox |

---

## 5. Firewall Configuration & Port Hardening

The IBM LinuxONE Community Cloud image defaults to rejecting all inbound traffic except port 22. The firewall was audited and narrowly updated:

```bash
# Audited iptables rules:
sudo iptables -L INPUT --line-numbers -n
```

1. **Rule 1 (`ACCEPT`):** Loopback interface (`127.0.0.0/8`)
2. **Rule 2 (`ACCEPT`):** SSH port 22 (`tcp dpt:22 ctstate NEW`)
3. **Rule 3 (`ACCEPT`):** HTTP port 80 (`tcp dpt:80 ctstate NEW`)
4. **Rule 4 (`ACCEPT`):** ICMP Echo / Ping
5. **Rule 5 (`ACCEPT`):** Established and related connections (`ctstate RELATED,ESTABLISHED`)
6. **Rule 6 (`REJECT`):** All other incoming connections rejected (`icmp-host-prohibited`)

Persisted in `/etc/iptables/rules.v4` to survive reboots.

---

## 6. Pre-Seeded Datathon Accounts (RBAC)

The deployment includes 3 pre-seeded personas representing the required enterprise SOC hierarchy. Use the **1-click Datathon Persona Switcher** in the top navigation bar or log in with credentials:

| Role | Username / Email | Password | Access Privileges |
| :--- | :--- | :--- | :--- |
| **Security Administrator** | `admin@sentinelz.local` | `SentinelAdmin#2026` | Full SOC management, user role configuration, audit trail inspection |
| **Security Analyst** | `analyst@sentinelz.local` | `SentinelAnalyst#2026` | Event ingestion, threat triage, privacy shield, finding disposition |
| **Viewer** | `viewer@sentinelz.local` | `SentinelViewer#2026` | Read-only aggregate metrics (blocked from mutating or viewing sensitive logs) |

---

## 7. Database Persistence & Backup Procedure

- **File Location:** `/opt/sentinelz-ai/sentinelz.db`
- **Ownership:** `linux1:linux1` (mode `0644`)
- **Engine:** SQLite 3 (WAL mode supported)

### Backup Procedure
To create an atomic, non-blocking backup of the live database:
```bash
# Perform an atomic backup to a timestamped archive
sqlite3 /opt/sentinelz-ai/sentinelz.db ".backup /opt/sentinelz-ai/backup-$(date +%Y%m%d%H%M%S).db"
```

---

## 8. Automated Remote Verification

Run the verification suites against the live LinuxONE public server from any workstation:

```bash
# 1. Execute full end-to-end HTTP smoke test (15 assertions)
python scripts/smoke_test.py http://148.100.98.222/api

# 2. Stream live synthetic telemetry and trigger real-time threat detection
python scripts/simulate_traffic.py --url http://148.100.98.222/api --count 20 --interval 1.0
```

---

## 9. Remaining Security Considerations & Next Steps

1. **Domain & TLS/HTTPS:** The application is currently served over HTTP on the public IP (`http://148.100.98.222`) because a custom domain name (DNS A Record) has not yet been assigned to the IP. Once a domain (e.g., `sentinelz.example.com`) is pointed to `148.100.98.222`, Let's Encrypt SSL can be enabled with one command:
   ```bash
   sudo certbot --nginx -d sentinelz.yourdomain.com
   ```
2. **Zero-Exposure Guarantee Preserved:** External AI forwarding remains disabled by default (`SENTINELZ_AI_ENABLED=false`). All threat scoring and redaction occur locally on the s390x mainframe virtual server.
