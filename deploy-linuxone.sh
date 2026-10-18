#!/usr/bin/env bash
# ==============================================================================
# SentinelZ AI — Deployment Script for IBM LinuxONE Community Cloud (s390x)
# Theme: AI Secured: Innovation Without Exposure (IBM Z Datathon 2026)
# ==============================================================================
set -e

echo "========================================================================"
echo " SentinelZ AI — Automated Deployment for IBM LinuxONE (s390x / Linux on Z)"
echo " Tagline: Intelligence Without Exposure"
echo "========================================================================"

# 1. Architecture & Environment Detection
ARCH=$(uname -m)
echo "[INFO] Detected Architecture: ${ARCH}"
if [ "${ARCH}" != "s390x" ]; then
    echo "[WARN] Host architecture is ${ARCH}, not native s390x."
    echo "       SentinelZ AI will proceed in cross-architecture compatibility mode."
fi

# 2. Check Prerequisites
echo "[INFO] Verifying runtime dependencies..."
command -v python3 >/dev/null 2>&1 || { echo "[ERROR] Python 3.10+ is required but not installed."; exit 1; }
command -v node >/dev/null 2>&1 || { echo "[ERROR] Node.js 18+ is required but not installed."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "[ERROR] npm is required but not installed."; exit 1; }

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
NODE_VER=$(node -v)
echo "[INFO] Python Version: ${PY_VER}"
echo "[INFO] Node Version: ${NODE_VER}"

# 3. Backend Setup
echo "[INFO] Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate

echo "[INFO] Installing Python dependencies (pure-Python wheels safe for s390x)..."
pip install --upgrade pip
pip install fastapi uvicorn pydantic sqlalchemy httpx pytest

# 4. Frontend Setup & Build
echo "[INFO] Installing frontend dependencies..."
npm install

echo "[INFO] Compiling Next.js frontend production bundle..."
npm run build

# 5. Database Initialization & Seeding
echo "[INFO] Initializing SQLite database and seeding synthetic baseline data..."
python3 -c "
from backend.app.database import engine, Base, SessionLocal
from backend.app.services.seeder import seed_database
Base.metadata.create_all(bind=engine)
db = SessionLocal()
seed_database(db)
db.close()
print('Database initialized and seeded successfully.')
"

# 6. Run Self-Verification Test Suite
echo "[INFO] Executing automated security test suite..."
python3 -m pytest backend/tests -v

echo "========================================================================"
echo "[SUCCESS] SentinelZ AI is ready for production service on IBM LinuxONE!"
echo "To launch services:"
echo "  Backend:  uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"
echo "  Frontend: npm start -- -p 3000"
echo "========================================================================"
