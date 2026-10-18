# ==============================================================================
# SentinelZ AI — Container Deployment Dockerfile
# Compatible with IBM LinuxONE (s390x) and x86_64
# IBM Z Datathon 2026: AI Secured — Innovation Without Exposure
# ==============================================================================
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINELZ_PORT=8000 \
    SENTINELZ_HOST=0.0.0.0

WORKDIR /app

# Install build dependencies for architecture neutrality
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend source code
COPY backend ./backend
COPY scripts ./scripts

# Create non-root user for least privilege security
RUN useradd -u 1001 -m -s /bin/bash sentinelz && \
    chown -R sentinelz:sentinelz /app

USER sentinelz

# Health check probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

EXPOSE 8000

# Start command
CMD ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
