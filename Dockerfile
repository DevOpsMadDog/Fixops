# ============================================
# ALdeci CTEM+ Platform — Production Image
# ============================================
# 3-stage build: UI → Python deps → Runtime
#
# Build:  docker build -t aldeci:latest .
# Run:    docker run -p 8000:8000 -e FIXOPS_API_TOKEN=<key> aldeci:latest
# ============================================

# ── Stage 1: Build React UI ───────────────────────────────────
FROM node:20-alpine AS ui-builder
WORKDIR /build
COPY suite-ui/aldeci-ui-new/package.json suite-ui/aldeci-ui-new/package-lock.json ./
RUN npm ci
COPY suite-ui/aldeci-ui-new/ .
RUN npx vite build

# ── Stage 2: Python dependencies ──────────────────────────────
FROM python:3.11-slim AS py-builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# CPU-only PyTorch (much smaller than GPU)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Stage 3: Production runtime ──────────────────────────────
FROM python:3.11-slim

# Non-root user
RUN groupadd -r aldeci && useradd -r -g aldeci -m -s /bin/bash aldeci

WORKDIR /app

# Runtime system deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl jq && rm -rf /var/lib/apt/lists/*

# Python venv from builder
COPY --from=py-builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy all 6 suites
COPY suite-api/       ./suite-api/
COPY suite-core/      ./suite-core/
COPY suite-attack/    ./suite-attack/
COPY suite-feeds/     ./suite-feeds/
COPY suite-evidence-risk/  ./suite-evidence-risk/
COPY suite-integrations/   ./suite-integrations/

# Built UI from stage 1
COPY --from=ui-builder /build/dist ./suite-ui/aldeci-ui-new/dist/

# Import resolution + entrypoint
COPY sitecustomize.py ./
COPY requirements.txt ./
COPY scripts/docker-entrypoint.sh ./scripts/docker-entrypoint.sh
RUN chmod +x /app/scripts/docker-entrypoint.sh

# Data directories
RUN mkdir -p /app/.fixops_data /app/data \
    && chown -R aldeci:aldeci /app

# Switch to non-root
USER aldeci

# Labels
LABEL org.opencontainers.image.title="ALdeci CTEM+ Platform"
LABEL org.opencontainers.image.description="Decision Intelligence for Application Security"
LABEL org.opencontainers.image.vendor="ALdeci"

EXPOSE 8000

# Environment
ENV FIXOPS_MODE=enterprise \
    FIXOPS_DATA_DIR=/app/.fixops_data \
    FIXOPS_DISABLE_TELEMETRY=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/suite-api:/app/suite-core:/app/suite-attack:/app/suite-feeds:/app/suite-evidence-risk:/app/suite-integrations:/app

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -sf http://localhost:8000/health || exit 1

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD ["api-only"]

