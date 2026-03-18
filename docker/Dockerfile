# ============================================
# ALdeci CTEM+ Platform — Docker Image
# ============================================
# 6-suite modular monolith running on port 8000.
# Multi-stage build: builder (deps) → runtime.
#
# Build:   docker build -f docker/Dockerfile -t fixops:local .
# Run:     docker run -p 8000:8000 fixops:local
# Compose: docker compose -f docker/docker-compose.yml up
# ============================================

# ── Stage 1: Builder ────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install CPU-only PyTorch first (much smaller than GPU version)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Copy and install requirements (cached layer unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Stage 2: Runtime ────────────────────────────────────────
FROM python:3.11-slim

# Add non-root user for security
RUN groupadd -r aldeci && useradd -r -g aldeci -m -s /bin/bash aldeci

WORKDIR /app

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy suite architecture (the ONLY active code)
COPY suite-api/ ./suite-api/
COPY suite-core/ ./suite-core/
COPY suite-attack/ ./suite-attack/
COPY suite-feeds/ ./suite-feeds/
COPY suite-evidence-risk/ ./suite-evidence-risk/
COPY suite-integrations/ ./suite-integrations/

# Copy essential supporting files
COPY scripts/docker-entrypoint.sh ./scripts/docker-entrypoint.sh
COPY scripts/fixops-interactive.sh ./scripts/fixops-interactive.sh
COPY scripts/aldeci-demo-runner.sh ./scripts/aldeci-demo-runner.sh
COPY scripts/demo-healthcheck.sh ./scripts/demo-healthcheck.sh
COPY scripts/feed_sidecar.py ./scripts/feed_sidecar.py
COPY scripts/micropentest_sidecar.py ./scripts/micropentest_sidecar.py

# Copy Python entry point (sitecustomize.py for import resolution)
COPY sitecustomize.py ./
COPY requirements.txt ./

# Create data directory with correct ownership
RUN mkdir -p /app/.fixops_data /app/data \
    && chown -R aldeci:aldeci /app/.fixops_data /app/data

# Make scripts executable
RUN chmod +x /app/scripts/*.sh

# Set ownership of app directory for non-root user
RUN chown -R aldeci:aldeci /app

# Switch to non-root user (CWE-250: Running with unnecessary privileges)
USER aldeci

# Labels for container identification
LABEL org.opencontainers.image.title="ALdeci CTEM+ Platform"
LABEL org.opencontainers.image.description="Decision Intelligence for Application Security"
LABEL org.opencontainers.image.vendor="ALdeci"
LABEL org.opencontainers.image.source="https://github.com/aldeci/fixops"

# Expose API port
EXPOSE 8000

# Environment variables
ENV FIXOPS_MODE=enterprise \
    FIXOPS_DATA_DIR=/app/.fixops_data \
    FIXOPS_API_URL=http://localhost:8000 \
    FIXOPS_DISABLE_TELEMETRY=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color \
    # Suite architecture: each suite dir must be on PYTHONPATH so
    # "from apps.api.app import ..." resolves from suite-api/apps/api/app.py
    PYTHONPATH=/app/suite-api:/app/suite-core:/app/suite-attack:/app/suite-feeds:/app/suite-evidence-risk:/app/suite-integrations:/app

# Health check — matches docker-compose.yml and nginx proxy
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -sf http://localhost:8000/health || exit 1

# Default: Run the API server
# Modes: api-only, interactive, enterprise, cli, shell
ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD ["api-only"]
