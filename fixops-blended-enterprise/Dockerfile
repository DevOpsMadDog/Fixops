# FixOps Enterprise - Production Dockerfile
# Multi-stage build for bank-grade deployment

# Stage 1: Build stage
FROM python:3.11.7-slim-bullseye as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Production stage
FROM python:3.11.7-slim-bullseye

# Create non-root user for security
RUN groupadd --gid 1000 fixops && \
    useradd --uid 1000 --gid fixops --shell /bin/bash --create-home fixops

# Set working directory
WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder
COPY --from=builder /root/.local /home/fixops/.local

# Copy application code
COPY --chown=fixops:fixops src/ ./src/
COPY --chown=fixops:fixops scripts/ ./scripts/
COPY --chown=fixops:fixops alembic.ini ./
COPY --chown=fixops:fixops server.py ./

# Create required directories
RUN mkdir -p /app/logs /app/data && \
    chown -R fixops:fixops /app

# Switch to non-root user
USER fixops

# Add user's local bin to PATH
ENV PATH=/home/fixops/.local/bin:$PATH
ENV PYTHONPATH=/app

# Production environment variables
ENV FIXOPS_ENVIRONMENT=production
ENV FIXOPS_LOG_LEVEL=info
ENV FIXOPS_DEMO_MODE=false
ENV FIXOPS_AUTH_DISABLED=false
ENV FIXOPS_UI_ENABLED=true
ENV FIXOPS_API_TOKEN_HEADER=X-API-Key

# Health check for Kubernetes
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Expose ports
EXPOSE 8001

COPY --chown=fixops:fixops scripts/entrypoint.sh ./scripts/entrypoint.sh
RUN chmod 0755 ./scripts/entrypoint.sh

ENTRYPOINT ["./scripts/entrypoint.sh"]