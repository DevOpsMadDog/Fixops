# ============================================
# FixOps Docker Image - Optimized for Size
# ============================================
# This image is optimized for easy distribution
# to customers with a smaller footprint.
# ============================================

FROM python:3.11-slim as builder

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

# Copy and install requirements
COPY requirements.txt .
# Install remaining requirements (pgmpy will use the CPU torch we installed)
RUN pip install --no-cache-dir -r requirements.txt

# ============================================
# Final stage - minimal runtime image
# ============================================
FROM python:3.11-slim

WORKDIR /app

# Install only runtime dependencies (including tools for demo scripts)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    jq \
    ncurses-bin \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code (exclude unnecessary files)
COPY apps/ ./apps/
COPY core/ ./core/
COPY risk/ ./risk/
COPY integrations/ ./integrations/
COPY config/ ./config/
COPY samples/ ./samples/
COPY simulations/ ./simulations/
COPY data/ ./data/
COPY backend/ ./backend/
COPY agents/ ./agents/
COPY scripts/ ./scripts/
COPY services/ ./services/
COPY telemetry/ ./telemetry/
COPY fixops/ ./fixops/
COPY domain/ ./domain/
COPY new_apps/ ./new_apps/
COPY new_backend/ ./new_backend/
COPY fixops-enterprise/ ./fixops-enterprise/
COPY *.py ./
COPY *.txt ./
COPY *.yml ./
COPY *.yaml ./
COPY *.md ./
COPY docs/ ./docs/
COPY cli/ ./cli/
COPY evidence/ ./evidence/
COPY lib4sbom/ ./lib4sbom/

# Create data directory
RUN mkdir -p /app/.fixops_data

# Make demo scripts executable
RUN chmod +x /app/scripts/fixops-interactive.sh \
    /app/scripts/aldeci-demo-runner.sh \
    /app/scripts/docker-entrypoint.sh 2>/dev/null || true

# Expose port
EXPOSE 8000

# Set environment variables
ENV FIXOPS_MODE=demo
ENV FIXOPS_DATA_DIR=/app/.fixops_data
ENV FIXOPS_API_TOKEN=demo-token-12345
ENV FIXOPS_API_URL=http://localhost:8000
ENV PYTHONUNBUFFERED=1
ENV FIXOPS_DISABLE_TELEMETRY=1
ENV TERM=xterm-256color
# Ensure /app is on Python's module search path for local packages
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default: Run the API server
# For demo mode, use: docker run -it fixops demo
# For interactive tester: docker run -it fixops interactive
ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD ["api-only"]
