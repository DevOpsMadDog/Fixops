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

# Install runtime dependencies including jq
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    jq \
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
COPY postman/ ./postman/
COPY docs/ ./docs/
COPY *.py ./
COPY *.txt ./
COPY *.yml ./
COPY *.yaml ./
COPY *.md ./

# Create data directory
RUN mkdir -p /app/.fixops_data

# Expose port
EXPOSE 8000

# Set environment variables
ENV FIXOPS_MODE=demo
ENV FIXOPS_DATA_DIR=/app/.fixops_data
ENV FIXOPS_API_TOKEN=demo-token
ENV PYTHONUNBUFFERED=1
ENV FIXOPS_DISABLE_TELEMETRY=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the API
CMD ["uvicorn", "apps.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
