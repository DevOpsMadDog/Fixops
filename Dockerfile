# ─────────────────────────────────────────────────────────────
# ALdeci FixOps CTEM+ Enterprise — Production Multi-Stage Build
# ─────────────────────────────────────────────────────────────

# Stage 1: Build the React UI
FROM node:20-alpine AS ui-builder
WORKDIR /build
COPY suite-ui/aldeci-ui-new/package.json suite-ui/aldeci-ui-new/package-lock.json ./
RUN npm ci --production=false
COPY suite-ui/aldeci-ui-new/ .
RUN npx vite build

# Stage 2: Production runtime
FROM python:3.11-slim AS runtime

# System deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl nodejs npm && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy full application
COPY suite-api/ suite-api/
COPY suite-core/ suite-core/
COPY suite-attack/ suite-attack/
COPY suite-evidence-risk/ suite-evidence-risk/
COPY suite-integrations/ suite-integrations/
COPY config/ config/
COPY scripts/ scripts/
COPY data/ data/

# Copy Node production server
COPY serve.js package.json ./
RUN npm install --production

# Copy built frontend from Stage 1
COPY --from=ui-builder /build/dist suite-ui/aldeci-ui-new/dist/

# Environment defaults (override at deploy time)
ENV PYTHONPATH=/app/suite-api:/app/suite-api/apps:/app:/app/suite-core:/app/suite-attack:/app/suite-evidence-risk:/app/suite-integrations
ENV FIXOPS_MODE=enterprise
ENV FIXOPS_DISABLE_RATE_LIMIT=0
ENV NODE_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD curl -f http://localhost:3000/api/v1/health || exit 1

# Expose the unified production server port
EXPOSE 3000

# Entrypoint: start API backend + Node production server
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
