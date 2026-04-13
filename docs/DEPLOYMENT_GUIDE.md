# ALDECI CTEM+ Platform — Deployment Guide

> Version: 1.0 | Branch: `features/intermediate-stage`
> Last updated: 2026-04-12

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Quick Start — Docker Compose](#2-quick-start--docker-compose)
3. [Production Deployment — Kubernetes](#3-production-deployment--kubernetes)
4. [Environment Variables Reference](#4-environment-variables-reference)
5. [TLS / SSL Setup](#5-tls--ssl-setup)
6. [Database Management](#6-database-management)
7. [Backup and Restore](#7-backup-and-restore)
8. [Scaling Guide](#8-scaling-guide)
9. [Monitoring Setup](#9-monitoring-setup)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

### Minimum Hardware

| Component | Development | Production |
|-----------|-------------|------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB (32 GB recommended) |
| Disk | 20 GB | 100 GB SSD |
| Network | — | 1 Gbps |

### Software Requirements

| Tool | Minimum Version | Notes |
|------|----------------|-------|
| Docker | 24.0+ | Compose plugin required |
| Docker Compose | 2.20+ | Bundled with Docker Desktop |
| Node.js | 20 LTS | For manual / dev builds only |
| Python | 3.11+ | For manual / dev installs only |
| kubectl | 1.28+ | Kubernetes deployments only |
| Helm | 3.12+ | Kubernetes deployments only |
| openssl | 3.0+ | TLS certificate generation |

### Verify Prerequisites

```bash
docker --version          # Docker version 24.x.x
docker compose version    # Docker Compose version v2.x.x
node --version            # v20.x.x
python3 --version         # Python 3.11.x
kubectl version --client  # Kubernetes deployments
```

---

## 2. Quick Start — Docker Compose

The fastest path from zero to a running ALDECI instance.

### Step 1 — Clone the Repository

```bash
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops
git checkout features/intermediate-stage
```

### Step 2 — Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```bash
# Required — change these before first boot
FIXOPS_API_TOKEN=fixops_sk_$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
FIXOPS_JWT_SECRET=$(openssl rand -hex 32)

# Optional — enable AI features
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
OPENROUTER_API_KEY=sk-or-v1-...
```

### Step 3 — Start the Stack

```bash
# API + UI (standard)
docker compose up -d

# With OWASP Dependency-Track (SBOM analysis)
docker compose --profile dtrack up -d

# Seed TrustGraph Knowledge Cores (run once after first boot)
docker compose --profile init run --rm trustgraph-init
```

### Step 4 — Verify

```bash
# Check all containers are healthy
docker compose ps

# API health check
curl http://localhost:8000/health

# UI
open http://localhost:3000
```

### Service Endpoints (default)

| Service | URL | Notes |
|---------|-----|-------|
| ALDECI UI | http://localhost:3000 | React 19 + Vite 6 |
| ALDECI API | http://localhost:8000 | FastAPI |
| API Docs | http://localhost:8000/docs | OpenAPI / Swagger |
| DTrack API | http://localhost:8080 | Optional — `--profile dtrack` |
| DTrack UI | http://localhost:8081 | Optional — `--profile dtrack` |

---

## 3. Production Deployment — Kubernetes

All Kubernetes manifests are in `docker/kubernetes/`.

### 3.1 Namespace and RBAC

```bash
kubectl apply -f docker/kubernetes/namespace.yaml
kubectl apply -f docker/kubernetes/rbac.yaml
```

### 3.2 Secrets

```bash
# Create secrets from environment or a secrets manager
kubectl create secret generic aldeci-secrets \
  --namespace=aldeci \
  --from-literal=api-token="$(openssl rand -hex 32)" \
  --from-literal=jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=anthropic-api-key="${ANTHROPIC_API_KEY}" \
  --from-literal=openai-api-key="${OPENAI_API_KEY}"
```

Or apply the provided template (edit values first):

```bash
cp docker/kubernetes/secrets.yaml secrets.local.yaml
# Edit secrets.local.yaml — base64-encode all values
kubectl apply -f secrets.local.yaml
```

### 3.3 Storage

```bash
kubectl apply -f docker/kubernetes/pvc.yaml
```

### 3.4 ConfigMap

```bash
kubectl apply -f docker/kubernetes/configmap.yaml
```

### 3.5 Deploy API and UI

```bash
kubectl apply -f docker/kubernetes/api-deployment.yaml
kubectl apply -f docker/kubernetes/api-service.yaml
kubectl apply -f docker/kubernetes/ui-deployment.yaml
kubectl apply -f docker/kubernetes/ui-service.yaml
```

### 3.6 Ingress (Nginx)

```bash
kubectl apply -f docker/kubernetes/ingress.yaml
```

### 3.7 Horizontal Pod Autoscaler

```bash
kubectl apply -f docker/kubernetes/hpa.yaml
```

### 3.8 Verify Deployment

```bash
kubectl get pods -n aldeci
kubectl get svc -n aldeci
kubectl get ingress -n aldeci
```

### 3.9 Kustomize Overlays

For environment-specific overrides (staging vs production):

```bash
# Production overlay
kubectl apply -k docker/kubernetes/overlays/production/

# Staging overlay
kubectl apply -k docker/kubernetes/overlays/staging/
```

---

## 4. Environment Variables Reference

### Core Application

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `FIXOPS_API_TOKEN` | `aldeci-demo-token` | YES | Master API authentication token |
| `FIXOPS_JWT_SECRET` | — | YES (prod) | JWT signing secret (min 32 chars) |
| `FIXOPS_MODE` | `enterprise` | No | Operating mode: `demo`, `enterprise` |
| `ALDECI_PORT` | `8000` | No | API server port |
| `ALDECI_UI_PORT` | `3000` | No | UI server port |
| `ALDECI_SEED_DEMO` | `1` | No | Seed demo data on first boot (0/1) |
| `FIXOPS_DISABLE_RATE_LIMIT` | `0` | No | Disable rate limiting (0/1) |
| `FIXOPS_USE_COUNCIL` | `0` | No | Enable LLM Consensus Council (0/1) |

### AI / LLM Integration

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `ANTHROPIC_API_KEY` | — | No | Claude API key (Opus for LLM Council) |
| `OPENAI_API_KEY` | — | No | OpenAI API key (GPT-4 fallback) |
| `OPENROUTER_API_KEY` | — | No | OpenRouter key (free model access) |

### Optional Integrations

| Variable | Default | Description |
|----------|---------|-------------|
| `DTRACK_API_PORT` | `8080` | Dependency-Track API port |
| `DTRACK_UI_PORT` | `8081` | Dependency-Track UI port |
| `ALDECI_IMAGE` | `aldeci:latest` | Custom API image tag |
| `ALDECI_UI_IMAGE` | `aldeci-ui:latest` | Custom UI image tag |

---

## 5. TLS / SSL Setup

### 5.1 Self-Signed (Development Only)

```bash
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout certs/aldeci.key \
  -out certs/aldeci.crt \
  -subj "/CN=aldeci.local/O=ALDECI/C=US"
```

### 5.2 Let's Encrypt via Certbot (Docker)

```bash
docker run -it --rm \
  -v $(pwd)/certs:/etc/letsencrypt \
  certbot/certbot certonly --standalone \
  -d your-domain.com \
  --email admin@your-domain.com \
  --agree-tos
```

### 5.3 Nginx TLS Termination

The nginx configuration is at `docker/nginx-aldeci.conf`. Update it to reference your certs:

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate     /etc/nginx/certs/aldeci.crt;
    ssl_certificate_key /etc/nginx/certs/aldeci.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://aldeci-ui:80;
    }

    location /api/ {
        proxy_pass http://aldeci-api:8000/;
    }
}
```

### 5.4 Kubernetes TLS (cert-manager)

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml

# Apply ClusterIssuer (Let's Encrypt)
kubectl apply -f docker/kubernetes/cluster-issuer.yaml
```

---

## 6. Database Management

ALDECI uses SQLite per domain (no external DB dependency by default). Files are stored in the `aldeci-data` volume.

### Database Files

| File | Purpose |
|------|---------|
| `data/fixops.db` | Core findings, vulnerabilities |
| `data/fixops_exposure_cases.db` | CTEM exposure cases |
| `data/fixops_dedup.db` | Finding deduplication index |
| `.fixops_data/` | Persistent state (PersistentDict) |

### Inspect a Database

```bash
# Enter the API container
docker compose exec aldeci bash

# Open SQLite shell
sqlite3 /app/data/fixops.db
.tables
.schema findings
```

### Run Migrations (Alembic)

```bash
docker compose exec aldeci bash -c "alembic upgrade head"
```

---

## 7. Backup and Restore

### 7.1 Docker Volume Backup

```bash
# Stop API to ensure data consistency
docker compose stop aldeci

# Backup both data volumes
docker run --rm \
  -v aldeci-data:/source/data \
  -v aldeci-state:/source/state \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/aldeci-backup-$(date +%Y%m%d-%H%M%S).tar.gz -C /source .

# Restart
docker compose start aldeci
```

### 7.2 Restore from Backup

```bash
docker compose stop aldeci

docker run --rm \
  -v aldeci-data:/target/data \
  -v aldeci-state:/target/state \
  -v $(pwd)/backups:/backup \
  alpine sh -c "tar xzf /backup/aldeci-backup-TIMESTAMP.tar.gz -C /target"

docker compose start aldeci
```

### 7.3 Automated Backups (Kubernetes CronJob)

A Kubernetes CronJob manifest is provided:

```bash
kubectl apply -f docker/kubernetes/cronjob-backup.yaml
```

This runs daily at 02:00 UTC and uploads backups to a configured S3 bucket (set `BACKUP_S3_BUCKET` in the ConfigMap).

### 7.4 Backup Rotation

Retain last 30 daily backups, 12 monthly backups:

```bash
# Keep last 30 backups
ls -t backups/aldeci-backup-*.tar.gz | tail -n +31 | xargs rm -f
```

---

## 8. Scaling Guide

### 8.1 Vertical Scaling (Single Node)

Increase the memory limit in `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      memory: 8G   # default: 4G
    reservations:
      memory: 2G
```

### 8.2 Horizontal Scaling (Kubernetes)

```bash
# Manual scale
kubectl scale deployment aldeci-api --replicas=3 -n aldeci
kubectl scale deployment aldeci-ui --replicas=2 -n aldeci

# Auto-scale (HPA is pre-configured)
kubectl get hpa -n aldeci
```

The HPA (`docker/kubernetes/hpa.yaml`) scales API pods between 2–10 replicas based on CPU > 70% and memory > 80%.

### 8.3 Multi-Region Deployment

For multi-region active-passive:
1. Deploy stack to each region
2. Configure read replicas for SQLite → migrate to PostgreSQL for multi-write
3. Use a global load balancer (Cloudflare, AWS ALB, GCP GLB) pointing to regional ingresses
4. Sync the `aldeci-data` volume via object storage (S3 / GCS / Azure Blob)

### 8.4 SQLite → PostgreSQL Migration

For deployments with >50 concurrent users, migrate to PostgreSQL:

```bash
# Set env variable to enable PostgreSQL driver
export ALDECI_DB_URL=postgresql+asyncpg://user:pass@host:5432/aldeci

# Run migration
docker compose exec aldeci alembic upgrade head
```

---

## 9. Monitoring Setup

### 9.1 Built-in Health Endpoint

```bash
curl http://localhost:8000/health
# {"status": "healthy", "version": "...", "uptime": ...}
```

### 9.2 Prometheus Metrics

ALDECI exposes a `/metrics` endpoint compatible with Prometheus:

```yaml
# prometheus.yml scrape config
scrape_configs:
  - job_name: aldeci
    static_configs:
      - targets: ['aldeci-api:8000']
    metrics_path: /metrics
```

### 9.3 Docker Compose Monitoring Stack (Optional)

```bash
# Start with monitoring profile
docker compose --profile monitoring up -d
# Grafana: http://localhost:3001 (admin/admin)
# Prometheus: http://localhost:9090
```

### 9.4 Key Metrics to Alert On

| Metric | Threshold | Severity |
|--------|-----------|----------|
| `http_request_duration_p99` | > 2s | Warning |
| `http_request_duration_p99` | > 10s | Critical |
| Container memory usage | > 80% | Warning |
| Container memory usage | > 95% | Critical |
| API error rate (5xx) | > 1% | Warning |
| API error rate (5xx) | > 5% | Critical |
| Disk usage (`aldeci-data`) | > 80% | Warning |

### 9.5 Log Aggregation

ALDECI uses `structlog` with JSON output. Integrate with any log shipper:

```bash
# Loki / Promtail
docker compose logs -f aldeci | promtail --stdin

# Datadog agent
docker run -d --name dd-agent \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e DD_API_KEY=$DD_API_KEY \
  datadog/agent:latest
```

---

## 10. Troubleshooting

### Container Fails to Start

```bash
# View startup logs
docker compose logs --tail=100 aldeci

# Common cause: missing FIXOPS_API_TOKEN
docker compose exec aldeci env | grep FIXOPS
```

### API Returns 401 Unauthorized

Verify the token in your request header matches `FIXOPS_API_TOKEN`:

```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/health
```

### UI Cannot Reach API (CORS / Proxy Errors)

Check that `VITE_API_URL` was set correctly at build time and the nginx proxy config routes `/api/*` to the API container on port 8000.

```bash
docker compose exec aldeci-ui cat /etc/nginx/conf.d/default.conf
```

### TrustGraph Indexer Exits Immediately

```bash
docker compose logs trustgraph-init
# If "No module named 'core.trustgraph_indexer'": ensure the API container was built with the full codebase context
docker compose build --no-cache
```

### Database Locked Error (SQLite)

SQLite does not support concurrent writes. If you see `database is locked`:
1. Ensure only one API replica is running (or migrate to PostgreSQL)
2. Check for zombie processes: `docker compose exec aldeci ps aux | grep python`

### Out of Memory (OOM Kill)

```bash
# Check if container was OOM-killed
docker inspect aldeci-api | grep OOMKilled

# Increase memory limit in docker-compose.yml or Kubernetes resource limits
```

### Reset to Clean State

```bash
# WARNING: destroys all data
docker compose down -v
docker compose up -d
docker compose --profile init run --rm trustgraph-init
```

---

*For architecture decisions see `docs/ALDECI_REARCHITECTURE.md`. For admin tasks see `docs/ADMIN_GUIDE.md`.*
