# ALdeci CTEM+ Platform — Development Environment Guide

> **Updated**: 2026-03-03 (Day 3) by devops-engineer
> **Sprint**: 2 — Enterprise Demo (2026-03-06, 3 days remaining)
> **Status**: 11/12 DEMO items done. Docker stack verified. 42-check health system. CI 7-job pipeline. Air-gapped test validates all 8 scanners. Compose validator: 40/40 pass, 2 warnings.

---

## Quick Start (< 5 minutes)

### Option 1: Automated Setup (Recommended)

```bash
git clone <repo-url> && cd Fixops
./scripts/local-dev-setup.sh          # Detects OS, installs deps, creates .env
./scripts/local-dev-setup.sh --check  # Just check prerequisites
./scripts/local-dev-setup.sh --docker # Docker-only mode
./scripts/local-dev-setup.sh --python # Backend-only mode
```

### Option 2: Docker (Recommended for Demos)

```bash
# Prerequisites: Docker Desktop running
git clone <repo-url> && cd Fixops

# One-command start
./scripts/demo-start.sh

# Or manually:
docker compose -f docker/docker-compose.yml up --build -d

# Verify everything is running (42 checks)
./scripts/demo-healthcheck.sh

# Stop
./scripts/demo-start.sh --stop

# Other commands
./scripts/demo-start.sh --status  # Check service health
./scripts/demo-start.sh --logs    # Tail logs
./scripts/demo-start.sh --check   # Run full health check
./scripts/demo-start.sh --reset   # Nuclear: remove volumes + images
```

**What starts:**
| Service | Port | URL |
|---------|------|-----|
| ALdeci API | 8000 | http://localhost:8000 |
| ALdeci UI | 3001 | http://localhost:3001 |
| Swagger Docs | 8000 | http://localhost:8000/docs |
| Swagger via UI | 3001 | http://localhost:3001/docs |
| ReDoc | 8000 | http://localhost:8000/redoc |

### Option 3: Local Development

```bash
# Prerequisites: Python 3.10+, Node.js 18+
git clone <repo-url> && cd Fixops

# Backend
pip install -r requirements.txt
python -m uvicorn apps.api.app:create_app --factory --port 8000

# Frontend (separate terminal)
cd suite-ui/aldeci && npm install && npm run dev

# Tests
python -m pytest tests/ --timeout=10 -x -q
```

---

## Environment Variables

| Variable | Default | Required | Purpose |
|----------|---------|----------|---------|
| `FIXOPS_API_TOKEN` | `demo-token-change-me` | Demo: No | API authentication key |
| `FIXOPS_JWT_SECRET` | auto-generated | No | JWT signing secret |
| `FIXOPS_MODE` | `enterprise` | No | Operating mode |
| `FIXOPS_DISABLE_TELEMETRY` | `1` | No | Disable telemetry |
| `FIXOPS_DISABLE_RATE_LIMIT` | `1` | No | Disable rate limiting (demo) |
| `FIXOPS_DATA_DIR` | `.fixops_data` | No | Data storage directory |
| `OPENAI_API_KEY` | (empty) | Optional | For AI-powered AutoFix |
| `ANTHROPIC_API_KEY` | (empty) | Optional | For AI-powered AutoFix |
| `GOOGLE_API_KEY` | (empty) | Optional | For AI-powered AutoFix |

**Note**: For demos, no API keys are required. AI features degrade gracefully without LLM keys.

---

## Port Map

| Port | Service | Protocol | Notes |
|------|---------|----------|-------|
| 8000 | ALdeci API | HTTP | FastAPI + uvicorn |
| 3001 | ALdeci UI | HTTP | nginx serving React SPA + API proxy |
| 8443 | MPTE (optional) | HTTPS | Micro-pentest engine |
| 5433 | MPTE DB (optional) | TCP | PostgreSQL + pgvector |

---

## Docker Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Customer's Laptop                    │
│                                                     │
│  ┌─────────────┐     ┌──────────────────────────┐  │
│  │  Browser     │────▶│  aldeci-ui (nginx:3001)  │  │
│  │  localhost:  │     │  • Serves React SPA      │  │
│  │  3001        │     │  • Proxies /api/* → API  │  │
│  │              │     │  • SSE for MCP [V7]      │  │
│  │              │     │  • WebSocket for RT [V3] │  │
│  └─────────────┘     └──────────┬───────────────┘  │
│                                  │                   │
│                     ┌────────────▼───────────────┐  │
│                     │  fixops-api (python:8000)  │  │
│                     │  • 759+ API endpoints      │  │
│                     │  • 8 native scanners       │  │
│                     │  • Brain pipeline (12-step)│  │
│                     │  • AutoFix engine          │  │
│                     │  • MCP gateway [V7]        │  │
│                     │  • SQLite WAL storage      │  │
│                     │  • Non-root user (aldeci)  │  │
│                     └────────────────────────────┘  │
│                                                     │
│  Volume: fixops-data (persistent SQLite databases)  │
└─────────────────────────────────────────────────────┘
```

---

## Docker Commands

```bash
# Build and start (first time takes 3-5 min)
docker compose -f docker/docker-compose.yml up --build -d

# View logs
docker compose -f docker/docker-compose.yml logs -f
docker compose -f docker/docker-compose.yml logs fixops    # API only
docker compose -f docker/docker-compose.yml logs aldeci-ui # UI only

# Restart a single service
docker compose -f docker/docker-compose.yml restart fixops

# Stop all
docker compose -f docker/docker-compose.yml down

# Full reset (remove volumes + images)
docker compose -f docker/docker-compose.yml down -v --rmi local

# Run health check
./scripts/demo-healthcheck.sh

# Validate Docker configs before committing
./scripts/compose-validate.sh
```

---

## Troubleshooting

### Port 8000 already in use
```bash
lsof -i :8000
kill <PID>
# Or use a different port:
FIXOPS_PORT=8001 docker compose -f docker/docker-compose.yml up -d
```

### Docker build fails
```bash
# Clear Docker cache and rebuild
docker compose -f docker/docker-compose.yml build --no-cache

# Check disk space
docker system df
docker system prune -f  # Clear unused images/containers
```

### API server won't start
```bash
# Check container logs for Python errors
docker compose -f docker/docker-compose.yml logs fixops 2>&1 | tail -50

# Shell into the container for debugging
docker exec -it fixops-api bash
python -c "from apps.api.app import create_app; print('OK')"
```

### UI shows blank page
```bash
# Check if API is reachable from UI container
docker exec aldeci-ui wget -qO- http://fixops:8000/health

# Check nginx proxy config
docker exec aldeci-ui cat /etc/nginx/conf.d/aldeci.conf
```

### npm/pip install fails
```bash
# Clear node_modules and retry
cd suite-ui/aldeci && rm -rf node_modules && npm install

# For pip, upgrade pip first
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Compose File Matrix

| File | Purpose | Default Start | Validated |
|------|---------|---------------|-----------|
| `docker-compose.yml` | **Demo stack** (API + UI) | ✅ Yes | ✅ |
| `docker-compose.enterprise.yml` | Enterprise mode with ChromaDB | No | ✅ |
| `docker-compose.air-gapped-test.yml` | **Air-gapped test (MOAT P1)** | No | ✅ |
| `docker-compose.mpte.yml` | MPTE pentest engine overlay | No | ✅ |
| `docker-compose.aldeci.yml` | ALdeci branding for MPTE (overlay) | No | ⚠️ Overlay only |
| `docker-compose.demo.yml` | VC demo mode | No | ✅ |
| `docker-compose.vc-demo.yml` | VC investor demo | No | ✅ |
| `docker-compose.integration.yml` | Integration testing (LocalStack + Azurite) | No | ✅ |
| `docker-compose.mindsdb.yml` | MindsDB ML layer | No | ✅ |
| `docker-compose.aldeci-complete.yml` | Full stack (MPTE + API + MindsDB + Redis) | No | ✅ |

---

## Key API Endpoints for Testing

```bash
TOKEN="demo-token-change-me"  # or $FIXOPS_API_TOKEN

# Health check (no auth)
curl http://localhost:8000/health

# Brain pipeline [V3]
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/brain/stats
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/autofix/health

# All 8 Native Scanners [V9]
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/sast/status
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/dast/status
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/secrets/status
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/container/status
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/cspm/status
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/iac/scanners/status
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/malware/status
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/api-fuzzer/status

# MPTE [V5]
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/mpte/stats
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/micro-pentest/health

# MCP Gateway [V7]
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/mcp/tools
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/mcp-protocol/status

# Evidence & Compliance [V10]
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/evidence/
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/compliance-engine/frameworks

# Swagger docs
open http://localhost:8000/docs
```

---

## Validation Scripts

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `scripts/demo-healthcheck.sh` | 42-endpoint health check | After starting services |
| `scripts/demo-start.sh` | One-command launcher | Starting ALdeci for demos |
| `scripts/compose-validate.sh` | Docker config validator | Before committing Docker changes |
| `scripts/local-dev-setup.sh` | Zero-config environment setup | First time clone / onboarding |
| `scripts/air-gapped-test.sh` | Air-gapped deployment validator | Testing offline capability |

---

## Air-Gapped Deployment Test

```bash
# Run the air-gapped validation (proves ZERO internet operation)
./scripts/air-gapped-test.sh

# Or manually with compose:
docker compose -f docker/docker-compose.air-gapped-test.yml up --build

# This validates:
# - API starts in isolated network (internal: true)
# - All 8 scanners respond to health checks
# - Brain Pipeline processes findings offline
# - Evidence signing works without external services
# - No external network calls are made
```

---

## CI/CD Workflows

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | push/PR | 7 jobs: lint, test+coverage, scanner-parsers, compose-validate, api-surface, docker-smoke (with layer cache + image size check), ui-build |
| `air-gapped-test.yml` | push/PR (docker/*) | Air-gapped deployment test (MOAT P1) |

---

## Health Check Modes

```bash
# Human-friendly output (default)
./scripts/demo-healthcheck.sh

# Machine-parseable JSON (for CI)
./scripts/demo-healthcheck.sh --json

# No colors, strict exit codes (for CI logs)
./scripts/demo-healthcheck.sh --ci

# Quick check — core endpoints only (7 checks, ~5s)
./scripts/demo-healthcheck.sh --quick

# Custom host
./scripts/demo-healthcheck.sh 192.168.1.100

# Custom timeout
TIMEOUT=60 ./scripts/demo-healthcheck.sh
```

---

## Sprint 2 Status (Day 3 / 2026-03-03)

| DEMO Item | Status | Owner |
|-----------|--------|-------|
| DEMO-001: Fix broken endpoints | ✅ Done | backend-hardener |
| DEMO-002: Postman GREEN (475/475) | ✅ Done | qa-engineer |
| DEMO-003: UI wiring | 🔄 In progress (90% done) | frontend-craftsman |
| DEMO-004: CTEM full loop | ✅ Done | threat-architect |
| DEMO-005: Persona scripts | ✅ Done | sales-engineer |
| DEMO-006: Coverage config | ✅ Done | qa-engineer |
| DEMO-007: Docker demo + hardened | ✅ Done | devops-engineer |
| DEMO-008: API docs | ✅ Done | technical-writer |
| DEMO-009: MCP demo | ✅ Done | data-scientist |
| DEMO-010: KG demo | ✅ Done | ai-researcher |
| DEMO-011: Evidence export | ✅ Done | security-analyst |
| DEMO-012: Self-learning | ✅ Done | enterprise-architect |

**11/12 complete (91.7%). Only DEMO-003 remains (UI wiring). 3 days to demo.**

---

## Docker Security Posture

| Control | Status | Details |
|---------|--------|---------|
| Non-root container | ✅ | `USER aldeci` in main + enterprise Dockerfiles |
| .dockerignore secrets | ✅ | .env, .env.*, *.db excluded from build context |
| No hardcoded secrets | ✅ | All compose files use `${VAR:-default}` pattern |
| Health checks | ✅ | HEALTHCHECK in all primary Dockerfiles |
| Multi-stage build | ✅ | builder (deps) → runtime (slim) |
| Image size guard | ✅ | CI rejects images > 2.5GB |
| Layer caching | ✅ | CI uses Docker Buildx layer cache |
| WebSocket/SSE proxy | ✅ | nginx proxies MCP SSE + WebSocket connections |
