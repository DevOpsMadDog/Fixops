# DevOps Engineer Memory

## Docker Infrastructure
- Main compose: `docker/docker-compose.yml` — only fixops (API:8000) + aldeci-ui (UI:3001) start by default
- Sidecars (feeds, demo, smoke, pentest) are profile-gated: `--profile feeds`, `--profile demo`, etc.
- Health endpoint: `/health` (no auth required) — returns `{"status":"healthy"}`
- API v1 endpoints require `X-API-Key` header with `FIXOPS_API_TOKEN` value
- PYTHONPATH in Docker: `/app/suite-api:/app/suite-core:/app/suite-attack:/app/suite-feeds:/app/suite-evidence-risk:/app/suite-integrations:/app`
- Entry point: `scripts/docker-entrypoint.sh` → mode `api-only` starts uvicorn with `apps.api.app:app`
- `sitecustomize.py` at repo root auto-prepends suite paths (works both local and Docker)

## Build Notes
- PyTorch is installed for `pgmpy` (Bayesian network) — makes image large (~2GB)
- Multi-stage build: builder (python:3.11-slim + build-essential) → runtime (python:3.11-slim)
- UI build: node:20-alpine → nginx:1.27-alpine-slim (multi-stage, served on port 3001)
- nginx proxies `/api/*` to `http://fixops:8000` (Docker DNS resolution)

## Known Issues
- `docker/config/` dir doesn't exist — removed volume mount from compose
- `simulations/demo_pack/` doesn't exist — removed from sidecar Dockerfile
- `docker-compose.aldeci.yml` is an overlay (needs `-f mpte.yml -f aldeci.yml`)
- Docker daemon may not be running on macOS — validate with `docker info`

## Compose Files Status (2026-03-01)
- docker-compose.yml: ✅ VALID (primary demo file)
- docker-compose.enterprise.yml: ✅ VALID (fixed token default)
- docker-compose.vc-demo.yml: ✅ VALID (fixed token default)
- docker-compose.demo.yml: ✅ VALID
- docker-compose.mpte.yml: ✅ VALID
- docker-compose.aldeci.yml: ⚠️ OVERLAY only

## Key Scripts
- `scripts/demo-start.sh` — customer launcher (--quick, --stop, --reset)
- `scripts/demo-healthcheck.sh` — 34 endpoint verifier
- `scripts/docker-entrypoint.sh` — container entry point (api-only, interactive, enterprise, cli, shell)

## Port Map
- 8000: ALdeci API (FastAPI + uvicorn)
- 3001: ALdeci UI (nginx + React SPA)
- 8443: MPTE (optional, separate compose)
- 5433: MPTE PostgreSQL (optional)
