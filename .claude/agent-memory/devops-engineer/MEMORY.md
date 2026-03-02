# DevOps Engineer Memory

## Docker Infrastructure
- Main compose: `docker/docker-compose.yml` — only fixops (API:8000) + aldeci-ui (UI:3001) start by default
- Sidecars (feeds, demo, smoke, pentest) are profile-gated: `--profile feeds`, `--profile demo`, etc.
- Health endpoint: `/health` (no auth required) — returns `{"status":"healthy"}`
- API v1 endpoints require `X-API-Key` header with `FIXOPS_API_TOKEN` value
- PYTHONPATH in Docker: `/app/suite-api:/app/suite-core:/app/suite-attack:/app/suite-feeds:/app/suite-evidence-risk:/app/suite-integrations:/app`
- Entry point: `scripts/docker-entrypoint.sh` → mode `api-only` starts uvicorn with `apps.api.app:app`
- `sitecustomize.py` at repo root auto-prepends suite paths (works both local and Docker)
- Container runs as non-root user `aldeci` (USER directive in Dockerfile)

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

## Compose Files Status (2026-03-02)
- docker-compose.yml: ✅ VALID (6 services, primary demo file)
- docker-compose.enterprise.yml: ✅ VALID (fixed token default)
- docker-compose.air-gapped-test.yml: ✅ VALID (internal:true network, 30+ checks)
- docker-compose.vc-demo.yml: ✅ VALID (fixed token default)
- docker-compose.demo.yml: ✅ VALID
- docker-compose.mpte.yml: ✅ VALID
- docker-compose.integration.yml: ✅ VALID
- docker-compose.aldeci-complete.yml: ✅ VALID (7 services)
- docker-compose.aldeci.yml: ⚠️ OVERLAY only

## Air-Gapped Test Infrastructure (MOAT P1)
- Compose: `docker/docker-compose.air-gapped-test.yml` — internal:true Docker network (zero internet)
- Uses main `docker/Dockerfile` (not enterprise variant)
- Script: `scripts/air-gapped-test.sh` — full build+test+cleanup runner
- Tests: 30+ checks — 8 scanners, brain pipeline, MCP, evidence, CTEM loop, network isolation
- Network isolation verified: curl to nvd.nist.gov and api.openai.com must FAIL

## Key Scripts
- `scripts/demo-start.sh` — customer launcher (--quick, --stop, --reset)
- `scripts/demo-healthcheck.sh` — 34 endpoint verifier (supports --json, --ci, --quick modes)
- `scripts/air-gapped-test.sh` — air-gapped deployment validator
- `scripts/docker-entrypoint.sh` — container entry point (api-only, interactive, enterprise, cli, shell)

## Health Check Modes (demo-healthcheck.sh)
- Default: 34 checks, colored output, human-friendly
- `--json`: Machine-parseable JSON output for CI
- `--ci`: No colors, strict exit codes
- `--quick`: 7 core checks only (~5s)
- Exit code 0 = pass, 1 = failures, 2 = API timeout

## Dockerfile Security
- Non-root `aldeci` user (groupadd + useradd + USER aldeci)
- Multi-stage build (builder has build-essential, runtime does not)
- Health check in Dockerfile AND compose
- .dockerignore excludes .env, .git, __pycache__, node_modules, *.db files

## Port Map
- 8000: ALdeci API (FastAPI + uvicorn)
- 3001: ALdeci UI (nginx + React SPA)
- 8443: MPTE (optional, separate compose)
- 5433: MPTE PostgreSQL (optional)

## CI Pipeline (ci.yml — 6 parallel jobs)
1. `lint`: ruff + bandit + compile check
2. `test`: pytest + coverage (18% baseline)
3. `scanner-parsers`: V9 air-gapped parser tests
4. `compose-validate`: 6 compose file syntax checks
5. `api-surface`: 363+ endpoint verification
6. `docker-smoke`: build image → start API → 15 CTEM+ endpoint smoke tests

## Security Advisory Status (2026-03-02)
- .env excluded from git (✅) and Docker (✅)
- .env.example has placeholder secrets only (✅)
- CI uses `ci-test-token` placeholders (✅)
- Container runs non-root (✅)
- OpenAI key rotation: PENDING (CEO action)
