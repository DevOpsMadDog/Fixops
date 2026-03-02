# DevOps Engineer Memory

## Docker Infrastructure
- Main compose: `docker/docker-compose.yml` — only fixops (API:8000) + aldeci-ui (UI:3001) start by default
- Sidecars (feeds, demo, smoke, pentest) are profile-gated: `--profile feeds`, `--profile demo`, etc.
- Health endpoint: `/health` (no auth required) — returns `{"status":"healthy"}`
- API v1 endpoints require `X-API-Key` header with `FIXOPS_API_TOKEN` value
- PYTHONPATH in Docker: `/app/suite-api:/app/suite-core:/app/suite-attack:/app/suite-feeds:/app/suite-evidence-risk:/app/suite-integrations:/app`
- Entry point: `scripts/docker-entrypoint.sh` → mode `api-only` starts uvicorn with `apps.api.app:app`
- `sitecustomize.py` at repo root auto-prepends suite paths (works both local and Docker)
- Container runs as non-root user `aldeci` (USER directive in ALL 10 Dockerfiles)

## Build Notes
- PyTorch is installed for `pgmpy` (Bayesian network) — makes image large (~2GB)
- Multi-stage build: builder (python:3.11-slim + build-essential) → runtime (python:3.11-slim)
- UI build: node:20-alpine → nginx:1.27-alpine-slim (multi-stage, served on port 3001)
- nginx proxies `/api/*`, `/health`, `/docs`, `/openapi.json`, `/redoc`, `/ws/`, MCP SSE to `http://fixops:8000`
- MCP SSE proxy requires: `proxy_buffering off`, `Connection ""`, `proxy_read_timeout 86400s`
- WebSocket proxy requires: `Upgrade $http_upgrade`, `Connection "upgrade"`

## Known Issues & Lessons Learned
- `docker/config/` dir doesn't exist — removed volume mount from compose
- `simulations/demo_pack/` doesn't exist — removed from Dockerfile.sidecar
- `docker-compose.aldeci.yml` is an overlay (needs `-f mpte.yml -f aldeci.yml`)
- Docker daemon may not be running on macOS — validate with `docker info`
- **CRITICAL**: Compose files in `docker/` must use `context: ..` (not `context: .`) because Dockerfiles COPY suite-* dirs from repo root
- **CRITICAL**: Air-gapped test must explicitly check all 8 scanner endpoints by name — using substitute endpoints (Sandbox/MPTE) misses real scanners (IaC, Malware, API-Fuzzer)
- demo-healthcheck.sh JSON mode must pass values via env vars, not shell string interpolation (injection risk)
- Dockerfile.demo needs precise COPY (suite-* dirs) not `COPY . .` which pulls in everything including .git
- `docker compose config --quiet` works WITHOUT Docker daemon running — good for validation-only checks
- Dockerfile.simple was using old COPY paths (apps/, core/, etc.) instead of suite-* — FIXED in Run 6

## Compose Files Status (2026-03-03)
- docker-compose.yml: ✅ VALID (6 services, primary demo file)
- docker-compose.enterprise.yml: ✅ VALID (fixed context: .. , non-root user, named volumes)
- docker-compose.air-gapped-test.yml: ✅ VALID (internal:true, all 8 scanners by name, 33+ checks)
- docker-compose.vc-demo.yml: ✅ VALID (fixed context: ..)
- docker-compose.demo.yml: ✅ VALID (legacy OTel demo)
- docker-compose.mpte.yml: ✅ VALID
- docker-compose.integration.yml: ✅ VALID
- docker-compose.aldeci-complete.yml: ✅ VALID (7 services, credentials now via env vars)
- docker-compose.mindsdb.yml: ✅ VALID (standalone)
- docker-compose.aldeci.yml: ⚠️ OVERLAY only (not standalone)
- ROOT docker-compose.demo.yml: ✅ VALID (legacy OTel demo, separate from docker/)

## All 8 Scanner Endpoints
1. SAST: `/api/v1/sast/status`
2. DAST: `/api/v1/dast/status`
3. Secrets: `/api/v1/secrets/status`
4. Container: `/api/v1/container/status`
5. CSPM: `/api/v1/cspm/status`
6. IaC: `/api/v1/iac/scanners/status` (NOTE: uses /scanners/status, not /status)
7. Malware: `/api/v1/malware/status`
8. API Fuzzer: `/api/v1/api-fuzzer/status`

## Air-Gapped Test Infrastructure (MOAT P1)
- Compose: `docker/docker-compose.air-gapped-test.yml` — internal:true Docker network (zero internet)
- Uses main `docker/Dockerfile` (not enterprise variant)
- Script: `scripts/air-gapped-test.sh` — full build+test+cleanup runner
- CI: `.github/workflows/air-gapped-test.yml` — weekly + on docker/* changes
- Tests: 33+ checks — ALL 8 scanners by name + brain pipeline + MCP + evidence + CTEM loop + network isolation
- Network isolation verified: curl to nvd.nist.gov and api.openai.com must FAIL

## Key Scripts (6 total)
- `scripts/demo-start.sh` — customer launcher (--quick, --stop, --reset, --status, --logs, --check)
- `scripts/demo-healthcheck.sh` — 44 endpoint verifier v2.3.0 (supports --json, --ci, --quick modes)
- `scripts/air-gapped-test.sh` — air-gapped deployment validator
- `scripts/docker-entrypoint.sh` — container entry point (api-only, interactive, enterprise, cli, shell)
- `scripts/compose-validate.sh` — local Docker config validator (40+ checks, --ci, --fix modes)
- `scripts/local-dev-setup.sh` — zero-config dev onboarding (--python, --docker, --check modes)

## Health Check Modes (demo-healthcheck.sh v2.3.0)
- Default: 44 checks, colored output, human-friendly (all 8 scanners)
- `--json`: Machine-parseable JSON output for CI (safe env var passing)
- `--ci`: No colors, strict exit codes
- `--quick`: 7 core checks only (~5s)
- Exit code 0 = pass, 1 = failures, 2 = API timeout

## Dockerfile Security (ALL 10 HARDENED as of Run 6)
- Non-root user in ALL 10 Dockerfiles: `aldeci` (8 files) or `nextjs` (risk-graph, aldeci-ui)
- HEALTHCHECK in ALL 10 Dockerfiles (Dockerfile.simple and risk-graph fixed in Run 6)
- `chown -R aldeci:aldeci /app` before USER switch
- Multi-stage build in 4: main, enterprise, interactive, risk-graph
- .dockerignore excludes .env, .env.*, .git, __pycache__, node_modules, *.db files

## Port Map
- 8000: ALdeci API (FastAPI + uvicorn)
- 3001: ALdeci UI (nginx + React SPA, proxies /api, /docs, /ws, MCP SSE to API)
- 8443: MPTE (optional, separate compose)
- 5433: MPTE PostgreSQL (optional)

## CI Pipeline (ci.yml — 8 parallel jobs, as of Run 6)
1. `lint`: ruff + bandit + compile check
2. `test`: pytest + coverage (18% baseline)
3. `scanner-parsers`: V9 air-gapped parser tests
4. `compose-validate`: 8 compose files + 8 Dockerfiles (HEALTHCHECK+USER) + 6 shell scripts + .dockerignore
5. `api-surface`: 363+ endpoint verification
6. `docker-smoke`: Buildx build (layer cache) → image size guard (max 2.5GB) → start API → startup time check → 22 CTEM+ endpoint smoke tests (all 8 scanners + brain/trends + self-learning/stats + OpenAPI)
7. `dep-audit`: pip-audit dependency vulnerability scan + JSON artifact
8. `ui-build`: npm ci → tsc check → vite build → verify dist output

## Security Advisory Status (2026-03-03)
- .env excluded from git (✅) and Docker (✅)
- .env.example has placeholder secrets only (✅)
- CI uses `ci-test-token` placeholders (✅)
- Container runs non-root (✅) — ALL 10 Dockerfiles
- Compose credentials via env vars (✅) — no hardcoded secrets in any compose file
- Docker socket mount in MPTE — ACCEPTED risk (intentional for pentest containers)
- OpenAI key rotation: PENDING (CEO action)
- pip-audit in CI: ✅ (added Run 6)
