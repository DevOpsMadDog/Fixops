# ALdeci Developer Guide

> Last verified against codebase: 2026-02-19
> Cross-references: [API_REFERENCE.md](API_REFERENCE.md) · [SUITE_ARCHITECTURE.md](SUITE_ARCHITECTURE.md) · [DEVIN_CONTEXT.md](../DEVIN_CONTEXT.md)

---

## 1. Quick Start (5 minutes)

```bash
# Clone and enter repo
git clone https://github.com/DevOpsMadDog/Fixops.git && cd Fixops

# Backend
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Set the PYTHONPATH (CRITICAL — namespace packages won't resolve without this)
export PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations"

# Start API (port 8000)
python -m uvicorn apps.api.app:create_app --factory --reload --port 8000

# Frontend (separate terminal)
cd suite-ui/aldeci && npm install && npm run dev
# → http://localhost:3001 (proxies /api/* to :8000)
```

API docs: `http://localhost:8000/docs` (Swagger UI) or `http://localhost:8000/redoc`

---

## 2. Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.11+ | Backend runtime |
| Node.js | 18+ | Frontend build |
| npm | 9+ | Frontend packages |
| Git | 2.30+ | Version control |
| Docker | 24+ | Container builds (optional) |

**Python dependencies** (from `requirements.txt`):

| Package | Version | Purpose |
|---------|---------|---------|
| FastAPI | ≥0.115,<0.128 | REST API framework |
| Uvicorn | ≥0.30,<1.0 | ASGI server |
| Pydantic | ≥2.6,<3.0 | Data validation |
| NetworkX | ≥3.5,<4.0 | Knowledge graph |
| structlog | ≥25.4,<26.0 | Structured logging |
| scikit-learn | ≥1.3,<2.0 | ML models (BN/LR) |
| pgmpy | 0.1.24 | Bayesian networks |
| OpenTelemetry | ≥1.25,<2.0 | Observability |
| PyJWT | ≥2.8,<3.0 | JWT auth |
| bcrypt | ≥4.0.0 | Password hashing |
| tenacity | ≥8.2,<9.0 | Retry logic |
| ssvc | ≥1.2,<2.0 | SSVC scoring |
| sarif-om | ≥1.0.4,<2.0 | SARIF parsing |
| PyYAML | ≥6.0.1,<7.0 | Overlay config |
| httpx | ≥0.27,<1.0 | Async HTTP client |
| cryptography | ≥46.0,<47.0 | Signing/encryption |

**Frontend stack** (`suite-ui/aldeci/package.json`):

| Library | Purpose |
|---------|---------|
| React 18.2 | UI framework |
| TypeScript 5.3 | Type safety |
| Vite 5.0 | Build tool + dev server |
| Tailwind CSS 3.4 | Utility-first styling |
| Radix UI | Accessible primitives (shadcn/ui) |
| Zustand 4.4 | Global state management |
| TanStack Query 5 | Server-state / API caching |
| TanStack Table 8 | Data tables |
| React Router 6 | Client-side routing |
| Recharts 2 | Charts / dashboards |
| Axios 1.6 | HTTP client |
| XY Flow 12 | Graph visualisations |
| Framer Motion 10 | Animations |
| Lucide React | Icon set |

---

## 3. Environment Variables

### Required (minimum to start)

```bash
export PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations"
```

That's it. Everything else has safe defaults for **demo mode**.

### All variables (grouped by function)

#### Core / Mode
| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_MODE` | `demo` | `demo` or `enterprise`. Controls auth strictness, feature flags |
| `FIXOPS_API_TOKEN` | `demo-token-12345` | API key for `X-API-Key` header auth |
| `FIXOPS_JWT_SECRET` | auto-generated | JWT signing secret. Required in enterprise mode |
| `FIXOPS_JWT_EXP_MINUTES` | `120` | JWT token expiry |
| `FIXOPS_VERSION` | `0.1.0` | Reported version string |
| `FIXOPS_DATA_DIR` | `.fixops_data` | Local data storage directory |
| `FIXOPS_FAIL_FAST` | `false` | Exit on startup errors if `true` |
| `FIXOPS_ALLOWED_ORIGINS` | `""` | CORS allowed origins (comma-separated) |
| `FIXOPS_DISABLE_TELEMETRY` | `0` | Set `1` to disable OpenTelemetry |
| `FIXOPS_SKIP_PATH_SECURITY` | `0` | Set `1` to skip path traversal checks (CI only) |

#### LLM Providers (all optional — demo mode uses deterministic fallbacks)
| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_ENABLE_OPENAI` | `false` | Enable OpenAI provider |
| `OPENAI_API_KEY` or `FIXOPS_OPENAI_KEY` | — | OpenAI API key |
| `FIXOPS_ENABLE_ANTHROPIC` | `false` | Enable Anthropic provider |
| `ANTHROPIC_API_KEY` or `FIXOPS_ANTHROPIC_KEY` | — | Anthropic API key |
| `FIXOPS_ENABLE_GEMINI` | `false` | Enable Gemini provider |
| `GOOGLE_API_KEY` or `FIXOPS_GEMINI_KEY` | — | Google Gemini API key |
| `FIXOPS_ENABLE_SENTINEL` | `false` | Enable Sentinel Cyber provider |

#### Database / Storage
| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./fixops_test.db` | Primary database URL |
| `REDIS_URL` | `""` | Redis URL (optional, for caching) |
| `FIXOPS_DATA_ROOT_ALLOWLIST` | `<repo>/data` | Colon-separated allowed data root paths |

#### Overlay Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_OVERLAY_PATH` | `suite-core/config/fixops.overlay.yml` | Path to overlay config |

#### Signing / Evidence
| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_SIGNING_KEY` | — | RSA private key PEM for evidence signing |
| `FIXOPS_SIGNING_KID` | — | Key ID for signed evidence bundles |
| `FIXOPS_EVIDENCE_KEY` | — | Fernet key for evidence encryption |

---

## 4. Project Structure

```
Fixops/
├── suite-api/          # HTTP layer — FastAPI app + 17 local routers
│   └── apps/api/       #   app.py (entry point), routers, middleware
├── suite-core/         # Business logic — 110+ modules
│   ├── core/           #   Services, models, engines, pipeline
│   └── config/         #   fixops.overlay.yml
├── suite-attack/       # Offensive security — MPTE, fuzzing, DAST
│   └── api/            #   12 attack routers
├── suite-feeds/        # Threat intel feeds — NVD, CISA KEV, EPSS, OSV
│   └── api/            #   3 feed routers
├── suite-evidence-risk/# Evidence bundling + risk scoring
│   └── api/            #   14 evidence/risk routers
├── suite-integrations/ # External integrations — Jira, webhooks, IDE, MCP
│   └── api/            #   16 integration routers
├── suite-ui/aldeci/    # React frontend (Vite + TypeScript)
│   └── src/            #   pages, components, stores, hooks
├── tests/              # 239+ test files (pytest)
├── scripts/            # Helper scripts (setup, seed, test, deploy)
├── docker/             # Dockerfile (multi-stage, suite architecture)
├── data/               # SQLite databases + file storage (gitignored in prod)
└── docs/               # API_REFERENCE.md, SUITE_ARCHITECTURE.md, schemas/
```

> Full directory trees → [SUITE_ARCHITECTURE.md](SUITE_ARCHITECTURE.md)

---

## 5. Running the Application

### Backend only

```bash
# Activate venv + PYTHONPATH
source .venv/bin/activate
export PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations"

# Development (auto-reload)
python -m uvicorn apps.api.app:create_app --factory --reload --port 8000

# Production-like
python -m uvicorn apps.api.app:create_app --factory --host 0.0.0.0 --port 8000 --workers 4
```

### Frontend only

```bash
cd suite-ui/aldeci
npm run dev      # Dev server on http://localhost:3001
npm run build    # Production build → dist/
npm run preview  # Preview production build
npm run lint     # ESLint check
```

The Vite dev server proxies `/api/*`, `/health`, `/evidence`, `/graph`, `/inputs` → `http://localhost:8000` (see `vite.config.ts`).

### Docker

```bash
# Build
docker build -f docker/Dockerfile -t aldeci:latest .

# Run (API-only mode, default)
docker run -p 8000:8000 aldeci:latest

# Run (interactive demo)
docker run -it -p 8000:8000 aldeci:latest demo

# Run (shell access)
docker run -it aldeci:latest shell

# Run with real LLM keys
docker run -p 8000:8000 \
  -e OPENAI_API_KEY=sk-... \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -e FIXOPS_ENABLE_OPENAI=true \
  -e FIXOPS_ENABLE_ANTHROPIC=true \
  aldeci:latest
```

Docker entrypoint modes: `api-only` (default), `interactive`, `demo`, `test-all`, `cli <args>`, `shell`, `python <args>`, `uvicorn <args>`, `bash <args>`.

### Helper scripts

| Script | Purpose |
|--------|---------|
| `scripts/dev-setup.sh` | Install backend + frontend deps |
| `scripts/start_api_server.sh` | Start API with safe defaults |
| `scripts/seed_real_data.py` | Seed database with real CVE data |
| `scripts/fetch_feeds.py` | Pull latest threat intel feeds |
| `scripts/run_all_tests.sh` | Run unit + integration + E2E tests |
| `scripts/run_e2e_tests.sh` | Run E2E tests only |
| `scripts/seed_data.py` | Seed demo data |
| `scripts/demo_orchestrator.py` | Run full demo workflow |

---

## 6. Overlay Configuration

ALdeci uses an **overlay configuration** system (`suite-core/core/configuration.py`). The overlay file is YAML/JSON and controls feature toggles, integrations, guardrails, and more.

**Location**: `suite-core/config/fixops.overlay.yml` (override with `FIXOPS_OVERLAY_PATH` env var)

**Supported top-level keys** (35 keys):
`mode`, `jira`, `confluence`, `git`, `ci`, `auth`, `data`, `data_directories`, `toggles`, `signing`, `guardrails`, `metadata`, `context_engine`, `evidence_hub`, `onboarding`, `compliance`, `policy_automation`, `policy_engine`, `pricing`, `limits`, `ai_agents`, `ssdlc`, `exploit_signals`, `modules`, `iac`, `probabilistic`, `analytics`, `tenancy`, `performance`, `enhanced_decision`, `decision_tree`, `telemetry_bridge`, `profiles`, `feature_flags`, `analysis_engines`, `oss_tools_config_path`, `fallback`

**Mode profiles**: The overlay supports profile-based overrides. Set `mode: demo` or `mode: enterprise`, then add a `profiles:` section with per-mode overrides that get deep-merged.

**Module flags** (in `modules:` section):
`guardrails`, `context_engine`, `onboarding`, `compliance`, `policy_automation`, `evidence`, `ai_agents`, `ssdlc`, `exploit_signals`, `probabilistic`, `pricing`, `iac_posture`, `analytics`, `tenancy`, `performance`, `vector_store` — all default to `true`.

---

## 7. Common Development Tasks

### Add a new API endpoint

1. **Choose the right suite** based on domain (see [SUITE_ARCHITECTURE.md](SUITE_ARCHITECTURE.md) §9 for guidance)
2. **Create or edit a router file** in that suite's `api/` directory:

```python
# Example: suite-attack/api/my_new_router.py
from fastapi import APIRouter
router = APIRouter(prefix="/api/my-feature", tags=["my-feature"])

@router.get("/items")
async def list_items():
    return {"items": []}
```

3. **Import in app.py** — add a try/except block in `suite-api/apps/api/app.py`:

```python
try:
    from api.my_new_router import router as my_new_router
except ImportError:
    my_new_router = None
```

4. **Mount the router** — add to the router mounting section:

```python
if my_new_router is not None:
    app.include_router(my_new_router)
```

5. **Test**: `curl http://localhost:8000/api/my-feature/items -H "X-API-Key: demo-token-12345"`

### Add a new threat intel feed

1. Create feed class in `suite-feeds/feeds/` (follow pattern of existing feeds like `nvd_client.py`)
2. Create router in `suite-feeds/api/` with endpoints for fetch/status
3. Import and mount in `app.py` (same pattern as above)
4. Add scheduler job in `suite-feeds/feeds/` if auto-refresh needed

### Add a new UI page

1. Create page component in `suite-ui/aldeci/src/pages/`
2. Add route in `suite-ui/aldeci/src/App.tsx`
3. Add navigation link in `suite-ui/aldeci/src/layouts/` or sidebar component
4. Use existing API hooks from `suite-ui/aldeci/src/hooks/` or create new ones

### Add a new core service/engine

1. Create module in `suite-core/core/` (e.g., `my_engine.py`)
2. If it needs an API, create a router in the appropriate suite's `api/` directory
3. Import from `core.my_engine` in your router (this import works because `suite-core` is on PYTHONPATH)

---

## 8. Testing

### Configuration (`pyproject.toml`)

- **Test paths**: `tests/`
- **File patterns**: `test_*.py`, `*_test.py`
- **Coverage targets**: `risk`, `automation`, `cli`, `apps`
- **Coverage threshold**: 60% (baseline 18% enforced in CI)
- **New code coverage**: 100% enforced via `diff-cover` in CI
- **Async mode**: `auto` (pytest-asyncio)

### Running tests

```bash
# Activate venv + PYTHONPATH first (see Quick Start)

# Run all passing tests
pytest tests/ -v

# Run by marker
pytest tests/ -m unit -v
pytest tests/ -m integration -v
pytest tests/ -m security -v
pytest tests/ -m "not slow" -v

# Run specific test file
pytest tests/test_knowledge_graph.py -v

# Run with coverage
pytest tests/ --cov=core --cov=apps --cov-report=term-missing

# Run E2E (requires running API server)
./scripts/start_api_server.sh &
sleep 5
pytest tests/e2e/ -v

# Full test suite (unit + integration + E2E)
./scripts/run_all_tests.sh
```

### Test markers

| Marker | Meaning |
|--------|---------|
| `@pytest.mark.unit` | Fast, isolated unit tests |
| `@pytest.mark.integration` | Tests that touch multiple modules |
| `@pytest.mark.e2e` | End-to-end with running server |
| `@pytest.mark.security` | Security-specific tests |
| `@pytest.mark.performance` | Performance benchmarks |
| `@pytest.mark.slow` | Tests > 10s |
| `@pytest.mark.requires_network` | Needs internet |
| `@pytest.mark.requires_docker` | Needs Docker daemon |
| `@pytest.mark.requires_k8s` | Needs Kubernetes |
| `@pytest.mark.regression` | Regression tests |
| `@pytest.mark.asyncio` | Async test (auto-detected) |

### Key fixtures (from `tests/conftest.py`)

| Fixture | Scope | Description |
|---------|-------|-------------|
| `api_token` | session | Returns the `FIXOPS_API_TOKEN` value |
| `auth_headers` | session | Returns `{"X-API-Key": <token>}` |
| `demo_client` | function | FastAPI `TestClient` in demo mode |
| `authenticated_client` | function | `TestClient` with auto-injected auth headers |
| `signing_env` | function | Sets up RSA signing keys for evidence tests |
| `mock_slack_connector` | function | Mocked Slack webhook |
| `mock_jira_connector` | function | Mocked Jira REST API |
| `mock_confluence_connector` | function | Mocked Confluence API |
| `mock_all_connectors` | function | All three mocks combined |

### Skipped test files

`tests/conftest.py` contains a `collect_ignore` list of ~40 test files that depend on legacy `src.*` imports or unimplemented features. These are tracked as tech debt. See `conftest.py` for the full list with reasons.

### Writing tests

```python
# tests/test_my_feature.py
import pytest
from fastapi.testclient import TestClient

@pytest.mark.unit
def test_my_function():
    from core.my_engine import compute
    assert compute(1, 2) == 3

@pytest.mark.integration
def test_my_endpoint(authenticated_client):
    resp = authenticated_client.get("/api/my-feature/items")
    assert resp.status_code == 200
    assert "items" in resp.json()
```

---

## 9. Debugging

### Structured logging

ALdeci uses `structlog` for structured JSON logging. All backend modules use:

```python
import structlog
logger = structlog.get_logger(__name__)
logger.info("event_name", key="value", count=42)
```

**Log level control** (in `pyproject.toml`):
- Default CLI log level: `INFO`
- Format: `%(asctime)s [%(levelname)8s] %(name)s: %(message)s`

### Common startup errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: No module named 'apps'` | PYTHONPATH not set | Export PYTHONPATH with all 6 suite dirs |
| `ModuleNotFoundError: No module named 'core'` | PYTHONPATH missing `suite-core` | Check PYTHONPATH includes `suite-core` |
| `ModuleNotFoundError: No module named 'api.xyz_router'` | Router file missing or misnamed | Check file exists in correct suite's `api/` dir |
| `ImportError: cannot import name 'router' from 'api'` | `__init__.py` in an `api/` dir | **Delete it** — namespace packages require no `__init__.py` in `api/` |
| `ValidationError: Unexpected overlay keys` | Typo in overlay YAML | Check against allowed keys (§6) |
| `Address already in use :8000` | Port conflict | Kill existing process: `lsof -ti:8000 \| xargs kill` |

### Debugging API requests

```bash
# Check if server is healthy
curl http://localhost:8000/health

# Test an endpoint with auth
curl -H "X-API-Key: demo-token-12345" http://localhost:8000/api/findings

# Swagger UI (interactive testing)
open http://localhost:8000/docs

# Verbose mode — see all request/response headers
curl -v -H "X-API-Key: demo-token-12345" http://localhost:8000/api/dashboard/summary
```

### Database inspection

All databases are SQLite files in `data/`:

```bash
# List databases
ls data/*.db

# Inspect a database
sqlite3 data/fixops_brain.db ".tables"
sqlite3 data/fixops_brain.db "SELECT count(*) FROM findings;"
```

Key databases: `fixops_brain.db` (knowledge graph), `analytics.db`, `audit.db`, `auth.db`, `mpte.db`, `feeds/feeds.db`.

---

## 10. CI/CD

### GitHub Actions Workflows

| Workflow | File | Triggers | Purpose |
|----------|------|----------|---------|
| CI | `ci.yml` | Push to specific branches, all PRs | Lint, format check, tests, coverage, API contract |
| QA | `qa.yml` | All PRs | Quality assurance checks |
| Docker Build | `docker-build.yml` | Push/PR | Build and test Docker image |
| FixOps CI | `fixops-ci.yml` | Push/PR | Extended CI pipeline |
| CodeQL | `codeql.yml` | Push/PR + scheduled | Security scanning (SAST) |
| Provenance | `provenance.yml` | Releases | SLSA provenance generation |
| Release Sign | `release-sign.yml` | Releases | Artifact signing |
| Repro Verify | `repro-verify.yml` | On demand | Reproducible build verification |

### CI environment

CI runs inside `devopsaico/fixops:latest` container with:
- `PYTHONPATH=suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations:.`
- `FIXOPS_MODE=enterprise`
- Coverage: baseline 18%, new code 100% (via `diff-cover`)

### Format / lint checks

```bash
# Format check (CI uses these)
black --check . --exclude '(\.git/)'
isort --check-only . --skip .git

# Auto-fix
black . --exclude '(\.git/)'
isort . --skip .git
```

---

## 11. Namespace Package Rules (CRITICAL)

These rules are **mandatory** for imports to work across suites:

1. **NEVER add `__init__.py` to any `api/` directory** — The `api` namespace is shared across all 6 suites via PEP 420 implicit namespace packages
2. **PYTHONPATH must list all 6 suite dirs** — Each suite root must be a separate PYTHONPATH entry
3. **Import pattern**: `from api.<router_name> import router` resolves by searching each suite's `api/` dir
4. **Import pattern**: `from core.<module> import Class` resolves from `suite-core/core/`
5. **Always use try/except for cross-suite imports** in `app.py` — graceful degradation if a suite is absent

```python
# ✅ CORRECT
from api.mpte_router import router          # Finds suite-attack/api/mpte_router.py
from core.knowledge_brain import KnowledgeBrain  # Finds suite-core/core/knowledge_brain.py

# ❌ WRONG — never use suite directory prefix in imports
from suite_attack.api.mpte_router import router
from suite_core.core.knowledge_brain import KnowledgeBrain
```

> Full namespace package details → [SUITE_ARCHITECTURE.md §11](SUITE_ARCHITECTURE.md)

---

## 12. Contributing

### Branch naming

```
features/<feature-name>
fix/<issue-description>
docs/<what-changed>
```

### Commit messages

Follow conventional commits:
```
feat: add new DAST scan engine
fix: resolve CORS header issue on /api/findings
docs: update API reference with new endpoints
ci: fix docker build PYTHONPATH
test: add E2E tests for micro-pentest flow
refactor: extract risk scoring to separate module
```

### PR process

1. Create feature branch from `features/intermediate-stage` (current active branch)
2. Make changes, write/update tests
3. Run format checks: `black . && isort .`
4. Run tests: `pytest tests/ -v -m "not slow"`
5. Push branch, open PR against `features/intermediate-stage`
6. CI must pass (lint, format, tests, coverage)
7. Get review approval
8. Merge

### Code style

- **Python**: Black formatter (line-length 88), isort (profile "black")
- **TypeScript**: ESLint with React hooks + refresh plugins
- **Target Python**: 3.11+ (type hints, `match` statements OK)
- **Pydantic**: v2 models (use `model_config`, not `class Config`)
- **Logging**: Always use `structlog.get_logger(__name__)`, never `print()`
- **Error handling**: Use `core.error_responses` patterns for API errors
- **Auth**: All non-health endpoints require `X-API-Key` or `Authorization: Bearer <jwt>`

---

## 13. Data Storage

### SQLite databases (in `data/`)

| Database | Purpose |
|----------|---------|
| `fixops_brain.db` | Knowledge graph (CVEs, CWEs, CPEs, assets, findings) |
| `analytics.db` | Dashboard analytics |
| `api_learning.db` | API learning store (MindsDB layer) |
| `audit.db` | Audit log |
| `auth.db` | Users, API keys, sessions |
| `collaboration.db` | Team collaboration |
| `feeds/feeds.db` | Cached threat intel feeds |
| `iac.db` | Infrastructure-as-Code scan results |
| `integrations.db` | Integration configs (webhooks, Jira, etc.) |
| `inventory.db` | Asset inventory |
| `mpte.db` | Micro-pentest results |
| `pentagi.db` | PentAGI agent data |
| `policies.db` | Security policies |
| `reports.db` | Generated reports |
| `secrets.db` | Secret scanning results |
| `users.db` | User management |
| `workflows.db` | Workflow definitions |

### File storage (in `data/`)

| Directory | Purpose |
|-----------|---------|
| `evidence/bundles/` | Signed evidence bundles (SOC2, ISO27001) |
| `evidence/manifests/` | Evidence manifests |
| `artifacts/sbom/` | SBOM files (CycloneDX, SPDX) |
| `artifacts/attestations/` | Build attestations |
| `feeds/vex/` | VEX advisories |
| `uploads/` | User uploads (demo + enterprise) |
| `reachability/` | Reachability analysis results |
| `remediation/` | Remediation task data |
