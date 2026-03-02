# ALdeci (FixOps) — Project Guide

> **Last verified**: 2026-03-02 by context-engineer (v26.0)
> **Platform**: CTEM+ Decision Intelligence for Application Security
> **Identity**: docs/CTEM_PLUS_IDENTITY.md | **Vision**: docs/CEO_VISION.md
> **Sprint**: 2 — Enterprise Demo (2026-03-06) | 12 items, 11/12 done (Day 2)

---

## Quick Start

```bash
# Backend (Python 3.10+)
pip install -r requirements.txt
python -m uvicorn apps.api.app:create_app --factory --port 8000

# Frontend (legacy, FROZEN — do NOT modify)
cd suite-ui/aldeci && npm install && npm run dev  # Port 3001

# Tests
python -m pytest tests/ --timeout=10 -x -q

# Docker
docker compose -f docker/docker-compose.yml up
```

---

## Project Structure

```
.
├── suite-api/          # FastAPI gateway — 20 routers, JWT auth, CORS (22.2K LOC)
│   └── apps/api/app.py # Entry point — 34 router mounts, 2742 LOC
├── suite-core/         # Core engines — brain pipeline, scanners, CLI (132.3K LOC)
│   ├── core/           # Business logic (engines, scanners, connectors)
│   └── api/            # 21 core routers
├── suite-attack/       # Offensive security — MPTE, attack sim, scanner routers (6.3K LOC)
├── suite-feeds/        # Threat intel feeds — NVD, KEV, EPSS, OSV (4.4K LOC)
├── suite-evidence-risk/# Evidence, risk scoring, compliance (20.3K LOC)
├── suite-integrations/ # External integrations — MCP, webhooks, IaC, OSS tools (6.7K LOC)
├── suite-ui/
│   ├── aldeci/         # Legacy React UI (ACTIVE — wiring to real APIs) 89 src TS/TSX files, 36.1K LOC
│   └── aldeci-ui-new/  # New UI (MISSING — directory does not exist)
├── tests/              # 360 test files, 171K LOC, 12,565 tests collected
├── docker/             # Dockerfiles + compose files + Kubernetes Helm chart
├── docs/               # Vision docs, debate transcript, identity docs
├── scripts/            # Shell scripts for orchestration, demos, CI/CD
├── .claude/            # Agent system — definitions, team state, knowledge index
│   ├── agents/         # 16 agent definitions (.md files)
│   ├── team-state/     # Shared state — codebase-map, briefings, sprint board
│   └── knowledge-index/# Compact codebase digests (SQLite + JSON)
├── sitecustomize.py    # Auto-injects all suite paths into sys.path
└── requirements.txt    # Python dependencies
```

---

## Import Mechanism

`sitecustomize.py` at repo root auto-prepends all suite directories to `sys.path` at Python startup:
```python
# Any file can do:
from core.brain_pipeline import BrainPipeline
from api.mpte_router import router
from core.connectors import AutomationConnectors
```

No `pip install -e` needed. Cross-suite imports "just work".

---

## Architecture

**Modular monolith**: 6 Python suites mounted on a single FastAPI app (port 8000).

### Core Pillars (Active Engineering)
| Pillar | What | Key Files |
|--------|------|-----------|
| **V3 — Decision Intelligence** | Brain pipeline, FAIL scoring, triage, AutoFix | brain_pipeline.py (1,354 LOC), autofix_engine.py (1,416 LOC), fail_engine.py (711 LOC) |
| **V5 — MPTE Verification** | Prove exploitability via micro-pentests | micro_pentest.py (2054 LOC), mpte_advanced.py (1089 LOC) |
| **V7 — MCP-Native Platform** | AI agent-consumable security tools | mcp_server.py (979 LOC), mcp_router.py (977 LOC auto-discovery), 759 endpoints |

### Design Constraints (Maintained, Not Actively Built)
- **V1**: APP_ID-centric data model
- **V2**: 10-phase lifecycle
- **V9**: Air-gapped deployment (works today)
- **V10**: CTEM + cryptographic evidence (crypto.py, 582 LOC)

### Deferred (Do Not Build This Sprint)
- V4 (Multi-LLM), V6 (Quantum-Secure), V8 (Self-Learning)

---

## Key Files

| File | LOC | Purpose |
|------|-----|---------|
| `suite-api/apps/api/app.py` | 2742 | FastAPI entry point, 34 router mounts |
| `suite-core/core/brain_pipeline.py` | 1,354 | 12-step CTEM decision pipeline |
| `suite-core/core/autofix_engine.py` | 1,416 | LLM-powered auto-remediation (10 fix types) |
| `suite-core/core/micro_pentest.py` | 2054 | MPTE core engine |
| `suite-core/core/connectors.py` | 3005 | 7 integration connectors (Jira, Confluence, Slack, ServiceNow, GitLab, AzureDevOps, GitHub) |
| `suite-core/core/security_connectors.py` | 1335 | 10 security tool connectors (Snyk, SonarQube, Dependabot, AWS SecurityHub, Azure Defender, Wiz, Prisma Cloud, Orca, Lacework, ThreatMapper) |
| `suite-core/core/cli.py` | 5911 | CLI with 22 commands |
| `suite-core/core/crypto.py` | 582 | RSA-SHA256 evidence signing |
| `suite-integrations/api/mcp_router.py` | 468 | MCP gateway for AI agents |

---

## API Surface

- **759 endpoints** across 64 router files + 8 non-standard files (687 @router + 47 non-standard + 25 @app direct)
- **Auth**: API key header (`X-API-Key`) + JWT tokens
- **Base path**: `/api/v1/`
- **Test token**: `FIXOPS_API_TOKEN` from environment (enterprise key required)

### Key API Prefixes
| Prefix | Router | Pillar |
|--------|--------|--------|
| `/api/v1/brain` | brain_router.py (23 endpoints) | V3 |
| `/api/v1/mpte` | mpte_router.py (23 endpoints) | V5 |
| `/api/v1/micro-pentest` | micro_pentest_router.py (19 endpoints) | V5 |
| `/api/v1/mcp-server` | mcp_router.py (10 endpoints) | V7 |
| `/api/v1/mcp` | mcp_router.py (7 endpoints, auto-discovery) | V7 |
| `/api/v1/scanner-ingest` | scanner_ingest_router.py (7 endpoints) | V7 |
| `/api/v1/mcp-protocol` | mcp_protocol_router.py (8 endpoints) | V7 |
| `/api/v1/autofix` | autofix_router.py (13 endpoints) | V3 |
| `/api/v1/feeds` | feeds_router.py (31 endpoints) | — |
| `/api/v1/agents` | agents_router.py (32 endpoints) | — |

---

## Database

SQLite WAL — 56 domain-specific `.db` files across `data/`, `.fixops_data/`, `suite-api/data/`. No shared schema, no migration system. Uses `PersistentDict` pattern for persistence.

---

## Testing

```bash
# Full test suite
python -m pytest tests/ --timeout=10 -x -q

# With coverage
python -m pytest tests/ --cov=. --cov-report=term --timeout=10

# Specific suite
python -m pytest tests/test_brain_pipeline.py -v
```

- **12,565 tests collected** (0 collection errors, 18.49s collection time)
- **19.22% coverage** (gate: 25% — currently FAILING, gap 5.78pp. DEMO-006 config fix applied but coverage still below gate.)
- **pytest-timeout**: 10s per test (prevents hanging)

---

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `FIXOPS_MODE` | `enterprise` | Operating mode |
| `FIXOPS_API_TOKEN` | — | API authentication key |
| `FIXOPS_JWT_SECRET` | auto-generated | JWT signing secret |
| `FIXOPS_DATA_DIR` | `.fixops_data` | Data storage directory |
| `FIXOPS_DISABLE_RATE_LIMIT` | `0` | Disable rate limiting |
| `FIXOPS_ALLOWED_ORIGINS` | — | CORS allowed origins |
| `MPTE_BASE_URL` | `https://localhost:8443` | MPTE service URL |
| `OPENAI_API_KEY` | — | OpenAI LLM provider |
| `ANTHROPIC_API_KEY` | — | Anthropic LLM provider |

---

## Conventions

- **Python**: FastAPI + Pydantic v2. Type hints required. structlog for logging.
- **Routers**: Each domain gets its own `*_router.py` with `router = APIRouter(prefix=...)`.
- **Auth**: Wrap sensitive endpoints with `Depends(_verify_api_key)` or `require_auth`.
- **DB**: Each domain creates its own SQLite file. Use `PersistentDict` or raw SQLAlchemy.
- **Events**: Use `core/event_bus.py` for cross-module communication.
- **Tests**: `test_*.py` in `tests/`. Use `pytest-asyncio` for async tests. 10s timeout.
- **UI**: Legacy in `suite-ui/aldeci/` (ACTIVE — being wired to real APIs). `suite-ui/aldeci-ui-new/` does NOT exist.
- **Commits**: Conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`).

---

## Agent System

16 AI agents operate as a virtual company. See `.claude/agents/` for definitions.
- **Shared state**: `.claude/team-state/` (codebase-map, sprint board, briefings)
- **Coordination**: `.claude/team-state/coordination-notes.md`
- **Debates**: `.claude/team-state/debates/`
- **Run order**: Phase 0 (doctor) → Phase 1 (context) → Phase 2-3 (build) → Phase 4 (validate) → Phase 5-9 (deploy/market)

---

## Known Issues

1. **New UI is missing** — `suite-ui/aldeci-ui-new/` directory does not exist on disk
2. **Test coverage at 19.22%** — Below 25% gate, CI failing (DEMO-006 config fix applied but still below gate)
3. **Non-standard endpoint files at non-obvious paths** — decisions.py (suite-core/api/), nerve_center.py (suite-core/api/), business_context*.py (suite-evidence-risk/api/) are conditionally mounted
4. **Single-process monolith** — No horizontal scaling (OK for demo/POC)
5. **No external message queue** — EventBus is in-process only
6. **Brain pipeline runs synchronously** — O(n^2) at graph step, LLM calls block

---

*Maintained by context-engineer. Full architecture: `.claude/team-state/architecture-context.md`*
