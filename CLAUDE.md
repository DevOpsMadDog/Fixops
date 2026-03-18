# ALdeci (FixOps) — Project Guide

> **Last verified**: 2026-03-08 by context-engineer (v34.0)
> **Platform**: CTEM+ Decision Intelligence for Application Security
> **Identity**: docs/CTEM_PLUS_IDENTITY.md | **Vision**: docs/CEO_VISION.md
> **Sprint**: 2 — Enterprise Demo (2026-03-06) | 11/12 done (Post-Demo Day 2)

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
├── suite-api/          # FastAPI gateway — 20 routers, JWT auth, CORS (22.6K LOC)
│   └── apps/api/app.py # Entry point — 34 router mounts, 2893 LOC
├── suite-core/         # Core engines — brain pipeline, scanners, CLI (140.1K LOC)
│   ├── core/           # Business logic (engines, scanners, connectors)
│   └── api/            # 21 core routers
├── suite-attack/       # Offensive security — MPTE, attack sim, scanner routers (6.7K LOC)
├── suite-feeds/        # Threat intel feeds — NVD, KEV, EPSS, OSV (4.4K LOC)
├── suite-evidence-risk/# Evidence, risk scoring, compliance (20.3K LOC)
├── suite-integrations/ # External integrations — MCP, webhooks, IaC, OSS tools (6.8K LOC)
├── suite-ui/
│   ├── aldeci/         # Legacy React UI (ACTIVE — wiring to real APIs) 101 src TS/TSX files, 45.5K LOC
│   └── aldeci-ui-new/  # New UI (MISSING — directory does not exist)
├── tests/              # 386 test files, 194K LOC, 14,133 tests collected
├── docker/             # Dockerfiles + compose files + Kubernetes Helm chart
├── docs/               # Vision docs, debate transcript, identity docs
├── scripts/            # Shell scripts for orchestration, demos, CI/CD
├── .claude/            # Agent system — definitions, team state, knowledge index
│   ├── agents/         # 19 agent definitions (.md files) — incl. ux-architect, persona-api-validator
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
| **V3 — Decision Intelligence** | Brain pipeline, FAIL scoring, triage, AutoFix | brain_pipeline.py (1,878 LOC), autofix_engine.py (1,534 LOC), fail_engine.py (717 LOC) |
| **V5 — MPTE Verification** | Prove exploitability via micro-pentests | micro_pentest.py (2,054 LOC), mpte_advanced.py (1,089 LOC) |
| **V7 — MCP-Native Platform** | AI agent-consumable security tools | mcp_server.py (978 LOC), mcp_router.py (977 LOC auto-discovery), 771 endpoints |

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
| `suite-api/apps/api/app.py` | 2,893 | FastAPI entry point, 34 router mounts |
| `suite-core/core/brain_pipeline.py` | 1,878 | 12-step CTEM decision pipeline |
| `suite-core/core/autofix_engine.py` | 1,534 | LLM-powered auto-remediation (10 fix types) |
| `suite-core/core/micro_pentest.py` | 2,054 | MPTE core engine |
| `suite-core/core/connectors.py` | 3,029 | 7 integration connectors (Jira, Confluence, Slack, ServiceNow, GitLab, AzureDevOps, GitHub) |
| `suite-core/core/security_connectors.py` | 1,335 | 10 security tool connectors (Snyk, SonarQube, Dependabot, AWS SecurityHub, Azure Defender, Wiz, Prisma Cloud, Orca, Lacework, ThreatMapper) |
| `suite-core/core/cli.py` | 5,929 | CLI with 22 commands |
| `suite-core/core/crypto.py` | 582 | RSA-SHA256 evidence signing |
| `suite-integrations/api/mcp_router.py` | 468 | MCP gateway for AI agents |

---

## API Surface

- **771 endpoints** across 64 router files + 8 non-standard files (699 @router + 47 non-standard + 25 @app direct)
- **Auth**: API key header (`X-API-Key`) + JWT tokens
- **Base path**: `/api/v1/`
- **Test token**: `FIXOPS_API_TOKEN` from environment (enterprise key required)

### Key API Prefixes
| Prefix | Router | Pillar |
|--------|--------|--------|
| `/api/v1/brain` | brain_router.py (24 endpoints) | V3 |
| `/api/v1/mpte` | mpte_router.py (23 endpoints) | V5 |
| `/api/v1/micro-pentest` | micro_pentest_router.py (19 endpoints) | V5 |
| `/api/v1/mcp-server` | mcp_router.py (10 endpoints) | V7 |
| `/api/v1/mcp` | mcp_router.py (8 endpoints, auto-discovery) | V7 |
| `/api/v1/scanner-ingest` | scanner_ingest_router.py (7 endpoints) | V7 |
| `/api/v1/mcp-protocol` | mcp_protocol_router.py (10 endpoints) | V7 |
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

- **14,133 tests collected** (0 collection errors, 15.46s collection time)
- **19.19% coverage** (gate: 25% — currently FAILING, gap 5.81pp. DEMO-006 config fix applied but coverage still below gate.)
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

19 AI agents operate as a virtual company. See `.claude/agents/` for definitions.
- **Shared state**: `.claude/team-state/` (codebase-map, sprint board, briefings)
- **Coordination**: `.claude/team-state/coordination-notes.md`
- **Debates**: `.claude/team-state/debates/`
- **Run order**: Phase 0 (doctor) → Phase 1 (context) → Phase 2-3 (build) → Phase 4 (validate) → Phase 5-9 (deploy/market)

---

## Skills (`.claude/skills/`)

Reusable domain expertise for any agent or session. Read the relevant skill before starting a task.

| Skill | File | When to Use |
|-------|------|-------------|
| **Codebase Navigation** | `.claude/skills/codebase-navigation.md` | First time in repo, finding files, understanding imports |
| **Database Migration** | `.claude/skills/database-migration.md` | Migrating sqlite3/PersistentDict → DatabaseManager |
| **Multi-Tenancy** | `.claude/skills/multi-tenancy.md` | Adding org_id isolation to any endpoint |
| **Error Handling** | `.claude/skills/error-handling.md` | Replacing bare `except Exception`, custom exception hierarchy |
| **Endpoint Hardening** | `.claude/skills/endpoint-hardening.md` | 8-point checklist for every API endpoint |
| **Testing Patterns** | `.claude/skills/testing-patterns.md` | Writing tests, fixing collection errors, growing coverage |
| **Knowledge Graph** | `.claude/skills/knowledge-graph.md` | Extending the security graph, attack path analysis |
| **Scanner Development** | `.claude/skills/scanner-development.md` | Hardening/extending the 8 native scanners |
| **Observability** | `.claude/skills/observability.md` | Metrics, tracing, structured logging, health checks |
| **Acquisition Readiness** | `.claude/skills/acquisition-readiness.md` | Due diligence prep, documentation, compliance |

**Rule**: Before working on a task, check if a matching skill exists. Load it. Follow its patterns.

---

## Known Issues

1. **New UI is missing** — `suite-ui/aldeci-ui-new/` directory does not exist on disk
2. **Test coverage at 19.19%** — Below 25% gate, CI failing (DEMO-006 config fix applied but still below gate)
3. **Non-standard endpoint files at non-obvious paths** — decisions.py (suite-core/api/), nerve_center.py (suite-core/api/), business_context*.py (suite-evidence-risk/api/) are conditionally mounted
4. **Single-process monolith** — No horizontal scaling (OK for demo/POC)
5. **No external message queue** — EventBus is in-process only
6. **Brain pipeline runs synchronously** — O(n) at graph step (optimized from O(n^2)), LLM calls block
7. **No git commits since 2026-03-03** — 5 days of uncommitted working directory changes

---

*Maintained by context-engineer. Full architecture: `.claude/team-state/architecture-context.md`*
