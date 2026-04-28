# ALDECI Developer Onboarding

Estimated time: 30-60 minutes. Follow each section in order.

---

## 1. Prerequisites

Install these before cloning.

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.14+ | `pyenv install 3.14` or system package manager |
| Node | 25+ | `nvm install 25` |
| Docker | 27+ | https://docs.docker.com/engine/install/ |
| ruflo | latest | `npm i -g ruflo` |
| graphify | latest | `brew install graphify` |
| git | 2.40+ | system package manager |

Verify:

```bash
python3 --version   # 3.14.x
node --version      # v25.x
docker info         # must show running daemon
ruflo --version
graphify --version
```

---

## 2. Clone and Repo Layout

```bash
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops
git checkout features/intermediate-stage
```

Directory map:

```
suite-api/          # FastAPI gateway — 34 router mounts (~6300 routes)
suite-core/         # Core engines — Brain Pipeline, connectors, CLI
  core/             # Business logic, 360+ engines
  connectors/       # PullConnector framework (13 PULL + 7 bidirectional)
  trustgraph/       # TrustGraph MCP server + KnowledgeStore
suite-attack/       # Offensive security — MPTE, attack simulation
suite-feeds/        # 28+ threat intel feeds
suite-evidence-risk/# Evidence, risk scoring, compliance
suite-integrations/ # External integrations — MCP, webhooks
suite-ui/
  aldeci-ui-new/    # Active UI (React 19 + Vite 6 + Tailwind v4) — work here
  aldeci/           # FROZEN legacy UI — do not modify
tests/              # 327 test files (13-file Beast Mode suite is canonical)
docs/               # Architecture, identity, session history
docker/             # Compose variants (enterprise, HA, prod, connectors)
```

`sitecustomize.py` at the repo root auto-prepends all `suite-*` directories to `sys.path`. This means any Python process started from the repo root can import core modules directly:

```python
from core.brain_pipeline import BrainPipeline   # no path manipulation needed
from core.scanner_parsers import ScannerParser
```

No `PYTHONPATH` exports required.

---

## 3. Backend Bootstrap

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install all dependencies (Makefile target handles sub-requirements too)
make bootstrap
# Equivalent manual command if make is unavailable:
# pip install -r requirements.txt

# Start the FastAPI server
cd suite-api
uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --reload
```

Confirm it is up:

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
# Expected: {"status": "healthy", ...}
```

The API token for local development defaults to `aldeci-demo-token`. Pass it as:

```bash
curl -H "Authorization: Bearer aldeci-demo-token" http://localhost:8000/api/v1/...
```

For Docker-based startup (no venv required):

```bash
docker compose up aldeci   # builds image, starts API on :8000
```

---

## 4. Frontend Bootstrap

The active UI lives in `suite-ui/aldeci-ui-new`. The frozen `suite-ui/aldeci` directory must not be touched.

```bash
cd suite-ui/aldeci-ui-new
npm install
npm run dev
# Vite starts on http://localhost:5173
```

The Vite dev server proxies `/api` to `http://localhost:8000` — the backend must be running first. Open `http://localhost:5173` in a browser. You should see the ALdeci login page with no console errors.

Docker alternative (serves production build via nginx on :3000):

```bash
docker compose up aldeci-ui
```

---

## 5. Beast Mode Tests

This 13-file suite is the canonical quality gate. Run it before every commit.

```bash
python -m pytest \
  tests/test_phase2_connectors.py tests/test_phase3_llm_council.py \
  tests/test_phase4_integration.py tests/test_phase5_enterprise.py \
  tests/test_phase6_streaming.py tests/test_phase7_analytics.py \
  tests/test_phase8_mcp.py tests/test_phase9_playbooks.py \
  tests/test_phase10_e2e.py tests/test_connector_framework.py \
  tests/test_trustgraph.py tests/test_pipeline_api.py \
  tests/test_persona_workflows.py \
  -x --tb=short --timeout=10 -q -o "addopts="
```

Expected result: **753 passing, 0 failed**. If any test fails, fix it before pushing — zero regressions is a hard rule.

Do not run `pytest tests/` (full suite) for day-to-day work. The 190 legacy test files test retired modules and will produce noise.

---

## 6. Multica Board

Multica is the team Kanban board (UI :3000, API :8080, Postgres :5433). It is not in the main `docker-compose.yml`; start it with:

```bash
docker run -d --name multica-postgres \
  -e POSTGRES_DB=multica -e POSTGRES_USER=multica -e POSTGRES_PASSWORD=multica \
  -p 5433:5432 postgres:16-alpine

docker run -d --name multica-api \
  -e DATABASE_URL=postgresql://multica:multica@host.docker.internal:5433/multica \
  -p 8080:8080 multica/api:latest

docker run -d --name multica-ui \
  -e API_URL=http://localhost:8080 \
  -p 3000:80 multica/ui:latest
```

Open `http://localhost:3000`. Current board state: ~2942 done / 72 todo / 9 in-progress. Query board state via psql:

```bash
docker exec multica-postgres psql -U multica -d multica \
  -c "SELECT status, count(*) FROM tasks GROUP BY status;"
```

---

## 7. Stack Tour

Read these files in order to build a mental model of the system:

| File | What it covers |
|------|----------------|
| `CLAUDE.md` | CTO operating manual — Beast Mode rules, stack inventory, operating rules |
| `docs/CTEM_PLUS_IDENTITY.md` | Canonical platform identity: 8 native engines, 12-step Brain Pipeline, MPTE, FAIL, AI consensus, AutoFix |
| `docs/architecture/README.md` | Graphify community map — 1516 communities, god nodes, module boundaries |
| `docs/api-reference/feeds_2026-04-27.md` | API reference for threat intel feeds |
| `docs/app_py_refactor_plan_2026-04-27.md` | Sub-app extraction plan for the FastAPI gateway |
| `graphify-out/GRAPH_REPORT.md` | Live knowledge graph: 119,765 nodes, 425,727 edges, hub rankings |

For any codebase question, query graphify before reading raw files:

```bash
graphify query "how does the Brain Pipeline ingest scanner findings"
graphify explain "suite-core/core/brain_pipeline.py"
```

---

## 8. Daily Dev Loop

Start of session:

```bash
git pull origin features/intermediate-stage
graphify update . --no-llm   # refresh graph — AST-only, no API cost
```

Before reading any source file, run a graphify query first. The graph surfaces the right file faster than directory browsing.

Pre-commit gate (non-negotiable):

```bash
# Run Beast Mode tests
python -m pytest tests/test_phase*.py tests/test_connector_framework.py \
  tests/test_trustgraph.py tests/test_pipeline_api.py \
  tests/test_persona_workflows.py -x --timeout=10 -q -o "addopts="
```

Commit format:

```bash
git commit -F /tmp/msg.txt
# msg.txt contents:
# beast-mode(scope): short imperative description
#
# Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

Auto-save rule: commit and push every 15-20 minutes during active sessions.

```bash
git add -A && git commit -F /tmp/autosave.txt && git push origin features/intermediate-stage
```

All work goes to `features/intermediate-stage`. Do not push to `main` without a PR.

---

## 9. Tooling Cheatsheet

**graphify**

```bash
graphify update . --no-llm           # refresh graph after code changes
graphify query "question"            # natural language codebase search
graphify explain "path/to/file.py"   # explain a file's role in the graph
# Graph lives in graphify-out/ — GRAPH_REPORT.md is the entry point
```

**ruflo**

```bash
ruflo --help                         # list available commands
# AgentDB (vector memory) is the primary active feature
# Swarm/hive-mind orchestration is BROKEN — skip those subcommands
# Active skills: memory_store, memory_search, hooks_route, vector_indexes
```

**claude (CLI)**

```bash
claude -p "task description"         # spawn a specialist agent for a task
# Agent tool (native): dispatch up to 12 specialist agents in parallel
# Agent types include: backend-hardener, frontend-craftsman, technical-writer,
#   enterprise-architect, security-analyst, qa-engineer, data-scientist
```

**Key environment variables** (copy `.env.example` to `.env`):

```
FIXOPS_API_TOKEN=aldeci-demo-token
ANTHROPIC_API_KEY=...
OPENAI_API_KEY=...
OPENROUTER_API_KEY=...       # Qwen 3.6 Max via mulerouter.ai
FIXOPS_USE_COUNCIL=0         # set to 1 to enable multi-LLM consensus
```

---

## 10. Common Gotchas

**Heredoc commits stall agents.** Never use `git commit -m "$(cat <<'EOF'...EOF)"` inside agent subprocesses — the heredoc blocks on stdin. Always write the message to a temp file first:

```bash
cat > /tmp/msg.txt << 'MSG'
beast-mode(scope): description

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
MSG
git commit -F /tmp/msg.txt
```

**`_*.py` gitignore is repo-root-only.** The `.gitignore` pattern `_*.py` applies only at the root. Files named `_helpers.py` in subdirectories are tracked normally. Don't assume underscore-prefix files are excluded in nested directories.

**NO MOCKS rule.** Every UI page must fire at least one real `/api/v1/...` call on mount. Static JSON imports from `src/data/` or `src/fixtures/` are treated as mock data and fail the task completion gate. If an endpoint returns empty, fix the data source — do not paper over with hardcoded arrays.

**Parallel git lock contention.** When multiple agents commit concurrently, `.git/index.lock` conflicts occur. Pattern: wrap git operations in a retry loop with jitter, or serialize commits through a single agent. Do not use `--force` to remove the lock file without first confirming no other process holds it.

**Port conflicts.** Vite defaults to `:5173`, not `:3000`. If you navigate to `http://localhost:3000` and get a 404, switch to `:5173`. Multica UI occupies `:3000`.

**`sitecustomize.py` requires running from repo root.** If you run Python from a subdirectory (e.g., `cd suite-core && python`), the `sitecustomize.py` at the repo root is not executed and imports will fail. Always run Python commands from `/path/to/Fixops/`.

---

*Last updated: 2026-04-27. Maintained by the technical-writer agent. Source of truth: `docs/ALDECI_REARCHITECTURE_v2.md`.*
