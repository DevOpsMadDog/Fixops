# Skill: Codebase Navigation

> How the ALdeci codebase is organized, how imports work, and how to find anything.

## Import System — sitecustomize.py

`sitecustomize.py` at project root auto-prepends all suite directories to `sys.path` at Python startup. Cross-suite imports "just work":

```python
# From ANY file in ANY suite:
from core.brain_pipeline import BrainPipeline       # suite-core/core/
from core.connectors import AutomationConnectors     # suite-core/core/
from apps.api.app import create_app                  # suite-api/apps/api/
from api.mpte_router import router                   # suite-attack/api/ OR suite-core/api/
from core.autofix_engine import AutoFixEngine        # suite-core/core/
```

**Never manually manipulate sys.path.** If an import fails, the module is genuinely missing — don't hack around it.

## Suite Directory Map

```
suite-api/apps/api/          → FastAPI routers + app factory (68 *_router.py files)
suite-api/apps/api/app.py    → Entry point: create_app() factory, ~2,900 LOC
suite-api/apps/api/middleware.py → SecurityHeaders, RateLimit, CorrelationId, Logging

suite-core/core/             → Business logic engines (brain, scanners, autofix, crypto)
suite-core/api/              → 21 additional core routers (knowledge_graph_router, copilot_router, etc.)
suite-core/core/db/enterprise/ → DatabaseManager, Alembic migrations, async sessions
suite-core/config/enterprise/  → Settings (DATABASE_URL, pool sizes, JWT, Redis)

suite-attack/api/            → Offensive security routers (MPTE, SAST, DAST, etc.)
suite-feeds/api/             → Threat intel feed routers
suite-evidence-risk/api/     → Evidence, risk, compliance routers
suite-integrations/api/      → External integration routers (Jira, Slack, MCP, webhooks)

suite-ui/aldeci/src/         → React frontend (47K+ LOC)
tests/                       → 386+ test files (232K LOC)
```

## Finding Things Fast

### Find all endpoints for a domain:
```bash
grep -rn "@router\.\(get\|post\|put\|patch\|delete\)" suite-api/apps/api/DOMAIN_router.py
```

### Find where a router is mounted:
```bash
grep -n "ROUTER_NAME" suite-api/apps/api/app.py
```

### Find all files that use a specific import:
```bash
grep -rn "from core.MODULE import" suite-api/ suite-core/ --include="*.py" | grep -v __pycache__
```

### Find all database calls in a file:
```bash
grep -n "sqlite3\|cursor\|execute\|PersistentDict\|DatabaseManager" path/to/file.py
```

### Find all endpoints missing auth:
```bash
grep -n "include_router" suite-api/apps/api/app.py | grep -v "Depends\|dependencies"
```

### Count total endpoints:
```bash
grep -rn "@router\.\|@app\." suite-api/ suite-core/api/ suite-attack/api/ suite-evidence-risk/api/ suite-integrations/api/ suite-feeds/api/ --include="*.py" | grep -E "\.(get|post|put|patch|delete)\(" | grep -v __pycache__ | wc -l
```

## Router Mount Pattern in app.py

Routers are mounted in `create_app()` with auth dependencies:

```python
# Direct mount with auth:
app.include_router(findings_router, dependencies=[Depends(_verify_api_key)])

# Mount with scope:
app.include_router(admin_router, dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))])

# Loop mount (core routers — ALL get auth):
for _r, _name, _prefix in _core_routers:
    if _r:
        kwargs = {"dependencies": [Depends(_verify_api_key)]}
        if _prefix:
            kwargs["prefix"] = _prefix
        app.include_router(_r, **kwargs)
```

## Running Tests

```bash
# With correct PYTHONPATH (sitecustomize.py handles this, but some test runners need it explicit):
PYTHONPATH=suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations:. python -m pytest tests/TEST_FILE.py -v --timeout=10

# Collect all (check for errors):
python -m pytest tests/ --collect-only -q --override-ini="addopts="

# Run with coverage:
python -m pytest tests/ --cov=. --cov-report=term --timeout=10
```

## Key Config Files

| File | Purpose |
|------|---------|
| `sitecustomize.py` | Auto-path injection (DO NOT MODIFY) |
| `pyproject.toml` | pytest config, coverage settings, isort/black config |
| `requirements.txt` | Python dependencies |
| `.env` | Runtime secrets (FIXOPS_API_TOKEN, FIXOPS_JWT_SECRET, DATABASE_URL) |
| `suite-core/config/enterprise/settings.py` | All enterprise settings (Pydantic BaseSettings) |
| `suite-api/apps/api/dependencies.py` | Auth dependencies (_verify_api_key, _require_scope) |
