# ALdeci / FixOps - Copilot Instructions

## Architecture Overview

**6-Suite Monolith** running on port 8000. All suites share imports via `sitecustomize.py` (auto-loaded by Python).

| Suite | Purpose | Key Files |
|-------|---------|-----------|
| `suite-api` | FastAPI gateway, routers, auth | `apps/api/app.py`, `*_router.py` |
| `suite-core` | Brain, pipeline, decisions, connectors | `core/connectors.py`, `core/brain_pipeline.py` |
| `suite-attack` | Micro-pentest engine (MPTE) | `attack/micro_pentest.py`, `attack/mpte_advanced.py` |
| `suite-feeds` | Threat intel (NVD, KEV, EPSS) | `feeds/*.py` |
| `suite-evidence-risk` | Compliance, evidence bundles | `risk/*.py`, `evidence/*.py` |
| `suite-integrations` | Jira, Slack, GitHub connectors | (shares connectors from suite-core) |
| `suite-ui` | React + Vite + shadcn/ui frontend | `aldeci/src/` |

## Critical Patterns

### Import Resolution
- **sitecustomize.py** at project root auto-prepends all suite paths to `sys.path`
- Imports like `from core.connectors import JiraConnector` work from anywhere
- Never manually manipulate `sys.path`; `sitecustomize.py` handles it

### Connector Pattern (suite-core/core/connectors.py)
All external connectors inherit from `_BaseConnector` with:
- Circuit breaker (`CircuitBreaker` dataclass)
- Retry with exponential backoff (`Retry` from urllib3)
- Rate limiting
- `health_check()` method for connectivity validation

```python
# Adding a new connector:
class MyConnector(_BaseConnector):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("url", "")
        # Set self.configured = True when all required fields present
    
    def health_check(self) -> Dict[str, Any]:
        return self._request("GET", "/health")
```

### Integration Types (suite-core/core/integration_models.py)
Add new integrations to `IntegrationType` enum, then wire in `integrations_router.py`:
- Add to `IntegrationType` enum
- Add connector import in `integrations_router.py`
- Add elif case in `test_integration()` and `trigger_sync()` endpoints

### Frontend API Client (suite-ui/aldeci/src/lib/api.ts)
- Uses axios with `X-API-Key` header
- Export API namespaces: `dashboardApi`, `integrationsApi`, `findingsApi`, etc.
- Add new endpoints following existing namespace pattern

## Developer Commands

```bash
# Backend
source .venv/bin/activate
uvicorn apps.api.app:app --port 8000 --reload

# Frontend (separate terminal)
cd suite-ui/aldeci && npm run dev  # http://localhost:3001

# Testing
make test                          # pytest with 60% coverage gate
pytest tests/test_<name>.py -v     # single test file
pytest -k "test_integrations" -v   # pattern match

# Formatting
make fmt                           # isort + black

# Demo pipeline
make demo                          # full end-to-end demo
```

## Testing Conventions

- Tests in `tests/` directory, named `test_*.py`
- Markers defined in `pyproject.toml`: `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.e2e`
- Use `conftest.py` fixtures for shared test setup
- Coverage gate: 60% minimum (`--cov-fail-under=60`)

## File Structure Conventions

- Routers: `suite-api/apps/api/*_router.py` (FastAPI APIRouter)
- Models: `suite-core/core/*_models.py` (dataclasses, Pydantic, enums)
- Database: `suite-core/core/*_db.py` (SQLite with WAL mode)
- UI Pages: `suite-ui/aldeci/src/pages/**/*.tsx`
- UI Components: `suite-ui/aldeci/src/components/ui/` (shadcn primitives) and `src/components/aldeci/` (custom)

## Key Design Decisions

1. **Multi-LLM Consensus**: GPT-4 + Claude + Gemini with 85% threshold (see `core/llm_providers.py`)
2. **SQLite WAL**: All DBs use WAL mode for concurrent reads
3. **No external message queues**: Event-driven via `core/event_bus.py`
4. **Signed evidence**: RSA-SHA256 signatures via `core/crypto.py`

## Common Pitfalls

- Don't create files in `WIP/` — excluded from formatting/linting
- Always add new routers to `apps/api/app.py` `include_router()` calls
- UI environment: `VITE_API_URL` and `VITE_API_KEY` in `.env`
- Backend auth: `X-API-Key` header required (see `dependencies.py`)
