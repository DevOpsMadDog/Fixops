# FixOps Engineering Handbook

## Environment
- **Python**: 3.11 (managed via `pyenv` or system interpreter)
- **Node.js**: 18+ (for enterprise/frontend demos)
- **Virtualenv**: `make bootstrap` creates `.venv/`

## Dependencies
```
make bootstrap
```
This installs:
- `requirements.txt` – shared tooling
- `apps/api/requirements.txt` – FastAPI ingestion service
- `enterprise/requirements.txt` (optional) – enterprise reference stack
- `requirements.dev.txt` – linting and testing helpers

## Running the ingestion API
```
source .venv/bin/activate
uvicorn apps.api.app:create_app --factory --reload
```
Environment variables:
- `FIXOPS_ALLOWED_ORIGINS` – comma separated CORS origins
- `FIXOPS_JWT_SECRET` – HMAC secret for JWT auth (generated automatically if unset)
- `FIXOPS_JWT_EXP_MINUTES` – token lifetime (default: 120)
- `FIXOPS_OVERLAY_PATH` – override path for `config/fixops.overlay.yml`

## Overlays & data directories
- Overlay profiles live in `config/fixops.overlay.yml`
- Allowlisted data roots default to `data/`; override via `FIXOPS_DATA_ROOT_ALLOWLIST`
- Evidence bundles are written to `data/evidence/<mode>/` (atomic writes, optional encryption)

## Demo & enterprise modes
- Demo CLI: `python -m core.cli demo --mode demo`
- Enterprise CLI: `python -m core.cli demo --mode enterprise`
- Full enterprise stack: `docker-compose up -d` from `enterprise/`

## Databases
- Demo mode uses local JSON and CSV fixtures
- Enterprise stack ships with SQLite (`enterprise/fixops_enterprise.db`) and Postgres-ready migrations under `enterprise/src/db/migrations`

## Scheduler & feeds
- `core.exploit_signals` configures an APScheduler background job to refresh KEV/EPSS every 24h. When APScheduler is unavailable it logs a warning and skips scheduling.

## Testing
- `pytest -q`
- `mypy core apps tests`
- `ruff check .`

## Useful scripts
- `scripts/generate_index.py` – repository inventory
- `scripts/generate_analysis.py` – file summaries and traceability
- `simulations/ssdlc/run.py` – SSDLC stage simulations
