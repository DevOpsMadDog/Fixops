# FixOps AI Coding Instructions

## Project Overview

FixOps is an enterprise DevSecOps Decision & Vulnerability Operations Platform. It ingests security artifacts (SBOM, SARIF, CVE, VEX, CNAPP), correlates findings into a Risk Graph, and produces release-gate decisions (Allow/Block/Needs Review) via multi-LLM consensus, policy evaluation, and probabilistic forecasting.

## Architecture

```
backend/app.py          → Uvicorn entrypoint (delegates to apps/api/app.py)
apps/api/app.py         → FastAPI application factory with 32+ routers
apps/api/*_router.py    → Domain-specific API routers (evidence, risk, policies, etc.)
apps/fixops_cli/        → CLI entrypoint (stage-run, ingest, make-decision commands)
core/                   → Shared business logic (decision engine, LLM providers, evidence, storage)
risk/                   → Risk scoring, reachability analysis, SBOM processing
config/                 → YAML overlays (fixops.overlay.yml controls behavior)
ui/aldeci/              → Vite + React + Tailwind frontend (TypeScript)
tests/                  → Pytest suite with markers: unit, integration, e2e, security
```

**Key Data Flow:** Upload artifacts → `apps/api/normalizers.py` → `apps/api/pipeline.py` → `core/enhanced_decision.py` (Multi-LLM consensus) → `core/evidence.py` (signed bundles)

## Development Commands

```bash
make bootstrap          # Create venv, install all deps
make fmt                # Run isort + black
make lint               # Run flake8
make test               # Pytest with 60% coverage gate

# Run backend (uvicorn with hot-reload)
python -m uvicorn backend.app:create_app --factory --reload --port 8000

# Run frontend (ui/aldeci/)
cd ui/aldeci && npm run dev

# Demo pipeline
make demo               # Quick demo with sample data
make demo-enterprise    # Enterprise mode with hardened overlay
```

## Code Conventions

- **Python 3.11+** with type hints; `black` (88 chars), `isort` (black profile)
- **Pydantic v2** for all API models; use `model_dump()` not `dict()`
- **Optional imports pattern** for enterprise features:
  ```python
  router: Optional[APIRouter] = None
  try:
      from apps.api.feature_router import router as feature_router
  except ImportError:
      logging.getLogger(__name__).warning("Feature router not available")
  ```
- **Environment variables** prefixed with `FIXOPS_` (e.g., `FIXOPS_CONSENSUS_THRESHOLD`, `FIXOPS_OVERLAY_PATH`)
- **Overlay configuration** in `config/fixops.overlay.yml` controls feature flags and modes

## API Router Pattern

New routers in `apps/api/` follow this structure:
```python
from fastapi import APIRouter, Depends
router = APIRouter(prefix="/api/v1/feature", tags=["feature"])

@router.post("/action")
async def action(payload: FeaturePayload) -> FeatureResponse:
    ...
```
Register in `apps/api/app.py` via `app.include_router(feature_router)`.

## Testing Patterns

- Fixtures in `tests/conftest.py`; use `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.e2e`
- Many tests are skipped in `conftest.py` due to missing enterprise modules (documented there)
- Use `FIXOPS_TEST_SEED` env var for deterministic test runs
- Test file naming: `test_<module>.py` with functions `test_<scenario>()`

## Multi-LLM Consensus Engine

Located in `core/enhanced_decision.py` with providers in `core/llm_providers.py`:
- Providers: OpenAI, Anthropic, Gemini, Sentinel-Cyber (weighted voting)
- Threshold: `FIXOPS_CONSENSUS_THRESHOLD` (default 85%)
- Falls back to `DeterministicLLMProvider` when APIs unavailable
- Returns tri-state: `Allow`, `Block`, `Needs Review`

## Evidence & Cryptographic Signing

`core/evidence.py` handles evidence bundles with:
- RSA-SHA256 signing via `core/crypto.py`
- Optional Fernet encryption for sensitive data
- Gzip compression for large bundles
- Atomic writes for data integrity

## Key Domain Models

- **NormalizedSBOM/SARIF/CVE/VEX** in `apps/api/normalizers.py`
- **OverlayConfig** in `core/configuration.py` (deep-merged YAML configs)
- **EvidenceHub** in `core/evidence.py` (signed artifact persistence)
- **EnhancedDecisionEngine** in `core/enhanced_decision.py`

## Frontend (ui/aldeci/)

- React 18 + TypeScript + Vite + Tailwind CSS
- Radix UI components, React Query for data fetching
- API client in `src/lib/api.ts`
- Run with `npm run dev` (requires backend on port 8000)
