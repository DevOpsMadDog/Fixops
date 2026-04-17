# PRD: Community 511 — config.ALDECIConfig.from_env

## Master Goal Mapping
**ALDECI Pillar**: Platform — Centralized Configuration  
**Persona**: Platform Engineer, DevOps  
**Business Value**: Constructs the validated ALDECIConfig singleton by reading all platform configuration from environment variables, replacing scattered `os.getenv()` calls across 344 engines with a single, type-safe, Pydantic-validated configuration object.

## Architecture Diagram
```mermaid
graph TD
    A[Application startup] --> B[ALDECIConfig.from_env]
    B --> C[Read env vars: API_PORT, API_HOST, etc.]
    C --> D[_env / _env_int / _env_bool helpers]
    D --> E[Pydantic field validation]
    E --> F{Validation passes?}
    F -->|yes| G[ALDECIConfig instance cached]
    F -->|no| H[ValidationError: fail_fast=True → exit]
    G --> I[get_config() returns cached instance]
    I --> J[All 344 engines use cfg.api_token, cfg.db_path, etc.]
    style B fill:#264653,color:#fff
```

## Code Proof
**File**: `suite-core/core/config.py`  
```python
@classmethod
def from_env(cls) -> ALDECIConfig:
    """Construct an ALDECIConfig by reading all values from environment variables."""
    return cls(
        api_port=_env_int("API_PORT", 8000),
        api_host=_env("API_HOST", "0.0.0.0"),
        api_workers=_env_int("API_WORKERS", 4),
        api_mode=_env("API_MODE", "development"),
        disable_rate_limit=_env_bool("DISABLE_RATE_LIMIT", False),
        detailed_logging=_env_bool("DETAILED_LOGGING", False),
        allowed_origins=_env("ALLOWED_ORIGINS", "http://localhost:3000"),
        fail_fast=_env_bool("FAIL_FAST", False),
        version=_env("ALDECI_VERSION", "0.1.0"),
        build_date=_env("BUILD_DATE", "unknown"),
        git_commit=_env("GIT_COMMIT", "unknown"),
        # ... all other fields
    )
```

## Inter-Dependencies
- **Upstream**: Environment variables (`.env` file, Docker/K8s secrets)
- **Downstream**: All 344 engines via `from core.config import get_config`
- **Thread safety**: `get_config()` uses double-checked locking singleton

## Data Flow
```
docker run -e API_PORT=8080 -e API_MODE=enterprise aldeci-api
  → app startup: cfg = get_config()
    → ALDECIConfig.from_env()
    → api_port=8080, api_mode="enterprise"
    → Pydantic validation passes
    → cache as module-level singleton
  → All routers: cfg.api_port, cfg.api_mode
```

## Referenced Docs
- `suite-core/core/config.py`
- ALDECI deployment guide
- Pydantic v2 BaseModel docs

## Acceptance Criteria
- [ ] All env vars read via type-safe `_env_int`, `_env_bool`, `_env_float` helpers
- [ ] Defaults are safe for local development
- [ ] `fail_fast=True` → `ValidationError` exits app on startup
- [ ] `get_config()` returns same instance on repeated calls (singleton)
- [ ] Tests can override config via `get_config.cache_clear()` or monkeypatch

## Effort Estimate
**XS** — 0.5 days. Implementation complete; verify all fields present and defaults safe.

## Status
**COMPLETE** — Implementation exists. Verify all 344 engines migrated from `os.getenv`.
