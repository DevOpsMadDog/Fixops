"""Suite-Core API Application.

Hosts all AI/ML, decision engine, and intelligence routers.
Attack/offensive routers have moved to suite-attack.
"""

from __future__ import annotations

import importlib
import logging
import os

from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security — real JWT + scoped API key auth
# ---------------------------------------------------------------------------
try:
    from core.auth_middleware import require_auth
    _auth_dep = Depends(require_auth)
    logger.info("Auth middleware loaded (JWT + scoped API keys)")
except ImportError:
    from fastapi.security import APIKeyHeader as _AKH
    _api_key_header = _AKH(name="X-API-Key", auto_error=False)
    async def _fallback_auth(api_key: str = Depends(_api_key_header)):
        pass
    _auth_dep = Depends(_fallback_auth)
    logger.warning("Auth middleware not available, using passthrough")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="FixOps Suite-Core API",
    description="AI/ML, Decision Engine, and Intelligence endpoints",
    version="0.1.0",
)

# CORS Configuration — production-safe origins
_origins_env = os.getenv("FIXOPS_ALLOWED_ORIGINS", "")
_origins = [o.strip() for o in _origins_env.split(",") if o.strip()]
if not _origins:
    _origins = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
        "https://*.devinapps.com",
    ]
    logger.warning(
        "FIXOPS_ALLOWED_ORIGINS not set. Using default localhost origins. "
        "Set FIXOPS_ALLOWED_ORIGINS for production deployments."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ML Learning Middleware — captures all API traffic for anomaly detection
try:
    from core.learning_middleware import LearningMiddleware
    app.add_middleware(LearningMiddleware)
    logger.info("LearningMiddleware enabled on suite-core")
except ImportError:
    logger.debug("LearningMiddleware not available on suite-core")

# ---------------------------------------------------------------------------
# Mount routers — direct imports (always available)
# suite-core is on sys.path, so api.xxx resolves to suite-core/api/xxx.py
# ---------------------------------------------------------------------------
from api.nerve_center import router as nerve_center_router
from api.decisions import router as decisions_router
from api.deduplication_router import router as deduplication_router
from api.brain_router import router as brain_router
from api.mindsdb_router import router as ml_router
from api.autofix_router import router as autofix_router
from api.fuzzy_identity_router import router as fuzzy_identity_router
from api.exposure_case_router import router as exposure_case_router
from api.pipeline_router import router as pipeline_router

app.include_router(nerve_center_router, dependencies=[_auth_dep])
app.include_router(decisions_router, dependencies=[_auth_dep])
app.include_router(deduplication_router, dependencies=[_auth_dep])
app.include_router(brain_router, dependencies=[_auth_dep])
app.include_router(ml_router, dependencies=[_auth_dep])
app.include_router(autofix_router, dependencies=[_auth_dep])
app.include_router(fuzzy_identity_router, dependencies=[_auth_dep])
app.include_router(exposure_case_router, dependencies=[_auth_dep])
app.include_router(pipeline_router, dependencies=[_auth_dep])

# ---------------------------------------------------------------------------
# Mount routers — optional (may require heavy ML deps)
# Note: mpte, micro_pentest, vuln_discovery, secrets moved to suite-attack
# ---------------------------------------------------------------------------
_optional_routers = {
    "predictions_router": "Predictive Analytics",
    "llm_router": "LLM Configuration",
    "algorithmic_router": "Algorithmic Engines",
    "copilot_router": "Copilot Chat",
    "agents_router": "Copilot Agents",
    "intelligent_engine_routes": "Intelligent Security Engine",
    "llm_monitor_router": "LLM Monitor",
    "code_to_cloud_router": "Code-to-Cloud Tracer",
}

for module_name, display_name in _optional_routers.items():
    try:
        mod = importlib.import_module(f"api.{module_name}")
        _router: APIRouter = getattr(mod, "router")
        app.include_router(_router, dependencies=[_auth_dep])
        logger.info("Loaded %s router", display_name)
    except Exception as exc:
        logger.warning("%s router not available: %s", display_name, exc)

