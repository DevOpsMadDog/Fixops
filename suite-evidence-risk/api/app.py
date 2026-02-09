"""Suite-Evidence-Risk API Application.

Hosts all evidence collection, risk scoring, provenance, graph analysis,
and business context routers. Feeds have moved to suite-feeds.
"""

from __future__ import annotations

import logging
import os

from fastapi import Depends, FastAPI
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
    title="FixOps Suite-Evidence-Risk API",
    description="Evidence collection, risk scoring, provenance, and graph analysis endpoints",
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

# ML Learning Middleware
try:
    from core.learning_middleware import LearningMiddleware
    app.add_middleware(LearningMiddleware)
    logger.info("LearningMiddleware enabled on suite-evidence-risk")
except ImportError:
    logger.debug("LearningMiddleware not available on suite-evidence-risk")

# ---------------------------------------------------------------------------
# Mount routers — direct imports
# suite-evidence-risk is on sys.path, so api.xxx resolves correctly
# ---------------------------------------------------------------------------
from api.evidence_router import router as evidence_router
from api.provenance_router import router as provenance_router
from api.risk_router import router as risk_router
from api.graph_router import router as graph_router
from api.business_context import router as business_context_router
from api.business_context_enhanced import router as business_context_enhanced_router

app.include_router(evidence_router, dependencies=[_auth_dep])
app.include_router(provenance_router, dependencies=[_auth_dep])
app.include_router(risk_router, dependencies=[_auth_dep])
app.include_router(graph_router, dependencies=[_auth_dep])
app.include_router(business_context_router, dependencies=[_auth_dep])
app.include_router(business_context_enhanced_router, dependencies=[_auth_dep])

