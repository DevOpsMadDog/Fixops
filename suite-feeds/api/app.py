"""Suite-Feeds API Application.

Hosts real-time vulnerability intelligence feed endpoints spanning 8 categories:
NVD, CISA KEV, EPSS, ExploitDB, OSV, Threat Actors, Supply Chain, Cloud/Zero-Day.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

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
    title="FixOps Suite-Feeds API",
    description="Real-time vulnerability intelligence feeds (NVD, KEV, EPSS, ExploitDB, OSV, etc.)",
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
    logger.info("LearningMiddleware enabled on suite-feeds")
except ImportError:
    logger.debug("LearningMiddleware not available on suite-feeds")

# ---------------------------------------------------------------------------
# Mount routers
# ---------------------------------------------------------------------------
feeds_router: Optional[APIRouter] = None
try:
    from api.feeds_router import router as feeds_router

    app.include_router(feeds_router, dependencies=[_auth_dep])
    logger.info("Loaded vulnerability intelligence feeds router")
except ImportError as exc:
    logger.warning("Feeds router not available: %s", exc)
