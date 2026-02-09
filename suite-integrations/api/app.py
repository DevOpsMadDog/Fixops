"""Suite-Integrations API Application.

Hosts all external integration routers: webhooks, IDE plugins,
IaC scanning, OSS tools, and third-party integrations.
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
    title="FixOps Suite-Integrations API",
    description="External integrations, webhooks, IDE plugins, IaC scanning, and OSS tools",
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
    logger.info("LearningMiddleware enabled on suite-integrations")
except ImportError:
    logger.debug("LearningMiddleware not available on suite-integrations")

# ---------------------------------------------------------------------------
# Mount routers
# ---------------------------------------------------------------------------
# suite-integrations is on sys.path; namespace-package `api` merges dirs.
from api.integrations_router import router as integrations_router
from api.webhooks_router import router as webhooks_router
from api.webhooks_router import receiver_router as webhooks_receiver_router
from api.iac_router import router as iac_router
from api.ide_router import router as ide_router
from api.oss_tools import router as oss_tools_router

app.include_router(integrations_router, dependencies=[_auth_dep])
app.include_router(iac_router, dependencies=[_auth_dep])
app.include_router(ide_router, dependencies=[_auth_dep])
app.include_router(oss_tools_router, dependencies=[_auth_dep])
app.include_router(webhooks_router, dependencies=[_auth_dep])
# Webhook receiver endpoints - NO API key required, uses signature verification
# External services (Jira, ServiceNow, GitLab, Azure DevOps) cannot provide FixOps API keys
app.include_router(webhooks_receiver_router)

