"""Suite-Attack API Application.

Hosts all offensive security routers: micro penetration testing,
vulnerability discovery, secrets scanning, and MPTE/MPTE integration.
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
    title="FixOps Suite-Attack API",
    description="Offensive security: MPTE, micro-pentest, vuln discovery, secrets scanning",
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
    logger.info("LearningMiddleware enabled on suite-attack")
except ImportError:
    logger.debug("LearningMiddleware not available on suite-attack")

# ---------------------------------------------------------------------------
# Mount routers — all optional (may require heavy deps)
# ---------------------------------------------------------------------------
_attack_routers = {
    "mpte_router": "MPTE (MPTE Enhanced)",
    "micro_pentest_router": "Micro Pentest",
    "vuln_discovery_router": "Vulnerability Discovery",
    "secrets_router": "Secrets Scanner",
    "attack_sim_router": "Attack Simulation (BAS)",
    "sast_router": "SAST Scanner",
    "container_router": "Container Scanner",
    "dast_router": "DAST Scanner",
    "cspm_router": "CSPM Scanner",
    "api_fuzzer_router": "API Fuzzer",
    "malware_router": "Malware Detector",
}

for module_name, display_name in _attack_routers.items():
    try:
        # suite-attack is on sys.path, so api.module_name resolves to suite-attack/api/module_name.py
        mod = importlib.import_module(f"api.{module_name}")
        _router: APIRouter = getattr(mod, "router")
        app.include_router(_router, dependencies=[_auth_dep])
        logger.info("Loaded %s router", display_name)
    except Exception as exc:
        logger.warning("%s router not available: %s", display_name, exc)

# Enterprise reachability analysis (lives in suite-evidence-risk/risk/reachability/)
try:
    from risk.reachability.api import router as reachability_router

    app.include_router(reachability_router, dependencies=[_auth_dep])
    logger.info("Loaded Reachability Analysis router")
except ImportError as exc:
    logger.warning("Reachability router not available: %s", exc)

