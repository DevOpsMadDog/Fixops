"""Deployment Router — health, status, initialization, and configuration endpoints.

Routes:
    GET  /api/v1/deployment/health      — Aggregate health check (all services)
    GET  /api/v1/deployment/status      — Full deployment status snapshot
    POST /api/v1/deployment/initialize  — Run first-boot initialization (idempotent)
    GET  /api/v1/deployment/config      — Current configuration (sanitized, no secrets)

All endpoints require a valid API key via _verify_api_key dependency (imported
from app.py — same pattern as kpi_router, connector_routes, etc.).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/deployment", tags=["Deployment"])

# ─── Lazy manager import (avoids circular deps at module load time) ───────────

def _get_manager():
    from core.deployment_manager import get_deployment_manager  # type: ignore
    return get_deployment_manager()


# ─── GET /api/v1/deployment/health ───────────────────────────────────────────

@router.get(
    "/health",
    summary="Aggregate health check",
    description=(
        "Check all ALDECI services concurrently: API (HTTP /health), "
        "UI (HTTP /nginx-health), TrustGraph (HTTP /api/v1/health), "
        "Redis (PING), Postgres (SELECT 1). Returns aggregate status."
    ),
    response_model=None,
)
async def get_deployment_health(request: Request) -> JSONResponse:
    """Return aggregate health across all services.

    Status codes:
    - 200: healthy or degraded (required services up, optional may be down)
    - 503: unavailable (at least one required service is down)
    """
    try:
        manager = _get_manager()
        health = await manager.aggregate_health()
        payload = health.as_dict()
        status_code = 200 if health.status in ("healthy", "degraded") else 503
        return JSONResponse(content=payload, status_code=status_code)
    except Exception as exc:
        logger.error("deployment health check failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Health check error: {exc}") from exc


# ─── GET /api/v1/deployment/status ───────────────────────────────────────────

@router.get(
    "/status",
    summary="Full deployment status",
    description=(
        "Returns overall deployment health, uptime, version, feature flags, "
        "enabled modules, and migration version."
    ),
    response_model=None,
)
async def get_deployment_status(request: Request) -> JSONResponse:
    """Return full deployment status snapshot."""
    try:
        manager = _get_manager()
        status = await manager.get_deployment_status()
        return JSONResponse(content=status.as_dict())
    except Exception as exc:
        logger.error("deployment status failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Status error: {exc}") from exc


# ─── POST /api/v1/deployment/initialize ──────────────────────────────────────

@router.post(
    "/initialize",
    summary="Run first-boot initialization",
    description=(
        "Idempotent first-boot sequence: apply database migrations, seed initial "
        "admin user, create default configuration, register services, and index "
        "entities into TrustGraph. Safe to re-run — already-complete steps are skipped."
    ),
    response_model=None,
)
async def initialize_deployment(request: Request) -> JSONResponse:
    """Run the first-boot initialization sequence."""
    try:
        manager = _get_manager()
        result = await manager.initialize_first_boot()
        status_code = 200 if result.get("status") in ("initialized", "already_initialized") else 207
        return JSONResponse(content=result, status_code=status_code)
    except Exception as exc:
        logger.error("deployment initialization failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Initialization error: {exc}") from exc


# ─── GET /api/v1/deployment/config ───────────────────────────────────────────

@router.get(
    "/config",
    summary="Current configuration (sanitized)",
    description=(
        "Returns current deployment configuration with all secrets redacted. "
        "Shows mode, version, data directory, LLM provider availability, "
        "feature flags, and enabled modules."
    ),
    response_model=None,
)
async def get_deployment_config(request: Request) -> JSONResponse:
    """Return sanitized configuration — no passwords or API keys exposed."""
    try:
        manager = _get_manager()
        config = manager.get_sanitized_config()
        return JSONResponse(content=config)
    except Exception as exc:
        logger.error("deployment config failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Config error: {exc}") from exc


# ─── GET /api/v1/deployment/migrations ───────────────────────────────────────

@router.get(
    "/migrations",
    summary="Migration history",
    description="Returns list of applied database migrations with version, name, and timestamp.",
    response_model=None,
)
async def get_migration_history(request: Request) -> JSONResponse:
    """Return migration history."""
    try:
        manager = _get_manager()
        history = manager.get_migration_history()
        return JSONResponse(content={
            "migrations": [
                {
                    "version": m.version,
                    "name": m.name,
                    "applied_at": m.applied_at,
                    "checksum": m.checksum,
                }
                for m in history
            ],
            "total": len(history),
        })
    except Exception as exc:
        logger.error("migration history failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Migration history error: {exc}") from exc


# ─── GET /api/v1/deployment/services ─────────────────────────────────────────

@router.get(
    "/services",
    summary="Service discovery",
    description="Detect which services are available and update the service registry.",
    response_model=None,
)
async def discover_services(request: Request) -> JSONResponse:
    """Run service discovery and return current registry."""
    try:
        manager = _get_manager()
        result = await manager.discover_services()
        return JSONResponse(content=result)
    except Exception as exc:
        logger.error("service discovery failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Service discovery error: {exc}") from exc


# ─── GET /api/v1/deployment/validate ─────────────────────────────────────────

@router.get(
    "/validate",
    summary="Validate configuration",
    description=(
        "Check environment variables, port availability, database connectivity, "
        "and data directory permissions."
    ),
    response_model=None,
)
async def validate_configuration(request: Request) -> JSONResponse:
    """Validate deployment configuration and return any issues."""
    try:
        manager = _get_manager()
        result = await manager.validate_configuration()
        status_code = 200 if result.get("status") == "ok" else 422
        return JSONResponse(content=result, status_code=status_code)
    except Exception as exc:
        logger.error("configuration validation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Validation error: {exc}") from exc
