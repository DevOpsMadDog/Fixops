"""
TrustGraph Migration Router for ALDECI.

Provides HTTP endpoints to trigger and monitor SQLite → TrustGraph migrations.

Endpoints:
    POST   /api/v1/trustgraph/migrate/all/{org_id}           — Run all migrations
    POST   /api/v1/trustgraph/migrate/{module}/{org_id}      — Run one module
    GET    /api/v1/trustgraph/migrate/status/{org_id}        — Per-module status
    GET    /api/v1/trustgraph/migrate/verify/{org_id}        — Count verification
    POST   /api/v1/trustgraph/migrate/rollback/{org_id}      — Rollback a module
    GET    /api/v1/trustgraph/migrate/health                  — Health check
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/trustgraph/migrate", tags=["trustgraph-migration"])

_VALID_MODULES = ["findings", "assets", "incidents", "compliance", "vendors", "threat_actors"]


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class MigrationStatusResponse(BaseModel):
    module_name: str
    records_migrated: int
    records_failed: int
    started_at: Optional[str]
    completed_at: Optional[str]
    status: str
    error: Optional[str] = None


class MigrationReportResponse(BaseModel):
    org_id: str
    modules: List[MigrationStatusResponse]
    total_migrated: int
    total_failed: int
    started_at: Optional[str]
    completed_at: Optional[str]
    overall_status: str


class VerificationModuleResult(BaseModel):
    module: str
    sqlite_count: int
    trustgraph_count: int
    match: bool


class VerificationReportResponse(BaseModel):
    org_id: str
    modules: List[VerificationModuleResult]
    verified_at: str
    all_match: bool


class RollbackRequest(BaseModel):
    module: str = Field(..., description="Module to roll back (e.g. 'findings')")


class RollbackResponse(BaseModel):
    org_id: str
    module: str
    status: str
    error: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    trustgraph: str
    valid_modules: List[str]


# ---------------------------------------------------------------------------
# Dependency: lazy-loaded migrator
# ---------------------------------------------------------------------------

_migrator_instance = None


def _get_migrator():
    global _migrator_instance
    if _migrator_instance is None:
        from core.trustgraph_migrator import TrustGraphMigrator
        _migrator_instance = TrustGraphMigrator()
    return _migrator_instance


def _status_to_dict(s) -> MigrationStatusResponse:
    return MigrationStatusResponse(
        module_name=s.module_name,
        records_migrated=s.records_migrated,
        records_failed=s.records_failed,
        started_at=s.started_at.isoformat() if s.started_at else None,
        completed_at=s.completed_at.isoformat() if s.completed_at else None,
        status=s.status,
        error=s.error,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/health", response_model=HealthResponse, summary="Migration service health check")
def migration_health() -> HealthResponse:
    """Check that the migrator and TrustGraph store are reachable."""
    try:
        migrator = _get_migrator()
        # Ping TrustGraph by calling core_stats on core 1
        migrator._store.core_stats(1)
        tg_status = "ok"
    except Exception as exc:
        logger.warning("TrustGraph health check failed: %s", exc)
        tg_status = f"error: {exc}"

    return HealthResponse(
        status="ok" if tg_status == "ok" else "degraded",
        trustgraph=tg_status,
        valid_modules=_VALID_MODULES,
    )


@router.post(
    "/all/{org_id}",
    response_model=MigrationReportResponse,
    summary="Run all migrations for an org",
)
def migrate_all(
    org_id: str = Path(..., description="Organisation ID"),
) -> MigrationReportResponse:
    """Execute all 6 module migrations sequentially and return a full report."""
    try:
        migrator = _get_migrator()
        report = migrator.migrate_all(org_id)
    except Exception as exc:
        logger.error("migrate_all failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return MigrationReportResponse(
        org_id=report.org_id,
        modules=[_status_to_dict(m) for m in report.modules],
        total_migrated=report.total_migrated,
        total_failed=report.total_failed,
        started_at=report.started_at.isoformat() if report.started_at else None,
        completed_at=report.completed_at.isoformat() if report.completed_at else None,
        overall_status=report.overall_status,
    )


@router.get(
    "/status/{org_id}",
    response_model=List[MigrationStatusResponse],
    summary="Get per-module migration status",
)
def get_migration_status(
    org_id: str = Path(..., description="Organisation ID"),
) -> List[MigrationStatusResponse]:
    """Return the current migration status for every module under the given org."""
    try:
        migrator = _get_migrator()
        statuses = migrator.get_migration_status(org_id)
    except Exception as exc:
        logger.error("get_migration_status failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return [_status_to_dict(s) for s in statuses]


@router.get(
    "/verify/{org_id}",
    response_model=VerificationReportResponse,
    summary="Verify SQLite counts match TrustGraph counts",
)
def verify_migration(
    org_id: str = Path(..., description="Organisation ID"),
) -> VerificationReportResponse:
    """Compare row counts in each SQLite source against TrustGraph entity counts."""
    try:
        migrator = _get_migrator()
        report = migrator.verify_migration(org_id)
    except Exception as exc:
        logger.error("verify_migration failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return VerificationReportResponse(
        org_id=report.org_id,
        modules=[
            VerificationModuleResult(
                module=m["module"],
                sqlite_count=m["sqlite_count"],
                trustgraph_count=m["trustgraph_count"],
                match=m["match"],
            )
            for m in report.modules
        ],
        verified_at=report.verified_at.isoformat(),
        all_match=report.all_match,
    )


@router.post(
    "/rollback/{org_id}",
    response_model=RollbackResponse,
    summary="Roll back a module migration",
)
def rollback_migration(
    org_id: str = Path(..., description="Organisation ID"),
    body: RollbackRequest = ...,
) -> RollbackResponse:
    """Soft-delete all TrustGraph entities that were created by the specified module migration."""
    module = body.module
    if module not in _VALID_MODULES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown module '{module}'. Valid: {_VALID_MODULES}",
        )

    try:
        migrator = _get_migrator()
        status = migrator.rollback_migration(org_id, module)
    except Exception as exc:
        logger.error("rollback_migration failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return RollbackResponse(
        org_id=org_id,
        module=module,
        status=status.status,
        error=status.error,
    )


# NOTE: This wildcard route MUST be declared last so that specific paths like
# /rollback/{org_id} and /status/{org_id} are matched first by FastAPI.
@router.post(
    "/{module}/{org_id}",
    response_model=MigrationStatusResponse,
    summary="Run a single module migration",
)
def migrate_module(
    module: str = Path(..., description="Module name: findings|assets|incidents|compliance|vendors|threat_actors"),
    org_id: str = Path(..., description="Organisation ID"),
) -> MigrationStatusResponse:
    """Migrate a single SQLite data source into TrustGraph."""
    if module not in _VALID_MODULES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown module '{module}'. Valid: {_VALID_MODULES}",
        )

    try:
        migrator = _get_migrator()
        fn = getattr(migrator, f"migrate_{module}")
        status = fn(org_id)
    except Exception as exc:
        logger.error("migrate_module(%s) failed: %s", module, exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return _status_to_dict(status)
