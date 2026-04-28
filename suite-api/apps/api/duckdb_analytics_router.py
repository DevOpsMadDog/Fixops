"""DuckDB Analytics Router — exposes AnalyticsEngine cross-domain queries.

Endpoints
---------
GET  /api/v1/duckdb-analytics/risk-summary                  Cross-domain risk summary.
GET  /api/v1/duckdb-analytics/asset-vulnerability           Asset+risk join (top 20).
GET  /api/v1/duckdb-analytics/threat-intel-correlation      Search IOC across threat DBs.
GET  /api/v1/duckdb-analytics/compliance-trend              Last 10 compliance scans.
GET  /api/v1/duckdb-analytics/executive-dashboard           Aggregated CISO view.
GET  /api/v1/duckdb-analytics/domains                       List available DB domains.
POST /api/v1/duckdb-analytics/custom-query                  Safe parameterised query.
GET  /api/v1/duckdb-analytics/health                        Liveness probe.
GET  /api/v1/duckdb-analytics/status                        Status alias.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth
except Exception:  # pragma: no cover
    def api_key_auth() -> None:  # type: ignore
        return None

logger = structlog.get_logger(__name__)
_stdlib_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/duckdb-analytics",
    tags=["DuckDB Analytics"],
    dependencies=[Depends(api_key_auth)],
)

_engine_singleton = None


def _engine():
    global _engine_singleton
    if _engine_singleton is None:
        from core.duckdb_analytics_engine import AnalyticsEngine

        _engine_singleton = AnalyticsEngine()
    return _engine_singleton


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CustomQueryRequest(BaseModel):
    db_name: str = Field(..., min_length=1, max_length=64)
    table_name: str = Field(..., min_length=1, max_length=64)
    where_clause: str = Field(default="", max_length=2048)
    limit: int = Field(default=100, ge=1, le=1000)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/risk-summary")
def risk_summary(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    try:
        return _engine().cross_domain_risk_summary(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("duckdb.risk_summary_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"risk_summary_failure: {exc}")


@router.get("/asset-vulnerability")
def asset_vulnerability(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> List[Dict[str, Any]]:
    try:
        return _engine().asset_vulnerability_correlation(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("duckdb.asset_vuln_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"asset_vulnerability_failure: {exc}")


@router.get("/threat-intel-correlation")
def threat_intel_correlation(
    org_id: str = Query(..., min_length=1, max_length=128),
    ioc: str = Query(..., min_length=1, max_length=512),
) -> Dict[str, Any]:
    try:
        return _engine().threat_intel_correlation(org_id=org_id, ioc=ioc)
    except Exception as exc:  # pragma: no cover
        logger.exception("duckdb.threat_intel_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"threat_intel_failure: {exc}")


@router.get("/compliance-trend")
def compliance_trend(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> List[Dict[str, Any]]:
    try:
        return _engine().compliance_posture_trend(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("duckdb.compliance_trend_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"compliance_trend_failure: {exc}")


@router.get("/executive-dashboard")
def executive_dashboard(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    try:
        return _engine().executive_dashboard_data(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("duckdb.executive_dashboard_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"executive_dashboard_failure: {exc}")


@router.get("/domains")
def domains() -> List[Dict[str, Any]]:
    try:
        return _engine().list_available_domains()
    except Exception as exc:  # pragma: no cover
        logger.exception("duckdb.domains_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"domains_failure: {exc}")


@router.post("/custom-query")
def custom_query(body: CustomQueryRequest) -> List[Dict[str, Any]]:
    try:
        return _engine().run_custom_query(
            db_name=body.db_name,
            table_name=body.table_name,
            where_clause=body.where_clause,
            limit=body.limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("duckdb.custom_query_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"custom_query_failure: {exc}")


@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "engine": "duckdb_analytics"}


@router.get("/status")
def status() -> Dict[str, Any]:
    return {"status": "ok", "engine": "duckdb_analytics", "ready": True}


__all__ = ["router"]
