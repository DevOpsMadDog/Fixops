"""Cross-domain analytics engine API endpoints — ALDECI.

Exposes DuckDB-powered cross-domain analytics over all SQLite domain databases.
Auth is injected by app.py via ``app.include_router(..., dependencies=[...])``.

Prefix: /api/v1/analytics-engine
Tags:   analytics-engine
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.duckdb_analytics_engine import AnalyticsEngine
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(
    prefix="/api/v1/analytics-engine",
    tags=["analytics-engine"],
)

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = AnalyticsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/summary",
    summary="Cross-domain risk summary",
    description=(
        "Unified risk picture from posture_score, risk_register, "
        "digital_forensics, and threat_hunting domain databases."
    ),
)
def get_risk_summary(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return cross-domain risk summary for the given org."""
    try:
        return _get_engine().cross_domain_risk_summary(org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/asset-vuln",
    summary="Asset-vulnerability correlation",
    description=(
        "Cross-join asset_inventory with risk_register on asset_id. "
        "Returns top 20 assets ordered by risk score descending."
    ),
)
def get_asset_vuln_correlation(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[Dict[str, Any]]:
    """Return asset-vulnerability correlations."""
    try:
        return _get_engine().asset_vulnerability_correlation(org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/threat-ioc",
    summary="Threat IOC correlation",
    description=(
        "Search for an IOC across threat_feed_aggregator and threat_hunting "
        "databases. Returns hit counts and correlation status."
    ),
)
def get_threat_ioc_correlation(
    org_id: str = Query("default", description="Organisation identifier"),
    ioc: str = Query(..., description="Indicator of compromise (IP, domain, hash, URL)"),
) -> Dict[str, Any]:
    """Search for IOC across all threat databases."""
    if not ioc or not ioc.strip():
        raise HTTPException(status_code=422, detail="ioc must not be empty")
    try:
        return _get_engine().threat_intel_correlation(org_id, ioc.strip())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/compliance-trend",
    summary="Compliance posture trend",
    description=(
        "Last 10 compliance scan results from compliance_scanner.db, "
        "ordered newest first."
    ),
)
def get_compliance_trend(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[Dict[str, Any]]:
    """Return compliance posture trend data."""
    try:
        return _get_engine().compliance_posture_trend(org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/executive",
    summary="Executive dashboard data",
    description=(
        "Aggregate view across ALL available domains: posture score, "
        "open incidents, critical vulns, active threats, compliance avg."
    ),
)
def get_executive_dashboard(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return aggregated CISO executive dashboard data."""
    try:
        return _get_engine().executive_dashboard_data(org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/domains",
    summary="List available domain databases",
    description="Scan the data directory and return all detected *.db domain files.",
)
def get_available_domains() -> List[Dict[str, Any]]:
    """List all domain databases found in data_dir."""
    try:
        return _get_engine().list_available_domains()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/query",
    summary="Run custom domain query",
    description=(
        "Execute SELECT * from any domain database table with optional WHERE clause. "
        "db and table names are validated against [a-z_]+ to prevent path traversal."
    ),
)
def run_custom_query(
    db: str = Query(..., description="Database name without .db extension (e.g. posture_score)"),
    table: str = Query(..., description="Table name to query"),
    where: Optional[str] = Query(None, description="Optional SQL WHERE clause"),
    limit: int = Query(50, ge=1, le=1000, description="Maximum rows (1-1000)"),
) -> List[Dict[str, Any]]:
    """Run a custom query against a domain database."""
    try:
        return _get_engine().run_custom_query(
            db_name=db,
            table_name=table,
            where_clause=where or "",
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
