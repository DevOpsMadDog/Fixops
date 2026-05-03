"""Data Export Router — ALDECI.

Bulk export of security data in CSV or JSON format.

Prefix: /api/v1/export
Auth: api_key_auth dependency

Routes:
  GET /api/v1/export/alerts          ?format=csv|json&org_id=...
  GET /api/v1/export/vulnerabilities ?format=csv|json&org_id=...
  GET /api/v1/export/compliance      ?format=csv|json&org_id=...
  GET /api/v1/export/assets          ?format=csv|json&org_id=...
"""

from __future__ import annotations

import csv
import io
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterator, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/export",
    tags=["Data Export"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# DB path helpers (match each engine's _DEFAULT_DB convention)
# ---------------------------------------------------------------------------
_DATA_ROOT = Path(__file__).resolve().parents[3] / ".fixops_data"


def _alert_db_path() -> str:
    return str(_DATA_ROOT / "alert_triage.db")


def _vuln_db_path() -> str:
    return str(_DATA_ROOT / "vuln_scan.db")


def _asset_db_path() -> str:
    return str(_DATA_ROOT / "asset_inventory.db")


def _compliance_db_path(org_id: str) -> str:
    return str(_DATA_ROOT / f"{org_id}_cloud_compliance.db")


# ---------------------------------------------------------------------------
# Low-level SQLite fetch helpers
# ---------------------------------------------------------------------------

def _fetch_rows(db_path: str, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Return all rows from a SQLite query as a list of dicts.

    Returns empty list if the DB file does not exist yet.
    """
    if not Path(db_path).exists():
        return []
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(query, params)
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except sqlite3.Error as exc:
        _logger.warning("export: SQLite error reading %s: %s", db_path, exc)
        return []


# ---------------------------------------------------------------------------
# CSV / JSON serialisation helpers
# ---------------------------------------------------------------------------

def _rows_to_csv(rows: List[Dict[str, Any]], columns: List[str]) -> str:
    """Serialise rows to a RFC-4180-compliant CSV string."""
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=columns,
        extrasaction="ignore",
        lineterminator="\r\n",
        quoting=csv.QUOTE_ALL,
    )
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def _streaming_json(rows: List[Dict[str, Any]]) -> Iterator[str]:
    """Yield a JSON array incrementally — one row at a time — for large datasets."""
    yield "[\n"
    for i, row in enumerate(rows):
        comma = ",\n" if i < len(rows) - 1 else "\n"
        yield json.dumps(row, default=str) + comma
    yield "]\n"


def _make_response(
    rows: List[Dict[str, Any]],
    columns: List[str],
    fmt: str,
    filename_stem: str,
) -> StreamingResponse:
    """Build a StreamingResponse for CSV or JSON depending on *fmt*."""
    fmt = fmt.lower()
    if fmt not in ("csv", "json"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format '{fmt}'. Use 'csv' or 'json'.",
        )

    if fmt == "csv":
        content = _rows_to_csv(rows, columns)
        return StreamingResponse(
            iter([content]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename_stem}.csv"',
                "X-Record-Count": str(len(rows)),
            },
        )

    # JSON streaming
    return StreamingResponse(
        _streaming_json(rows),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename_stem}.json"',
            "X-Record-Count": str(len(rows)),
        },
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

_ALERT_COLUMNS = [
    "id", "org_id", "title", "source_system", "severity", "priority",
    "status", "assigned_to", "triage_notes", "escalation_reason",
    "ingested_at", "triaged_at", "resolved_at",
]

_VULN_COLUMNS = [
    "id", "org_id", "scan_id", "cve_id", "title", "severity", "cvss_score",
    "finding_status", "affected_asset", "plugin_id", "description",
    "remediation", "detected_at", "resolved_at",
]

_COMPLIANCE_COLUMNS = [
    "id", "org_id", "assessment_id", "control_id", "control_name",
    "section", "severity", "status", "evidence", "resource_id",
    "resource_type",
]

_ASSET_COLUMNS = [
    "id", "org_id", "name", "asset_type", "hostname", "ip_address",
    "cloud_provider", "region", "owner_email", "owner_name", "team",
    "business_unit", "criticality", "criticality_tier", "data_classification",
    "environment", "lifecycle", "risk_score", "finding_count",
    "first_discovered", "last_seen",
]


@router.get("/alerts")
def export_alerts(
    org_id: str = Query("default", description="Organization ID"),
    format: str = Query("csv", description="Export format: csv or json"),
    severity: str = Query(None, description="Filter by severity"),
    status: str = Query(None, description="Filter by status"),
) -> StreamingResponse:
    """Export all alerts for an org as CSV or JSON download.

    Optional filters: severity (critical|high|medium|low|info),
    status (new|triaging|escalated|investigating|resolved|false_positive|duplicate).
    """
    query = "SELECT * FROM at_alerts WHERE org_id = ?"
    params: list = [org_id]
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY ingested_at DESC"

    rows = _fetch_rows(_alert_db_path(), query, tuple(params))
    # Exclude raw_alert_json (large/internal) from export columns
    return _make_response(rows, _ALERT_COLUMNS, format, f"alerts_{org_id}")


@router.get("/vulnerabilities")
def export_vulnerabilities(
    org_id: str = Query("default", description="Organization ID"),
    format: str = Query("csv", description="Export format: csv or json"),
    severity: str = Query(None, description="Filter by severity"),
    finding_status: str = Query(None, description="Filter by finding_status"),
) -> StreamingResponse:
    """Export all vulnerability findings for an org as CSV or JSON download.

    Optional filters: severity (critical|high|medium|low|info),
    finding_status (open|in_progress|remediated|accepted|false_positive).
    """
    query = "SELECT * FROM vuln_findings WHERE org_id = ?"
    params: list = [org_id]
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if finding_status:
        query += " AND finding_status = ?"
        params.append(finding_status)
    query += " ORDER BY detected_at DESC"

    rows = _fetch_rows(_vuln_db_path(), query, tuple(params))
    return _make_response(rows, _VULN_COLUMNS, format, f"vulnerabilities_{org_id}")


@router.get("/compliance")
def export_compliance(
    org_id: str = Query("default", description="Organization ID"),
    format: str = Query("csv", description="Export format: csv or json"),
    framework: str = Query(None, description="Filter by compliance framework"),
    status: str = Query(None, description="Filter control status"),
) -> StreamingResponse:
    """Export compliance control results for an org as CSV or JSON download.

    Optional filters: framework (CIS_AWS|NIST_800_53|SOC2|PCI_DSS|ISO_27001|GDPR),
    status (passed|failed|not_applicable|manual_check).
    """
    query = "SELECT * FROM control_results WHERE org_id = ?"
    params: list = [org_id]
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY rowid DESC"

    rows = _fetch_rows(_compliance_db_path(org_id), query, tuple(params))

    # Apply framework filter via JOIN on assessments if requested
    if framework and rows:
        # Fetch assessment IDs that match the requested framework
        asmts = _fetch_rows(
            _compliance_db_path(org_id),
            "SELECT id FROM compliance_assessments WHERE org_id = ? AND framework = ?",
            (org_id, framework),
        )
        allowed_ids = {a["id"] for a in asmts}
        rows = [r for r in rows if r.get("assessment_id") in allowed_ids]

    return _make_response(rows, _COMPLIANCE_COLUMNS, format, f"compliance_{org_id}")


@router.get("/dashboard")
def export_dashboard(
    org_id: str = Query("default", description="Organization ID"),
    format: str = Query("json", description="Export format: csv or json"),
) -> StreamingResponse:
    """Export a dashboard summary for an org — alert/vuln/asset counts by severity.

    Returns one row per severity tier (critical, high, medium, low, info) with
    the counts of alerts, open vulnerabilities, and assets at that tier.
    Useful for executive reporting and automated compliance evidence.
    """
    # Fetch raw rows from each domain DB
    alert_rows = _fetch_rows(
        _alert_db_path(),
        "SELECT severity, COUNT(*) AS cnt FROM at_alerts WHERE org_id = ? GROUP BY severity",
        (org_id,),
    )
    vuln_rows = _fetch_rows(
        _vuln_db_path(),
        "SELECT severity, COUNT(*) AS cnt FROM vuln_findings WHERE org_id = ? AND finding_status = 'open' GROUP BY severity",
        (org_id,),
    )
    asset_rows = _fetch_rows(
        _asset_db_path(),
        "SELECT criticality AS severity, COUNT(*) AS cnt FROM managed_assets WHERE org_id = ? GROUP BY criticality",
        (org_id,),
    )

    # Aggregate by severity tier
    TIERS = ["critical", "high", "medium", "low", "info"]
    alert_by_sev = {r["severity"]: r["cnt"] for r in alert_rows}
    vuln_by_sev = {r["severity"]: r["cnt"] for r in vuln_rows}
    asset_by_sev = {r["severity"]: r["cnt"] for r in asset_rows}

    summary_rows = [
        {
            "org_id": org_id,
            "severity": tier,
            "alert_count": alert_by_sev.get(tier, 0),
            "open_vuln_count": vuln_by_sev.get(tier, 0),
            "asset_count": asset_by_sev.get(tier, 0),
        }
        for tier in TIERS
    ]

    _DASHBOARD_COLUMNS = [
        "org_id", "severity", "alert_count", "open_vuln_count", "asset_count",
    ]
    return _make_response(summary_rows, _DASHBOARD_COLUMNS, format, f"dashboard_{org_id}")


@router.get("/assets")
def export_assets(
    org_id: str = Query("default", description="Organization ID"),
    format: str = Query("csv", description="Export format: csv or json"),
    asset_type: str = Query(None, description="Filter by asset type"),
    criticality: str = Query(None, description="Filter by criticality"),
    environment: str = Query(None, description="Filter by environment"),
) -> StreamingResponse:
    """Export asset inventory for an org as CSV or JSON download.

    Optional filters: asset_type, criticality (critical|high|medium|low),
    environment (production|staging|development|test).
    """
    query = "SELECT * FROM managed_assets WHERE org_id = ?"
    params: list = [org_id]
    if asset_type:
        query += " AND asset_type = ?"
        params.append(asset_type)
    if criticality:
        query += " AND criticality = ?"
        params.append(criticality)
    if environment:
        query += " AND environment = ?"
        params.append(environment)
    query += " ORDER BY last_seen DESC"

    rows = _fetch_rows(_asset_db_path(), query, tuple(params))
    return _make_response(rows, _ASSET_COLUMNS, format, f"assets_{org_id}")
