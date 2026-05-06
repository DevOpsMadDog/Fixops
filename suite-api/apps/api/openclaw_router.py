"""OpenClaw Autonomous Pentest Swarm Router — ALDECI.

Endpoints:
  GET    /api/v1/openclaw/campaigns                         list_campaigns
  POST   /api/v1/openclaw/campaigns                         create_campaign
  GET    /api/v1/openclaw/campaigns/{id}                    get_campaign
  POST   /api/v1/openclaw/campaigns/{id}/start              start_campaign
  POST   /api/v1/openclaw/campaigns/{id}/advance            advance_phase
  POST   /api/v1/openclaw/campaigns/{id}/pause              pause_campaign
  POST   /api/v1/openclaw/campaigns/{id}/complete           complete_campaign
  GET    /api/v1/openclaw/campaigns/{id}/tasks              list_tasks
  GET    /api/v1/openclaw/findings                          list_findings
  PATCH  /api/v1/openclaw/findings/{id}/status              update_finding_status
  GET    /api/v1/openclaw/stats                             get_stats

  # Self-testing (ALDECI pentests itself)
  POST   /api/v1/openclaw/scan                             start_self_scan
  GET    /api/v1/openclaw/results                          list_scan_results
  GET    /api/v1/openclaw/status                           get_scan_status
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "openclaw_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.openclaw_engine import OpenClawEngine, get_openclaw_engine

logger = logging.getLogger(__name__)

_SIMULATION_WARNING = {
    "is_simulated": True,
    "engine": "openclaw_engine",
    "real_integration_required": "/api/v1/connectors/pentest/configure",
    "do_not_use_in_demo": True,
}

router = APIRouter(
    prefix="/api/v1/openclaw",
    tags=["openclaw"],
    dependencies=_AUTH_DEP,
)

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")
    campaign_type: str = Field(
        default="network_pentest",
        description="network_pentest|web_app|cloud_security|social_engineering|physical_access|full_red_team",
    )
    target_scope: List[str] = Field(default_factory=list)
    attack_tactics: List[str] = Field(default_factory=list)
    operators_count: int = Field(default=3, ge=1, le=5)
    authorization_token: str = Field(
        ...,
        min_length=1,
        description="Required authorization token confirming written approval for this pentest",
    )
    authorized_by: str = Field(default="")
    authorized_until: str = Field(default="")


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., description="open|accepted|remediated")


# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------

_engines: Dict[str, OpenClawEngine] = {}


def _get_engine(org_id: str) -> OpenClawEngine:
    if org_id not in _engines:
        _engines[org_id] = get_openclaw_engine(org_id)
    return _engines[org_id]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/campaigns")
def list_campaigns(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    campaign_type: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List pentest campaigns for an org."""
    engine = _get_engine(org_id)
    return engine.list_campaigns(org_id, status=status, campaign_type=campaign_type)


@router.post("/campaigns", status_code=201)
def create_campaign(
    body: CampaignCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Create a new pentest campaign. Requires authorization_token."""
    engine = _get_engine(org_id)
    try:
        return engine.create_campaign(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/campaigns/{campaign_id}")
def get_campaign(
    campaign_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a campaign with tasks, findings, and operators."""
    engine = _get_engine(org_id)
    result = engine.get_campaign(org_id, campaign_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
    return result


@router.post("/campaigns/{campaign_id}/start")
def start_campaign(
    campaign_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Start a staged campaign — queues and simulates initial tasks."""
    engine = _get_engine(org_id)
    try:
        return engine.start_campaign(org_id, campaign_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/campaigns/{campaign_id}/advance")
def advance_phase(
    campaign_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Advance the campaign to the next MITRE ATT&CK phase."""
    engine = _get_engine(org_id)
    try:
        result = engine.advance_phase(org_id, campaign_id)
        return {"data": result, "_simulation_warning": _SIMULATION_WARNING}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/campaigns/{campaign_id}/pause")
def pause_campaign(
    campaign_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Pause a running campaign."""
    engine = _get_engine(org_id)
    try:
        return engine.pause_campaign(org_id, campaign_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/campaigns/{campaign_id}/complete")
def complete_campaign(
    campaign_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Complete a campaign and calculate final risk score."""
    engine = _get_engine(org_id)
    try:
        return engine.complete_campaign(org_id, campaign_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/campaigns/{campaign_id}/tasks")
def list_tasks(
    campaign_id: str,
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List tasks for a campaign, optionally filtered by status."""
    engine = _get_engine(org_id)
    return engine.list_tasks(org_id, campaign_id, status=status)


@router.get("/findings")
def list_findings(
    org_id: str = Query(default="default"),
    campaign_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List findings across all campaigns or filtered by campaign/severity."""
    engine = _get_engine(org_id)
    return engine.list_findings(org_id, campaign_id=campaign_id, severity=severity)


@router.patch("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: str,
    body: FindingStatusUpdate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Update a finding's status (open → accepted → remediated)."""
    engine = _get_engine(org_id)
    try:
        return engine.update_finding_status(org_id, finding_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/stats")
def get_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Aggregate pentest stats for an org."""
    engine = _get_engine(org_id)
    return engine.get_stats(org_id)


# ---------------------------------------------------------------------------
# Self-testing — ALDECI pentests itself
# ---------------------------------------------------------------------------

# In-memory store for autonomous scan runs (keyed by scan_id)
_scan_store: Dict[str, Dict[str, Any]] = {}
_scan_store_lock = threading.Lock()

_SELF_TEST_AUTH_TOKEN = "ALDECI-SELF-PENTEST-AUTHORIZED"
_SELF_TEST_ORG = "aldeci_self"
_SELF_TEST_SCOPE = [
    "localhost:8000",
    "127.0.0.1:8000",
    "/api/v1",
]
_OWASP_TOP10_TACTICS = [
    "A01:BrokenAccessControl",
    "A02:CryptographicFailures",
    "A03:Injection",
    "A04:InsecureDesign",
    "A05:SecurityMisconfiguration",
    "A06:VulnerableComponents",
    "A07:AuthFailures",
    "A08:IntegrityFailures",
    "A09:LoggingFailures",
    "A10:SSRF",
]


class SelfScanRequest(BaseModel):
    target_url: str = Field(
        default="http://localhost:8000",
        description="Base URL of ALDECI to pentest. Defaults to localhost self-test.",
    )
    campaign_type: str = Field(
        default="web_app",
        description="OpenClaw campaign type — web_app runs OWASP Top 10 checks.",
    )
    operators_count: int = Field(default=3, ge=1, le=5)
    run_owasp_checks: bool = Field(
        default=True,
        description="When True, also runs auto_pentest OWASP Top 10 probes against the target.",
    )


def _run_owasp_async(scan_id: str, target_url: str) -> None:
    """Background thread: run auto_pentest OWASP probes and store results."""
    try:
        from core.auto_pentest import get_auto_pentest  # type: ignore[import]

        engine = get_auto_pentest()
        results = engine.run_all(target_url)
        report = engine.generate_report(results)

        with _scan_store_lock:
            if scan_id in _scan_store:
                _scan_store[scan_id]["owasp_report"] = report
                _scan_store[scan_id]["owasp_status"] = "completed"
                _scan_store[scan_id]["owasp_total_probes"] = report["summary"]["total_probes"]
                _scan_store[scan_id]["owasp_vulnerable_count"] = report["summary"]["vulnerable"]
    except Exception as exc:  # noqa: BLE001 — best-effort background task
        logger.warning("openclaw self-scan owasp probes failed for %s: %s", scan_id, exc)
        with _scan_store_lock:
            if scan_id in _scan_store:
                _scan_store[scan_id]["owasp_status"] = "failed"
                _scan_store[scan_id]["owasp_error"] = str(exc)


@router.post("/scan", status_code=202)
def start_self_scan(
    body: SelfScanRequest,
    org_id: str = Query(default=_SELF_TEST_ORG),
) -> Dict[str, Any]:
    """Start an autonomous pentest of ALDECI itself.

    Creates an OpenClaw web_app campaign targeting ALDECI's own API endpoints,
    runs MITRE ATT&CK-mapped tasks via the swarm operators, and optionally
    fires OWASP Top 10 probes via auto_pentest in the background.

    Returns a scan_id that can be polled via GET /api/v1/openclaw/status.
    """
    scan_id = f"self-scan-{uuid4().hex[:12]}"
    started_at = datetime.now(timezone.utc).isoformat()

    engine = _get_engine(org_id)

    # Create the OpenClaw campaign
    campaign_data: Dict[str, Any] = {
        "name": f"ALDECI Self-Pentest {scan_id}",
        "description": f"Autonomous OWASP + MITRE ATT&CK pentest of ALDECI API at {body.target_url}",
        "campaign_type": body.campaign_type if body.campaign_type in (
            "network_pentest", "web_app", "cloud_security",
            "social_engineering", "physical_access", "full_red_team"
        ) else "web_app",
        "target_scope": [body.target_url] + _SELF_TEST_SCOPE,
        "attack_tactics": _OWASP_TOP10_TACTICS,
        "operators_count": body.operators_count,
        "authorization_token": _SELF_TEST_AUTH_TOKEN,
        "authorized_by": "ALDECI-SYSTEM",
        "authorized_until": "2099-12-31",
    }

    try:
        campaign = engine.create_campaign(org_id, campaign_data)
        campaign_id = campaign["id"]
        start_result = engine.start_campaign(org_id, campaign_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    scan_record: Dict[str, Any] = {
        "scan_id": scan_id,
        "org_id": org_id,
        "campaign_id": campaign_id,
        "target_url": body.target_url,
        "started_at": started_at,
        "status": "running",
        "tasks_queued": start_result.get("tasks_queued", 0),
        "owasp_status": "pending" if body.run_owasp_checks else "skipped",
        "owasp_report": None,
        "owasp_total_probes": 0,
        "owasp_vulnerable_count": 0,
    }

    with _scan_store_lock:
        _scan_store[scan_id] = scan_record

    # Fire OWASP probes in background thread (non-blocking)
    if body.run_owasp_checks:
        t = threading.Thread(
            target=_run_owasp_async,
            args=(scan_id, body.target_url),
            daemon=True,
        )
        t.start()

    logger.info("openclaw self-scan started: %s campaign=%s", scan_id, campaign_id)
    return {
        "scan_id": scan_id,
        "campaign_id": campaign_id,
        "status": "running",
        "started_at": started_at,
        "tasks_queued": start_result.get("tasks_queued", 0),
        "owasp_checks": body.run_owasp_checks,
        "message": "Self-pentest started. Poll GET /api/v1/openclaw/status?scan_id={scan_id} for results.",
    }


@router.get("/results")
def list_scan_results(
    org_id: str = Query(default=_SELF_TEST_ORG),
    limit: int = Query(default=20, ge=1, le=100),
) -> Dict[str, Any]:
    """List all autonomous self-pentest scan runs for an org.

    Returns summary of each scan including OpenClaw campaign findings and
    OWASP probe results where available.
    """
    with _scan_store_lock:
        all_scans = [
            v for v in _scan_store.values() if v.get("org_id") == org_id
        ]

    # Sort newest first
    all_scans.sort(key=lambda s: s.get("started_at", ""), reverse=True)
    all_scans = all_scans[:limit]

    # Enrich each scan with live finding counts from the engine
    engine = _get_engine(org_id)
    enriched = []
    for scan in all_scans:
        entry = dict(scan)
        campaign_id = scan.get("campaign_id")
        if campaign_id:
            try:
                findings = engine.list_findings(org_id, campaign_id=campaign_id)
                entry["openclaw_findings_total"] = len(findings)
                entry["openclaw_findings_critical"] = sum(
                    1 for f in findings if f.get("severity") == "critical"
                )
                entry["openclaw_findings_high"] = sum(
                    1 for f in findings if f.get("severity") == "high"
                )
            except Exception:  # noqa: BLE001 — best-effort enrichment
                pass
        enriched.append(entry)

    return {
        "total": len(enriched),
        "scans": enriched,
    }


@router.get("/status")
def get_scan_status(
    scan_id: Optional[str] = Query(default=None, description="Specific scan ID. Omit for latest."),
    org_id: str = Query(default=_SELF_TEST_ORG),
) -> Dict[str, Any]:
    """Return status of a specific (or the most recent) autonomous self-pentest scan.

    Includes:
    - OpenClaw campaign status + live findings summary
    - OWASP Top 10 probe results (when complete)
    - Overall risk posture verdict
    """
    with _scan_store_lock:
        if scan_id:
            scan = _scan_store.get(scan_id)
            if scan is None or scan.get("org_id") != org_id:
                raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
        else:
            # Latest scan for org
            candidates = [
                v for v in _scan_store.values() if v.get("org_id") == org_id
            ]
            if not candidates:
                return {
                    "status": "no_scans",
                    "message": "No self-pentest scans found. POST /api/v1/openclaw/scan to start one.",
                }
            scan = max(candidates, key=lambda s: s.get("started_at", ""))

    scan = dict(scan)
    campaign_id = scan.get("campaign_id")
    engine = _get_engine(org_id)

    # Enrich with live OpenClaw campaign data
    campaign = None
    if campaign_id:
        try:
            campaign = engine.get_campaign(org_id, campaign_id)
        except Exception:  # noqa: BLE001 — best-effort
            pass

    findings_summary: Dict[str, Any] = {}
    if campaign:
        findings_summary = campaign.get("findings_by_severity", {})
        scan["campaign_status"] = campaign.get("status")
        scan["campaign_phase"] = campaign.get("phase")
        scan["openclaw_risk_score"] = campaign.get("risk_score", 0.0)

    total_findings = sum(findings_summary.values()) if findings_summary else 0
    critical_findings = findings_summary.get("critical", 0)
    high_findings = findings_summary.get("high", 0)

    # Derive overall posture verdict
    owasp_vuln = scan.get("owasp_vulnerable_count", 0)
    if critical_findings > 0 or owasp_vuln >= 3:
        posture = "CRITICAL"
    elif high_findings > 0 or owasp_vuln >= 1:
        posture = "HIGH_RISK"
    elif total_findings > 0:
        posture = "MEDIUM_RISK"
    else:
        posture = "PASS"

    return {
        "scan_id": scan.get("scan_id"),
        "campaign_id": campaign_id,
        "target_url": scan.get("target_url"),
        "started_at": scan.get("started_at"),
        "status": scan.get("status"),
        "campaign_status": scan.get("campaign_status"),
        "campaign_phase": scan.get("campaign_phase"),
        "tasks_queued": scan.get("tasks_queued", 0),
        "openclaw_findings": {
            "total": total_findings,
            "by_severity": findings_summary,
            "risk_score": scan.get("openclaw_risk_score", 0.0),
        },
        "owasp": {
            "status": scan.get("owasp_status"),
            "total_probes": scan.get("owasp_total_probes", 0),
            "vulnerable_count": owasp_vuln,
        },
        "posture_verdict": posture,
    }


@router.get("/", summary="OpenClaw index", tags=["openclaw"])
async def openclaw_index(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return OpenClaw red-team campaign summary for the org."""
    try:
        engine = _get_engine()
        campaigns = engine.list_campaigns(org_id=org_id) if hasattr(engine, "list_campaigns") else []
        count = len(campaigns)
    except Exception:
        campaigns = []
        count = 0
    return {"router": "openclaw", "org_id": org_id, "items": campaigns, "count": count}
