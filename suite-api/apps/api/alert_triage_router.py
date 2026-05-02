"""Alert Triage Router — ALDECI.

Centralized alert ingestion and triage workflow across SIEM, EDR, NDR,
Cloud, WAF, IDS, and Firewall sources.

Prefix: /api/v1/alert-triage
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/alert-triage/alerts                  ingest_alert
  GET    /api/v1/alert-triage/alerts                  list_alerts
  GET    /api/v1/alert-triage/alerts/{id}             get_alert
  PATCH  /api/v1/alert-triage/alerts/{id}/triage      triage_alert
  POST   /api/v1/alert-triage/bulk-triage             bulk_triage
  GET    /api/v1/alert-triage/queue                   get_triage_queue
  GET    /api/v1/alert-triage/stats                   get_triage_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional

from apps.api.auth_deps import api_key_auth, require_role
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator, model_validator

_logger = logging.getLogger(__name__)

_ANALYST_ROLES = ("admin", "super_admin", "org_admin", "security_engineer", "analyst")

router = APIRouter(
    prefix="/api/v1/alert-triage",
    tags=["Alert Triage"],
    dependencies=[require_role(*_ANALYST_ROLES)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.alert_triage_engine import AlertTriageEngine
        _engine = AlertTriageEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IngestAlertRequest(BaseModel):
    title: str = Field(..., description="Short alert title")
    source_system: str = Field(
        default="siem",
        description="siem | edr | ndr | cloud | waf | ids | firewall | custom",
    )
    severity: str = Field(
        default="medium",
        description="critical | high | medium | low | info",
    )
    raw_alert_json: Optional[Dict[str, Any]] = Field(
        default=None, description="Raw alert payload from source system"
    )


class TriageAlertRequest(BaseModel):
    triage_status: str = Field(
        ...,
        description=(
            "new | triaging | escalated | investigating | "
            "resolved | false_positive | duplicate"
        ),
    )
    assigned_to: Optional[str] = Field(default=None, description="Assignee username")
    triage_notes: Optional[str] = Field(default=None, description="Analyst notes")
    escalation_reason: Optional[str] = Field(
        default=None, description="Required when escalating"
    )


# Engine-level actions are these three; "acknowledge"/"ack" are accepted as
# aliases for "resolve" and normalised in the router. Pydantic enforces the
# enum at the request boundary so callers get a 422 with a clear error
# instead of silently passing through to the engine.
BulkAction = Literal["acknowledge", "ack", "resolve", "false_positive", "escalate"]


class BulkTriageRequest(BaseModel):
    """Request body for POST /api/v1/alert-triage/bulk-triage.

    Validation rules (enforced by Pydantic before reaching the route handler):
      * ``alert_ids`` (or ``alert_id``) must be supplied and non-empty.
      * Every ID must be a non-empty, whitespace-stripped string.
      * Duplicates are removed while preserving caller order.
      * ``action`` must be one of: acknowledge | ack | resolve | false_positive | escalate.
    """

    alert_ids: Optional[List[str]] = Field(
        default=None,
        description="List of alert IDs to action (1-500 entries)",
        max_length=500,
    )
    alert_id: Optional[str] = Field(
        default=None,
        description="Single alert ID (convenience alias for alert_ids)",
        min_length=1,
        max_length=128,
    )
    action: BulkAction = Field(
        ...,
        description="acknowledge | ack | resolve | false_positive | escalate",
    )
    org_id: Optional[str] = Field(
        default=None,
        description="Organization ID (can also be passed as query param)",
        min_length=1,
        max_length=128,
    )

    @field_validator("alert_ids")
    @classmethod
    def _clean_alert_ids(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        cleaned: List[str] = []
        seen: set[str] = set()
        for raw in value:
            if not isinstance(raw, str):
                raise ValueError("alert_ids entries must be strings")
            stripped = raw.strip()
            if not stripped:
                raise ValueError("alert_ids entries must be non-empty strings")
            if len(stripped) > 128:
                raise ValueError("alert_ids entries must be <= 128 chars")
            if stripped in seen:
                continue
            seen.add(stripped)
            cleaned.append(stripped)
        if not cleaned:
            raise ValueError("alert_ids must contain at least one non-empty ID")
        return cleaned

    @field_validator("alert_id")
    @classmethod
    def _clean_alert_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("alert_id must be a non-empty string")
        return stripped

    @model_validator(mode="after")
    def _require_one_id_source(self) -> "BulkTriageRequest":
        if not self.alert_ids and not self.alert_id:
            raise ValueError("alert_ids or alert_id is required")
        return self


# ---------------------------------------------------------------------------
# Endpoints

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_alert_triage(org_id: str = Query("default")) -> Dict[str, Any]:
    """List alerts in the triage queue for the org."""
    alerts = _get_engine().list_alerts(org_id=org_id)
    return {"org_id": org_id, "alerts": alerts, "total": len(alerts)}
# ---------------------------------------------------------------------------

@router.post("/alerts", dependencies=[Depends(api_key_auth)])
def ingest_alert(
    req: IngestAlertRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Ingest a new alert. Priority is auto-assigned from severity."""
    try:
        return _get_engine().ingest_alert(
            org_id,
            {
                "title": req.title,
                "source_system": req.source_system,
                "severity": req.severity,
                "raw_alert_json": req.raw_alert_json or {},
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/alerts", dependencies=[Depends(api_key_auth)])
def list_alerts(
    org_id: str = Query(..., description="Organization ID"),
    source_system: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    priority: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List alerts with optional filters."""
    return _get_engine().list_alerts(
        org_id,
        source_system=source_system,
        severity=severity,
        status=status,
        priority=priority,
    )


@router.get("/alerts/{alert_id}", dependencies=[Depends(api_key_auth)])
def get_alert(
    alert_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single alert by ID."""
    alert = _get_engine().get_alert(org_id, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert


@router.patch("/alerts/{alert_id}/triage", dependencies=[Depends(api_key_auth)])
def triage_alert(
    alert_id: str,
    req: TriageAlertRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update triage status and metadata for an alert."""
    try:
        return _get_engine().triage_alert(
            org_id,
            alert_id,
            {
                "triage_status": req.triage_status,
                "assigned_to": req.assigned_to or "",
                "triage_notes": req.triage_notes or "",
                "escalation_reason": req.escalation_reason or "",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/bulk-triage", dependencies=[Depends(api_key_auth)])
def bulk_triage(
    req: BulkTriageRequest,
    org_id: Optional[str] = Query(default=None, description="Organization ID"),
) -> Dict[str, Any]:
    """Apply the same triage action to multiple alerts at once.

    Accepts either ``alert_ids`` (list) or ``alert_id`` (single string).
    ``org_id`` may be provided as a query parameter or in the request body.
    Valid actions: acknowledge, ack, resolve, false_positive, escalate.

    Validation contract:
      * 422 — request shape invalid (missing IDs, empty list, bad enum, missing org).
      * 403 — at least one ID belongs to a different org (cross-tenant attempt).
      * 404 — at least one ID does not exist anywhere.
      * 200 — all IDs validated and updated atomically.
    """
    # Resolve org_id: query param takes precedence, fallback to body field
    resolved_org_id = (org_id or req.org_id or "").strip()
    if not resolved_org_id:
        raise HTTPException(
            status_code=422,
            detail="org_id is required (query param or body field)",
        )

    # Pydantic guarantees alert_ids (list) is non-empty if present.
    ids: List[str] = list(req.alert_ids) if req.alert_ids else [req.alert_id or ""]
    # Defensive: drop any empty entries that slipped through (alert_id branch).
    ids = [i for i in ids if i]
    if not ids:
        raise HTTPException(status_code=422, detail="alert_ids or alert_id is required")

    # Normalise action: map 'acknowledge'/'ack' -> 'resolve' for the engine.
    _action_aliases = {"acknowledge": "resolve", "ack": "resolve"}
    action = _action_aliases.get(req.action, req.action)

    # ── Cross-tenant + existence pre-check (atomic) ───────────────────────
    # Iterate once over the requested IDs and classify them. We refuse to
    # mutate ANY row unless every requested ID is present and belongs to
    # the caller's org. This prevents:
    #   (a) cross-org IDOR — caller passes IDs from another tenant; without
    #       this check the engine returns updated=0 (silent success).
    #   (b) partial success — some IDs missing, others updated, with no
    #       way for the caller to tell which.
    engine = _get_engine()
    cross_org: List[str] = []
    missing: List[str] = []
    for aid in ids:
        if engine.get_alert(resolved_org_id, aid) is not None:
            continue
        # Not found in caller's org. Determine whether it exists elsewhere.
        if engine.alert_exists_anywhere(aid):
            cross_org.append(aid)
        else:
            missing.append(aid)

    if cross_org:
        # Do not echo back the foreign IDs to avoid confirming their
        # existence — log internally, return a generic 403.
        _logger.warning(
            "alert_triage.bulk_triage cross-org attempt: org=%s tried to mutate %d alert(s) outside its tenant",
            resolved_org_id,
            len(cross_org),
        )
        raise HTTPException(
            status_code=403,
            detail=(
                f"{len(cross_org)} alert ID(s) do not belong to org "
                f"'{resolved_org_id}'"
            ),
        )

    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"Alert ID(s) not found: {missing}",
        )

    try:
        return engine.bulk_triage(resolved_org_id, ids, action)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/queue", dependencies=[Depends(api_key_auth)])
def get_triage_queue(
    org_id: str = Query(..., description="Organization ID"),
    limit: int = Query(default=50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """Return the prioritized triage queue (new + triaging, p1 first)."""
    return _get_engine().get_triage_queue(org_id, limit=limit)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_triage_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregate triage statistics."""
    return _get_engine().get_triage_stats(org_id)


@router.get("/alerts/{alert_id}/context", dependencies=[Depends(api_key_auth)])
def get_alert_context(
    alert_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return TrustGraph cross-domain context for an alert (related assets, findings, incidents)."""
    return _get_engine().get_alert_context(org_id, alert_id)


@router.post("/investigate/{alert_id}", dependencies=[Depends(api_key_auth)])
def investigate_alert(
    alert_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """SOC analyst investigation endpoint.

    Correlates an alert across all security domains and returns:
    - The alert record with full metadata
    - Related alerts from the same source/severity in last 24 h
    - Affected assets extracted from raw_alert_json (host, ip, user)
    - Incident history matching those assets
    - IOC summary (IPs, domains, hashes) parsed from raw payload
    - TrustGraph GraphRAG cross-domain context
    - Recommended IR playbook based on source/severity heuristics
    """
    try:
        return _get_engine().investigate(org_id, alert_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
