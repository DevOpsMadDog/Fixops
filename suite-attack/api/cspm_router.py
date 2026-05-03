"""CSPM Router — Cloud Security Posture Management API endpoints.

Endpoints:
  GET  /api/v1/cspm/posture              — Overall cloud security posture score
  GET  /api/v1/cspm/findings             — Misconfigurations found
  GET  /api/v1/cspm/resources            — Cloud resource inventory
  GET  /api/v1/cspm/benchmarks           — CIS benchmark compliance status
  POST /api/v1/cspm/scan                 — Trigger cloud posture scan
  GET  /api/v1/cspm/drift                — Drift detection results
  GET  /api/v1/cspm/remediation/{id}     — Remediation steps for a finding
  GET  /api/v1/cspm/compliance-map       — Mapping of CIS checks to compliance frameworks

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.cspm_engine import (
    AllowlistEntry,
    CloudProvider,
    CloudResource,
    CSPMFinding,
    FindingStatus,
    OrgPosture,
    RemediationPlaybook,
    ResourceType,
    ScanResult,
    Severity,
    get_cspm_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cspm", tags=["CSPM"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterResourceRequest(BaseModel):
    provider: CloudProvider
    resource_type: ResourceType
    name: str
    region: str = "global"
    account_id: str = "unknown"
    org_id: str = "default"
    tags: Dict[str, str] = Field(default_factory=dict)
    owner: Optional[str] = None
    is_public: bool = False
    is_encrypted: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TriggerScanRequest(BaseModel):
    org_id: str = "default"
    account_ids: List[str] = Field(default_factory=list)
    providers: List[CloudProvider] = Field(default_factory=list)
    rule_ids: Optional[List[str]] = None


class SuppressFindingRequest(BaseModel):
    reason: str = Field(..., description="Reason for suppressing this finding")


class AddAllowlistRequest(BaseModel):
    rule_id: str = Field(..., description="CSPM rule ID to suppress (e.g. CSPM-AWS-001)")
    resource_id: Optional[str] = Field(
        None, description="Specific resource ID — omit to suppress rule org-wide"
    )
    reason: str = Field(..., description="Business justification for this exception")
    created_by: str = Field("system", description="User or service creating the entry")
    expires_at: Optional[str] = Field(
        None, description="ISO-8601 expiry timestamp — omit for permanent exception"
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _engine():
    return get_cspm_engine()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/posture", summary="Overall cloud security posture score")
def get_posture(
    org_id: str = Query("default", description="Organisation ID"),
) -> OrgPosture:
    """Return the aggregated cloud security posture for the org.

    The overall_score is 0-100 where higher is better (less risk).
    """
    return _engine().get_posture(org_id=org_id)


@router.get("/findings", summary="List CSPM misconfigurations", response_model=List[CSPMFinding])
def list_findings(
    org_id: str = Query("default", description="Organisation ID"),
    status: Optional[FindingStatus] = Query(None, description="Filter by status"),
    severity: Optional[Severity] = Query(None, description="Filter by severity"),
) -> List[CSPMFinding]:
    """List all CSPM findings for an org with optional filters."""
    return _engine().list_findings(org_id=org_id, status=status, severity=severity)


@router.get("/resources", summary="Cloud resource inventory", response_model=List[CloudResource])
def list_resources(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[CloudResource]:
    """Return the full cloud resource inventory for an org."""
    return _engine().list_resources(org_id=org_id)


@router.post("/resources", summary="Register a cloud resource", response_model=CloudResource)
def register_resource(req: RegisterResourceRequest) -> CloudResource:
    """Register or update a cloud resource in the CSPM inventory."""
    resource = CloudResource(
        provider=req.provider,
        resource_type=req.resource_type,
        name=req.name,
        region=req.region,
        account_id=req.account_id,
        org_id=req.org_id,
        tags=req.tags,
        owner=req.owner,
        is_public=req.is_public,
        is_encrypted=req.is_encrypted,
        metadata=req.metadata,
    )
    try:
        return _engine().register_resource(resource)
    except Exception as exc:
        logger.exception("Failed to register resource: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to register resource: {exc}") from exc


@router.get("/benchmarks", summary="CIS benchmark compliance status")
def get_benchmarks(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return CIS Benchmark compliance status grouped by cloud provider.

    Shows total/passing/failing rule counts and per-rule status.
    """
    return _engine().get_benchmark_status(org_id=org_id)


@router.post("/scan", summary="Trigger cloud posture scan", response_model=ScanResult)
def trigger_scan(req: TriggerScanRequest) -> ScanResult:
    """Trigger a CSPM scan for all registered resources in an org.

    Evaluates all applicable CIS Benchmark rules and detects configuration
    drift against the saved baseline. Returns the full scan result including
    the updated posture score.
    """
    try:
        return _engine().run_scan(org_id=req.org_id, rule_ids=req.rule_ids)
    except Exception as exc:
        logger.exception("CSPM scan failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"CSPM scan failed: {exc}") from exc


@router.get("/drift", summary="Configuration drift detection results")
def get_drift(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return configuration drift events detected against the saved baseline.

    Drift events include: new public resources, removed security controls,
    changed encryption settings, and modified security metadata.
    """
    events = _engine().list_drift(org_id=org_id)
    return {
        "drift_events": [e.model_dump() for e in events],
        "total": len(events),
        "org_id": org_id,
    }


@router.post("/baseline", summary="Save current state as drift baseline")
def save_baseline(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Snapshot the current resource state as the baseline for drift detection."""
    count = _engine().save_baseline(org_id=org_id)
    return {"snapshotted": count, "org_id": org_id}


@router.get("/remediation/{finding_id}", summary="Remediation steps for a finding", response_model=RemediationPlaybook)
def get_remediation(finding_id: str) -> RemediationPlaybook:
    """Return a step-by-step remediation playbook for a specific finding.

    Includes CLI commands and Terraform blocks where available, plus
    estimated effort and downtime risk indicators.
    """
    playbook = _engine().get_remediation(finding_id)
    if not playbook:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return playbook


@router.get("/compliance-map", summary="Mapping of CIS checks to compliance frameworks")
def get_compliance_map() -> Dict[str, Any]:
    """Return the full mapping of CIS Benchmark checks to compliance frameworks.

    Frameworks covered: SOC2, PCI-DSS, HIPAA, FedRAMP, NIST 800-53, CIS.
    """
    return _engine().get_compliance_map()


@router.get("/findings/{finding_id}", summary="Get a single finding", response_model=CSPMFinding)
def get_finding(finding_id: str) -> CSPMFinding:
    """Retrieve a single CSPM finding by ID."""
    finding = _engine().get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return finding


@router.post("/findings/{finding_id}/suppress", summary="Suppress a finding", response_model=CSPMFinding)
def suppress_finding(finding_id: str, req: SuppressFindingRequest) -> CSPMFinding:
    """Mark a finding as suppressed with a documented reason (e.g. accepted risk)."""
    finding = _engine().suppress_finding(finding_id, req.reason)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return finding


@router.post("/findings/{finding_id}/resolve", summary="Resolve a finding", response_model=CSPMFinding)
def resolve_finding(finding_id: str) -> CSPMFinding:
    """Mark a finding as resolved after applying remediation."""
    finding = _engine().resolve_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return finding


@router.get("/scans", summary="Recent scan history")
def list_scans(
    org_id: str = Query("default", description="Organisation ID"),
    limit: int = Query(10, ge=1, le=100, description="Max results"),
) -> Dict[str, Any]:
    """Return recent CSPM scan results for an org."""
    scans = _engine().list_scans(org_id=org_id, limit=limit)
    return {"scans": [s.model_dump() for s in scans], "total": len(scans)}


@router.get("/resources/{resource_id}", summary="Get a single cloud resource", response_model=CloudResource)
def get_resource(resource_id: str) -> CloudResource:
    """Retrieve a single cloud resource from the inventory by ID."""
    resource = _engine().get_resource(resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail=f"Resource '{resource_id}' not found")
    return resource


@router.delete("/resources/{resource_id}", summary="Remove a cloud resource")
def delete_resource(resource_id: str) -> Dict[str, Any]:
    """Remove a cloud resource from the CSPM inventory."""
    deleted = _engine().delete_resource(resource_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Resource '{resource_id}' not found")
    return {"deleted": True, "resource_id": resource_id}


@router.get("/health", summary="CSPM engine health check")
def cspm_health() -> Dict[str, Any]:
    """Health check — returns CSPM engine operational status."""
    try:
        engine = _engine()
        resource_count = len(engine.get_resources())
        return {
            "status": "healthy",
            "engine": "cspm",
            "version": "1.0.0",
            "resources_tracked": resource_count,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("CSPM health check degraded: %s", exc)
        return {"status": "degraded", "engine": "cspm", "error": str(exc)}


@router.get("/status", summary="CSPM engine status alias")
def cspm_status() -> Dict[str, Any]:
    """Status alias for /health — returns CSPM engine operational status."""
    return cspm_health()


# ---------------------------------------------------------------------------
# Allowlist / finding-suppression endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/allowlist",
    summary="Add a CSPM finding-suppression allowlist entry",
    response_model=AllowlistEntry,
    status_code=201,
)
def add_allowlist_entry(req: AddAllowlistRequest) -> AllowlistEntry:
    """Create a persistent allowlist entry that suppresses future findings for a
    given rule (optionally scoped to a specific resource).

    Use this when a finding represents an accepted risk or a known false-positive
    that should not surface in posture dashboards.  Supply an *expires_at*
    timestamp for time-boxed exceptions; omit for permanent suppression.
    """
    entry = AllowlistEntry(
        rule_id=req.rule_id,
        resource_id=req.resource_id,
        reason=req.reason,
        created_by=req.created_by,
        expires_at=req.expires_at,
    )
    try:
        return _engine().add_allowlist_entry(entry)
    except Exception as exc:
        logger.exception("Failed to add allowlist entry: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to add allowlist entry: {exc}") from exc


@router.get(
    "/allowlist",
    summary="List CSPM finding-suppression allowlist entries",
    response_model=List[AllowlistEntry],
)
def list_allowlist_entries(
    org_id: str = Query("default", description="Organisation ID"),
    rule_id: Optional[str] = Query(None, description="Filter by CSPM rule ID"),
) -> List[AllowlistEntry]:
    """Return all allowlist entries for an org, optionally filtered by rule ID."""
    return _engine().list_allowlist(org_id=org_id, rule_id=rule_id)


@router.delete(
    "/allowlist/{entry_id}",
    summary="Delete a CSPM allowlist entry",
)
def delete_allowlist_entry(entry_id: str) -> Dict[str, Any]:
    """Remove an allowlist entry — future scans will re-raise the finding if still applicable."""
    deleted = _engine().delete_allowlist_entry(entry_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Allowlist entry '{entry_id}' not found")
    return {"deleted": True, "entry_id": entry_id}
