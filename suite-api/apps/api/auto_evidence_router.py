"""
Automated Evidence Collection API endpoints.

Pulls real evidence from ALDECI's own systems (audit logs, scan results,
config snapshots, access matrix, encryption status, backup records, incidents)
and maps it to SOC2 / PCI-DSS / HIPAA controls.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from core.auto_evidence import (
    FRAMEWORK_CONTROL_MAP,
    AutoEvidence,
    AutoEvidenceCollector,
    EvidenceCoverage,
    EvidenceSource,
    get_collector,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/auto-evidence", tags=["auto-evidence"])


def _col() -> AutoEvidenceCollector:
    return get_collector()


# ---------------------------------------------------------------------------
# Request / response helpers
# ---------------------------------------------------------------------------


class CollectRequest(BaseModel):
    org_id: str
    control_id: str
    framework: str = "SOC2"


class BulkCollectRequest(BaseModel):
    org_id: str
    framework: str = "SOC2"


class VerifyResponse(BaseModel):
    evidence_id: str
    valid: bool
    message: str


class FrameworkControlsResponse(BaseModel):
    framework: str
    controls: Dict[str, List[str]]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/frameworks", response_model=List[FrameworkControlsResponse])
def list_frameworks() -> List[FrameworkControlsResponse]:
    """List all supported frameworks and their mapped controls."""
    result = []
    for fw, controls in FRAMEWORK_CONTROL_MAP.items():
        result.append(
            FrameworkControlsResponse(
                framework=fw,
                controls={cid: [s.value for s in srcs] for cid, srcs in controls.items()},
            )
        )
    return result


@router.post("/collect/audit-logs", response_model=AutoEvidence)
def collect_audit_logs(req: CollectRequest) -> AutoEvidence:
    """Collect audit log entries as evidence for the given control."""
    return _col().collect_from_audit_logs(req.org_id, req.control_id, req.framework)


@router.post("/collect/scan-results", response_model=AutoEvidence)
def collect_scan_results(req: CollectRequest) -> AutoEvidence:
    """Collect scan findings as evidence for the given control."""
    return _col().collect_from_scan_results(req.org_id, req.control_id, req.framework)


@router.post("/collect/config", response_model=AutoEvidence)
def collect_config(req: CollectRequest) -> AutoEvidence:
    """Snapshot current ALDECI configuration as evidence."""
    return _col().collect_from_config(req.org_id, req.control_id, req.framework)


@router.post("/collect/access-matrix", response_model=AutoEvidence)
def collect_access_matrix(req: CollectRequest) -> AutoEvidence:
    """Pull access control state as evidence for the given control."""
    return _col().collect_from_access_matrix(req.org_id, req.control_id, req.framework)


@router.post("/collect/encryption-status", response_model=AutoEvidence)
def collect_encryption_status(
    org_id: str = Query(..., description="Organisation ID"),
    framework: str = Query("SOC2", description="Compliance framework"),
) -> AutoEvidence:
    """Pull FIPS encryption status as evidence."""
    return _col().collect_from_encryption_status(org_id, framework)


@router.post("/collect/backup-records", response_model=AutoEvidence)
def collect_backup_records(
    org_id: str = Query(..., description="Organisation ID"),
    framework: str = Query("SOC2", description="Compliance framework"),
) -> AutoEvidence:
    """Pull backup history as evidence."""
    return _col().collect_from_backup_records(org_id, framework)


@router.post("/collect/incidents", response_model=AutoEvidence)
def collect_incidents(req: CollectRequest) -> AutoEvidence:
    """Pull incident reports as evidence for the given control."""
    return _col().collect_from_incidents(req.org_id, req.control_id, req.framework)


@router.post("/collect/all", response_model=List[AutoEvidence])
def collect_all(req: BulkCollectRequest) -> List[AutoEvidence]:
    """
    Auto-collect evidence for ALL controls in a framework in one call.

    Uses the built-in SOC2/PCI/HIPAA control → source mapping to determine
    which evidence sources to pull for each control.
    """
    results = _col().auto_collect_all(req.org_id, req.framework)
    if not results:
        raise HTTPException(
            status_code=400,
            detail=f"No controls mapped for framework '{req.framework}'. "
            f"Supported: {list(FRAMEWORK_CONTROL_MAP.keys())}",
        )
    return results


@router.post("/verify/{evidence_id}", response_model=VerifyResponse)
def verify_evidence(evidence_id: str) -> VerifyResponse:
    """Hash-verify a stored evidence artifact."""
    valid, message = _col().verify_evidence(evidence_id)
    return VerifyResponse(evidence_id=evidence_id, valid=valid, message=message)


@router.get("/coverage", response_model=EvidenceCoverage)
def get_coverage(
    org_id: str = Query(..., description="Organisation ID"),
    framework: str = Query("SOC2", description="Compliance framework"),
) -> EvidenceCoverage:
    """Return evidence coverage report: which controls have fresh evidence."""
    return _col().get_evidence_coverage(org_id, framework)


@router.get("/", response_model=List[AutoEvidence])
def list_evidence(
    org_id: str = Query(..., description="Organisation ID"),
    framework: Optional[str] = Query(None, description="Filter by framework"),
    control_id: Optional[str] = Query(None, description="Filter by control ID"),
    source: Optional[EvidenceSource] = Query(None, description="Filter by evidence source"),
    limit: int = Query(100, ge=1, le=1000),
) -> List[AutoEvidence]:
    """List collected evidence artifacts with optional filters."""
    try:
        return _col().list_evidence(
            org_id=org_id,
            framework=framework,
            control_id=control_id,
            source=source,
            limit=limit,
        )
    except Exception:
        return []


@router.get("/{evidence_id}", response_model=AutoEvidence)
def get_evidence(evidence_id: str) -> AutoEvidence:
    """Retrieve a single evidence artifact by ID."""
    ev = _col().get_evidence(evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")
    return ev
