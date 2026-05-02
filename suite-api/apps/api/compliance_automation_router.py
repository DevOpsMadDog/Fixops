"""
Compliance Automation API — ALDECI (Vanta killer).

Exposes the ComplianceAutomationEngine covering 7 frameworks:
  SOC2, PCI-DSS v4.0, HIPAA, FedRAMP, ISO 27001, NIST 800-53 rev5, CMMC 2.0.

Endpoints:
  GET  /api/v1/compliance/status                    Overall status across all frameworks
  GET  /api/v1/compliance/framework/{framework}     Detailed status for one framework
  GET  /api/v1/compliance/gaps                      Gap analysis + remediation roadmap
  GET  /api/v1/compliance/evidence                  Evidence inventory
  POST /api/v1/compliance/evidence/collect          Trigger evidence collection
  GET  /api/v1/compliance/crossmap                  Cross-framework control mapping
  GET  /api/v1/compliance/poam                      POA&M list
  POST /api/v1/compliance/report/{framework}        Generate audit-ready report
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.compliance_engine import (
    FRAMEWORKS,
    ComplianceAutomationEngine,
    POAMStatus,
    RemediationPriority,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance Automation"])

# Module-level singleton (shared across requests in one process)
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = ComplianceAutomationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class CollectEvidenceRequest(BaseModel):
    framework: str = Field(..., description="Target framework (SOC2, PCI-DSS, HIPAA, FedRAMP, ISO27001, NIST-800-53, CMMC)")
    control_id: Optional[str] = Field(None, description="Specific control ID; omit to collect for all controls in the framework")
    org_id: Optional[str] = Field(None, description="Organisation identifier")


class CreatePOAMRequest(BaseModel):
    control_id: str = Field(..., description="Control ID the POA&M addresses")
    framework: str = Field(..., description="Framework the control belongs to")
    title: str = Field(..., description="Short title for the POA&M item")
    description: str = Field(..., description="Detailed description of the finding and remediation plan")
    responsible_party: str = Field("Security Team", description="Team or person responsible")
    risk_level: RemediationPriority = Field(RemediationPriority.MEDIUM, description="Risk severity")
    target_date: Optional[str] = Field(None, description="ISO8601 target remediation date")


class UpdatePOAMStatusRequest(BaseModel):
    status: POAMStatus = Field(..., description="New status")
    risk_accepted: bool = Field(False, description="Set true to mark the risk as formally accepted")


# ---------------------------------------------------------------------------
# GET /api/v1/compliance/  — summary landing
# ---------------------------------------------------------------------------


@router.get("/", summary="Compliance automation summary")
async def get_compliance_summary() -> Dict[str, Any]:
    """Return overall compliance posture summary: frameworks, scores, total controls, gaps."""
    try:
        status = _get_engine().get_overall_status()
        return {
            "status": "ok",
            "frameworks": FRAMEWORKS,
            "summary": status,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /api/v1/compliance/status
# ---------------------------------------------------------------------------


@router.get("/status", summary="Overall compliance status across all frameworks")
async def get_overall_status() -> Dict[str, Any]:
    """
    Return a high-level compliance posture spanning all 7 frameworks:
    SOC2, PCI-DSS, HIPAA, FedRAMP, ISO 27001, NIST 800-53, CMMC.

    Includes per-framework score, control breakdown, and an aggregate overall score.
    """
    try:
        return _get_engine().get_overall_status()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /api/v1/compliance/framework/{framework}
# ---------------------------------------------------------------------------


@router.get("/framework/{framework}", summary="Detailed compliance status for one framework")
async def get_framework_status(framework: str) -> Dict[str, Any]:
    """
    Return full control-by-control status for a single framework.

    Includes: score, status breakdown, per-control evidence count and last-checked date.
    """
    try:
        return _get_engine().get_framework_status(framework)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /api/v1/compliance/gaps
# ---------------------------------------------------------------------------


@router.get("/gaps", summary="Gap analysis with priority-ranked remediation roadmap")
async def get_gaps(
    framework: Optional[str] = Query(None, description="Filter by framework; omit for all frameworks"),
) -> List[Dict[str, Any]]:
    """
    Identify controls that are failing, not started, or have stale evidence (>30 days).

    Returns a priority-ranked list (critical → high → medium → low) with
    recommended actions and estimated remediation effort.
    """
    try:
        gaps = _get_engine().get_gaps(framework=framework)
        return [g.model_dump() for g in gaps]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /api/v1/compliance/evidence
# ---------------------------------------------------------------------------


@router.get("/evidence", summary="Evidence inventory")
async def get_evidence(
    framework: Optional[str] = Query(None, description="Filter by framework"),
    control_id: Optional[str] = Query(None, description="Filter by control ID"),
) -> List[Dict[str, Any]]:
    """
    Return all evidence items collected from ALDECI modules.

    Each item includes the source module, evidence type, whether it is
    currently passing, and whether it is stale (older than 30 days).
    """
    try:
        return _get_engine().get_evidence(framework=framework, control_id=control_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /api/v1/compliance/evidence/collect
# ---------------------------------------------------------------------------


@router.post("/evidence/collect", summary="Trigger evidence collection", status_code=201)
async def collect_evidence(body: CollectEvidenceRequest) -> Dict[str, Any]:
    """
    Trigger automated evidence collection from ALDECI modules.

    Evidence is pulled from: scan results, RBAC config, encryption settings,
    audit logs, config snapshots, policy documents, incident reports, and
    training records.

    If `control_id` is omitted, evidence is collected for all controls in the
    framework.
    """
    try:
        items = _get_engine().collect_evidence(
            framework=body.framework,
            control_id=body.control_id,
            org_id=body.org_id,
        )
        return {
            "framework": body.framework,
            "control_id": body.control_id,
            "items_collected": len(items),
            "evidence": [
                {
                    "id": it.id,
                    "evidence_type": it.evidence_type.value,
                    "title": it.title,
                    "is_passing": it.is_passing,
                    "collected_at": it.collected_at,
                }
                for it in items
            ],
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /api/v1/compliance/crossmap
# ---------------------------------------------------------------------------


@router.get("/crossmap", summary="Cross-framework control mapping")
async def get_cross_map() -> List[Dict[str, Any]]:
    """
    Return cross-framework control mappings.

    Shows that a single implementation can satisfy multiple frameworks.
    Example: access control implementation covers SOC2 CC6.1 + PCI-DSS REQ-7
    + HIPAA 164.312(a)(1) + NIST-800-53 AC-3 simultaneously.
    """
    try:
        entries = _get_engine().get_cross_map()
        return [e.model_dump() for e in entries]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /api/v1/compliance/poam
# ---------------------------------------------------------------------------


@router.get("/poam", summary="POA&M list")
async def get_poam(
    framework: Optional[str] = Query(None, description="Filter by framework"),
) -> List[Dict[str, Any]]:
    """
    Return all Plan of Action and Milestones items.

    Each item tracks: failing control, responsible party, target date,
    current status, risk level, and whether the risk has been formally accepted.
    """
    try:
        items = _get_engine().get_poam_list(framework=framework)
        return [it.model_dump() for it in items]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/poam", summary="Create a POA&M item", status_code=201)
async def create_poam(body: CreatePOAMRequest) -> Dict[str, Any]:
    """
    Create a Plan of Action and Milestones item for a failing control.
    """
    try:
        item = _get_engine().create_poam(
            control_id=body.control_id,
            framework=body.framework,
            title=body.title,
            description=body.description,
            responsible_party=body.responsible_party,
            risk_level=body.risk_level,
            target_date=body.target_date,
        )
        return item.model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.patch("/poam/{poam_id}", summary="Update POA&M status")
async def update_poam_status(poam_id: str, body: UpdatePOAMStatusRequest) -> Dict[str, Any]:
    """
    Update the status of a POA&M item. Set `risk_accepted=true` to formally
    accept the residual risk without remediation.
    """
    try:
        item = _get_engine().update_poam_status(
            poam_id=poam_id,
            status=body.status,
            risk_accepted=body.risk_accepted,
        )
        return item.model_dump()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /api/v1/compliance/report/{framework}
# ---------------------------------------------------------------------------


@router.post("/report/{framework}", summary="Generate audit-ready compliance report")
async def generate_report(
    framework: str,
    org_id: Optional[str] = Query(None, description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Generate an audit-ready compliance report for a single framework.

    The report includes:
    - Executive summary (score, breakdown, gap count, open POA&M count)
    - Control-by-control status with evidence references
    - Gap analysis with remediation roadmap
    - POA&M items
    - Remediation timeline sorted by target date

    Output is machine-readable JSON suitable for ingestion by GRC tools.
    """
    try:
        report = _get_engine().generate_report(framework=framework, org_id=org_id)
        return report.model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Score history endpoints
# ---------------------------------------------------------------------------


@router.post("/score/{framework}", summary="Record compliance score snapshot", status_code=201)
async def record_score(framework: str) -> Dict[str, Any]:
    """Record the current compliance score for a framework (for trend tracking)."""
    try:
        score = _get_engine().record_score(framework)
        return score.model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/score/{framework}/trend", summary="Compliance score trend")
async def get_score_trend(
    framework: str,
    limit: int = Query(30, ge=1, le=365, description="Max number of historical snapshots to return"),
) -> List[Dict[str, Any]]:
    """Return historical compliance score snapshots for trend analysis."""
    try:
        return _get_engine().get_score_trend(framework=framework, limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Frameworks listing
# ---------------------------------------------------------------------------


@router.get("/frameworks", summary="List supported compliance frameworks")
async def list_frameworks() -> Dict[str, Any]:
    """Return metadata for all 7 supported compliance frameworks."""
    from core.compliance_engine import _FRAMEWORK_META
    return {
        "frameworks": FRAMEWORKS,
        "count": len(FRAMEWORKS),
        "metadata": _FRAMEWORK_META,
    }
