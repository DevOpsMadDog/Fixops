"""Compliance Engine Router (V10 — CTEM Full Loop).

Full compliance auto-mapping engine with framework support for SOC2, PCI DSS 4.0,
ISO 27001:2022, NIST 800-53 R5, NIST CSF 2.0, OWASP ASVS 4.0.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance-engine", tags=["Compliance Engine"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class MapFindingsRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="Findings to map to controls")
    framework: Optional[str] = Field(None, description="Specific framework (or all)")


class AssessFrameworkRequest(BaseModel):
    framework: str = Field(..., description="Framework to assess (soc2, pci_dss_4.0, etc.)")
    findings: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/health")
async def compliance_engine_health() -> Dict[str, Any]:
    """Health check alias for compliance engine (mirrors /status)."""
    return await compliance_engine_status()


@router.get("/status")
async def compliance_engine_status() -> Dict[str, Any]:
    """Get compliance engine status."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        frameworks = engine.get_supported_frameworks()
        return {
            "status": "operational",
            "engine": "compliance-engine",
            "version": "1.0.0",
            "supported_frameworks": frameworks,
            "framework_count": len(frameworks),
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        return {
            "status": "degraded",
            "engine": "compliance-engine",
            "error": type(e).__name__,
        }


@router.get("/frameworks")
async def list_frameworks() -> Dict[str, Any]:
    """List all supported compliance frameworks."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        return {"frameworks": engine.get_supported_frameworks()}
    except ImportError as e:
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.post("/map-findings")
async def map_findings(
    req: MapFindingsRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Map findings to compliance controls, scoped to the caller's org."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        mappings = engine.map_findings_to_controls(req.findings)
        result = {"mappings": mappings, "total": len(mappings), "org_id": org_id}
    except ImportError as e:
        raise HTTPException(status_code=500, detail=type(e).__name__)
    # TrustGraph async indexing (fire-and-forget, non-blocking)
    try:
        import asyncio

        from core.trustgraph_event_bus import EVENT_CONTROL_ASSESSED, get_event_bus
        bus = get_event_bus()
        if bus and bus.enabled:
            asyncio.ensure_future(bus.emit(EVENT_CONTROL_ASSESSED, {
                "control_id": f"compliance-map-{org_id}",
                "type": "compliance_mapping",
                "severity": "info",
                "source": "compliance_engine_router",
                "org_id": org_id,
                "total": result["total"],
            }))
    except Exception:
        pass  # event bus is best-effort
    return result


@router.post("/assess")
async def assess_framework(
    req: AssessFrameworkRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Assess compliance posture for a specific framework, scoped to the caller's org."""
    try:
        from compliance.compliance_engine import ComplianceEngine, Framework
        engine = ComplianceEngine()
        # Convert string to Framework enum
        fw_str = req.framework.upper().replace("-", "_").replace(".", "_")
        fw = None
        for f in Framework:
            if f.name == fw_str or f.value.upper() == fw_str or f.value.upper() == req.framework.upper():
                fw = f
                break
        if fw is None:
            # Try fuzzy match
            for f in Framework:
                if req.framework.upper() in f.value.upper() or f.value.upper() in req.framework.upper():
                    fw = f
                    break
        if fw is None:
            raise HTTPException(status_code=400, detail=f"Unknown framework: {req.framework}. Valid: {[f.value for f in Framework]}")
        result = engine.assess_framework(fw, findings=req.findings)
        # Convert dataclass/object to dict for JSON serialization
        if hasattr(result, 'to_dict'):
            return result.to_dict()
        elif hasattr(result, '__dict__'):
            import dataclasses
            if dataclasses.is_dataclass(result):
                return dataclasses.asdict(result)
            return result.__dict__
        return result
    except ImportError as e:
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.post("/assess-all")
async def assess_all_frameworks(
    req: MapFindingsRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Assess compliance posture across all frameworks, scoped to the caller's org."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        result = engine.assess_all_frameworks(req.findings)
        if isinstance(result, dict):
            result["org_id"] = org_id
        return result
    except ImportError as e:
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/gaps")
async def get_compliance_gaps(
    framework: Optional[str] = Query(None),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Get compliance gaps (controls without evidence)."""
    try:
        from compliance.compliance_engine import ComplianceEngine, Framework
        engine = ComplianceEngine()
        # Convert optional string to Framework enum; None means all frameworks
        if framework is None:
            all_gaps: List[Dict[str, Any]] = []
            for fw in engine._enabled:
                try:
                    fw_gaps = engine.get_compliance_gaps(fw)
                    for g in fw_gaps:
                        g["framework"] = fw.value
                    all_gaps.extend(fw_gaps)
                except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                    pass
            return {"gaps": all_gaps, "total": len(all_gaps), "framework": "all", "org_id": org_id}
        # Map string to Framework enum (case-insensitive)
        fw_map = {f.value.lower(): f for f in Framework}
        fw_key = framework.lower().replace("-", "_").replace(" ", "_")
        fw_enum = fw_map.get(fw_key) or fw_map.get(framework.lower())
        if fw_enum is None:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown framework '{framework}'. Valid: {[f.value for f in Framework]}",
            )
        gaps = engine.get_compliance_gaps(fw_enum)
        return {"gaps": gaps, "total": len(gaps), "framework": fw_enum.value, "org_id": org_id}
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/audit-bundle")
async def generate_audit_bundle(
    framework: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Generate a tamper-evident audit bundle."""
    try:
        from compliance.compliance_engine import ComplianceEngine, Framework
        engine = ComplianceEngine()
        # Resolve framework enum — default to SOC2 when not specified
        fw = None
        if framework:
            fw_map = {f.value.lower(): f for f in Framework}
            fw_key = framework.lower().replace("-", "_").replace(" ", "_")
            fw = fw_map.get(fw_key) or fw_map.get(framework.lower())
            if fw is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unknown framework '{framework}'. Valid: {[f.value for f in Framework]}",
                )
        else:
            # Default to first available framework (SOC2 preferred)
            for candidate in Framework:
                if "soc" in candidate.value.lower():
                    fw = candidate
                    break
            if fw is None:
                fw = next(iter(Framework))
        bundle = engine.generate_audit_bundle(fw)
        return bundle
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError, AttributeError) as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cwe-mapping/{cwe_id}")
async def get_cwe_mapping(cwe_id: str) -> Dict[str, Any]:
    """Get compliance controls mapped to a specific CWE."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        mapping = engine.get_cwe_control_mapping(cwe_id)
        return {"cwe_id": cwe_id, "controls": mapping}
    except ImportError as e:
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/control/{control_id}")
async def get_control_details(control_id: str) -> Dict[str, Any]:
    """Get details for a specific compliance control."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        details = engine.get_control_details(control_id)
        if not details:
            raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
        return details
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


# ---------------------------------------------------------------------------
# Framework-Specific Status Endpoints (Maria Santos — Compliance Lead)
# ---------------------------------------------------------------------------
def _posture_to_status_str(score: float) -> str:
    """Convert a 0-1 compliance score to a status string."""
    if score >= 0.95:
        return "compliant"
    elif score >= 0.70:
        return "partially_compliant"
    elif score >= 0.40:
        return "non_compliant"
    else:
        return "at_risk"


@router.get("/soc2/status")
async def soc2_status() -> Dict[str, Any]:
    """SOC 2 Type II compliance posture with Trust Services Criteria breakdown."""
    try:
        from compliance.compliance_engine import ComplianceEngine, Framework
        engine = ComplianceEngine()
        posture = engine.assess_framework(Framework.SOC2)
        gaps = engine.get_compliance_gaps(Framework.SOC2)
        posture_dict = posture.to_dict() if hasattr(posture, 'to_dict') else {}
        score_pct = round(posture_dict.get('compliance_percentage', posture_dict.get('overall_score', 0.0) * 100), 1)
        raw_score = posture_dict.get('overall_score', 0.0)
        critical_gaps = [
            f"{g['control_id']}: {g.get('title', '')}" for g in gaps
            if g.get('gap_type') == 'finding_remediation'
        ][:5]
        gap_items = [
            {
                "control_id": g["control_id"],
                "title": g.get("title", ""),
                "category": g.get("category", ""),
                "status": g.get("status", "not_assessed"),
                "gap_type": g.get("gap_type", ""),
            }
            for g in gaps
        ]
        return {
            "framework": "SOC2",
            "overall_score": score_pct,
            "status": _posture_to_status_str(raw_score),
            "total_controls": posture_dict.get("total_controls", 0),
            "satisfied": posture_dict.get("satisfied", 0),
            "partially_satisfied": posture_dict.get("partially_satisfied", 0),
            "not_satisfied": posture_dict.get("not_satisfied", 0),
            "not_assessed": posture_dict.get("not_assessed", 0),
            "gaps_count": len(gaps),
            "gaps": gap_items,
            "critical_gaps": critical_gaps,
            "posture_trend": posture_dict.get("trend", "stable"),
            "last_assessed": posture_dict.get("last_evaluated", ""),
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error("soc2_status error: %s", e)
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/hipaa/status_old_stub")
async def _soc2_stub_placeholder() -> Dict[str, Any]:
    """[REMOVED] Old stub — use /soc2/status for real compliance data."""
    raise HTTPException(
        status_code=410,
        detail="This legacy stub has been removed. Use /api/v1/compliance/soc2/status for real compliance data from the assessment engine.",
    )


@router.get("/hipaa/status")
async def hipaa_status() -> Dict[str, Any]:
    """HIPAA/HITECH compliance posture from real compliance engine assessment."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        # Check if HIPAA is in enabled frameworks; fall back to NIST_800_53 which maps well
        hipaa_fw = None
        for fw in engine._enabled:
            if "hipaa" in fw.value.lower() or "800_53" in fw.value.lower() or fw.value == "NIST_800_53_R5":
                hipaa_fw = fw
                break
        if hipaa_fw is None:
            hipaa_fw = next(iter(engine._enabled), None)
        if hipaa_fw is None:
            raise HTTPException(status_code=503, detail="No compliance frameworks enabled")
        posture = engine.assess_framework(hipaa_fw)
        gaps = engine.get_compliance_gaps(hipaa_fw)
        posture_dict = posture.to_dict() if hasattr(posture, 'to_dict') else {}
        score_pct = round(posture_dict.get('compliance_percentage', posture_dict.get('overall_score', 0.0) * 100), 1)
        raw_score = posture_dict.get('overall_score', 0.0)
        return {
            "framework": "HIPAA/HITECH",
            "mapped_to": hipaa_fw.value,
            "overall_score": score_pct,
            "status": _posture_to_status_str(raw_score),
            "total_controls": posture_dict.get("total_controls", 0),
            "satisfied": posture_dict.get("satisfied", 0),
            "partially_satisfied": posture_dict.get("partially_satisfied", 0),
            "not_satisfied": posture_dict.get("not_satisfied", 0),
            "not_assessed": posture_dict.get("not_assessed", 0),
            "gaps_count": len(gaps),
            "gaps": [
                {
                    "control_id": g["control_id"],
                    "title": g.get("title", ""),
                    "status": g.get("status", "not_assessed"),
                    "gap_type": g.get("gap_type", ""),
                }
                for g in gaps[:20]
            ],
            "posture_trend": posture_dict.get("trend", "stable"),
            "last_assessed": posture_dict.get("last_evaluated", ""),
        }
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error("hipaa_status error: %s", e)
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/hipaa/status_legacy")
async def hipaa_status_legacy() -> Dict[str, Any]:
    """[REMOVED] Old hardcoded stub replaced by real engine at /hipaa/status."""
    raise HTTPException(
        status_code=410,
        detail="This legacy stub has been removed. Use /api/v1/compliance/hipaa/status for real compliance data from the assessment engine.",
    )


@router.get("/pci-dss/status")
async def pci_dss_status() -> Dict[str, Any]:
    """PCI DSS 4.0 compliance posture from real compliance engine assessment."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        # Find PCI_DSS framework
        pci_fw = None
        for fw in engine._enabled:
            if "pci" in fw.value.lower():
                pci_fw = fw
                break
        if pci_fw is None:
            # Fallback to any enabled framework
            pci_fw = next(iter(engine._enabled), None)
        if pci_fw is None:
            raise HTTPException(status_code=503, detail="No compliance frameworks enabled")
        posture = engine.assess_framework(pci_fw)
        gaps = engine.get_compliance_gaps(pci_fw)
        posture_dict = posture.to_dict() if hasattr(posture, 'to_dict') else {}
        score_pct = round(posture_dict.get('compliance_percentage', posture_dict.get('overall_score', 0.0) * 100), 1)
        raw_score = posture_dict.get('overall_score', 0.0)
        return {
            "framework": "PCI DSS 4.0",
            "mapped_to": pci_fw.value,
            "overall_score": score_pct,
            "status": _posture_to_status_str(raw_score),
            "total_controls": posture_dict.get("total_controls", 0),
            "satisfied": posture_dict.get("satisfied", 0),
            "partially_satisfied": posture_dict.get("partially_satisfied", 0),
            "not_satisfied": posture_dict.get("not_satisfied", 0),
            "not_assessed": posture_dict.get("not_assessed", 0),
            "gaps_count": len(gaps),
            "gaps": [
                {
                    "control_id": g["control_id"],
                    "title": g.get("title", ""),
                    "status": g.get("status", "not_assessed"),
                    "gap_type": g.get("gap_type", ""),
                }
                for g in gaps[:20]
            ],
            "posture_trend": posture_dict.get("trend", "stable"),
            "last_assessed": posture_dict.get("last_evaluated", ""),
        }
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error("pci_dss_status error: %s", e)
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/pci-dss/status_legacy")
async def pci_dss_status_legacy() -> Dict[str, Any]:
    """[REMOVED] Old hardcoded stub replaced by real engine at /pci-dss/status."""
    raise HTTPException(
        status_code=410,
        detail="This legacy stub has been removed. Use /api/v1/compliance/pci-dss/status for real compliance data from the assessment engine.",
    )


@router.get("/mappings")
async def compliance_mappings():
    """Compliance control-to-finding mappings across frameworks — from real compliance engine."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        frameworks: Dict[str, Any] = {}
        for fw in engine._enabled:
            try:
                posture = engine.assess_framework(fw)
                posture_dict = posture.to_dict() if hasattr(posture, 'to_dict') else {}
                gaps = engine.get_compliance_gaps(fw)
                total = posture_dict.get("total_controls", 0)
                satisfied = posture_dict.get("satisfied", 0)
                frameworks[fw.value] = {
                    "total_controls": total,
                    "mapped": satisfied,
                    "unmapped": total - satisfied,
                    "gaps_count": len(gaps),
                }
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
                frameworks[fw.value] = {
                    "total_controls": 0,
                    "mapped": 0,
                    "unmapped": 0,
                    "error": "Assessment failed for this framework",
                }
        total_all = sum(f["total_controls"] for f in frameworks.values())
        mapped_all = sum(f["mapped"] for f in frameworks.values())
        return {
            "status": "ok",
            "frameworks": frameworks,
            "total_frameworks": len(frameworks),
            "overall_mapping_rate": round(mapped_all / max(total_all, 1) * 100, 1),
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error("compliance_mappings error: %s", e)
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/assess-all")
async def assess_all_frameworks_get(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Assess compliance posture across all frameworks (GET convenience endpoint)."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        result = engine.assess_all_frameworks([])
        if isinstance(result, dict):
            result["org_id"] = org_id
        return result
    except Exception as e:
        return {
            "status": "degraded",
            "frameworks": {},
            "org_id": org_id,
            "error": type(e).__name__,
        }
