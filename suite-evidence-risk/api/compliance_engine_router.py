"""Compliance Engine Router (V10 — CTEM Full Loop).

Full compliance auto-mapping engine with framework support for SOC2, PCI DSS 4.0,
ISO 27001:2022, NIST 800-53 R5, NIST CSF 2.0, OWASP ASVS 4.0.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
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
    except Exception as e:
        return {
            "status": "degraded",
            "engine": "compliance-engine",
            "error": str(e),
        }


@router.get("/frameworks")
async def list_frameworks() -> Dict[str, Any]:
    """List all supported compliance frameworks."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        return {"frameworks": engine.get_supported_frameworks()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/map-findings")
async def map_findings(req: MapFindingsRequest) -> Dict[str, Any]:
    """Map findings to compliance controls."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        mappings = engine.map_findings_to_controls(req.findings)
        return {"mappings": mappings, "total": len(mappings)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/assess")
async def assess_framework(req: AssessFrameworkRequest) -> Dict[str, Any]:
    """Assess compliance posture for a specific framework."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        result = engine.assess_framework(req.framework, req.findings)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/assess-all")
async def assess_all_frameworks(req: MapFindingsRequest) -> Dict[str, Any]:
    """Assess compliance posture across all frameworks."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        result = engine.assess_all_frameworks(req.findings)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/gaps")
async def get_compliance_gaps(
    framework: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Get compliance gaps (controls without evidence)."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        gaps = engine.get_compliance_gaps(framework)
        return {"gaps": gaps, "total": len(gaps)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audit-bundle")
async def generate_audit_bundle(
    framework: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Generate a tamper-evident audit bundle."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        bundle = engine.generate_audit_bundle(framework)
        return bundle
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cwe-mapping/{cwe_id}")
async def get_cwe_mapping(cwe_id: str) -> Dict[str, Any]:
    """Get compliance controls mapped to a specific CWE."""
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        mapping = engine.get_cwe_control_mapping(cwe_id)
        return {"cwe_id": cwe_id, "controls": mapping}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
