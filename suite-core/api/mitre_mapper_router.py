"""
FixOps MITRE ATT&CK Application-Layer Mapping API Router.

Maps application vulnerability scanner findings to MITRE ATT&CK v14
techniques and tactics. Supports CWE IDs, CVE IDs, and text-based matching.

All mapping data is embedded — no external API calls required (air-gapped safe).

Endpoints:
    POST /api/v1/mitre/map-findings     — Map list of findings to ATT&CK techniques
    GET  /api/v1/mitre/techniques       — List all techniques with metadata
    GET  /api/v1/mitre/tactics          — List all 14 ATT&CK tactics
    POST /api/v1/mitre/navigator-json   — Generate ATT&CK Navigator layer JSON
    POST /api/v1/mitre/kill-chain       — Kill chain coverage analysis
    GET  /api/v1/mitre/cwe/{cwe_id}     — Get technique mappings for a CWE
    GET  /api/v1/mitre/health           — Health check
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/mitre", tags=["MITRE ATT&CK"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_mapper():
    """Lazy-load the MITRE mapper singleton."""
    from core.mitre_mapper import get_mitre_mapper
    return get_mitre_mapper()


def _finding_result_to_dict(fr) -> Dict[str, Any]:
    """Convert a FindingMappingResult dataclass to a JSON-serializable dict."""
    return {
        "finding_id": fr.finding_id,
        "finding_title": fr.finding_title,
        "cwe_id": fr.cwe_id,
        "cve_ids": fr.cve_ids,
        "primary_tactic": fr.primary_tactic,
        "risk_score": fr.risk_score,
        "techniques": [
            {
                "technique_id": tm.technique_id,
                "technique_name": tm.technique_name,
                "tactic_ids": tm.tactic_ids,
                "tactic_names": tm.tactic_names,
                "confidence": tm.confidence,
                "source": tm.source,
                "source_ref": tm.source_ref,
                "rationale": tm.rationale,
                "technique_url": tm.technique_url,
            }
            for tm in fr.techniques
        ],
    }


def _kc_to_dict(kc) -> Dict[str, Any]:
    """Convert a KillChainCoverage dataclass to a dict."""
    return {
        "tactic_id": kc.tactic_id,
        "tactic_name": kc.tactic_name,
        "covered": kc.covered,
        "technique_count": kc.technique_count,
        "techniques": kc.techniques,
        "highest_confidence": kc.highest_confidence,
    }


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class FindingInput(BaseModel):
    """A single security finding from a scanner."""

    id: Optional[str] = Field(None, description="Finding ID")
    title: str = Field(..., description="Finding title or name")
    description: Optional[str] = Field(None, description="Finding description")
    severity: Optional[str] = Field(
        "medium",
        description="Severity: critical, high, medium, low, info",
    )
    cwe_id: Optional[Any] = Field(
        None,
        description="CWE ID (e.g., 'CWE-89', '89', 89, 'cwe-89')",
    )

    @validator("cwe_id", pre=True, always=True)
    def coerce_cwe_id(cls, v):
        if v is None:
            return v
        return str(v)

    cve_ids: Optional[List[str]] = Field(
        default_factory=list,
        description="List of CVE IDs (e.g., ['CVE-2021-44228'])",
    )
    cve_id: Optional[str] = Field(None, description="Single CVE ID (alias for cve_ids)")

    @validator("severity", pre=True, always=True)
    def normalize_severity(cls, v):
        if not v:
            return "medium"
        v = str(v).lower().strip()
        valid = {"critical", "high", "medium", "low", "info", "informational"}
        if v not in valid:
            return "medium"
        return "info" if v == "informational" else v


class MapFindingsRequest(BaseModel):
    """Request to map a list of findings to MITRE ATT&CK techniques."""

    findings: List[FindingInput] = Field(
        ...,
        min_items=1,
        description="List of security findings to map (max 500)",
    )

    @validator("findings")
    def limit_findings(cls, v):
        if len(v) > 500:
            raise ValueError("Maximum 500 findings per request")
        return v


class NavigatorLayerRequest(BaseModel):
    """Request to generate a MITRE ATT&CK Navigator layer JSON."""

    findings: List[FindingInput] = Field(
        ...,
        min_items=1,
        description="Security findings to include in the Navigator layer",
    )
    layer_name: str = Field(
        "FixOps Application Vulnerability Coverage",
        description="Display name for the ATT&CK Navigator layer",
    )
    description: str = Field(
        "Auto-generated by FixOps MITRE ATT&CK Mapper",
        description="Layer description",
    )


class KillChainRequest(BaseModel):
    """Request for kill chain coverage analysis."""

    findings: List[FindingInput] = Field(
        ...,
        min_items=1,
        description="Security findings for kill chain analysis",
    )


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------


class TechniqueMappingResponse(BaseModel):
    technique_id: str
    technique_name: str
    tactic_ids: List[str]
    tactic_names: List[str]
    confidence: float
    source: str
    source_ref: str
    rationale: str
    technique_url: str


class FindingMappingResponse(BaseModel):
    finding_id: str
    finding_title: str
    cwe_id: Optional[str]
    cve_ids: List[str]
    primary_tactic: Optional[str]
    risk_score: float
    techniques: List[TechniqueMappingResponse]


class KillChainCoverageResponse(BaseModel):
    tactic_id: str
    tactic_name: str
    covered: bool
    technique_count: int
    techniques: List[str]
    highest_confidence: float


class MapFindingsResponse(BaseModel):
    session_id: str
    mapped_at: str
    total_findings: int
    total_techniques: int
    total_tactics_covered: int
    coverage_percentage: float
    all_techniques: List[str]
    technique_frequency: Dict[str, int]
    kill_chain_coverage: List[KillChainCoverageResponse]
    finding_results: List[FindingMappingResponse]


class KillChainResponse(BaseModel):
    session_id: str
    mapped_at: str
    total_findings: int
    total_tactics_covered: int
    total_tactics: int
    coverage_percentage: float
    kill_chain_coverage: List[KillChainCoverageResponse]
    summary: Dict[str, Any]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/map-findings",
    summary="Map findings to MITRE ATT&CK techniques",
    response_model=MapFindingsResponse,
)
async def map_findings(req: MapFindingsRequest, org_id: str = Depends(get_org_id)):
    """
    Map a list of application vulnerability scanner findings to MITRE ATT&CK v14
    techniques using CWE IDs, CVE IDs, and text-based matching.

    Returns the full ATT&CK mapping with technique details, kill chain coverage,
    and technique frequency analysis across all findings.
    """
    try:
        mapper = _get_mapper()
        findings_dicts = [f.dict() for f in req.findings]
        result = mapper.map_findings(findings_dicts)

        return MapFindingsResponse(
            session_id=result.session_id,
            mapped_at=result.mapped_at,
            total_findings=result.total_findings,
            total_techniques=result.total_techniques,
            total_tactics_covered=result.total_tactics_covered,
            coverage_percentage=result.coverage_percentage,
            all_techniques=result.all_techniques,
            technique_frequency=result.technique_frequency,
            kill_chain_coverage=[
                KillChainCoverageResponse(**_kc_to_dict(kc))
                for kc in result.kill_chain_coverage
            ],
            finding_results=[
                FindingMappingResponse(**_finding_result_to_dict(fr))
                for fr in result.finding_results
            ],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error mapping findings: %s", exc)
        raise HTTPException(status_code=500, detail="Internal mapping error")


@router.get(
    "/techniques",
    summary="List all MITRE ATT&CK techniques",
)
async def list_techniques(
    tactic_id: Optional[str] = Query(None, description="Filter by tactic ID (e.g., TA0001)"),
    subtechniques: bool = Query(True, description="Include sub-techniques"),
    platform: Optional[str] = Query(None, description="Filter by platform (e.g., Windows, Linux)"),
):
    """
    List all MITRE ATT&CK v14 Enterprise techniques with metadata.

    Optionally filter by tactic ID or platform.
    """
    try:
        mapper = _get_mapper()
        techniques = mapper.list_techniques()

        # Apply filters
        if tactic_id:
            tactic_id_upper = tactic_id.upper()
            techniques = [t for t in techniques if tactic_id_upper in t["tactic_ids"]]

        if not subtechniques:
            techniques = [t for t in techniques if not t["is_subtechnique"]]

        if platform:
            platform_lower = platform.lower()
            techniques = [
                t for t in techniques
                if any(p.lower() == platform_lower for p in t.get("platforms", []))
            ]

        return {
            "total": len(techniques),
            "attack_version": "14",
            "techniques": techniques,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error listing techniques: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


@router.get(
    "/tactics",
    summary="List all 14 MITRE ATT&CK tactics",
)
async def list_tactics(org_id: str = Depends(get_org_id)):
    """
    List all 14 MITRE ATT&CK v14 Enterprise tactics (Reconnaissance through Impact).
    """
    try:
        mapper = _get_mapper()
        return {
            "total": 14,
            "attack_version": "14",
            "tactics": mapper.list_tactics(),
        }
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error listing tactics: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


@router.post(
    "/navigator-json",
    summary="Generate MITRE ATT&CK Navigator layer JSON",
)
async def generate_navigator_json(req: NavigatorLayerRequest, org_id: str = Depends(get_org_id)):
    """
    Generate a MITRE ATT&CK Navigator layer JSON from scanner findings.

    The returned JSON conforms to the ATT&CK Navigator layer schema v4.5 and can
    be imported directly at https://mitre-attack.github.io/attack-navigator/

    Techniques are color-coded by confidence:
    - Red (#d32f2f): High confidence ≥ 80%
    - Orange (#f57c00): Medium confidence 60–79%
    - Yellow (#fbc02d): Lower confidence < 60%
    """
    try:
        mapper = _get_mapper()
        findings_dicts = [f.dict() for f in req.findings]
        layer = mapper.generate_navigator_layer(
            findings=findings_dicts,
            layer_name=req.layer_name,
            description=req.description,
        )
        return {
            "status": "ok",
            "layer_name": req.layer_name,
            "techniques_count": len(layer.get("techniques", [])),
            "navigator_layer": layer,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error generating Navigator JSON: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error generating Navigator layer")


@router.post(
    "/kill-chain",
    summary="Kill chain coverage analysis",
    response_model=KillChainResponse,
)
async def kill_chain_analysis(req: KillChainRequest, org_id: str = Depends(get_org_id)):
    """
    Analyze which MITRE ATT&CK kill chain phases are covered by the provided findings.

    Returns coverage across all 14 tactics with technique details and confidence scores.
    Useful for understanding the attacker's potential kill chain given the discovered
    vulnerabilities.
    """
    try:
        mapper = _get_mapper()
        findings_dicts = [f.dict() for f in req.findings]
        result = mapper.map_findings(findings_dicts)

        covered_tactics = [kc for kc in result.kill_chain_coverage if kc.covered]
        uncovered_tactics = [kc for kc in result.kill_chain_coverage if not kc.covered]

        return KillChainResponse(
            session_id=result.session_id,
            mapped_at=result.mapped_at,
            total_findings=result.total_findings,
            total_tactics_covered=result.total_tactics_covered,
            total_tactics=14,
            coverage_percentage=result.coverage_percentage,
            kill_chain_coverage=[
                KillChainCoverageResponse(**_kc_to_dict(kc))
                for kc in result.kill_chain_coverage
            ],
            summary={
                "covered_phases": [kc.tactic_name for kc in covered_tactics],
                "uncovered_phases": [kc.tactic_name for kc in uncovered_tactics],
                "total_techniques_mapped": result.total_techniques,
                "highest_risk_phase": max(
                    (kc for kc in result.kill_chain_coverage if kc.covered),
                    key=lambda kc: kc.highest_confidence,
                    default=None,
                ) and max(
                    (kc for kc in result.kill_chain_coverage if kc.covered),
                    key=lambda kc: kc.highest_confidence,
                ).tactic_name,
                "most_covered_phase": max(
                    (kc for kc in result.kill_chain_coverage if kc.covered),
                    key=lambda kc: kc.technique_count,
                    default=None,
                ) and max(
                    (kc for kc in result.kill_chain_coverage if kc.covered),
                    key=lambda kc: kc.technique_count,
                ).tactic_name,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=type(exc).__name__)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error in kill chain analysis: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error in kill chain analysis")


@router.get(
    "/cwe/{cwe_id}",
    summary="Get ATT&CK technique mappings for a CWE",
)
async def get_cwe_mapping(cwe_id: str, org_id: str = Depends(get_org_id)):
    """
    Get MITRE ATT&CK technique mappings for a specific CWE ID.

    Accepts formats: '89', 'CWE-89', 'cwe-89'

    Returns all mapped techniques with confidence scores and rationale.
    """
    try:
        mapper = _get_mapper()
        mappings = mapper.get_cwe_mapping(cwe_id)
        if mappings is None:
            raise HTTPException(
                status_code=404,
                detail=f"No ATT&CK technique mappings found for CWE-{cwe_id}. "
                       f"This CWE may not be in the mapping database or the ID may be invalid.",
            )
        return {
            "cwe_id": cwe_id,
            "cwe_url": f"https://cwe.mitre.org/data/definitions/{cwe_id.lstrip('CWEcwe-').lstrip('0') or cwe_id}.html",
            "total_techniques": len(mappings),
            "techniques": mappings,
        }
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("Error fetching CWE mapping for %s: %s", cwe_id, exc)
        raise HTTPException(status_code=500, detail="Internal error")


@router.get(
    "/health",
    summary="MITRE ATT&CK mapper health check",
)
async def health(org_id: str = Depends(get_org_id)):
    """
    Health check for the MITRE ATT&CK mapping engine.

    Returns engine status and capability summary.
    """
    try:
        mapper = _get_mapper()
        techniques = mapper.list_techniques()
        tactics = mapper.list_tactics()

        from core.mitre_mapper import CVE_TO_TECHNIQUES, CWE_TO_TECHNIQUES

        return {
            "status": "healthy",
            "engine": "MITREMapper",
            "attack_version": "14",
            "capabilities": {
                "total_techniques": len(techniques),
                "total_tactics": len(tactics),
                "cwe_mappings": len(CWE_TO_TECHNIQUES),
                "cve_mappings": len(CVE_TO_TECHNIQUES),
                "subtechniques": sum(1 for t in techniques if t["is_subtechnique"]),
                "parent_techniques": sum(1 for t in techniques if not t["is_subtechnique"]),
                "air_gapped_safe": True,
                "external_api_calls": False,
            },
            "supported_sources": ["cwe_id", "cve_ids", "title_text_match", "description_text_match"],
            "output_formats": ["json", "mitre_navigator_layer_v4.5"],
        }
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.exception("MITRE mapper health check failed: %s", exc)
        return {
            "status": "unhealthy",
            "engine": "MITREMapper",
            "error": str(exc),
        }
