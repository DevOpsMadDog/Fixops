"""
MITRE ATT&CK Coverage Router — /api/v1/mitre/coverage-analysis

4 endpoints that wrap MITREATTACKMapper for higher-level coverage analysis:

    POST /api/v1/mitre/map          — map findings to techniques
    GET  /api/v1/mitre/coverage     — coverage report across a set of findings
    GET  /api/v1/mitre/gaps         — uncovered techniques prioritised by prevalence
    GET  /api/v1/mitre/heatmap      — ATT&CK Navigator heatmap layer data

Note: the existing mitre_mapper_router.py and mitre_navigator_router.py are
preserved. This router uses a separate mapper class (MITREATTACKMapper) that
exposes the coverage/gap/heatmap API described in the task spec.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/mitre", tags=["MITRE ATT&CK Coverage"])


# ---------------------------------------------------------------------------
# Lazy singleton access
# ---------------------------------------------------------------------------


def _get_mapper():
    from core.mitre_attack_mapper import get_mitre_attack_mapper
    return get_mitre_attack_mapper()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class FindingItem(BaseModel):
    """A single finding submitted for ATT&CK mapping."""

    id: Optional[str] = Field(None, description="Finding ID")
    title: str = Field(..., description="Finding title")
    description: Optional[str] = Field(None, description="Finding description")
    cwe_id: Optional[Any] = Field(None, description="CWE ID (e.g. 'CWE-89', '89', 89)")
    severity: Optional[str] = Field("medium", description="critical/high/medium/low/info")

    @field_validator("cwe_id", mode="before")
    @classmethod
    def coerce_cwe(cls, v):
        return str(v) if v is not None else None

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v):
        if not v:
            return "medium"
        v = str(v).lower().strip()
        return v if v in {"critical", "high", "medium", "low", "info"} else "medium"


class MapRequest(BaseModel):
    findings: List[FindingItem] = Field(..., min_length=1, description="Findings to map (max 500)")

    @field_validator("findings")
    @classmethod
    def cap_findings(cls, v):
        if len(v) > 500:
            raise ValueError("Maximum 500 findings per request")
        return v


class CoverageRequest(BaseModel):
    findings: List[FindingItem] = Field(..., min_length=1)

    @field_validator("findings")
    @classmethod
    def cap_findings(cls, v):
        if len(v) > 500:
            raise ValueError("Maximum 500 findings per request")
        return v


class GapsRequest(BaseModel):
    covered_technique_ids: List[str] = Field(
        ..., description="Technique IDs already covered (e.g. ['T1190', 'T1059'])"
    )


class HeatmapRequest(BaseModel):
    findings: List[FindingItem] = Field(..., min_length=1)

    @field_validator("findings")
    @classmethod
    def cap_findings(cls, v):
        if len(v) > 500:
            raise ValueError("Maximum 500 findings per request")
        return v


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _mapping_to_dict(m) -> Dict[str, Any]:
    return {
        "technique_id": m.technique_id,
        "technique_name": m.technique_name,
        "tactic": m.tactic,
        "confidence": m.confidence,
        "finding_id": m.finding_id,
        "match_source": m.match_source,
        "match_ref": m.match_ref,
    }


def _coverage_to_dict(cov) -> Dict[str, Any]:
    return {
        "total_techniques_in_db": cov.total_techniques_in_db,
        "covered_technique_count": len(cov.covered_technique_ids),
        "covered_technique_ids": sorted(cov.covered_technique_ids),
        "covered_tactic_count": len(cov.covered_tactic_ids),
        "covered_tactic_ids": sorted(cov.covered_tactic_ids),
        "technique_coverage_pct": cov.technique_coverage_pct,
        "tactic_coverage_pct": cov.tactic_coverage_pct,
        "tactic_breakdown": cov.tactic_breakdown,
        "technique_frequency": cov.technique_frequency,
    }


def _gap_to_dict(g) -> Dict[str, Any]:
    return {
        "technique_id": g.technique_id,
        "technique_name": g.technique_name,
        "tactic": g.tactic,
        "tactic_id": g.tactic_id,
        "priority": g.priority,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/map",
    summary="Map findings to MITRE ATT&CK techniques",
)
async def map_findings(req: MapRequest, org_id: str = Depends(get_org_id)):
    """Map a list of security findings to MITRE ATT&CK v14 techniques.

    Uses CWE ID matching (highest confidence) and keyword matching on
    title/description. Returns per-finding technique lists sorted by
    confidence (HIGH → MED → LOW).
    """
    try:
        mapper = _get_mapper()
        results = []
        for finding in req.findings:
            fd = finding.dict()
            mappings = mapper.map_finding_to_techniques(fd)
            results.append({
                "finding_id": finding.id,
                "finding_title": finding.title,
                "cwe_id": finding.cwe_id,
                "technique_count": len(mappings),
                "techniques": [_mapping_to_dict(m) for m in mappings],
            })
        return {
            "total_findings": len(results),
            "results": results,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (OSError, KeyError, RuntimeError) as exc:
        logger.exception("Error in /mitre/map: %s", exc)
        raise HTTPException(status_code=500, detail="Internal mapping error")


@router.post(
    "/coverage",
    summary="ATT&CK coverage report for a set of findings",
)
async def coverage_report(req: CoverageRequest, org_id: str = Depends(get_org_id)):
    """Calculate ATT&CK matrix coverage across all provided findings.

    Returns the percentage of techniques and tactics covered, a per-tactic
    breakdown, and technique frequency counts.
    """
    try:
        mapper = _get_mapper()
        findings = [f.dict() for f in req.findings]
        cov = mapper.calculate_coverage(findings)
        return _coverage_to_dict(cov)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (OSError, KeyError, RuntimeError) as exc:
        logger.exception("Error in /mitre/coverage: %s", exc)
        raise HTTPException(status_code=500, detail="Internal coverage error")


@router.post(
    "/gaps",
    summary="ATT&CK techniques not covered by current findings",
)
async def gaps_report(req: GapsRequest, org_id: str = Depends(get_org_id)):
    """Identify ATT&CK techniques not covered by any finding.

    Pass the set of technique IDs already detected. Returns uncovered
    techniques sorted by real-world prevalence (HIGH priority first).
    """
    try:
        mapper = _get_mapper()
        covered: Set[str] = set(req.covered_technique_ids)
        gaps = mapper.identify_gaps(covered)
        return {
            "total_gaps": len(gaps),
            "high_priority_gaps": sum(1 for g in gaps if g.priority == "HIGH"),
            "med_priority_gaps": sum(1 for g in gaps if g.priority == "MED"),
            "low_priority_gaps": sum(1 for g in gaps if g.priority == "LOW"),
            "gaps": [_gap_to_dict(g) for g in gaps],
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (OSError, KeyError, RuntimeError) as exc:
        logger.exception("Error in /mitre/gaps: %s", exc)
        raise HTTPException(status_code=500, detail="Internal gap analysis error")


@router.post(
    "/heatmap",
    summary="ATT&CK Navigator heatmap data from findings",
)
async def heatmap_data(req: HeatmapRequest, org_id: str = Depends(get_org_id)):
    """Generate ATT&CK Navigator layer JSON from security findings.

    The returned JSON conforms to ATT&CK Navigator layer schema v4.5 and
    can be imported at https://mitre-attack.github.io/attack-navigator/
    """
    try:
        mapper = _get_mapper()
        findings = [f.dict() for f in req.findings]
        layer = mapper.generate_heatmap_data(findings)
        return {
            "status": "ok",
            "techniques_scored": len(layer.get("techniques", [])),
            "layer": layer,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (OSError, KeyError, RuntimeError) as exc:
        logger.exception("Error in /mitre/heatmap: %s", exc)
        raise HTTPException(status_code=500, detail="Internal heatmap error")
