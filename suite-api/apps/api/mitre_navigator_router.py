"""MITRE ATT&CK Navigator API Router for ALDECI.

8 endpoints under /api/v1/mitre providing full ATT&CK Navigator functionality:
- GET  /matrix          — full ATT&CK matrix (14 tactics + 200+ techniques)
- GET  /coverage        — detection coverage per tactic + overall score
- GET  /coverage/{id}   — coverage for a specific technique
- GET  /gaps            — gap analysis prioritized by real-world attack frequency
- GET  /threat-groups   — list all threat groups with overlay stats
- GET  /threat-groups/{id}/overlay — coverage overlay for a specific threat actor
- POST /layers          — create a custom Navigator layer
- GET  /layers/coverage — export ALDECI coverage as ATT&CK Navigator JSON layer
- GET  /layers/threat-group/{id} — export threat group layer as Navigator JSON
- GET  /detection-rules — all detection rules; filter by technique or engine
- GET  /health          — health check
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from core.mitre_navigator import (
    get_mitre_navigator_engine,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/mitre", tags=["mitre-navigator"])


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class CustomAnnotation(BaseModel):
    technique_id: str = Field(..., description="MITRE technique ID (e.g. T1059.001)")
    score: float = Field(0.0, ge=0.0, le=100.0, description="Score 0-100")
    color: str = Field("", description="Hex color code")
    comment: str = Field("", description="Annotation comment")
    enabled: bool = Field(True, description="Whether technique is enabled in the layer")
    metadata: List[Dict[str, str]] = Field(default_factory=list, description="Key-value metadata")


class CreateLayerRequest(BaseModel):
    name: str = Field(..., description="Layer name")
    description: str = Field("", description="Layer description")
    annotations: List[CustomAnnotation] = Field(..., description="Per-technique annotations")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/matrix")
async def get_attack_matrix(
    tactic_id: Optional[str] = Query(None, description="Filter by tactic ID (e.g. TA0001)"),
    include_subtechniques: bool = Query(True, description="Include sub-techniques"),
    severity: Optional[str] = Query(None, description="Filter by severity: low/medium/high/critical"),
):
    """Return the full MITRE ATT&CK Enterprise matrix.

    Returns all 14 tactics and 200+ techniques with IDs, names, descriptions,
    platforms, data sources, and detection hints.
    """
    engine = get_mitre_navigator_engine()
    tactics = engine.get_tactics()

    if tactic_id:
        tactic_match = next((t for t in tactics if t.id == tactic_id), None)
        if not tactic_match:
            raise HTTPException(status_code=404, detail=f"Tactic {tactic_id} not found")
        tactics = [tactic_match]

    result = []
    for tactic in tactics:
        techs = engine.get_techniques_for_tactic(tactic.id)
        if not include_subtechniques:
            techs = [t for t in techs if not t.is_subtechnique]
        if severity:
            techs = [t for t in techs if t.severity == severity]
        result.append({
            "tactic": tactic.to_dict(),
            "techniques": [t.to_dict() for t in techs],
            "technique_count": len(techs),
        })

    total_techniques = sum(r["technique_count"] for r in result)
    return {
        "domain": "enterprise-attack",
        "version": "14.1",
        "tactic_count": len(result),
        "technique_count": total_techniques,
        "matrix": result,
    }


@router.get("/coverage")
async def get_coverage_summary(
    tactic_id: Optional[str] = Query(None, description="Get coverage for a specific tactic"),
):
    """Return detection coverage summary.

    Shows coverage percentage per tactic and overall score. Coverage levels:
    - full: ALDECI engine(s) fully detect this technique
    - partial: Some detection exists but gaps remain
    - none: No detection coverage
    """
    engine = get_mitre_navigator_engine()

    if tactic_id:
        try:
            tactic_cov = engine.get_tactic_coverage(tactic_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        return {"tactic_coverage": tactic_cov.to_dict()}

    # All tactics
    overall = engine.get_overall_coverage_score()
    tactic_coverages = []
    for tactic in engine.get_tactics():
        tc = engine.get_tactic_coverage(tactic.id)
        tactic_coverages.append(tc.to_dict())

    return {
        "overall": overall,
        "by_tactic": tactic_coverages,
    }


@router.get("/coverage/{technique_id}")
async def get_technique_coverage(technique_id: str):
    """Return detection coverage detail for a specific technique."""
    engine = get_mitre_navigator_engine()

    tech = engine.get_technique(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")

    cov = engine.get_coverage(technique_id)
    rule = engine.get_detection_rule(technique_id)

    return {
        "technique": tech.to_dict(),
        "coverage": cov.to_dict(),
        "detection_rule": rule.to_dict() if rule else None,
    }


@router.get("/gaps")
async def get_gap_analysis(
    limit: int = Query(50, ge=1, le=200, description="Max gaps to return"),
    severity: Optional[str] = Query(None, description="Filter gaps by severity"),
    tactic_id: Optional[str] = Query(None, description="Filter gaps by tactic"),
):
    """Return gap analysis: uncovered techniques prioritized by real-world attack frequency.

    Higher frequency_score = seen more often in real attacks = higher priority to cover.
    """
    engine = get_mitre_navigator_engine()
    gaps = engine.get_gap_analysis(limit=limit)

    if severity:
        gaps = [g for g in gaps if g.severity == severity]
    if tactic_id:
        gaps = [g for g in gaps if tactic_id in g.tactic_ids]

    return {
        "total_gaps": len(gaps),
        "filter_severity": severity,
        "filter_tactic": tactic_id,
        "gaps": [g.to_dict() for g in gaps],
        "summary": {
            "critical_gaps": len([g for g in gaps if g.severity == "critical"]),
            "high_gaps": len([g for g in gaps if g.severity == "high"]),
            "medium_gaps": len([g for g in gaps if g.severity == "medium"]),
            "low_gaps": len([g for g in gaps if g.severity == "low"]),
        },
    }


@router.get("/threat-groups")
async def list_threat_groups():
    """List all known threat groups with ALDECI coverage overlay stats."""
    engine = get_mitre_navigator_engine()
    overlays = engine.get_all_threat_group_overlays()

    return {
        "total": len(overlays),
        "threat_groups": [o.to_dict() for o in overlays],
        "summary": {
            "critical_risk": len([o for o in overlays if o.risk_level == "critical"]),
            "high_risk": len([o for o in overlays if o.risk_level == "high"]),
            "medium_risk": len([o for o in overlays if o.risk_level == "medium"]),
            "low_risk": len([o for o in overlays if o.risk_level == "low"]),
        },
    }


@router.get("/threat-groups/{group_id}")
async def get_threat_group_detail(group_id: str):
    """Return detailed info + coverage overlay for a specific threat group."""
    engine = get_mitre_navigator_engine()

    group = engine.get_threat_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail=f"Threat group {group_id} not found")

    try:
        overlay = engine.get_threat_group_overlay(group_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    # Enrich blind spots with technique details
    blind_spot_details = []
    for tid in overlay.blind_spots:
        tech = engine.get_technique(tid)
        if tech:
            blind_spot_details.append({
                "id": tid,
                "name": tech.name,
                "severity": tech.severity,
                "frequency_score": tech.frequency_score,
                "tactic_ids": tech.tactic_ids,
            })

    return {
        "group": group.to_dict(),
        "overlay": overlay.to_dict(),
        "blind_spot_details": sorted(blind_spot_details, key=lambda x: x["frequency_score"], reverse=True),
    }


@router.get("/threat-groups/{group_id}/layer")
async def export_threat_group_layer(group_id: str):
    """Export ATT&CK Navigator JSON layer for a threat group's TTP coverage."""
    engine = get_mitre_navigator_engine()

    if not engine.get_threat_group(group_id):
        raise HTTPException(status_code=404, detail=f"Threat group {group_id} not found")

    try:
        layer = engine.create_threat_group_layer(group_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return layer.to_dict()


@router.get("/layers/coverage")
async def export_coverage_layer(
    name: str = Query("ALDECI Detection Coverage", description="Layer name"),
):
    """Export ALDECI coverage as ATT&CK Navigator JSON layer.

    The returned JSON can be loaded directly into https://mitre-attack.github.io/attack-navigator/
    """
    engine = get_mitre_navigator_engine()
    layer = engine.create_coverage_layer(name=name)
    return layer.to_dict()


@router.post("/layers")
async def create_custom_layer(request: CreateLayerRequest):
    """Create a custom ATT&CK Navigator layer with user-defined annotations."""
    engine = get_mitre_navigator_engine()

    annotations_dicts = [a.model_dump() for a in request.annotations]
    layer = engine.create_custom_layer(
        name=request.name,
        description=request.description,
        annotations=annotations_dicts,
    )

    return {
        "message": "Custom layer created",
        "layer_name": layer.name,
        "technique_count": len(layer.techniques),
        "layer": layer.to_dict(),
    }


@router.get("/layers")
async def list_custom_layers():
    """List all saved custom layers."""
    engine = get_mitre_navigator_engine()
    names = engine.list_custom_layers()
    return {
        "total": len(names),
        "layers": names,
    }


@router.get("/layers/{layer_name}")
async def get_custom_layer(layer_name: str):
    """Retrieve a saved custom layer by name."""
    engine = get_mitre_navigator_engine()
    layer = engine.get_custom_layer(layer_name)
    if not layer:
        raise HTTPException(status_code=404, detail=f"Layer '{layer_name}' not found")
    return layer.to_dict()


@router.get("/detection-rules")
async def get_detection_rules(
    technique_id: Optional[str] = Query(None, description="Filter by technique ID"),
    engine_name: Optional[str] = Query(None, description="Filter by ALDECI engine name"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
):
    """Return detection rules for ATT&CK techniques.

    Each rule specifies: what to look for, which data sources, which ALDECI engine
    to use, a query hint, and false positive guidance.
    """
    nav_engine = get_mitre_navigator_engine()

    if technique_id:
        rule = nav_engine.get_detection_rule(technique_id)
        if not rule:
            raise HTTPException(
                status_code=404,
                detail=f"No detection rule for technique {technique_id}",
            )
        return {"rule": rule.to_dict()}

    if engine_name:
        rules = nav_engine.get_detection_rules_for_engine(engine_name)
    else:
        rules = nav_engine.get_all_detection_rules()

    if severity:
        rules = [r for r in rules if r.severity == severity]

    return {
        "total": len(rules),
        "filter_engine": engine_name,
        "filter_severity": severity,
        "rules": [r.to_dict() for r in rules],
    }


@router.get("/health")
async def mitre_navigator_health():
    """Health check for MITRE ATT&CK Navigator engine."""
    engine = get_mitre_navigator_engine()
    overall = engine.get_overall_coverage_score()

    return {
        "status": "healthy",
        "engine": "MITRENavigatorEngine",
        "tactics": len(engine.get_tactics()),
        "techniques": len(engine.get_all_techniques()),
        "threat_groups": len(engine.get_threat_groups()),
        "detection_rules": len(engine.get_all_detection_rules()),
        "coverage_score_pct": overall["coverage_score_pct"],
        "coverage_grade": overall["grade"],
        "features": [
            "full_attack_matrix",
            "detection_coverage_mapping",
            "coverage_scoring",
            "gap_analysis",
            "threat_group_overlay",
            "custom_layer_creation",
            "navigator_json_export",
            "detection_rules",
        ],
    }
