"""
TrustGraph Integration Router — HTTP endpoints wiring ALL ALDECI security
engines into the TrustGraph knowledge graph backbone.

Routes:
    POST /api/v1/graph/index              — Index findings from any engine
    GET  /api/v1/graph/query/{template}   — Run pre-built GraphRAG query template
    GET  /api/v1/graph/impact/{entity_id} — Blast radius / impact analysis
    GET  /api/v1/graph/correlate          — Cross-domain correlation (CVE or finding)
    GET  /api/v1/graph/attack-paths       — Attack path analysis with enrichment

All endpoints are org-scoped (org_id query param, default="default").
TrustGraph unavailability is returned as available=False, never a 500.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/graph", tags=["TrustGraph Integration"])


# ============================================================================
# Request / Response Models
# ============================================================================


class IndexFindingsRequest(BaseModel):
    """Index one or more findings from any ALDECI security engine."""

    findings: List[Dict[str, Any]] = Field(
        ...,
        description="List of finding dicts. Each must include 'engine' key.",
        min_length=1,
    )
    org_id: Optional[str] = Field(default="default", description="Tenant org ID")
    batch: bool = Field(
        default=False,
        description="If true, use batch indexer with dedup/merge. If false, index individually.",
    )


class IndexFindingsResponse(BaseModel):
    """Response after indexing findings."""

    indexed: int
    entity_ids: List[str]
    deduplicated: int = 0
    merged: int = 0
    failed: int = 0
    errors: List[str] = Field(default_factory=list)
    status: str


class QueryTemplateResponse(BaseModel):
    """Response from a pre-built GraphRAG query template."""

    template: str
    available: bool
    data: Dict[str, Any]


class ImpactResponse(BaseModel):
    """Blast radius analysis response."""

    entity_id: str
    available: bool
    blast_radius: int
    upstream_dependencies: List[Dict[str, Any]] = Field(default_factory=list)
    downstream_consumers: List[Dict[str, Any]] = Field(default_factory=list)
    data_flows: List[Dict[str, Any]] = Field(default_factory=list)
    compliance_impact: List[Dict[str, Any]] = Field(default_factory=list)
    risk_weight: float = 0.0
    summary: str = ""


class CorrelationResponse(BaseModel):
    """Cross-domain correlation response."""

    query: str
    query_type: str
    available: bool
    result: Dict[str, Any]


# ============================================================================
# Dependency helpers
# ============================================================================


def _get_indexer(org_id: str = "default"):
    from core.trustgraph_integrations import UniversalFindingIndexer
    return UniversalFindingIndexer(org_id=org_id)


def _get_batch_indexer(org_id: str = "default"):
    from core.trustgraph_integrations import BatchIndexer
    return BatchIndexer(org_id=org_id)


def _get_graphrag(org_id: str = "default"):
    from core.trustgraph_integrations import GraphRAGQueries
    return GraphRAGQueries(org_id=org_id)


def _get_impact_analyzer(org_id: str = "default"):
    from core.trustgraph_integrations import ImpactAnalyzer
    return ImpactAnalyzer(org_id=org_id)


def _get_correlator(org_id: str = "default"):
    from core.trustgraph_integrations import CrossDomainCorrelator
    return CrossDomainCorrelator(org_id=org_id)


def _get_enricher(org_id: str = "default"):
    from core.trustgraph_integrations import AttackPathEnricher
    return AttackPathEnricher(org_id=org_id)


# ============================================================================
# POST /api/v1/graph/index
# ============================================================================


@router.post("/index", response_model=IndexFindingsResponse)
async def index_findings(req: IndexFindingsRequest) -> Dict[str, Any]:
    """Index findings from ANY ALDECI security engine into TrustGraph.

    Accepts findings from SAST, DAST, SCA, CSPM, RASP, ASM, threat intel
    feeds, and any other engine. Each finding must include at minimum an
    'engine' field.

    Set batch=true to enable deduplication and merging (same CVE from
    multiple scanners → single entity, multiple scanner relationships).

    Args:
        req: List of findings with engine metadata and optional batch flag.

    Returns:
        Count of indexed findings, entity IDs, dedup/merge stats.
    """
    org_id = req.org_id or "default"

    try:
        if req.batch:
            indexer = _get_batch_indexer(org_id=org_id)
            result = indexer.index_batch(req.findings)
            return {
                "indexed": result.indexed,
                "entity_ids": result.entity_ids,
                "deduplicated": result.deduplicated,
                "merged": result.merged,
                "failed": result.failed,
                "errors": result.errors,
                "status": "batch_indexed",
            }
        else:
            indexer = _get_indexer(org_id=org_id)
            entity_ids: List[str] = []
            errors: List[str] = []
            for finding in req.findings:
                try:
                    eid = indexer.index(finding)
                    entity_ids.append(eid)
                except Exception as exc:
                    errors.append(str(exc))
            return {
                "indexed": len(entity_ids),
                "entity_ids": entity_ids,
                "deduplicated": 0,
                "merged": 0,
                "failed": len(errors),
                "errors": errors,
                "status": "indexed",
            }
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/index failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/query/{template}
# ============================================================================


@router.get("/query/{template}")
async def run_query_template(
    template: str,
    org_id: str = Query(default="default", description="Tenant org ID"),
    limit: int = Query(default=20, ge=1, le=200, description="Max results"),
    framework: Optional[str] = Query(default=None, description="Framework filter for compliance_gaps"),
    asset_id: Optional[str] = Query(default=None, description="Asset ID scope for exposure_chain"),
) -> Dict[str, Any]:
    """Run a pre-built GraphRAG query template.

    Available templates:
    - **top_risks**: Top-N highest risk findings across all engines
    - **exposure_chain**: Internet-exposed assets → findings → compliance impact
    - **compliance_gaps**: Controls with open findings that violate them
    - **attack_surface**: All assets with open findings, grouped by type/exposure
    - **threat_landscape**: Active threat actors, campaigns, TTPs, targeted assets

    Args:
        template: Template name (see list above)
        org_id: Tenant org ID
        limit: Max results returned by the template
        framework: Framework filter for compliance_gaps (e.g. NIST, SOC2, PCI)
        asset_id: Asset scope for exposure_chain template

    Returns:
        Template-specific structured JSON.
    """
    from core.trustgraph_integrations import _QUERY_TEMPLATES

    if template not in _QUERY_TEMPLATES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown template '{template}'. Valid: {sorted(_QUERY_TEMPLATES)}",
        )

    try:
        graphrag = _get_graphrag(org_id=org_id)

        kwargs: Dict[str, Any] = {"limit": limit}
        if template == "compliance_gaps" and framework:
            kwargs["framework"] = framework
        if template == "exposure_chain" and asset_id:
            kwargs["asset_id"] = asset_id

        result = graphrag.run_template(template, **kwargs)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/query/%s failed: %s", template, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/impact/{entity_id}
# ============================================================================


@router.get("/impact/{entity_id}", response_model=ImpactResponse)
async def get_impact_analysis(
    entity_id: str,
    depth: int = Query(default=2, ge=1, le=3, description="Traversal depth"),
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """Blast radius / impact analysis for any entity in the graph.

    Calculates:
    - Upstream dependencies (what this entity depends on)
    - Downstream consumers (what depends on this entity)
    - Data flows (zone and component relationships)
    - Compliance impact (violated or mitigated controls)
    - Aggregate risk weight

    Works for any entity type: finding, asset, CVE, control, actor, etc.

    Args:
        entity_id: Entity to analyze (graph node ID)
        depth: Graph traversal depth (1-3, default 2)
        org_id: Tenant org ID

    Returns:
        ImpactResult with blast radius metrics and structured JSON.
    """
    try:
        analyzer = _get_impact_analyzer(org_id=org_id)
        result = analyzer.blast_radius(entity_id=entity_id, depth=depth)
        return result.model_dump()
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/impact/%s failed: %s", entity_id, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/correlate
# ============================================================================


@router.get("/correlate", response_model=CorrelationResponse)
async def cross_domain_correlate(
    cve_id: Optional[str] = Query(
        default=None,
        description="CVE to correlate (e.g. CVE-2024-1234)",
    ),
    finding_id: Optional[str] = Query(
        default=None,
        description="Finding entity ID to correlate",
    ),
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """Cross-domain correlation across all ALDECI security engines.

    Given a CVE, shows: which containers use it → which K8s namespaces
    → which data they process → which compliance controls are affected
    → dollar risk estimate.

    Given a finding_id, shows: CVEs exploited, affected assets, violated
    controls, detecting scanners.

    Exactly one of cve_id or finding_id must be provided.

    Args:
        cve_id: CVE identifier for CVE-centric correlation.
        finding_id: Finding entity ID for finding-centric correlation.
        org_id: Tenant org ID.

    Returns:
        Cross-domain correlation chain with dollar risk estimate.
    """
    if not cve_id and not finding_id:
        raise HTTPException(
            status_code=400,
            detail="Provide at least one of: cve_id, finding_id",
        )

    try:
        correlator = _get_correlator(org_id=org_id)

        if cve_id:
            result = correlator.correlate_cve(cve_id)
            return {
                "query": cve_id,
                "query_type": "cve",
                "available": result.available,
                "result": result.model_dump(),
            }
        else:
            raw = correlator.correlate_finding(finding_id)  # type: ignore[arg-type]
            return {
                "query": finding_id,
                "query_type": "finding",
                "available": raw.get("available", False),
                "result": raw,
            }
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/correlate failed cve=%s finding=%s: %s", cve_id, finding_id, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/attack-paths
# ============================================================================


@router.get("/attack-paths")
async def get_attack_paths(
    source: Optional[str] = Query(default=None, description="Source / entry-point entity ID (exposed asset)"),
    target: Optional[str] = Query(default=None, description="Target / high-value entity ID"),
    enrich: bool = Query(
        default=True,
        description="If true, enrich each path node with vuln/config context from all engines",
    ),
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """Attack path analysis using graph traversal.

    Finds all graph paths from source to target (BFS, max depth 4).
    When enrich=true, each asset node in each path is enriched with:
    - Known vulnerabilities (SCA findings)
    - Misconfigurations (CSPM findings)
    - Runtime blocks (RASP findings)
    - Aggregate risk score

    Useful for modeling lateral movement and supply chain attack vectors.

    Args:
        source: Source entity ID (typically an internet-exposed asset)
        target: Target entity ID (typically a high-value asset)
        enrich: Whether to enrich path nodes with cross-engine context
        org_id: Tenant org ID

    Returns:
        Dict with paths (enriched if requested), path count, summary.
    """
    # When called without source/target, return an overview of known attack paths
    if not source or not target:
        try:
            from core.trustgraph_backbone import GraphRAGEnhanced
            graphrag = GraphRAGEnhanced(org_id=org_id)
            if hasattr(graphrag, "get_all_attack_paths"):
                paths = graphrag.get_all_attack_paths()
            else:
                paths = []
            return {"paths": paths, "total": len(paths), "org_id": org_id}
        except Exception:
            return {"paths": [], "total": 0, "org_id": org_id}

    try:
        if enrich:
            enricher = _get_enricher(org_id=org_id)
            result = enricher.find_attack_paths_from_exposure(
                exposed_asset_id=source,
                target_asset_id=target,
            )
        else:
            from core.trustgraph_backbone import GraphRAGEnhanced
            graphrag = GraphRAGEnhanced(org_id=org_id)
            result = graphrag.query_attack_path(source_id=source, target_id=target)

        return result
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/attack-paths failed %s->%s: %s", source, target, exc)
        raise HTTPException(status_code=500, detail=str(exc))
