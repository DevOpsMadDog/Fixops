"""
FixOps Fuzzy Asset Identity REST API — Step 3 of the ALdeci Brain Data Flow.

Resolves asset identity confusion across multiple scanner outputs.
Provides registration, alias management, resolution, and statistics.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.event_bus import Event, EventType, get_event_bus
from core.knowledge_brain import get_brain
from core.services.fuzzy_identity import get_fuzzy_resolver
from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/identity", tags=["fuzzy-identity"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class RegisterCanonicalRequest(BaseModel):
    canonical_id: str = Field(..., description="Unique canonical asset identifier")
    org_id: Optional[str] = None
    properties: Optional[Dict[str, Any]] = None


class AddAliasRequest(BaseModel):
    canonical_id: str
    alias_name: str
    source: str = "manual"
    confidence: float = 1.0


class ResolveRequest(BaseModel):
    name: str = Field(..., description="Asset name to resolve")
    org_id: Optional[str] = None
    threshold: float = 0.65


class ResolveBatchRequest(BaseModel):
    names: List[str]
    org_id: Optional[str] = None
    threshold: float = 0.65


class MatchResultResponse(BaseModel):
    canonical_id: str
    matched_name: str
    confidence: float
    strategy: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/canonical", summary="Register a canonical asset identity")
async def register_canonical(req: RegisterCanonicalRequest):
    resolver = get_fuzzy_resolver()
    cid = resolver.register_canonical(
        req.canonical_id, org_id=req.org_id, properties=req.properties
    )
    # Register in Knowledge Graph (non-fatal if brain is unavailable)
    try:
        brain = get_brain()
        brain.ingest_asset(cid, org_id=req.org_id, **(req.properties or {}))
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.warning("Knowledge Brain unavailable for asset ingestion: %s", exc)
    # Emit event (non-fatal if event bus fails)
    try:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.ASSET_DISCOVERED,
                source="fuzzy_identity",
                data={"canonical_id": cid, "org_id": req.org_id},
            )
        )
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.warning("Event bus unavailable for asset event: %s", exc)
    return {"canonical_id": cid, "status": "registered"}


@router.post("/alias", summary="Add an alias for a canonical asset")
async def add_alias(req: AddAliasRequest):
    resolver = get_fuzzy_resolver()
    resolver.add_alias(
        req.canonical_id, req.alias_name, source=req.source, confidence=req.confidence
    )
    return {
        "canonical_id": req.canonical_id,
        "alias": req.alias_name,
        "status": "added",
    }


@router.post("/resolve", summary="Resolve an asset name to its canonical identity")
async def resolve_name(req: ResolveRequest):
    resolver = get_fuzzy_resolver()
    result = resolver.resolve(req.name, org_id=req.org_id, threshold=req.threshold)
    if result is None:
        return {"resolved": False, "input": req.name, "match": None}
    return {
        "resolved": True,
        "input": req.name,
        "match": {
            "canonical_id": result.canonical_id,
            "matched_name": result.matched_name,
            "confidence": round(result.confidence, 4),
            "strategy": result.strategy.value,
        },
    }


@router.post("/resolve/batch", summary="Resolve multiple asset names")
async def resolve_batch(req: ResolveBatchRequest):
    resolver = get_fuzzy_resolver()
    results = resolver.resolve_batch(
        req.names, org_id=req.org_id, threshold=req.threshold
    )
    output = {}
    for name, match in results.items():
        if match is None:
            output[name] = None
        else:
            output[name] = {
                "canonical_id": match.canonical_id,
                "matched_name": match.matched_name,
                "confidence": round(match.confidence, 4),
                "strategy": match.strategy.value,
            }
    return {
        "results": output,
        "total": len(results),
        "resolved": sum(1 for v in results.values() if v),
    }


@router.get("/similar", summary="Find similar canonical assets")
async def find_similar(
    name: str = Query(...),
    org_id: Optional[str] = Query(None),
    threshold: float = Query(0.5),
    top_k: int = Query(10),
):
    resolver = get_fuzzy_resolver()
    results = resolver.find_similar(
        name, org_id=org_id, threshold=threshold, top_k=top_k
    )
    return {
        "query": name,
        "matches": [
            {
                "canonical_id": r.canonical_id,
                "matched_name": r.matched_name,
                "confidence": round(r.confidence, 4),
                "strategy": r.strategy.value,
            }
            for r in results
        ],
    }


@router.get("/canonical", summary="List canonical assets")
async def list_canonical(
    org_id: Optional[str] = Query(None),
    limit: int = Query(100),
):
    resolver = get_fuzzy_resolver()
    return {"assets": resolver.list_canonical(org_id=org_id, limit=limit)}


@router.get("/stats", summary="Get resolution statistics")
async def get_stats(org_id: Optional[str] = Query(None)):
    try:
        resolver = get_fuzzy_resolver()
        return resolver.get_resolution_stats(org_id=org_id)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.warning("Failed to get identity resolution stats: %s", exc)
        return {
            "total_canonical": 0,
            "total_aliases": 0,
            "total_resolutions": 0,
            "resolution_rate": 0.0,
            "strategies_used": {},
            "status": "unavailable",
            "error": type(exc).__name__,
        }


@router.get("/health")
async def fuzzy_identity_health():
    """Fuzzy identity resolver health check."""
    return {"status": "healthy", "engine": "fuzzy-identity", "version": "1.0.0"}


@router.get("/findings")
async def list_identity_findings(
    org_id: Optional[str] = Query(None),
    min_aliases: int = Query(default=2, ge=1, description="Min alias count to flag as ambiguous"),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """List identity resolution findings — assets with conflicting or ambiguous identities.

    Returns canonical assets that have >= min_aliases aliases, which indicates
    multiple scanner outputs disagree on the asset name (identity conflict).
    Each finding includes the canonical ID, alias list, alias count, and severity.
    """
    try:
        resolver = get_fuzzy_resolver()
        assets = resolver.list_canonical(org_id=org_id, limit=limit)
        stats = resolver.get_resolution_stats(org_id=org_id)

        findings = []
        for asset in assets:
            aliases = asset.get("aliases", [])
            alias_count = len(aliases)
            if alias_count >= min_aliases:
                # More aliases → higher identity conflict severity
                if alias_count >= 5:
                    severity = "high"
                elif alias_count >= 3:
                    severity = "medium"
                else:
                    severity = "low"
                findings.append({
                    "canonical_id": asset["canonical_id"],
                    "org_id": asset.get("org_id"),
                    "alias_count": alias_count,
                    "aliases": aliases,
                    "severity": severity,
                    "created_at": asset.get("created_at"),
                    "description": (
                        f"Asset '{asset['canonical_id']}' has {alias_count} aliases "
                        "indicating identity ambiguity across scanner outputs."
                    ),
                })

        # Sort by alias_count descending (most ambiguous first)
        findings.sort(key=lambda f: f["alias_count"], reverse=True)

        return {
            "findings": findings,
            "total": len(findings),
            "stats": stats,
            "engine": "fuzzy-identity",
            "filter": {"org_id": org_id, "min_aliases": min_aliases},
        }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        logger.warning("list_identity_findings error: %s", exc)
        return {
            "findings": [],
            "total": 0,
            "stats": {},
            "engine": "fuzzy-identity",
            "error": type(exc).__name__,
        }


@router.get("/status")
async def fuzzy_identity_status():
    """Fuzzy identity resolver status (alias for /health)."""
    return await fuzzy_identity_health()
