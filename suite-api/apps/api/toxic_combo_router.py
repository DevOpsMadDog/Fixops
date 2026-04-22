"""Toxic-Combo Router — ALDECI (GAP-021).

Endpoints for Wiz-parity toxic-combo correlation.

Prefix: /api/v1/toxic-combo

Endpoints:
    POST /evaluate   — run correlation across registered entities, returns match counts.
    GET  /matches    — list persisted matches (filter by combo_id / entity_ref).
    GET  /rules      — catalog of builtin toxic-combo rules.
    POST /simulate   — what-if evaluator over user-supplied attributes (no DB write).

All endpoints are gated by ``api_key_auth`` (via router-level dependencies).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

try:
    from apps.api.auth_deps import api_key_auth
except ImportError:  # pragma: no cover — only in stripped-down test envs
    async def api_key_auth() -> str:
        return "anon"


router = APIRouter(
    prefix="/api/v1/toxic-combo",
    tags=["toxic-combo"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------


def _get_engine(org_id: str):
    from core.threat_correlation_engine import ThreatCorrelationEngine
    return ThreatCorrelationEngine.for_org(org_id)


def _get_attack_chain_engine():
    from core.attack_chain_engine import AttackChainEngine
    return AttackChainEngine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class EntityAttributesBody(BaseModel):
    """Body for POST /simulate."""

    entity_attributes: Dict[str, Any] = Field(default_factory=dict)


class EvaluateBody(BaseModel):
    """Body for POST /evaluate.

    Optional list of entity attribute payloads to register first, then evaluate.
    Each entry needs ``entity_ref`` and ``attributes``.
    """

    entities: List[Dict[str, Any]] = Field(default_factory=list)


class UpgradeBody(BaseModel):
    """Body for POST /upgrade-to-chain."""

    match_id: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/evaluate")
def evaluate_org(
    org_id: str = Query("default"),
    body: Optional[EvaluateBody] = None,
) -> Dict[str, Any]:
    """Run toxic-combo correlation across all registered entities for ``org_id``.

    If ``body.entities`` is provided, each one is upserted into the entity
    registry before evaluation. Returns aggregate match counts.
    """
    engine = _get_engine(org_id)

    if body and body.entities:
        for ent in body.entities:
            ref = str(ent.get("entity_ref") or "").strip()
            attrs = ent.get("attributes") or {}
            if not ref:
                raise HTTPException(status_code=400, detail="entity_ref is required.")
            if not isinstance(attrs, dict):
                raise HTTPException(status_code=400, detail="attributes must be a dict.")
            engine.upsert_entity_attributes(org_id, ref, attrs)

    try:
        matches = engine.correlate_toxic_combos(org_id)
    except Exception as exc:
        _logger.exception("toxic-combo evaluate failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    by_combo: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    for m in matches:
        by_combo[m["combo_id"]] = by_combo.get(m["combo_id"], 0) + 1
        by_severity[m["severity"]] = by_severity.get(m["severity"], 0) + 1

    return {
        "org_id": org_id,
        "total_matches": len(matches),
        "by_combo": by_combo,
        "by_severity": by_severity,
        "matches": matches,
    }


@router.get("/matches")
def list_matches(
    org_id: str = Query("default"),
    combo_id: Optional[str] = Query(None),
    entity_ref: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """List persisted toxic-combo matches."""
    engine = _get_engine(org_id)
    matches = engine.list_toxic_combo_matches(
        org_id, combo_id=combo_id, entity_ref=entity_ref, limit=limit
    )
    return {
        "org_id": org_id,
        "count": len(matches),
        "matches": matches,
    }


@router.get("/rules")
def list_rules() -> Dict[str, Any]:
    """Return the builtin toxic-combo rule catalog."""
    from core.toxic_combo_rules import list_builtin_rules

    rules = [r.to_dict() for r in list_builtin_rules()]
    return {
        "count": len(rules),
        "rules": rules,
    }


@router.post("/simulate")
def simulate(body: EntityAttributesBody) -> Dict[str, Any]:
    """What-if evaluator. Evaluates all builtin rules against the supplied
    attributes and returns which match (no DB write)."""
    from core.toxic_combo_rules import BUILTIN_RULES, evaluate_combo

    attrs = body.entity_attributes or {}
    results: List[Dict[str, Any]] = []
    for rule in BUILTIN_RULES:
        matched, satisfied = evaluate_combo(rule, attrs)
        results.append(
            {
                "combo_id": rule.id,
                "combo_name": rule.name,
                "severity": rule.severity,
                "matched": matched,
                "satisfied_predicates": satisfied,
                "total_predicates": len(rule.predicates),
            }
        )
    matched_count = sum(1 for r in results if r["matched"])
    return {
        "matched_count": matched_count,
        "evaluated_count": len(results),
        "results": results,
    }


@router.post("/upgrade-to-chain")
def upgrade_to_chain(
    body: UpgradeBody,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Upgrade a toxic-combo match into a formal attack_chain."""
    engine = _get_engine(org_id)
    chain_engine = _get_attack_chain_engine()
    try:
        result = chain_engine.build_chain_from_toxic_combo(
            org_id, body.match_id, threat_correlation_engine=engine
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result
