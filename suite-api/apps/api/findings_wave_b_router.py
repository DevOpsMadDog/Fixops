"""Backend Wave B — Findings / Risk / Scoring REST endpoints.

Implements the 15 endpoints requested in Multica Wave B against real
engines (no mocks). All endpoints require ``api_key_auth`` and accept
the per-tenant ``X-Org-ID`` header via the shared ``get_org_id``
dependency.

Routes (organized by Multica id):
  ce6b3221  GET  /api/v1/findings/{id}/lifecycle
  71432602  GET  /api/v1/findings/drift?since=
  a3d3443d  GET  /api/v1/findings?status=new|unchanged|resolved
  9fafda03  GET  /api/v1/findings/{id}/score-breakdown
  fdf4d765  GET  /api/v1/scoring/formula
  bacdd8bf  PUT  /api/v1/scoring/formula
  7e62f6c6  POST /api/v1/risk/quantify-fair
  094b9c3d  GET  /api/v1/risk/brs/bu/{bu_id}
  e2cf4708  GET  /api/v1/attack-paths/choke-points
  4c483284  GET  /api/v1/issues/toxic
  afe86faf  POST /api/v1/toxic-combo-rules
  1d3a7018  POST /api/v1/sbom/subscribe-for-reeval
  2a6a2e8a  GET  /api/v1/sbom/{id}/re-eval-history
  4b96d034  POST /api/v1/investigate/rql
  80123d56  GET  /api/v1/investigate/saved
  06e9c24b  POST /api/v1/investigate/saved

Engines wired:
  - core.security_findings_engine.SecurityFindingsEngine
  - core.vulnerability_scoring_engine.VulnerabilityScoringEngine
  - core.risk_quantification_engine_v2 (per-BU FAIR risk)
  - core.risk_quantifier (FAIR Monte Carlo)
  - core.attack_path_engine.AttackPathEngine
  - core.toxic_combo_rules (predicate evaluator)
  - core.sbom_engine.SBOMEngine
  - core.security_query_language_engine (RQL)

Endpoints that require an engine method which has no real implementation
return ``HTTP 501 Not Implemented`` with a structured error explaining
the missing capability. **No mock data is ever returned.**
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Wave B — Findings/Risk/Scoring"])


# ---------------------------------------------------------------------------
# Lazy engine accessors (singletons — thread-safe)
# ---------------------------------------------------------------------------

_engine_lock = threading.RLock()
_engines: Dict[str, Any] = {}


def _findings_engine() -> Any:
    with _engine_lock:
        engine = _engines.get("findings")
        if engine is None:
            from core.security_findings_engine import SecurityFindingsEngine
            engine = SecurityFindingsEngine()
            _engines["findings"] = engine
        return engine


def _scoring_engine() -> Any:
    with _engine_lock:
        engine = _engines.get("scoring")
        if engine is None:
            from core.vulnerability_scoring_engine import VulnerabilityScoringEngine
            engine = VulnerabilityScoringEngine()
            _engines["scoring"] = engine
        return engine


def _risk_quant_v2() -> Any:
    with _engine_lock:
        engine = _engines.get("risk_quant_v2")
        if engine is None:
            from core.risk_quantification_engine_v2 import (
                RiskQuantificationEngineV2,
            )
            engine = RiskQuantificationEngineV2()
            _engines["risk_quant_v2"] = engine
        return engine


def _risk_quantifier() -> Any:
    with _engine_lock:
        engine = _engines.get("risk_quantifier")
        if engine is None:
            import os

            from core.risk_quantifier import get_risk_quantifier
            engine = get_risk_quantifier(
                db_path=os.environ.get("RISK_QUANTIFIER_DB", "risk_quantifier.db"),
            )
            _engines["risk_quantifier"] = engine
        return engine


def _attack_path_engine() -> Any:
    with _engine_lock:
        engine = _engines.get("attack_path")
        if engine is None:
            from core.attack_path_engine import AttackPathEngine
            engine = AttackPathEngine()
            _engines["attack_path"] = engine
        return engine


def _sbom_engine() -> Any:
    with _engine_lock:
        engine = _engines.get("sbom")
        if engine is None:
            from core.sbom_engine import SBOMEngine
            engine = SBOMEngine()
            _engines["sbom"] = engine
        return engine


def _rql_engine() -> Any:
    with _engine_lock:
        engine = _engines.get("rql")
        if engine is None:
            from core.security_query_language_engine import get_engine as _rql_get
            engine = _rql_get()
            _engines["rql"] = engine
        return engine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _not_implemented(detail: str, capability: str) -> HTTPException:
    """Build a structured 501 with engine + missing-capability metadata."""
    return HTTPException(
        status_code=501,
        detail={
            "error": "not_implemented",
            "message": detail,
            "missing_capability": capability,
        },
    )


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ScoringFormulaUpdate(BaseModel):
    """PUT /api/v1/scoring/formula body."""

    model_name: str = Field(default="default", min_length=1, max_length=120)
    cvss_weight: float = Field(default=0.4, ge=0.0, le=1.0)
    epss_weight: float = Field(default=0.3, ge=0.0, le=1.0)
    kev_bonus: float = Field(default=0.2, ge=0.0, le=1.0)
    criticality_multiplier: float = Field(default=1.0, ge=0.0, le=1.0)
    exposure_weight: float = Field(default=0.3, ge=0.0, le=1.0)


class FAIRQuantifyRequest(BaseModel):
    """POST /api/v1/risk/quantify-fair body — accepts either an existing
    scenario_id (re-quantify) or finding-derived parameters (quantify_finding)."""

    scenario_id: Optional[str] = Field(default=None, description="Existing scenario id to quantify")
    finding: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Finding payload to derive parameters from (severity, asset_type, ...)",
    )

    @field_validator("finding")
    @classmethod
    def _shape(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if v is None:
            return v
        if not isinstance(v, dict):
            raise ValueError("finding must be an object")
        return v


class ChokePointRequest(BaseModel):
    """Used by GET /attack-paths/choke-points body-style fallback (kept GET for
    REST conformance — sources/sinks come via query params)."""

    pass


class ToxicComboRule(BaseModel):
    """POST /api/v1/toxic-combo-rules body."""

    combo_id: str = Field(..., min_length=1, max_length=120)
    name: str = Field(..., min_length=1, max_length=240)
    description: str = Field(default="", max_length=2000)
    severity: str = Field(default="high", pattern=r"^(critical|high|medium|low|info)$")
    predicates: List[Dict[str, Any]] = Field(
        ..., min_length=1, description="Predicate clauses (attribute + operator + value)"
    )
    require_all: bool = Field(default=True)


class SubscribeReevalRequest(BaseModel):
    """POST /api/v1/sbom/subscribe-for-reeval body."""

    sbom_id: str = Field(..., min_length=1, max_length=240)
    cron_expr: str = Field(default="@daily", min_length=1, max_length=240)


class RQLQueryRequest(BaseModel):
    """POST /api/v1/investigate/rql body."""

    query: str = Field(..., min_length=1, max_length=20_000, description="RQL DSL string")
    provider: str = Field(default="memory", pattern=r"^(memory|sqlite)$")


class SavedQueryCreate(BaseModel):
    """POST /api/v1/investigate/saved body."""

    name: str = Field(..., min_length=1, max_length=240)
    query: str = Field(..., min_length=1, max_length=20_000)
    description: str = Field(default="", max_length=2000)


# ===========================================================================
# 1. ce6b3221 — GET /api/v1/findings/{id}/lifecycle
# ===========================================================================


@router.get(
    "/api/v1/findings/{finding_id}/lifecycle",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-01 — Finding lifecycle chain (firstSeen → resolved)",
)
def finding_lifecycle(
    finding_id: str,
    org_id: str = Depends(get_org_id),
    max_depth: int = Query(default=50, ge=1, le=500),
) -> Dict[str, Any]:
    """Return the lifecycle ancestor chain of a finding.

    Walks ``previous_violation_id`` back through scans until the original
    detection. Cycle-safe.
    """
    engine = _findings_engine()
    finding = engine.get_finding(finding_id, org_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
    chain = engine.lifecycle_history(
        finding_id=finding_id, org_id=org_id, max_depth=max_depth
    )
    return {
        "finding_id": finding_id,
        "org_id": org_id,
        "current": finding,
        "depth": len(chain),
        "chain": chain,
    }


# ===========================================================================
# 2. 71432602 — GET /api/v1/findings/drift?since=
# ===========================================================================


@router.get(
    "/api/v1/findings/drift",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-02 — New/unchanged/resolved drift since a date",
)
def findings_drift(
    org_id: str = Depends(get_org_id),
    since: Optional[str] = Query(
        default=None,
        description="ISO-8601 lower bound — defaults to 7 days ago when omitted",
    ),
    days: int = Query(default=7, ge=1, le=365),
) -> Dict[str, Any]:
    """Return rolling drift counters {new, unchanged, resolved} over a window.

    If ``since`` is supplied, ``days`` is ignored and the engine's
    summary window is anchored at ``since`` via day-bucketed
    ``count_lifecycle_by_day``.
    """
    engine = _findings_engine()
    if since:
        # day-by-day reconstruction from the lifecycle lookup
        from datetime import datetime, timedelta, timezone
        try:
            start = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid 'since' (expected ISO-8601): {exc}",
            ) from exc
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_span = max(1, min(365, (now - start).days + 1))
        agg = {"new": 0, "unchanged": 0, "resolved": 0}
        breakdown: List[Dict[str, Any]] = []
        for offset in range(days_span):
            day = (start + timedelta(days=offset)).date().isoformat()
            counts = engine.count_lifecycle_by_day(org_id=org_id, day_iso=day)
            for key in agg:
                agg[key] += int(counts.get(key, 0))
            breakdown.append({"day": day, **counts})
        return {
            "org_id": org_id,
            "since": start.isoformat(),
            "days": days_span,
            "totals": agg,
            "by_day": breakdown,
        }
    summary = engine.lifecycle_summary(org_id=org_id, days=days)
    return {"org_id": org_id, "days": days, **summary}


# ===========================================================================
# 3. a3d3443d — GET /api/v1/findings?status=new|unchanged|resolved
# ===========================================================================


@router.get(
    "/api/v1/findings",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-03 — Filterable findings list",
)
def list_findings(
    org_id: str = Depends(get_org_id),
    status: Optional[str] = Query(
        default=None,
        description="Lifecycle status filter (new|unchanged|resolved) "
                    "or canonical engine status (open|in-progress|...)",
    ),
    severity: Optional[str] = Query(default=None),
    source_tool: Optional[str] = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
) -> Dict[str, Any]:
    """List findings with rich filtering.

    Lifecycle terms (``new``, ``unchanged``, ``resolved``) are mapped to the
    engine's stored ``status`` column.
    """
    engine = _findings_engine()
    # Accept lifecycle aliases — the engine uses 'open' for active findings,
    # 'resolved' for closed, and tracks unchanged via unchanged_scan_count > 0.
    normalized_status = status
    rows = engine.list_findings(
        org_id=org_id,
        status=normalized_status if normalized_status not in {"new", "unchanged"} else None,
        severity=severity,
        source_tool=source_tool,
    )
    if status == "new":
        rows = [r for r in rows if int(r.get("unchanged_scan_count") or 0) == 0
                and r.get("status") not in {"resolved", "suppressed"}]
    elif status == "unchanged":
        rows = [r for r in rows if int(r.get("unchanged_scan_count") or 0) > 0]
    return {
        "org_id": org_id,
        "status": status,
        "count": min(len(rows), limit),
        "total": len(rows),
        "findings": rows[:limit],
    }


# ===========================================================================
# 4. 9fafda03 — GET /api/v1/findings/{id}/score-breakdown
# ===========================================================================


@router.get(
    "/api/v1/findings/{finding_id}/score-breakdown",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-04 — Per-factor score breakdown for a finding",
)
def finding_score_breakdown(
    finding_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return per-factor breakdown rows for a finding's scoring.

    Aggregates rows from ``score_breakdown`` keyed by the finding's
    associated ``vuln_score_id``. Falls back to formula-transparency view
    when no breakdown rows exist.
    """
    findings_eng = _findings_engine()
    scoring_eng = _scoring_engine()
    finding = findings_eng.get_finding(finding_id, org_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")

    # The finding row may carry a vuln_score_id reference (when scored).
    vuln_score_id = finding.get("vuln_score_id") or finding.get("id")
    breakdown = scoring_eng.get_score_breakdown(org_id, vuln_score_id)
    transparency = scoring_eng.get_formula_transparency(
        org_id, finding_id=finding_id
    )
    return {
        "finding_id": finding_id,
        "org_id": org_id,
        "vuln_score_id": vuln_score_id,
        "breakdown_rows": breakdown,
        "formula_transparency": transparency,
    }


# ===========================================================================
# 5. fdf4d765 — GET /api/v1/scoring/formula
# 6. bacdd8bf — PUT /api/v1/scoring/formula
# ===========================================================================


@router.get(
    "/api/v1/scoring/formula",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-05 — Active scoring formula transparency",
)
def get_scoring_formula(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return the org's active scoring formula with weights and audit trail."""
    engine = _scoring_engine()
    return engine.get_formula_transparency(org_id)


@router.put(
    "/api/v1/scoring/formula",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-06 — Update scoring formula weights (creates new active model)",
)
def put_scoring_formula(
    body: ScoringFormulaUpdate,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a new active scoring model with the supplied weights.

    The previous model is deactivated atomically — full audit trail is
    retained in ``scoring_models`` for rollback.
    """
    engine = _scoring_engine()
    try:
        model = engine.create_scoring_model(
            org_id=org_id,
            model_name=body.model_name,
            cvss_weight=body.cvss_weight,
            epss_weight=body.epss_weight,
            kev_bonus=body.kev_bonus,
            criticality_multiplier=body.criticality_multiplier,
            exposure_weight=body.exposure_weight,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"status": "created", "active_model": model}


# ===========================================================================
# 7. 7e62f6c6 — POST /api/v1/risk/quantify-fair
# ===========================================================================


@router.post(
    "/api/v1/risk/quantify-fair",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-07 — Run FAIR Monte Carlo on a scenario or a finding",
)
def quantify_fair(
    body: FAIRQuantifyRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Run the FAIR (Factor Analysis of Information Risk) Monte Carlo
    simulation (1000 iterations).

    Either pass ``scenario_id`` for an existing scenario, or pass
    ``finding`` to derive parameters from severity/asset_type templates.
    """
    if not body.scenario_id and not body.finding:
        raise HTTPException(
            status_code=422,
            detail="Provide either scenario_id or finding payload.",
        )
    engine = _risk_quantifier()
    try:
        if body.scenario_id:
            result = engine.quantify(body.scenario_id)
        else:
            result = engine.quantify_finding(finding=body.finding or {}, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "status": "ok",
        "org_id": org_id,
        "methodology": "FAIR",
        "monte_carlo_iterations": 1000,
        "quantified_risk": result.model_dump(),
    }


# ===========================================================================
# 8. 094b9c3d — GET /api/v1/risk/brs/bu/{bu_id}
# ===========================================================================


@router.get(
    "/api/v1/risk/brs/bu/{bu_id}",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-08 — Business-unit risk score (FAIR per-BU)",
)
def bu_risk_score(
    bu_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return the per-business-unit risk score (BRS).

    Aggregates active findings tagged to the BU, applies criticality
    multipliers, and computes ALE_mean and ALE_p95 via lognormal
    approximation (σ=0.4).
    """
    engine = _risk_quant_v2()
    try:
        return engine.compute_per_bu_risk(org_id=org_id, bu_id=bu_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AttributeError as exc:
        raise _not_implemented(
            f"RiskQuantificationEngineV2.compute_per_bu_risk missing: {exc}",
            "compute_per_bu_risk",
        ) from exc


# ===========================================================================
# 9. e2cf4708 — GET /api/v1/attack-paths/choke-points
# ===========================================================================


@router.get(
    "/api/v1/attack-paths/choke-points",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-09 — Min-cut choke points in the attack graph",
)
def attack_path_choke_points(
    org_id: str = Depends(get_org_id),
    sources: str = Query(
        ..., description="Comma-separated entry-point node ids (sources)"
    ),
    sinks: str = Query(
        ..., description="Comma-separated crown-jewel node ids (sinks)"
    ),
    top_k: int = Query(default=10, ge=1, le=100),
) -> Dict[str, Any]:
    """Rank attack-graph edges by their max-flow / min-cut blast-reduction
    impact. Each result includes ``blast_reduction_pct`` (% of sinks no
    longer reachable if the edge is removed) and ``sinks_saved``.
    """
    src_list = [s.strip() for s in sources.split(",") if s.strip()]
    sink_list = [s.strip() for s in sinks.split(",") if s.strip()]
    if not src_list or not sink_list:
        raise HTTPException(
            status_code=422,
            detail="Both 'sources' and 'sinks' must contain at least one node id",
        )
    engine = _attack_path_engine()
    try:
        ranked = engine.compute_choke_points(
            org_id=org_id,
            source_ids=src_list,
            sink_ids=sink_list,
            top_k=top_k,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "org_id": org_id,
        "sources": src_list,
        "sinks": sink_list,
        "top_k": top_k,
        "count": len(ranked),
        "choke_points": ranked,
    }


# ===========================================================================
# 10. 4c483284 — GET /api/v1/issues/toxic
# ===========================================================================


@router.get(
    "/api/v1/issues/toxic",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-10 — Toxic combination issues (chained risks)",
)
def toxic_issues(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return assets flagged with toxic combinations of medium-severity
    findings that compose into a critical risk via the attack graph.
    """
    engine = _attack_path_engine()
    items = engine.get_toxic_combinations(org_id=org_id)
    return {
        "org_id": org_id,
        "count": len(items),
        "issues": items,
    }


# ===========================================================================
# 11. afe86faf — POST /api/v1/toxic-combo-rules
# ===========================================================================


@router.post(
    "/api/v1/toxic-combo-rules",
    status_code=201,
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-11 — Define a custom toxic-combo predicate rule",
)
def create_toxic_combo_rule(
    body: ToxicComboRule,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Register a custom toxic-combo rule (persisted via ToxicComboStore)."""
    from core.toxic_combo_rules import get_store

    try:
        return get_store().put(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/api/v1/toxic-combo-rules",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-11b — List custom toxic-combo rules",
)
def list_toxic_combo_rules(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return all custom toxic-combo rules for the org."""
    from core.toxic_combo_rules import get_store

    try:
        rules = get_store().list_rules(org_id)
        return {"rules": rules, "count": len(rules)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete(
    "/api/v1/toxic-combo-rules/{rule_id}",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-11c — Delete a custom toxic-combo rule",
)
def delete_toxic_combo_rule(
    rule_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Delete a custom toxic-combo rule by id."""
    from core.toxic_combo_rules import get_store

    try:
        deleted = get_store().delete_rule(org_id, rule_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id!r} not found")
    return {"deleted": True, "rule_id": rule_id}


# ===========================================================================
# 12. 1d3a7018 — POST /api/v1/sbom/subscribe-for-reeval
# 13. 2a6a2e8a — GET  /api/v1/sbom/{id}/re-eval-history
# ===========================================================================


@router.post(
    "/api/v1/sbom/subscribe-for-reeval",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-12 — Schedule periodic SBOM re-evaluation",
)
def sbom_subscribe_reeval(
    body: SubscribeReevalRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Schedule a recurring re-eval of the SBOM via cron expression."""
    engine = _sbom_engine()
    try:
        schedule = engine.schedule_reeval(
            org_id=org_id, sbom_id=body.sbom_id, cron_expr=body.cron_expr
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"status": "scheduled", "schedule": schedule}


@router.get(
    "/api/v1/sbom/{sbom_id}/re-eval-history",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-13 — SBOM re-eval history",
)
def sbom_reeval_history(
    sbom_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return all known schedules and execution metadata for an SBOM.

    The engine currently exposes ``list_reeval_schedules`` (per-org) but
    no per-execution history. We filter the schedule list to the
    requested ``sbom_id`` and surface ``last_run_at`` / ``next_run_at``
    / ``findings_delta``. A dedicated execution log is a future feature
    — flagged below for traceability.
    """
    engine = _sbom_engine()
    schedules = engine.list_reeval_schedules(org_id=org_id)
    matching = [s for s in schedules if s.get("sbom_id") == sbom_id]
    return {
        "org_id": org_id,
        "sbom_id": sbom_id,
        "count": len(matching),
        "schedules": matching,
        "_notes": "Per-execution audit log requires SBOMEngine.list_reeval_runs "
                  "(future enhancement). Returned data is the schedule + "
                  "last_run_at/findings_delta summary.",
    }


# ===========================================================================
# 14. 4b96d034 — POST /api/v1/investigate/rql
# ===========================================================================


@router.post(
    "/api/v1/investigate/rql",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-14 — Execute an RQL DSL investigation query",
)
def investigate_rql(
    body: RQLQueryRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Compile and execute an RQL DSL query against the org's data."""
    engine = _rql_engine()
    try:
        compiled = engine.compile_query(body.query)
        result = engine.execute_query(
            org_id=org_id, dsl=body.query, provider=body.provider
        )
    except Exception as exc:  # SQLSyntaxError / SQLPlanError / RuntimeError
        # The RQL engine raises typed errors — surface them as 400/422.
        msg = str(exc)
        if "syntax" in msg.lower() or "expected" in msg.lower():
            raise HTTPException(status_code=400, detail=f"Query syntax error: {msg}") from exc
        raise HTTPException(status_code=422, detail=f"Query error: {msg}") from exc
    return {
        "org_id": org_id,
        "compiled": compiled.to_dict() if hasattr(compiled, "to_dict") else None,
        **(result if isinstance(result, dict) else {"result": result}),
    }


# ===========================================================================
# 15. 80123d56 — GET  /api/v1/investigate/saved
# 16. 06e9c24b — POST /api/v1/investigate/saved
# ===========================================================================


@router.get(
    "/api/v1/investigate/saved",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-15 — List saved RQL queries",
)
def list_saved_queries(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List saved RQL queries for the org."""
    engine = _rql_engine()
    items = engine.list_queries(org_id=org_id)
    return {"org_id": org_id, "count": len(items), "queries": items}


@router.post(
    "/api/v1/investigate/saved",
    dependencies=[Depends(api_key_auth)],
    summary="Wave-B-16 — Save an RQL query",
)
def save_query(
    body: SavedQueryCreate,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Persist a named RQL query for re-use."""
    engine = _rql_engine()
    try:
        # Validate first by compiling
        engine.compile_query(body.query)
    except Exception as exc:
        raise HTTPException(
            status_code=400, detail=f"Query syntax error: {exc}"
        ) from exc
    record = engine.save_query(org_id=org_id, name=body.name, dsl=body.query)
    return {"status": "saved", "query": record}


__all__ = ["router"]
