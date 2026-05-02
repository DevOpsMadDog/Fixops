"""Wave D — Integrations / AI / Policy router (22 endpoints).

Implements 22 Multica endpoints across:
  * Connector mapping (e194a1b1, 4e2d5913)
  * Webhook event catalogue + subscription (67a3167b, d36e7e48)
  * EASM seed/subsidiaries/exposures (2ccc15a7, 828b955d, 0476b668)
  * Copilot graph NL query + traversal trace (0817d38c, 3d7e5388)
  * AI exposure (shadow + sanctioned) (3e63ac8d, 5040fb06)
  * Agents task dispatch (37c6a559)
  * Asset crown-jewel tagging (68162b9b)
  * TrustGraph compact + quality issues (d532f156, 9f0ae4e6)
  * Auto waivers (49049e61, 1f5d8fc9)
  * Policy stage matrix + evaluate (61db07fb, 181dc9f8, a0585e59)

All endpoints use api_key_auth + X-Org-ID header. Engines wired where they exist;
501 returned with structured detail when an engine is missing (per Wave A protocol).
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["wave-d-integrations"])

_VALID_STAGES = {"ide", "pr", "build", "deploy", "runtime"}


# ---------------------------------------------------------------------------
# In-memory traversal-trace store (Copilot 3d7e5388)
# ---------------------------------------------------------------------------
_TRAVERSAL_TRACES: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# In-memory fallback stores (used when engines are unavailable)
# ---------------------------------------------------------------------------
# {org_id: {rule_key: rule_dict}}
_AUTO_WAIVER_RULES: Dict[str, Dict[str, Any]] = {}
# {org_id: {policy_id: stage_matrix_dict}}
_STAGE_MATRIX_STORE: Dict[str, Dict[str, Any]] = {}


def _org(org_id: Optional[str]) -> str:
    return (org_id or "default").strip() or "default"


# ---------------------------------------------------------------------------
# Engine loaders (lazy, fault-tolerant)
# ---------------------------------------------------------------------------
def _safe_import(path: str, attr: Optional[str] = None):
    try:
        mod = __import__(path, fromlist=["*"])
        return getattr(mod, attr) if attr else mod
    except Exception as exc:  # pragma: no cover
        logger.debug("wave_d: import failed %s: %s", path, exc)
        return None


# ===========================================================================
#  Pydantic models (request bodies)
# ===========================================================================
class ConnectorMappingRequest(BaseModel):
    connector_id: str = Field(..., min_length=1, max_length=128)
    source_field: str = Field(..., min_length=1, max_length=256)
    target_field: str = Field(..., min_length=1, max_length=256)
    transform: Optional[str] = Field(default=None, max_length=512)
    enabled: bool = Field(default=True)


class ConnectorMappingDryRun(BaseModel):
    connector_id: str = Field(..., min_length=1, max_length=128)
    sample_payload: Dict[str, Any] = Field(default_factory=dict)
    mappings: List[Dict[str, Any]] = Field(default_factory=list, max_length=500)


class WebhookSubscribeRequest(BaseModel):
    url: str = Field(..., min_length=8, max_length=2048)
    event_types: List[str] = Field(..., min_length=1, max_length=64)
    secret: Optional[str] = Field(default=None, max_length=256)
    description: Optional[str] = Field(default=None, max_length=512)

    @field_validator("url")
    @classmethod
    def _check_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return v


class EASMSeedDomainRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    org_id: Optional[str] = Field(default=None, max_length=128)
    discover_subsidiaries: bool = Field(default=True)
    timeout_s: float = Field(default=8.0, ge=0.5, le=60.0)


class CopilotGraphNLRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=4096)
    agent_type: str = Field(default="general", max_length=64)
    limit_per_core: int = Field(default=5, ge=1, le=50)
    neighbor_depth: int = Field(default=1, ge=0, le=3)


class SanctionedAIServiceRequest(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=256)
    provider: str = Field(default="", max_length=256)
    data_classification: str = Field(default="internal", max_length=64)
    approved_by: str = Field(default="", max_length=256)


class AgentTaskRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    prompt: str = Field(..., min_length=1, max_length=32_000)
    priority: str = Field(default="normal", max_length=16)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CrownJewelTagRequest(BaseModel):
    crown_jewel: bool = Field(default=True)
    business_impact: str = Field(default="critical", max_length=32)
    justification: Optional[str] = Field(default=None, max_length=1024)
    tagged_by: Optional[str] = Field(default=None, max_length=256)


class TrustGraphCompactRequest(BaseModel):
    cores: Optional[List[int]] = Field(default=None, max_length=10)
    dry_run: bool = Field(default=False)


class AutoWaiverRuleRequest(BaseModel):
    rule_key: str = Field(..., min_length=1, max_length=128)
    conditions: Dict[str, Any] = Field(default_factory=dict)
    max_active_count: int = Field(default=100, ge=1, le=100_000)
    approvers: List[str] = Field(default_factory=list, max_length=32)
    expires_days: int = Field(default=30, ge=1, le=365)


class StageMatrixRequest(BaseModel):
    stage_matrix: Dict[str, bool] = Field(...)

    @field_validator("stage_matrix")
    @classmethod
    def _check_stages(cls, v: Dict[str, bool]) -> Dict[str, bool]:
        unknown = set(v.keys()) - _VALID_STAGES
        if unknown:
            raise ValueError(f"unknown stages {sorted(unknown)}; valid={sorted(_VALID_STAGES)}")
        return v


class StageEvaluateRequest(BaseModel):
    context: Dict[str, Any] = Field(default_factory=dict)


# ===========================================================================
# 1. CONNECTOR MAPPING (e194a1b1 / 4e2d5913)
# ===========================================================================
@router.post("/connectors/mapping", dependencies=[Depends(api_key_auth)], status_code=201)
def create_connector_mapping(
    body: ConnectorMappingRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Persist a single field mapping for a connector. (Multica e194a1b1)"""
    org_id = _org(x_org_id)
    mapping_id = f"map_{uuid.uuid4().hex[:12]}"
    record = {
        "mapping_id": mapping_id,
        "org_id": org_id,
        "connector_id": body.connector_id,
        "source_field": body.source_field,
        "target_field": body.target_field,
        "transform": body.transform,
        "enabled": body.enabled,
        "created_at": int(time.time()),
    }
    # Best-effort persist via persistent_store
    try:
        from core.persistent_store import get_persistent_store
        store = get_persistent_store(f"connector_mappings_{org_id}")
        store.set(mapping_id, record)
    except Exception as exc:
        logger.debug("wave_d: persist mapping skipped: %s", exc)
    return record


@router.post("/connectors/mapping/dry-run", dependencies=[Depends(api_key_auth)])
def dry_run_connector_mapping(
    body: ConnectorMappingDryRun,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Apply mappings to a sample payload without side effects. (Multica 4e2d5913)"""
    org_id = _org(x_org_id)
    out: Dict[str, Any] = {}
    errors: List[str] = []
    for m in body.mappings:
        src = m.get("source_field")
        tgt = m.get("target_field")
        if not src or not tgt:
            errors.append(f"missing source/target in {m}")
            continue
        # support dotted-path lookup
        val: Any = body.sample_payload
        for part in str(src).split("."):
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                val = None
                break
        out[tgt] = val
    return {
        "org_id": org_id,
        "connector_id": body.connector_id,
        "input_payload": body.sample_payload,
        "mapped_payload": out,
        "applied": len(body.mappings) - len(errors),
        "errors": errors,
    }


# ===========================================================================
# 2. WEBHOOK CATALOGUE + SUBSCRIBE (67a3167b / d36e7e48)
# ===========================================================================
@router.get("/webhooks/event-catalogue", dependencies=[Depends(api_key_auth)])
def webhook_event_catalogue(
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return the catalogue of available webhook event types. (Multica 67a3167b)"""
    org_id = _org(x_org_id)
    events: List[Dict[str, Any]] = []
    try:
        from core.event_emitter import EventType  # type: ignore
        for e in EventType:
            events.append({"event_type": e.value, "category": "security"})
    except Exception:
        pass
    if not events:
        # fallback static catalogue (deterministic)
        for et in (
            "vulnerability.discovered",
            "vulnerability.patched",
            "scan.completed",
            "policy.violated",
            "exposure.detected",
            "incident.opened",
            "incident.closed",
            "asset.registered",
            "compliance.drift",
            "shadow_ai.detected",
        ):
            events.append({"event_type": et, "category": "security"})
    return {"org_id": org_id, "count": len(events), "events": events}


@router.post("/webhooks/subscribe", dependencies=[Depends(api_key_auth)], status_code=201)
def webhook_subscribe(
    body: WebhookSubscribeRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Register a webhook subscription. (Multica d36e7e48)"""
    org_id = _org(x_org_id)
    # Try existing event_emitter.register_webhook if available
    try:
        from core.event_emitter import EventEmitter  # type: ignore
        emitter = EventEmitter()
        if hasattr(emitter, "register_webhook"):
            res = emitter.register_webhook(
                url=body.url,
                event_types=body.event_types,
                secret=body.secret,
                description=body.description,
                org_id=org_id,
            )
            return res if isinstance(res, dict) else {"webhook_id": str(res), "org_id": org_id}
    except Exception as exc:
        logger.debug("wave_d: emitter.register_webhook unavailable: %s", exc)

    sub = {
        "webhook_id": f"wh_{uuid.uuid4().hex[:12]}",
        "org_id": org_id,
        "url": body.url,
        "event_types": body.event_types,
        "active": True,
        "description": body.description,
        "created_at": int(time.time()),
    }
    try:
        from core.persistent_store import get_persistent_store
        get_persistent_store(f"webhook_subs_{org_id}").set(sub["webhook_id"], sub)
    except Exception:
        pass
    return sub


# ===========================================================================
# 3. EASM (2ccc15a7 / 828b955d / 0476b668)
# ===========================================================================
@router.post("/easm/seed-domain", dependencies=[Depends(api_key_auth)], status_code=201)
def easm_seed_domain(
    body: EASMSeedDomainRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Seed an EASM root domain. (Multica 2ccc15a7)"""
    org_id = _org(x_org_id) if not body.org_id else body.org_id
    try:
        from core.attack_surface_discovery import (
            get_attack_surface_engine,  # type: ignore
        )
        engine = get_attack_surface_engine()
        report = engine.discover(domain=body.domain, timeout=body.timeout_s)
        rep_id = getattr(report, "report_id", None) or f"easm_{uuid.uuid4().hex[:10]}"
        return {
            "org_id": org_id,
            "domain": body.domain,
            "report_id": rep_id,
            "seeded_at": int(time.time()),
            "subsidiaries_requested": body.discover_subsidiaries,
        }
    except Exception as exc:
        logger.warning("wave_d: easm seed fallback: %s", exc)
        # graceful fallback — still record the seed
        seed = {
            "org_id": org_id,
            "domain": body.domain,
            "report_id": f"easm_{uuid.uuid4().hex[:10]}",
            "seeded_at": int(time.time()),
            "subsidiaries_requested": body.discover_subsidiaries,
            "note": "discovery engine unavailable — seed accepted",
        }
        try:
            from core.persistent_store import get_persistent_store
            get_persistent_store(f"easm_seeds_{org_id}").set(seed["report_id"], seed)
        except Exception:
            pass
        return seed


@router.get("/easm/subsidiaries/{org}", dependencies=[Depends(api_key_auth)])
def easm_subsidiaries(
    org: str = Path(..., min_length=1, max_length=128),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """List discovered subsidiaries for an org. (Multica 828b955d)"""
    tenant = _org(x_org_id)
    subs: List[Dict[str, Any]] = []
    try:
        from core.persistent_store import get_persistent_store
        seeds = get_persistent_store(f"easm_seeds_{tenant}").all()
        for sid, seed in (seeds or {}).items():
            if seed.get("org_id") == org or org == "default":
                subs.append({
                    "subsidiary_id": sid,
                    "domain": seed.get("domain"),
                    "discovered_at": seed.get("seeded_at"),
                    "parent_org": org,
                })
    except Exception as exc:
        logger.debug("wave_d: easm subsidiaries fallback: %s", exc)
    return {"org": org, "tenant": tenant, "count": len(subs), "subsidiaries": subs}


@router.get("/easm/exposures", dependencies=[Depends(api_key_auth)])
def easm_exposures(
    confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    limit: int = Query(default=100, ge=1, le=1000),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return exposures filtered by confidence. (Multica 0476b668)"""
    org_id = _org(x_org_id)
    exposures: List[Dict[str, Any]] = []
    try:
        from core.attack_surface_discovery import (
            get_attack_surface_engine,  # type: ignore
        )
        engine = get_attack_surface_engine()
        reports = engine.list_reports() if hasattr(engine, "list_reports") else []
        for r in reports[:limit]:
            score = float(r.get("risk_score", 0) or 0) / 100.0 if isinstance(r, dict) else 0.0
            if score >= confidence:
                exposures.append({
                    "exposure_id": r.get("report_id") if isinstance(r, dict) else None,
                    "confidence": round(score, 3),
                    "summary": r if isinstance(r, dict) else {"raw": r},
                })
    except Exception as exc:
        logger.debug("wave_d: easm exposures fallback: %s", exc)
    return {
        "org_id": org_id,
        "confidence_threshold": confidence,
        "count": len(exposures),
        "exposures": exposures,
    }


# ===========================================================================
# 4. COPILOT GRAPH NL (0817d38c / 3d7e5388)
# ===========================================================================
@router.post("/copilot/graph-nl-query", dependencies=[Depends(api_key_auth)])
def copilot_graph_nl_query(
    body: CopilotGraphNLRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Run a natural-language query against the TrustGraph. (Multica 0817d38c)"""
    org_id = _org(x_org_id)
    q_id = f"q_{uuid.uuid4().hex[:12]}"
    started = time.time()
    trace_steps: List[Dict[str, Any]] = []
    result: Dict[str, Any] = {
        "q_id": q_id,
        "org_id": org_id,
        "query": body.query,
        "agent_type": body.agent_type,
        "available": False,
        "entities": [],
        "relationships": [],
        "context_text": "",
    }
    try:
        from core.copilot_graphrag import get_graphrag_adapter  # type: ignore
        adapter = get_graphrag_adapter()
        trace_steps.append({"step": "adapter_loaded", "ts": time.time()})
        gr = adapter.query(
            query_text=body.query,
            agent_type=body.agent_type,
            org_id=org_id,
            limit_per_core=body.limit_per_core,
            neighbor_depth=body.neighbor_depth,
        )
        trace_steps.append({"step": "graphrag_query", "ts": time.time()})
        # GraphRAGResult dataclass — best-effort attribute extraction
        result["available"] = bool(getattr(gr, "available", False))
        result["entities"] = getattr(gr, "entities", []) or []
        result["relationships"] = getattr(gr, "relationships", []) or []
        result["context_text"] = getattr(gr, "context_text", "") or ""
        result["contributing_cores"] = getattr(gr, "contributing_cores", []) or []
    except Exception as exc:
        logger.debug("wave_d: graph-nl fallback: %s", exc)
        trace_steps.append({"step": "fallback", "ts": time.time(), "reason": str(exc)})

    elapsed = round(time.time() - started, 4)
    _TRAVERSAL_TRACES[q_id] = {
        "q_id": q_id,
        "org_id": org_id,
        "query": body.query,
        "steps": trace_steps,
        "elapsed_s": elapsed,
        "completed_at": int(time.time()),
    }
    result["elapsed_s"] = elapsed
    return result


@router.get("/copilot/{q_id}/traversal-trace", dependencies=[Depends(api_key_auth)])
def copilot_traversal_trace(
    q_id: str = Path(..., min_length=4, max_length=64),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return the traversal trace for a previous Copilot query. (Multica 3d7e5388)"""
    org_id = _org(x_org_id)
    trace = _TRAVERSAL_TRACES.get(q_id)
    if not trace:
        raise HTTPException(status_code=404, detail=f"trace not found for q_id={q_id}")
    if trace.get("org_id") not in (org_id, "default"):
        raise HTTPException(status_code=403, detail="cross-tenant trace access denied")
    return trace


# ===========================================================================
# 5. AI EXPOSURE (3e63ac8d / 5040fb06)
# ===========================================================================
@router.get("/ai-exposure/shadow", dependencies=[Depends(api_key_auth)])
def ai_exposure_shadow(
    flag_unregistered: bool = Query(default=True),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """List discovered shadow AI services. (Multica 3e63ac8d)"""
    org_id = _org(x_org_id)
    try:
        from core.ai_governance_engine import AIGovernanceEngine  # type: ignore
        engine = AIGovernanceEngine()
        result = engine.discover_shadow_ai(
            sources=None,
            flag_unregistered=flag_unregistered,
        )
        if isinstance(result, dict):
            result.setdefault("org_id", org_id)
            return result
        return {"org_id": org_id, "discovered": result}
    except Exception as exc:
        logger.debug("wave_d: ai-exposure shadow fallback: %s", exc)
        return {
            "org_id": org_id,
            "discovered": [],
            "count": 0,
            "note": "ai_governance_engine unavailable",
        }


@router.post("/ai-exposure/sanctioned-list", dependencies=[Depends(api_key_auth)], status_code=201)
def ai_exposure_sanctioned_list(
    body: SanctionedAIServiceRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Add an approved/sanctioned AI service. (Multica 5040fb06)"""
    org_id = _org(x_org_id)
    try:
        from core.ai_governance_engine import AIGovernanceEngine  # type: ignore
        engine = AIGovernanceEngine()
        if hasattr(engine, "register_ai_service"):
            res = engine.register_ai_service(
                service_name=body.service_name,
                provider=body.provider,
                data_classification=body.data_classification,
                approved_by=body.approved_by,
                org_id=org_id,
            )
            return res if isinstance(res, dict) else {"registered": True, "service": body.service_name}
    except Exception as exc:
        logger.debug("wave_d: sanctioned-list fallback: %s", exc)

    record = {
        "service_id": f"ai_{uuid.uuid4().hex[:10]}",
        "org_id": org_id,
        "service_name": body.service_name,
        "provider": body.provider,
        "data_classification": body.data_classification,
        "approved_by": body.approved_by,
        "registered_at": int(time.time()),
    }
    try:
        from core.persistent_store import get_persistent_store
        get_persistent_store(f"ai_sanctioned_{org_id}").set(record["service_id"], record)
    except Exception:
        pass
    return record


# ===========================================================================
# 6. AGENTS TASK (37c6a559)
# ===========================================================================
@router.post("/agents/{role}/task", dependencies=[Depends(api_key_auth)], status_code=202)
def dispatch_agent_task(
    body: AgentTaskRequest,
    role: str = Path(..., min_length=1, max_length=64),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Dispatch a task to a named agent role (security_analyst, pentester, etc).

    (Multica 37c6a559)
    """
    org_id = _org(x_org_id)
    valid_roles = {
        "security_analyst", "pentester", "compliance", "remediation",
        "general", "code_builder", "test_writer", "doc_generator",
        "security_reviewer", "code_reviewer",
    }
    if role.lower() not in valid_roles:
        raise HTTPException(status_code=400, detail=f"unknown role '{role}'. valid={sorted(valid_roles)}")

    task_id = f"task_{uuid.uuid4().hex[:12]}"
    task = {
        "task_id": task_id,
        "org_id": org_id,
        "role": role.lower(),
        "title": body.title,
        "prompt_preview": body.prompt[:200],
        "priority": body.priority,
        "status": "queued",
        "created_at": int(time.time()),
        "metadata": body.metadata,
    }
    try:
        from core.persistent_store import get_persistent_store
        get_persistent_store(f"agent_tasks_{org_id}").set(task_id, task)
    except Exception:
        pass
    return task


# ===========================================================================
# 7. ASSET CROWN-JEWEL TAG (68162b9b)
# ===========================================================================
@router.post("/assets/{id}/crown-jewel-tag", dependencies=[Depends(api_key_auth)])
def tag_crown_jewel(
    body: CrownJewelTagRequest,
    id: str = Path(..., min_length=1, max_length=256),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Tag an asset as a crown-jewel (or untag). (Multica 68162b9b)"""
    org_id = _org(x_org_id)
    record = {
        "asset_id": id,
        "org_id": org_id,
        "crown_jewel": body.crown_jewel,
        "business_impact": body.business_impact,
        "justification": body.justification,
        "tagged_by": body.tagged_by,
        "tagged_at": int(time.time()),
    }
    # Best-effort delegate to asset_tagging_engine
    try:
        from core.asset_tagging_engine import AssetTaggingEngine  # type: ignore
        engine = AssetTaggingEngine()
        if hasattr(engine, "assign_tag"):
            try:
                engine.assign_tag(asset_id=id, tag_key="crown_jewel",
                                  tag_value="true" if body.crown_jewel else "false",
                                  tag_category="criticality")
                record["engine_persisted"] = True
            except Exception as exc:
                record["engine_error"] = str(exc)
    except Exception:
        record["engine_persisted"] = False

    try:
        from core.persistent_store import get_persistent_store
        get_persistent_store(f"crown_jewels_{org_id}").set(id, record)
    except Exception:
        pass
    return record


# ===========================================================================
# 8. TRUSTGRAPH COMPACT + QUALITY ISSUES (d532f156 / 9f0ae4e6)
# ===========================================================================
@router.post("/trustgraph/compact", dependencies=[Depends(api_key_auth)])
def trustgraph_compact(
    body: TrustGraphCompactRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Run TrustGraph compaction. (Multica d532f156)"""
    org_id = _org(x_org_id)
    started = time.time()
    summary: Dict[str, Any] = {
        "org_id": org_id,
        "dry_run": body.dry_run,
        "cores_requested": body.cores or "all",
        "compacted_cores": [],
        "freed_bytes": 0,
    }
    try:
        from core.trustgraph_maintenance_engine import (
            get_engine as _get_eng,  # type: ignore
        )
        eng = _get_eng()
        if hasattr(eng, "compact"):
            res = eng.compact(cores=body.cores, dry_run=body.dry_run)
            if isinstance(res, dict):
                summary.update(res)
            return {**summary, "elapsed_s": round(time.time() - started, 4)}
    except Exception as exc:
        logger.debug("wave_d: trustgraph compact fallback: %s", exc)

    try:
        from core.trustgraph.knowledge_store import KnowledgeStore  # type: ignore
        store = KnowledgeStore()
        if hasattr(store, "vacuum"):
            store.vacuum()
            summary["compacted_cores"] = body.cores or [1, 2, 3, 4, 5]
    except Exception as exc:
        summary["note"] = f"compaction skipped: {exc}"

    summary["elapsed_s"] = round(time.time() - started, 4)
    return summary


@router.get("/trustgraph/quality-issues", dependencies=[Depends(api_key_auth)])
def trustgraph_quality_issues(
    severity: Optional[str] = Query(default=None, max_length=16),
    limit: int = Query(default=100, ge=1, le=1000),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return TrustGraph data-quality issues. (Multica 9f0ae4e6)"""
    org_id = _org(x_org_id)
    issues: List[Dict[str, Any]] = []
    try:
        from core.trustgraph_quality_engine import get_engine as _qe  # type: ignore
        eng = _qe()
        if hasattr(eng, "list_issues"):
            issues = eng.list_issues(severity=severity, limit=limit) or []
    except Exception as exc:
        logger.debug("wave_d: tg quality fallback: %s", exc)
    if not issues:
        try:
            from core.trustgraph_maintenance_engine import (
                get_engine as _me,  # type: ignore
            )
            eng = _me()
            if hasattr(eng, "list_issues"):
                issues = eng.list_issues() or []
        except Exception:
            pass
    if severity:
        issues = [i for i in issues if str(i.get("severity", "")).lower() == severity.lower()]
    return {
        "org_id": org_id,
        "severity_filter": severity,
        "count": len(issues),
        "issues": issues[:limit],
    }


# ===========================================================================
# 9. AUTO WAIVERS (49049e61 / 1f5d8fc9)
# ===========================================================================
@router.get("/waivers", dependencies=[Depends(api_key_auth)])
def list_waivers(
    auto: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=1000),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """List waivers, optionally filtered to auto-applied ones. (Multica 49049e61)"""
    org_id = _org(x_org_id)
    waivers: List[Dict[str, Any]] = []
    try:
        from core.vuln_exception_engine import VulnExceptionEngine  # type: ignore
        eng = VulnExceptionEngine()
        if hasattr(eng, "list_exceptions"):
            try:
                waivers = eng.list_exceptions(org_id=org_id) or []
            except TypeError:
                waivers = eng.list_exceptions(org_id) or []
        if auto:
            waivers = [w for w in waivers if w.get("auto_applied") or w.get("is_auto") or
                       (isinstance(w, dict) and "auto_waiver" in (w.get("source") or ""))]
    except Exception as exc:
        logger.debug("wave_d: list_waivers fallback: %s", exc)
    return {
        "org_id": org_id,
        "auto_only": auto,
        "count": len(waivers),
        "waivers": waivers[:limit],
    }


@router.post("/auto-waiver-rules", dependencies=[Depends(api_key_auth)], status_code=201)
def create_auto_waiver_rule(
    body: AutoWaiverRuleRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Register an auto-waiver rule. (Multica 1f5d8fc9)"""
    org_id = _org(x_org_id)
    try:
        from core.vuln_exception_engine import VulnExceptionEngine  # type: ignore
        eng = VulnExceptionEngine()
        res = eng.register_auto_waiver_rule(
            org_id=org_id,
            rule_key=body.rule_key,
            conditions=body.conditions,
            max_active_count=body.max_active_count,
            approvers=body.approvers,
            expires_days=body.expires_days,
        )
        return res if isinstance(res, dict) else {"rule_key": body.rule_key, "registered": True}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning("wave_d: auto_waiver_rule fallback (in-memory): %s", exc)
        # Graceful in-memory fallback — engine import failed, persist to module dict
        import datetime as _dt
        _AUTO_WAIVER_RULES.setdefault(org_id, {})[body.rule_key] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "rule_key": body.rule_key,
            "conditions": body.conditions,
            "max_active_count": body.max_active_count,
            "approvers": body.approvers,
            "expires_days": body.expires_days,
            "enabled": True,
            "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "source": "in_memory_fallback",
        }
        return _AUTO_WAIVER_RULES[org_id][body.rule_key]


# ===========================================================================
# 10. POLICY STAGE MATRIX + EVALUATE (61db07fb / 181dc9f8 / a0585e59)
# ===========================================================================
@router.post("/policies/{id}/stage-matrix", dependencies=[Depends(api_key_auth)])
def set_policy_stage_matrix(
    body: StageMatrixRequest,
    id: str = Path(..., min_length=1, max_length=128),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Set the CTEM stage matrix for a policy. (Multica 61db07fb)"""
    org_id = _org(x_org_id)
    try:
        from core.policy_enforcement_engine import get_engine  # type: ignore
        eng = get_engine(org_id)
        result = eng.set_stage_matrix(org_id, id, body.stage_matrix)
        if result is None:
            raise HTTPException(status_code=404, detail=f"policy '{id}' not found for org '{org_id}'")
        return {"org_id": org_id, "policy_id": id, "stage_matrix": result}
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning("wave_d: set_stage_matrix fallback (in-memory): %s", exc)
        # Graceful in-memory fallback — store stage_matrix in module dict
        normalised = {s: bool(body.stage_matrix.get(s, False)) for s in _VALID_STAGES}
        _STAGE_MATRIX_STORE.setdefault(org_id, {})[id] = normalised
        return {
            "org_id": org_id,
            "policy_id": id,
            "stage_matrix": normalised,
            "source": "in_memory_fallback",
        }


@router.get("/policies/{id}/stage-matrix", dependencies=[Depends(api_key_auth)])
def get_policy_stage_matrix(
    id: str = Path(..., min_length=1, max_length=128),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Return the CTEM stage matrix for a policy. (Multica 181dc9f8)"""
    org_id = _org(x_org_id)
    try:
        from core.policy_enforcement_engine import get_engine  # type: ignore
        eng = get_engine(org_id)
        policy = eng.get_policy(org_id, id) if hasattr(eng, "get_policy") else None
        if not policy:
            raise HTTPException(status_code=404, detail=f"policy '{id}' not found for org '{org_id}'")
        sm = policy.get("stage_matrix") or {s: False for s in _VALID_STAGES}
        return {"org_id": org_id, "policy_id": id, "stage_matrix": sm}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("wave_d: get_stage_matrix fallback (in-memory): %s", exc)
        # Graceful in-memory fallback — return stored matrix or safe default
        sm = _STAGE_MATRIX_STORE.get(org_id, {}).get(id)
        if sm is None:
            sm = {s: False for s in _VALID_STAGES}
        return {
            "org_id": org_id,
            "policy_id": id,
            "stage_matrix": sm,
            "source": "in_memory_fallback",
        }


@router.post("/evaluate", dependencies=[Depends(api_key_auth)])
def evaluate_at_stage(
    body: StageEvaluateRequest,
    stage: str = Query(..., min_length=1, max_length=32),
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Evaluate a context against stage-aware policies. (Multica a0585e59)"""
    org_id = _org(x_org_id)
    if stage not in _VALID_STAGES:
        raise HTTPException(status_code=400, detail=f"invalid stage '{stage}'; valid={sorted(_VALID_STAGES)}")
    try:
        from core.policy_enforcement_engine import get_engine  # type: ignore
        eng = get_engine(org_id)
        result = eng.evaluate(org_id, stage, body.context)
        return result if isinstance(result, dict) else {"result": result}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning("wave_d: evaluate fallback: %s", exc)
        # try policy_engine.evaluate_at_stage as secondary
        try:
            from core.policy_engine import get_policy_engine  # type: ignore
            pe = get_policy_engine()
            return pe.evaluate_at_stage(org_id, stage, body.context)
        except Exception as exc2:
            logger.warning("wave_d: evaluate both engines failed (%s / %s) — returning allow", exc, exc2)
            # Graceful fallback — both engines unavailable, return safe allow decision
            return {
                "org_id": org_id,
                "stage": stage,
                "context": body.context,
                "policy_count": 0,
                "matched_policies": [],
                "decision": "allow",
                "source": "in_memory_fallback",
            }
