"""Brain Pipeline REST API.

Exposes endpoints to trigger, monitor, and query the 12-step
ALdeci Brain Pipeline orchestrator.

Endpoints:
    POST /api/v1/pipeline/run            - Execute full pipeline
    GET  /api/v1/pipeline/runs           - List past runs (scoped to org)
    GET  /api/v1/pipeline/runs/{id}      - Get run details (org-scoped)
    POST /api/v1/pipeline/evidence/generate - Generate SOC2 evidence pack
    GET  /api/v1/pipeline/evidence/packs    - List evidence packs (org-scoped)
    GET  /api/v1/pipeline/evidence/packs/{id} - Get evidence pack (org-scoped)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from apps.api.endpoint_rate_limit import enforce as _rl_enforce
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/pipeline", tags=["Brain Pipeline"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class FindingInput(BaseModel):
    id: str = Field("", max_length=256)
    cve_id: Optional[str] = Field(None, max_length=32)
    severity: str = Field("medium", max_length=32)
    asset_name: str = Field("", max_length=512)
    title: str = Field("", max_length=512)
    description: str = Field("", max_length=4096)
    source: str = Field("", max_length=256)
    code_context: Optional[Dict[str, Any]] = None


class AssetInput(BaseModel):
    id: str = Field("", max_length=256)
    name: str = Field("", max_length=512)
    criticality: float = Field(1.0, ge=0.0, le=10.0)
    url: Optional[str] = Field(None, max_length=2048)
    endpoint: Optional[str] = Field(None, max_length=2048)
    type: str = Field("service", max_length=64)


# Maximum findings/assets per pipeline run — prevents 40s+ DoS via 10k-item payloads
_MAX_PIPELINE_FINDINGS = 500
_MAX_PIPELINE_ASSETS = 200


class PipelineRunRequest(BaseModel):
    org_id: str = Field("default", max_length=128)
    findings: List[FindingInput] = Field(default_factory=list, max_length=_MAX_PIPELINE_FINDINGS)
    assets: List[AssetInput] = Field(default_factory=list, max_length=_MAX_PIPELINE_ASSETS)
    source: str = Field("api", max_length=128)
    run_pentest: bool = False
    run_playbooks: bool = False
    generate_evidence: bool = False
    evidence_framework: str = Field("SOC2", max_length=32)
    evidence_timeframe_days: int = Field(90, ge=1, le=365)
    policy_rules: Optional[List[Dict[str, Any]]] = Field(None, max_length=100)

    @field_validator("findings", mode="before")
    @classmethod
    def _cap_findings(cls, v: Any) -> Any:
        if isinstance(v, list) and len(v) > _MAX_PIPELINE_FINDINGS:
            raise ValueError(
                f"findings list exceeds maximum allowed size of {_MAX_PIPELINE_FINDINGS}. "
                f"Split into smaller batches."
            )
        return v

    @field_validator("assets", mode="before")
    @classmethod
    def _cap_assets(cls, v: Any) -> Any:
        if isinstance(v, list) and len(v) > _MAX_PIPELINE_ASSETS:
            raise ValueError(
                f"assets list exceeds maximum allowed size of {_MAX_PIPELINE_ASSETS}."
            )
        return v


class EvidenceGenerateRequest(BaseModel):
    org_id: str = Field("default", max_length=128)
    timeframe_days: int = Field(90, ge=1, le=365)
    controls: Optional[List[str]] = Field(None, max_length=200)
    pipeline_run_id: Optional[str] = Field(None, max_length=256)
    findings: List[FindingInput] = Field(default_factory=list, max_length=_MAX_PIPELINE_FINDINGS)
    assets: List[AssetInput] = Field(default_factory=list, max_length=_MAX_PIPELINE_ASSETS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_verdict(result_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a normalised top-level verdict from a PipelineResult dict.

    Priority order:
      1. llm_council step output  (council_verdict via CouncilPipelineAdapter)
      2. llm_consensus step output (multi-provider consensus)
      3. apply_policy step output  (OPA/deterministic policy)
      4. deterministic fallback from summary risk score

    The ``source`` field is always honest:
      - "council"        — real LLM council verdict
      - "consensus"      — multi-provider LLM consensus
      - "policy"         — OPA / rule-based policy engine
      - "deterministic"  — heuristic fallback, no LLM
      - "degraded"       — pipeline status is not completed
    """
    # Find step outputs by name
    steps_by_name: Dict[str, Any] = {
        s["name"]: s.get("output", {})
        for s in result_dict.get("steps", [])
        if s.get("status") == "completed"
    }

    # 1. LLM Council (step: llm_council)
    council_out = steps_by_name.get("llm_council", {})
    if council_out.get("decision") or council_out.get("final_decision"):
        decision = council_out.get("decision") or council_out.get("final_decision", "review")
        return {
            "decision": decision,
            "confidence": float(council_out.get("confidence", council_out.get("consensus_pct", 0.0))),
            "summary": council_out.get("summary") or council_out.get("note") or f"Council decision: {decision}",
            "source": "council",
        }

    # 2. LLM Consensus (step: llm_consensus)
    consensus_out = steps_by_name.get("llm_consensus", {})
    if consensus_out.get("decision") or consensus_out.get("final_decision"):
        decision = consensus_out.get("decision") or consensus_out.get("final_decision", "review")
        method = consensus_out.get("method", "")
        source = "deterministic" if "deterministic" in method else "consensus"
        return {
            "decision": decision,
            "confidence": float(consensus_out.get("consensus_pct", 0.0)),
            "summary": consensus_out.get("note") or f"Consensus decision: {decision} (method={method})",
            "source": source,
        }

    # 3. Policy step (step: apply_policy)
    policy_out = steps_by_name.get("apply_policy", {})
    if policy_out.get("decision") or policy_out.get("opa_verdict"):
        decision = policy_out.get("decision") or policy_out.get("opa_verdict", "review")
        return {
            "decision": decision,
            "confidence": 1.0,
            "summary": f"Policy engine decision: {decision}",
            "source": "policy",
        }

    # 4. Heuristic fallback from summary
    status = result_dict.get("status", "")
    if status not in ("completed", "partial"):
        return {
            "decision": "review",
            "confidence": 0.0,
            "summary": f"Pipeline did not complete (status={status}); manual review required.",
            "source": "degraded",
        }

    avg_risk = result_dict.get("summary", {}).get("avg_risk_score", 0.0)
    critical = result_dict.get("summary", {}).get("critical_cases", 0)
    if critical > 0 or avg_risk >= 0.75:
        decision = "block"
    elif avg_risk >= 0.5:
        decision = "review"
    else:
        decision = "allow"

    return {
        "decision": decision,
        "confidence": 0.0,
        "summary": (
            f"Heuristic fallback (no LLM verdict available): avg_risk={avg_risk:.2f}, "
            f"critical_cases={critical}. Configure OPENROUTER_API_KEY for real verdicts."
        ),
        "source": "deterministic",
    }


# ---------------------------------------------------------------------------
# Pipeline Endpoints
# ---------------------------------------------------------------------------
@router.post("/run")
async def run_pipeline(
    request: Request,
    req: PipelineRunRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Execute the full 12-step ALdeci Brain Pipeline synchronously.

    Rate-limited to 5 runs/minute per IP — each run is O(findings) CPU/LLM.
    Max 500 findings and 200 assets per request (validated by PipelineRunRequest).
    """
    # Rate-limit: pipeline runs are expensive (LLM calls, graph ops, db writes)
    _rl_enforce(request, limit_key="pipeline:run", max_per_minute=5)

    from core.brain_pipeline import PipelineInput, get_brain_pipeline

    # The request body's org_id takes precedence (caller may specify a sub-org);
    # fall back to the JWT/header derived org_id.
    effective_org_id = req.org_id or org_id
    pipeline = get_brain_pipeline()
    inp = PipelineInput(
        org_id=effective_org_id,
        findings=[f.model_dump() for f in req.findings],
        assets=[a.model_dump() for a in req.assets],
        source=req.source,
        run_pentest=req.run_pentest,
        run_playbooks=req.run_playbooks,
        generate_evidence=req.generate_evidence,
        evidence_framework=req.evidence_framework,
        evidence_timeframe_days=req.evidence_timeframe_days,
        policy_rules=req.policy_rules,
    )
    result = pipeline.run(inp)
    result_dict = result.to_dict()
    # Issue 2: inject top-level verdict derived from real pipeline step outputs
    result_dict["verdict"] = _extract_verdict(result_dict)
    return result_dict


@router.get("/runs")
async def list_pipeline_runs(
    limit: int = Query(20, ge=1, le=500, description="Max results (1-500)"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List past pipeline runs for the authenticated org."""
    from core.brain_pipeline import get_brain_pipeline

    pipeline = get_brain_pipeline()
    # Issue 5: filter by org_id — only return this org's runs
    all_runs = pipeline.list_runs(limit=limit + offset)
    org_runs = [r for r in all_runs if r.get("org_id") == org_id]
    page = org_runs[offset : offset + limit]
    return {
        "total": len(org_runs),
        "limit": limit,
        "offset": offset,
        "runs": page,
    }


@router.get("/runs/{run_id}")
async def get_pipeline_run(
    run_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Get details of a specific pipeline run (org-scoped)."""
    from core.brain_pipeline import get_brain_pipeline

    pipeline = get_brain_pipeline()
    result = pipeline.get_run(run_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    # Issue 5: cross-tenant guard
    if result.org_id != org_id:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    result_dict = result.to_dict()
    result_dict["verdict"] = _extract_verdict(result_dict)
    return result_dict


# ---------------------------------------------------------------------------
# Evidence Endpoints
# ---------------------------------------------------------------------------
@router.post("/evidence/generate")
async def generate_evidence_pack(
    req: EvidenceGenerateRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Generate a SOC2 Type II evidence pack (persisted, org-scoped)."""
    from core.soc2_evidence_generator import get_evidence_generator

    effective_org_id = req.org_id or org_id
    # Issue 4: use the persistent singleton, not a throw-away instance
    generator = get_evidence_generator()
    platform_data = _collect_platform_data(req)
    pack = generator.generate(
        org_id=effective_org_id,
        timeframe_days=req.timeframe_days,
        controls=req.controls,
        platform_data=platform_data,
    )
    return pack.to_dict()


@router.get("/evidence/packs")
async def list_evidence_packs(
    limit: int = 20,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List generated evidence packs for the authenticated org."""
    from core.soc2_evidence_generator import get_evidence_generator

    generator = get_evidence_generator()
    # Issue 5: filter by org_id — SOC2 evidence is highly sensitive
    all_packs = generator.list_packs()
    org_packs = [p for p in all_packs if p.org_id == org_id]
    return {"total": len(org_packs), "packs": [p.to_dict() for p in org_packs[:limit]]}


@router.get("/evidence/packs/{pack_id}")
async def get_evidence_pack(
    pack_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Get a specific evidence pack (org-scoped)."""
    from core.soc2_evidence_generator import get_evidence_generator

    generator = get_evidence_generator()
    pack = generator.get_pack(pack_id)
    if not pack:
        raise HTTPException(status_code=404, detail=f"Pack {pack_id} not found")
    # Issue 5: cross-tenant guard — SOC2 evidence is highly sensitive
    if pack.org_id != org_id:
        raise HTTPException(status_code=404, detail=f"Pack {pack_id} not found")
    return pack.to_dict()


# ---------------------------------------------------------------------------
# Platform data helper
# ---------------------------------------------------------------------------
def _collect_platform_data(req: EvidenceGenerateRequest) -> Dict[str, Any]:
    """Collect platform telemetry data for evidence assessment."""
    data: Dict[str, Any] = {
        "findings": [f.model_dump() for f in req.findings],
        "assets": [a.model_dump() for a in req.assets],
        "findings_count": len(req.findings),
        "assets_count": len(req.assets),
    }

    # Try to collect from brain graph
    try:
        from core.knowledge_brain import get_brain

        brain = get_brain()
        stats = brain.stats()
        data["graph_stats"] = stats
    except ImportError:
        pass

    # Try to collect exposure case stats
    try:
        from core.exposure_case import ExposureCaseManager

        mgr = ExposureCaseManager.get_instance()
        data["case_stats"] = mgr.stats()
    except ImportError:
        pass

    return data


@router.get("/health")
async def pipeline_health():
    """Pipeline engine health check."""
    return {"status": "healthy", "engine": "pipeline", "version": "1.0.0"}


@router.get("/status")
async def pipeline_status():
    """Pipeline engine status (alias for /health)."""
    return await pipeline_health()
