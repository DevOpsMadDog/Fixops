"""Brain Pipeline REST API.

Exposes endpoints to trigger, monitor, and query the 12-step
ALdeci Brain Pipeline orchestrator.

Endpoints:
    POST /api/v1/brain/pipeline/run     - Execute full pipeline
    GET  /api/v1/brain/pipeline/runs     - List past runs
    GET  /api/v1/brain/pipeline/runs/{id} - Get run details
    POST /api/v1/brain/pipeline/run-async - Start async run (returns immediately)
    POST /api/v1/brain/evidence/generate - Generate SOC2 evidence pack
    GET  /api/v1/brain/evidence/packs    - List evidence packs
    GET  /api/v1/brain/evidence/packs/{id} - Get evidence pack details
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/brain", tags=["Brain Pipeline"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class FindingInput(BaseModel):
    id: str = ""
    cve_id: Optional[str] = None
    severity: str = "medium"
    asset_name: str = ""
    title: str = ""
    description: str = ""
    source: str = ""
    code_context: Optional[Dict[str, Any]] = None


class AssetInput(BaseModel):
    id: str = ""
    name: str = ""
    criticality: float = 1.0
    url: Optional[str] = None
    endpoint: Optional[str] = None
    type: str = "service"


class PipelineRunRequest(BaseModel):
    org_id: str
    findings: List[FindingInput] = Field(default_factory=list)
    assets: List[AssetInput] = Field(default_factory=list)
    source: str = "api"
    run_pentest: bool = False
    run_playbooks: bool = False
    generate_evidence: bool = False
    evidence_framework: str = "SOC2"
    evidence_timeframe_days: int = 90
    policy_rules: Optional[List[Dict[str, Any]]] = None


class EvidenceGenerateRequest(BaseModel):
    org_id: str
    timeframe_days: int = 90
    controls: Optional[List[str]] = None
    pipeline_run_id: Optional[str] = None
    findings: List[FindingInput] = Field(default_factory=list)
    assets: List[AssetInput] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Pipeline Endpoints
# ---------------------------------------------------------------------------
@router.post("/pipeline/run")
async def run_pipeline(req: PipelineRunRequest) -> Dict[str, Any]:
    """Execute the full 12-step ALdeci Brain Pipeline synchronously."""
    from core.brain_pipeline import PipelineInput, get_brain_pipeline

    pipeline = get_brain_pipeline()
    inp = PipelineInput(
        org_id=req.org_id,
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
    return result.to_dict()


@router.get("/pipeline/runs")
async def list_pipeline_runs(limit: int = 20, offset: int = 0) -> Dict[str, Any]:
    """List past pipeline runs."""
    from core.brain_pipeline import get_brain_pipeline

    pipeline = get_brain_pipeline()
    runs = pipeline.list_runs()
    total = len(runs)
    page = runs[offset : offset + limit]
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "runs": page,
    }


@router.get("/pipeline/runs/{run_id}")
async def get_pipeline_run(run_id: str) -> Dict[str, Any]:
    """Get details of a specific pipeline run."""
    from core.brain_pipeline import get_brain_pipeline

    pipeline = get_brain_pipeline()
    result = pipeline.get_run(run_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return result.to_dict()


# ---------------------------------------------------------------------------
# Evidence Endpoints
# ---------------------------------------------------------------------------
@router.post("/evidence/generate")
async def generate_evidence_pack(req: EvidenceGenerateRequest) -> Dict[str, Any]:
    """Generate a SOC2 Type II evidence pack."""
    from core.soc2_evidence_generator import SOC2EvidenceGenerator

    generator = SOC2EvidenceGenerator()
    platform_data = _collect_platform_data(req)
    pack = generator.generate(
        org_id=req.org_id,
        timeframe_days=req.timeframe_days,
        controls=req.controls,
        platform_data=platform_data,
    )
    return pack.to_dict()


@router.get("/evidence/packs")
async def list_evidence_packs(limit: int = 20) -> Dict[str, Any]:
    """List generated evidence packs."""
    from core.soc2_evidence_generator import get_evidence_generator

    generator = get_evidence_generator()
    packs = generator.list_packs()[:limit]
    return {"total": len(packs), "packs": [p.to_dict() for p in packs]}


@router.get("/evidence/packs/{pack_id}")
async def get_evidence_pack(pack_id: str) -> Dict[str, Any]:
    """Get a specific evidence pack."""
    from core.soc2_evidence_generator import get_evidence_generator

    generator = get_evidence_generator()
    pack = generator.get_pack(pack_id)
    if not pack:
        raise HTTPException(status_code=404, detail=f"Pack {pack_id} not found")
    return pack.to_dict()


# ---------------------------------------------------------------------------
# Helpers
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
    except Exception:
        pass

    # Try to collect exposure case stats
    try:
        from core.exposure_case import ExposureCaseManager

        mgr = ExposureCaseManager.get_instance()
        data["case_stats"] = mgr.stats()
    except Exception:
        pass

    return data
