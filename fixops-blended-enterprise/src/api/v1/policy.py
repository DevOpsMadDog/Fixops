"""
Policy evaluation endpoints for CI/CD gates (SSVC-aware)
"""
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import structlog

from src.config.settings import get_settings

logger = structlog.get_logger()
router = APIRouter(prefix="/policy", tags=["policy-gates"])
settings = get_settings()

class GateRequest(BaseModel):
    decision: str  # ALLOW/BLOCK/DEFER
    confidence: float
    signals: Dict[str, Any] = {}
    findings: List[Dict[str, Any]] = []

class GateResponse(BaseModel):
    allow: bool
    reason: str
    required_actions: List[str]

@router.post("/evaluate", response_model=GateResponse)
async def evaluate_gate(req: GateRequest):
    try:
        # Simple gate logic: block if KEV present and any high/critical finding or low confidence
        kev_count = int(req.signals.get("kev_count", 0) or 0)
        epss_risk = int(req.signals.get("epss_count", 0) or 0) > 0
        low_confidence = req.confidence < max(settings.LLM_CONSENSUS_THRESHOLD, 0.75)

        has_high = any(f.get("severity") in ("high", "critical") for f in (req.findings or []))

        if req.decision == "BLOCK":
            return GateResponse(allow=False, reason="Engine decided BLOCK", required_actions=["Fix blocking issues", "Request re-evaluation"]) 
        if kev_count and has_high:
            return GateResponse(allow=False, reason="KEV present with high severity findings", required_actions=["Patch KEV-listed vulns", "Re-run scans"]) 
        if low_confidence:
            return GateResponse(allow=False, reason=f"Consensus confidence too low ({req.confidence:.0%})", required_actions=["Manual review", "Add business context"]) 

        return GateResponse(allow=True, reason="Policy checks passed", required_actions=["Proceed with deployment"]) 
    except Exception as e:
        logger.error(f"Policy evaluate failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
