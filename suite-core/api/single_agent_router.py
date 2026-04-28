"""Single AI Agent / Multi-LLM Consensus Router (V4).

Exposes AI-powered decision making with multi-LLM consensus engine.
Supports vLLM, Ollama, GGUF self-hosted, and API fallback backends.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ai-agent", tags=["AI Agent"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class DecideRequest(BaseModel):
    finding: Dict[str, Any] = Field(..., description="Finding to analyze")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")


class BatchDecideRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="Findings to analyze")
    context: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/health")
async def ai_agent_health() -> Dict[str, Any]:
    """Health check alias for AI agent engine (mirrors /status)."""
    return await ai_agent_status()


@router.get("/status")
async def ai_agent_status() -> Dict[str, Any]:
    """Get AI agent engine status and backend availability."""
    try:
        from core.single_agent import SingleAgentEngine
        engine = SingleAgentEngine()
        backend = engine._backend
        expert_roles = ["analyst", "architect", "auditor", "attacker"]
        return {
            "status": "operational",
            "engine": "single-agent",
            "version": "1.0.0",
            "backend": backend.__class__.__name__,
            "model_info": backend.model_info(),
            "expert_count": len(expert_roles),
            "experts": expert_roles,
            "cache_size": len(engine._decision_cache),
            "consensus_threshold": engine.consensus_threshold,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        return {
            "status": "degraded",
            "engine": "single-agent",
            "error": type(e).__name__,
        }


@router.post("/decide")
async def decide(req: DecideRequest) -> Dict[str, Any]:
    """Get AI consensus decision for a single finding."""
    try:
        from core.single_agent import SingleAgentEngine
        engine = SingleAgentEngine()
        decision = engine.decide(req.finding)
        return {
            "decision_id": decision.decision_id,
            "action": decision.action,
            "priority": decision.priority,
            "confidence": decision.confidence,
            "consensus": decision.consensus.value,
            "reasoning": decision.reasoning,
            "expert_opinions": decision.expert_opinions,
            "dissenting_views": decision.dissenting_views,
            "decided_at": decision.decided_at,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=f"Decision failed: {e}")


@router.post("/batch-decide")
async def batch_decide(req: BatchDecideRequest) -> Dict[str, Any]:
    """Get AI consensus decisions for multiple findings."""
    try:
        from core.single_agent import SingleAgentEngine
        engine = SingleAgentEngine()
        decisions = engine.batch_decide(req.findings)
        return {
            "decisions": [
                {
                    "decision_id": d.decision_id,
                    "action": d.action,
                    "priority": d.priority,
                    "confidence": d.confidence,
                    "consensus": d.consensus.value,
                }
                for d in decisions
            ],
            "total": len(decisions),
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=f"Batch decision failed: {e}")


@router.get("/experts")
async def list_experts() -> Dict[str, Any]:
    """List available expert roles in the consensus engine."""
    return {
        "experts": [
            {"role": "analyst", "focus": "Risk assessment and severity validation"},
            {"role": "architect", "focus": "Systemic impact and architectural risk"},
            {"role": "auditor", "focus": "Compliance implications and evidence requirements"},
            {"role": "attacker", "focus": "Exploitability assessment and attack vectors"},
        ],
        "moderator": "Synthesizes all expert opinions into consensus decision",
        "threshold": "85% agreement required for AGREED status",
    }


@router.get("/backends")
async def list_backends() -> Dict[str, Any]:
    """List available inference backends (vLLM, Ollama, GGUF, API)."""
    backends = []
    try:
        from core.single_agent import VLLMBackend
        b = VLLMBackend()
        backends.append({"name": "vLLM", "available": b.is_available(), "info": b.model_info()})
    except ImportError:
        backends.append({"name": "vLLM", "available": False})

    try:
        from core.single_agent import OllamaBackend
        b = OllamaBackend()
        backends.append({"name": "Ollama", "available": b.is_available(), "info": b.model_info()})
    except ImportError:
        backends.append({"name": "Ollama", "available": False})

    try:
        from core.single_agent import GGUFBackend
        b = GGUFBackend()
        backends.append({"name": "GGUF", "available": b.is_available(), "info": b.model_info()})
    except ImportError:
        backends.append({"name": "GGUF", "available": False})

    backends.append({"name": "API Fallback", "available": True, "info": {"provider": "OpenAI/Anthropic"}})

    return {"backends": backends}


@router.delete("/cache")
async def clear_cache() -> Dict[str, Any]:
    """Clear the decision cache."""
    try:
        from core.single_agent import SingleAgentEngine
        engine = SingleAgentEngine()
        engine.clear_cache()
        return {"cleared": True}
    except ImportError as e:
        raise HTTPException(status_code=500, detail=type(e).__name__)
