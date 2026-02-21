"""LLM Monitor Router — AI/LLM Security Monitoring endpoints."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/llm-monitor", tags=["LLM Monitor"])


class AnalyzeRequest(BaseModel):
    prompt: str = ""
    response: str = ""
    model: str = "unknown"
    max_tokens: int = 0


@router.post("/analyze")
async def analyze_llm(req: AnalyzeRequest) -> Dict[str, Any]:
    """Analyze an LLM prompt/response for security threats."""
    from core.llm_monitor import get_llm_monitor

    monitor = get_llm_monitor()
    result = monitor.analyze(
        prompt=req.prompt,
        response=req.response,
        model=req.model,
        max_tokens=req.max_tokens,
    )
    return result.to_dict()


@router.post("/scan/prompt")
async def scan_prompt(req: AnalyzeRequest) -> Dict[str, Any]:
    """Quick scan just the prompt for jailbreak/injection."""
    from core.llm_monitor import get_llm_monitor

    monitor = get_llm_monitor()
    result = monitor.analyze(prompt=req.prompt)
    return {
        "threats": [t.to_dict() for t in result.prompt_threats],
        "risk_score": result.risk_score,
        "safe": result.total_threats == 0,
    }


@router.get("/patterns")
async def list_patterns() -> Dict[str, Any]:
    """List all detection patterns."""
    from core.llm_monitor import JAILBREAK_PATTERNS, PII_PATTERNS, SENSITIVE_TOPICS

    return {
        "jailbreak_patterns": len(JAILBREAK_PATTERNS),
        "pii_patterns": len(PII_PATTERNS),
        "sensitive_topics": len(SENSITIVE_TOPICS),
        "total": len(JAILBREAK_PATTERNS) + len(PII_PATTERNS) + len(SENSITIVE_TOPICS),
    }


@router.get("/status")
async def llm_monitor_status() -> Dict[str, Any]:
    return {"engine": "llm_monitor", "status": "ready", "version": "1.0.0"}
