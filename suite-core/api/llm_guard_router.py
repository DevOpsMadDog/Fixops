"""LLM-Guard Security Router — /api/v1/llm-guard.

Exposes LLM-Guard prompt/output scanning as REST endpoints.
Protects against prompt injection, PII leakage, and toxic content.
Air-gap compatible: regex fallback when LLM-Guard models unavailable.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/llm-guard", tags=["LLM Guard"])


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class ScanPromptRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=50000, description="Prompt text to scan")
    fail_fast: bool = Field(True, description="Stop on first detected issue")


class ScanOutputRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=50000, description="Original prompt")
    output: str = Field(..., min_length=1, max_length=100000, description="LLM output to scan")
    fail_fast: bool = Field(True, description="Stop on first detected issue")


class ScanResponse(BaseModel):
    blocked: bool
    issues: list
    sanitized_text: str
    method: str
    scanner_scores: Dict[str, float] = {}
    scan_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# Singleton service
# ---------------------------------------------------------------------------

_svc = None


def _get_service():
    global _svc
    if _svc is None:
        from core.llm_guard_service import LLMGuardService
        _svc = LLMGuardService()
    return _svc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan-prompt", response_model=ScanResponse, summary="Scan prompt for threats")
async def scan_prompt(req: ScanPromptRequest) -> Dict[str, Any]:
    """Scan an input prompt for injection attacks, secrets, and invisible text.

    Returns whether the prompt was blocked and any issues detected.
    """
    svc = _get_service()
    result = svc.scan_prompt(req.prompt)
    return {
        "blocked": result.blocked,
        "issues": result.issues,
        "sanitized_text": result.sanitized_text,
        "method": result.method,
        "scanner_scores": result.scanner_scores,
        "scan_time_ms": result.scan_time_ms,
    }


@router.post("/scan-output", response_model=ScanResponse, summary="Scan LLM output")
async def scan_output(req: ScanOutputRequest) -> Dict[str, Any]:
    """Scan LLM output for sensitive data leakage, bias, and toxic content.

    Returns whether the output was blocked and any issues detected.
    """
    svc = _get_service()
    result = svc.scan_output(req.prompt, req.output)
    return {
        "blocked": result.blocked,
        "issues": result.issues,
        "sanitized_text": result.sanitized_text,
        "method": result.method,
        "scanner_scores": result.scanner_scores,
        "scan_time_ms": result.scan_time_ms,
    }


@router.get("/status", summary="LLM-Guard service status")
async def llm_guard_status() -> Dict[str, Any]:
    """Return LLM-Guard health, backend type, active scanners, and scan statistics."""
    svc = _get_service()
    return svc.get_status()


@router.get("/health", summary="Health check")
async def llm_guard_health() -> Dict[str, Any]:
    """Lightweight health probe for load balancers."""
    svc = _get_service()
    status = svc.get_status()
    return {
        "status": "healthy",
        "engine": "llm_guard",
        "backend": status["backend"],
        "input_scanners": len(status["input_scanners"]),
        "output_scanners": len(status["output_scanners"]),
    }

