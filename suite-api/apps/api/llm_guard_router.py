"""LLM Guard Router — prompt injection detection and LLM firewall endpoints.

Exposes LLMGuardService (core.llm_guard_service) for:
  - Prompt injection / jailbreak detection  (POST /scan-prompt)
  - LLM output scanning                     (POST /scan-output)
  - Service health / status                 (GET  /health, /status)
  - Runtime configuration read              (GET  /config)
  - Cumulative scan statistics              (GET  /stats)
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/llm-guard", tags=["LLM Guard"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanPromptRequest(BaseModel):
    prompt: str = Field(..., description="Raw prompt text to scan before sending to LLM")
    fail_fast: bool = Field(True, description="Stop on first detected issue")


class ScanOutputRequest(BaseModel):
    prompt: str = Field("", description="Original prompt (used for context in output scan)")
    output: str = Field(..., description="LLM response text to scan before returning to caller")
    fail_fast: bool = Field(True, description="Stop on first detected issue")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
async def llm_guard_health() -> Dict[str, Any]:
    """Health check — confirms the LLM Guard service is initialised."""
    from core.llm_guard_service import get_llm_guard_service

    svc = get_llm_guard_service()
    status = svc.get_status()
    return {
        "status": "healthy",
        "engine": "llm_guard",
        "backend": status.get("backend", "regex_fallback"),
        "version": "1.0.0",
    }


@router.get("/status")
async def llm_guard_status() -> Dict[str, Any]:
    """Full status including scanner list, config, and cumulative stats."""
    from core.llm_guard_service import get_llm_guard_service

    svc = get_llm_guard_service()
    return svc.get_status()


@router.get("/config")
async def llm_guard_config() -> Dict[str, Any]:
    """Return current scanner configuration (read-only)."""
    from core.llm_guard_service import get_llm_guard_service

    svc = get_llm_guard_service()
    status = svc.get_status()
    return {
        "config": status.get("config", {}),
        "backend": status.get("backend", "regex_fallback"),
        "input_scanners": status.get("input_scanners", []),
        "output_scanners": status.get("output_scanners", []),
    }


@router.get("/stats")
async def llm_guard_stats() -> Dict[str, Any]:
    """Cumulative scan statistics (prompts/outputs scanned and blocked)."""
    from core.llm_guard_service import get_llm_guard_service

    svc = get_llm_guard_service()
    status = svc.get_status()
    return {"stats": status.get("stats", {})}


@router.post("/scan-prompt")
async def scan_prompt(req: ScanPromptRequest) -> Dict[str, Any]:
    """Scan a prompt for injection, secrets, and invisible-text attacks.

    Returns the sanitised text and a ``blocked`` flag.  When ``blocked`` is
    true the caller MUST NOT forward the prompt to any LLM.
    """
    from core.llm_guard_service import get_llm_guard_service

    svc = get_llm_guard_service(fail_fast=req.fail_fast)
    result = svc.scan_prompt(req.prompt)
    return result.to_dict()


@router.post("/scan-output")
async def scan_output(req: ScanOutputRequest) -> Dict[str, Any]:
    """Scan an LLM response for sensitive data leakage before returning to caller.

    Returns the sanitised text and a ``blocked`` flag.
    """
    from core.llm_guard_service import get_llm_guard_service

    svc = get_llm_guard_service(fail_fast=req.fail_fast)
    result = svc.scan_output(prompt=req.prompt, output=req.output)
    return result.to_dict()
