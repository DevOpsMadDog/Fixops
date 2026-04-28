"""vLLM Self-Hosted LLM Router [V9 — Air-Gapped Deployment].

Exposes management and status endpoints for self-hosted LLM inference
backends (vLLM, Ollama). Enables air-gapped operation of the Brain
Pipeline, AutoFix engine, and LLM Consensus without external API keys.

Endpoints:
    GET  /api/v1/vllm/status           — Self-hosted backend status
    GET  /api/v1/vllm/models           — Available models
    POST /api/v1/vllm/test-inference   — Test inference round-trip
    GET  /api/v1/vllm/autofix-status   — AutoFix adapter status
    POST /api/v1/vllm/generate-fix     — Generate fix via self-hosted LLM
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vllm", tags=["Self-Hosted LLM (Air-Gapped)"])


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------

class TestInferenceRequest(BaseModel):
    prompt: str = Field(
        "Explain SQL injection in one sentence.",
        description="Test prompt to send to the self-hosted LLM",
    )
    backend: Optional[str] = Field(
        None, description="Backend to test: vllm, ollama, or auto"
    )


class GenerateFixRequest(BaseModel):
    finding: Dict[str, Any] = Field(..., description="Vulnerability finding")
    source_code: Optional[str] = Field(None, description="Vulnerable source code")


# ---------------------------------------------------------------------------
# Singleton adapter
# ---------------------------------------------------------------------------

_adapter = None


def _get_adapter():
    global _adapter
    if _adapter is None:
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        _adapter = VLLMAutoFixAdapter()
    return _adapter


_provider_manager = None


def _get_provider_manager():
    global _provider_manager
    if _provider_manager is None:
        from core.llm_providers import LLMProviderManager
        _provider_manager = LLMProviderManager()
    return _provider_manager


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
async def vllm_health() -> Dict[str, Any]:
    """Health check for self-hosted LLM engine."""
    return {"status": "healthy", "engine": "vllm", "version": "1.0.0"}


@router.get("/status")
async def vllm_status() -> Dict[str, Any]:
    """Get status of all self-hosted LLM backends.

    Returns availability, model info, and active backend for:
    - vLLM (high-throughput, recommended for production)
    - Ollama (easy setup, good for development)
    """
    try:
        adapter = _get_adapter()
        status = adapter.get_status()
        manager = _get_provider_manager()

        # Check which providers are in the manager
        available_providers = []
        for name in ("vllm", "ollama", "openai", "anthropic", "gemini"):
            provider = manager.get_provider(name)
            available_providers.append({
                "name": name,
                "type": type(provider).__name__,
                "air_gapped": name in ("vllm", "ollama"),
            })

        return {
            "status": "operational",
            "air_gapped_ready": status["active_backend"] != "none",
            **status,
            "all_providers": available_providers,
            "recommendation": _get_recommendation(status),
        }
    except Exception as e:  # graceful degradation when backends unavailable
        return {
            "status": "degraded",
            "error": type(e).__name__,
            "air_gapped_ready": False,
            "active_backend": "none",
            "backends": {"vllm": False, "ollama": False},
            "all_providers": [
                {"name": "vllm", "type": "VLLMProvider", "air_gapped": True},
                {"name": "ollama", "type": "OllamaProvider", "air_gapped": True},
                {"name": "openai", "type": "OpenAIProvider", "air_gapped": False},
                {"name": "anthropic", "type": "AnthropicProvider", "air_gapped": False},
                {"name": "gemini", "type": "GeminiProvider", "air_gapped": False},
            ],
            "recommendation": "Install vLLM or Ollama for air-gapped operation",
        }


@router.get("/models")
async def list_models() -> Dict[str, Any]:
    """List available models across all self-hosted backends."""
    adapter = _get_adapter()
    models = {
        "vllm": {
            "configured_model": adapter._vllm_model,
            "recommended_models": [
                {
                    "name": "deepseek-ai/deepseek-coder-33b-instruct",
                    "purpose": "Code fix generation",
                    "vram_required": "~20GB (FP16), ~10GB (INT8)",
                    "throughput": "~500 tokens/s on A100",
                },
                {
                    "name": "codellama/CodeLlama-34b-Instruct-hf",
                    "purpose": "Code analysis and fixes",
                    "vram_required": "~20GB (FP16)",
                    "throughput": "~400 tokens/s on A100",
                },
                {
                    "name": "meta-llama/Llama-3.1-70B-Instruct",
                    "purpose": "General security reasoning",
                    "vram_required": "~40GB (FP16), ~20GB (INT8)",
                    "throughput": "~300 tokens/s on A100",
                },
            ],
        },
        "ollama": {
            "configured_model": adapter._ollama_model,
            "recommended_models": [
                {
                    "name": "codellama:13b",
                    "purpose": "Code fixes (lighter)",
                    "ram_required": "~8GB",
                },
                {
                    "name": "deepseek-coder:33b",
                    "purpose": "Code fixes (higher quality)",
                    "ram_required": "~20GB",
                },
                {
                    "name": "llama3.1:8b",
                    "purpose": "General reasoning (light)",
                    "ram_required": "~5GB",
                },
            ],
        },
    }
    return models


@router.post("/test-inference")
async def test_inference(req: TestInferenceRequest) -> Dict[str, Any]:
    """Test inference round-trip to verify self-hosted LLM is working.

    Sends a test prompt and returns the response with timing metrics.
    Useful for verifying air-gapped setup before demo.
    """
    adapter = _get_adapter()
    backend = req.backend or adapter.get_active_backend()

    if backend == "none":
        return {
            "success": False,
            "error": "No self-hosted backend available",
            "recommendation": "Start vLLM or Ollama server first",
            "vllm_command": "python -m vllm.entrypoints.openai.api_server --model deepseek-ai/deepseek-coder-33b-instruct --port 8001",
            "ollama_command": "ollama serve && ollama pull codellama:13b",
        }

    manager = _get_provider_manager()
    provider = manager.get_provider(backend)

    start = time.perf_counter()
    result = provider.analyse(
        prompt=req.prompt,
        context={"test": True},
        default_action="analyze",
        default_confidence=0.5,
        default_reasoning="Test inference",
    )
    duration_ms = (time.perf_counter() - start) * 1000

    return {
        "success": result.metadata.get("mode") != "deterministic",
        "backend": backend,
        "model": getattr(provider, "model", "unknown"),
        "response": {
            "action": result.recommended_action,
            "confidence": result.confidence,
            "reasoning": result.reasoning[:500],
        },
        "duration_ms": round(duration_ms, 2),
        "metadata": result.metadata,
    }


@router.get("/autofix-status")
async def autofix_status() -> Dict[str, Any]:
    """Get AutoFix self-hosted adapter status.

    Shows whether AutoFix can generate fixes without external API keys.
    """
    try:
        adapter = _get_adapter()
        return adapter.get_status()
    except Exception as e:
        return {
            "active_backend": "none",
            "backends": {"vllm": False, "ollama": False},
            "can_generate_fixes": False,
            "provider_info": {"status": "unavailable", "error": type(e).__name__},
            "status": "degraded",
        }


@router.post("/generate-fix")
async def generate_fix_endpoint(req: GenerateFixRequest) -> Dict[str, Any]:
    """Generate a security fix using self-hosted LLM.

    This endpoint demonstrates air-gapped fix generation without
    external API keys. Falls back to deterministic rules if no
    LLM backend is available.
    """
    try:
        adapter = _get_adapter()
        result = adapter.generate_fix(req.finding, req.source_code)

        return {
            "success": result.success,
            "fix": {
                "code": result.fix_code,
                "explanation": result.explanation,
                "confidence": result.confidence,
                "unified_diff": result.unified_diff,
            },
            "backend": result.backend,
            "model": result.model,
            "duration_ms": result.duration_ms,
            "error": result.error or None,
            "metadata": result.metadata,
        }
    except Exception as e:
        return {
            "success": False,
            "fix": {
                "code": "",
                "explanation": f"No LLM backend available: {type(e).__name__}",
                "confidence": 0.0,
                "unified_diff": "",
            },
            "backend": "none",
            "model": "none",
            "duration_ms": 0,
            "error": str(e),
            "metadata": {"fallback": True},
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_recommendation(status: Dict[str, Any]) -> str:
    """Generate setup recommendation based on current status."""
    active = status.get("active_backend", "none")
    if active == "vllm":
        return "✅ vLLM is active — full air-gapped operation ready"
    elif active == "ollama":
        return "✅ Ollama is active — air-gapped operation ready (consider vLLM for higher throughput)"
    else:
        return (
            "⚠️ No self-hosted backend detected. For air-gapped operation:\n"
            "  1. Start vLLM: python -m vllm.entrypoints.openai.api_server "
            "--model deepseek-ai/deepseek-coder-33b-instruct --port 8001\n"
            "  2. Or start Ollama: ollama serve && ollama pull codellama:13b"
        )
