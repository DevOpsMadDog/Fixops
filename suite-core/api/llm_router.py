"""LLM API Router - Configuration and status for LLM providers.

This router provides endpoints for:
- Checking LLM provider status and availability
- Configuring LLM providers (OpenAI, Anthropic, Google)
- Testing LLM connectivity
- Managing LLM settings
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/llm", tags=["LLM"])


class LLMProviderStatus(BaseModel):
    """Status of an LLM provider."""
    
    name: str
    enabled: bool
    configured: bool
    api_key_set: bool
    model: str
    status: str  # "ready", "unconfigured", "error"
    error: Optional[str] = None


class LLMConfigResponse(BaseModel):
    """Response for LLM configuration endpoint."""
    
    status: str
    providers: List[LLMProviderStatus]
    active_provider: Optional[str] = None
    message: str


class LLMTestRequest(BaseModel):
    """Request to test an LLM provider."""
    
    provider: str = Field(..., description="Provider name: openai, anthropic, google")
    prompt: str = Field(
        default="Hello, respond with 'LLM is working' to confirm connectivity.",
        description="Test prompt to send"
    )


class LLMTestResponse(BaseModel):
    """Response from LLM test."""
    
    success: bool
    provider: str
    response: Optional[str] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class LLMSettingsUpdate(BaseModel):
    """Request to update LLM settings."""
    
    default_provider: Optional[str] = Field(None, description="Default provider to use")
    timeout_seconds: Optional[int] = Field(None, ge=5, le=120, description="Request timeout")
    max_tokens: Optional[int] = Field(None, ge=100, le=4096, description="Max response tokens")
    temperature: Optional[float] = Field(None, ge=0.0, le=1.0, description="Sampling temperature")


class LLMSettings(BaseModel):
    """Current LLM settings."""
    
    default_provider: str
    timeout_seconds: int
    max_tokens: int
    temperature: float


# In-memory settings (in production, these would be persisted)
_settings: Dict[str, Any] = {
    "default_provider": "openai",
    "timeout_seconds": 30,
    "max_tokens": 1024,
    "temperature": 0.0,
}


def _check_provider_status(name: str, env_vars: List[str], model: str) -> LLMProviderStatus:
    """Check the status of an LLM provider."""
    api_key_set = False
    for env_var in env_vars:
        if os.getenv(env_var):
            api_key_set = True
            break
    
    if api_key_set:
        return LLMProviderStatus(
            name=name,
            enabled=True,
            configured=True,
            api_key_set=True,
            model=model,
            status="ready",
        )
    else:
        return LLMProviderStatus(
            name=name,
            enabled=False,
            configured=False,
            api_key_set=False,
            model=model,
            status="unconfigured",
            error=f"API key not set. Set one of: {', '.join(env_vars)}",
        )


@router.get("/status", response_model=LLMConfigResponse)
async def get_llm_status() -> LLMConfigResponse:
    """Get the status of all configured LLM providers.
    
    Returns information about which LLM providers are available and their
    configuration status. Useful for debugging LLM integration issues.
    """
    providers = [
        _check_provider_status(
            "openai",
            ["OPENAI_API_KEY", "FIXOPS_OPENAI_KEY"],
            "gpt-4o-mini",
        ),
        _check_provider_status(
            "anthropic",
            ["ANTHROPIC_API_KEY", "FIXOPS_ANTHROPIC_KEY"],
            "claude-3-5-sonnet-20240620",
        ),
        _check_provider_status(
            "google",
            ["GOOGLE_API_KEY", "FIXOPS_GOOGLE_KEY"],
            "gemini-1.5-pro",
        ),
    ]
    
    ready_providers = [p for p in providers if p.status == "ready"]
    active_provider = ready_providers[0].name if ready_providers else None
    
    if ready_providers:
        status = "ready"
        message = f"{len(ready_providers)} LLM provider(s) configured and ready"
    else:
        status = "unconfigured"
        message = (
            "No LLM providers configured. Set at least one API key: "
            "OPENAI_API_KEY, ANTHROPIC_API_KEY, or GOOGLE_API_KEY"
        )
    
    return LLMConfigResponse(
        status=status,
        providers=providers,
        active_provider=active_provider,
        message=message,
    )


@router.post("/test", response_model=LLMTestResponse)
async def test_llm_provider(request: LLMTestRequest) -> LLMTestResponse:
    """Test connectivity to an LLM provider.
    
    Sends a simple test prompt to verify the provider is working correctly.
    Useful for validating API key configuration and connectivity.
    """
    import time
    
    provider = request.provider.lower()
    
    # Check if provider is configured
    env_vars_map = {
        "openai": ["OPENAI_API_KEY", "FIXOPS_OPENAI_KEY"],
        "anthropic": ["ANTHROPIC_API_KEY", "FIXOPS_ANTHROPIC_KEY"],
        "google": ["GOOGLE_API_KEY", "FIXOPS_GOOGLE_KEY"],
    }
    
    if provider not in env_vars_map:
        return LLMTestResponse(
            success=False,
            provider=provider,
            error=f"Unknown provider: {provider}. Supported: openai, anthropic, google",
        )
    
    api_key = None
    for env_var in env_vars_map[provider]:
        api_key = os.getenv(env_var)
        if api_key:
            break
    
    if not api_key:
        return LLMTestResponse(
            success=False,
            provider=provider,
            error=f"API key not configured. Set one of: {', '.join(env_vars_map[provider])}",
        )
    
    start = time.perf_counter()
    
    try:
        if provider == "openai":
            from core.llm_providers import OpenAIChatProvider
            llm = OpenAIChatProvider("test-openai")
            response = llm.analyse(
                prompt=request.prompt,
                context={},
                default_action="test",
                default_confidence=0.5,
                default_reasoning="Test response",
            )
            latency = (time.perf_counter() - start) * 1000
            if response.metadata.get("mode") == "remote":
                return LLMTestResponse(
                    success=True,
                    provider=provider,
                    response=response.reasoning,
                    latency_ms=round(latency, 2),
                )
            else:
                return LLMTestResponse(
                    success=False,
                    provider=provider,
                    error=response.metadata.get("error", "Unknown error"),
                    latency_ms=round(latency, 2),
                )
        
        elif provider == "anthropic":
            from core.llm_providers import AnthropicMessagesProvider
            llm = AnthropicMessagesProvider("test-anthropic")
            response = llm.analyse(
                prompt=request.prompt,
                context={},
                default_action="test",
                default_confidence=0.5,
                default_reasoning="Test response",
            )
            latency = (time.perf_counter() - start) * 1000
            if response.metadata.get("mode") == "remote":
                return LLMTestResponse(
                    success=True,
                    provider=provider,
                    response=response.reasoning,
                    latency_ms=round(latency, 2),
                )
            else:
                return LLMTestResponse(
                    success=False,
                    provider=provider,
                    error=response.metadata.get("error", "Unknown error"),
                    latency_ms=round(latency, 2),
                )
        
        elif provider == "google":
            from core.llm_providers import GoogleGeminiProvider
            llm = GoogleGeminiProvider("test-google")
            response = llm.analyse(
                prompt=request.prompt,
                context={},
                default_action="test",
                default_confidence=0.5,
                default_reasoning="Test response",
            )
            latency = (time.perf_counter() - start) * 1000
            if response.metadata.get("mode") == "remote":
                return LLMTestResponse(
                    success=True,
                    provider=provider,
                    response=response.reasoning,
                    latency_ms=round(latency, 2),
                )
            else:
                return LLMTestResponse(
                    success=False,
                    provider=provider,
                    error=response.metadata.get("error", "Unknown error"),
                    latency_ms=round(latency, 2),
                )
    
    except ImportError as e:
        return LLMTestResponse(
            success=False,
            provider=provider,
            error=f"Provider not available: {e}",
        )
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return LLMTestResponse(
            success=False,
            provider=provider,
            error=str(e),
            latency_ms=round(latency, 2),
        )


@router.get("/settings", response_model=LLMSettings)
async def get_llm_settings() -> LLMSettings:
    """Get current LLM settings."""
    return LLMSettings(**_settings)


@router.patch("/settings", response_model=LLMSettings)
async def update_llm_settings(updates: LLMSettingsUpdate) -> LLMSettings:
    """Update LLM settings.
    
    Updates the default provider, timeout, max tokens, or temperature settings.
    """
    if updates.default_provider is not None:
        valid_providers = ["openai", "anthropic", "google", "deterministic"]
        if updates.default_provider not in valid_providers:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid provider. Must be one of: {', '.join(valid_providers)}",
            )
        _settings["default_provider"] = updates.default_provider
    
    if updates.timeout_seconds is not None:
        _settings["timeout_seconds"] = updates.timeout_seconds
    
    if updates.max_tokens is not None:
        _settings["max_tokens"] = updates.max_tokens
    
    if updates.temperature is not None:
        _settings["temperature"] = updates.temperature
    
    return LLMSettings(**_settings)


@router.get("/providers")
async def list_providers() -> Dict[str, Any]:
    """List all available LLM providers with their capabilities.
    
    Returns detailed information about each supported provider including
    available models and supported features.
    """
    return {
        "providers": [
            {
                "name": "openai",
                "display_name": "OpenAI",
                "models": [
                    {"id": "gpt-4o", "name": "GPT-4 Omni", "max_tokens": 128000},
                    {"id": "gpt-4o-mini", "name": "GPT-4 Omni Mini", "max_tokens": 128000},
                    {"id": "gpt-4-turbo", "name": "GPT-4 Turbo", "max_tokens": 128000},
                    {"id": "gpt-3.5-turbo", "name": "GPT-3.5 Turbo", "max_tokens": 16384},
                ],
                "features": ["json_mode", "function_calling", "vision"],
                "env_vars": ["OPENAI_API_KEY", "FIXOPS_OPENAI_KEY"],
            },
            {
                "name": "anthropic",
                "display_name": "Anthropic",
                "models": [
                    {"id": "claude-3-5-sonnet-20240620", "name": "Claude 3.5 Sonnet", "max_tokens": 200000},
                    {"id": "claude-3-opus-20240229", "name": "Claude 3 Opus", "max_tokens": 200000},
                    {"id": "claude-3-haiku-20240307", "name": "Claude 3 Haiku", "max_tokens": 200000},
                ],
                "features": ["vision", "tool_use"],
                "env_vars": ["ANTHROPIC_API_KEY", "FIXOPS_ANTHROPIC_KEY"],
            },
            {
                "name": "google",
                "display_name": "Google AI",
                "models": [
                    {"id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro", "max_tokens": 1000000},
                    {"id": "gemini-1.5-flash", "name": "Gemini 1.5 Flash", "max_tokens": 1000000},
                    {"id": "gemini-pro", "name": "Gemini Pro", "max_tokens": 32000},
                ],
                "features": ["vision", "function_calling"],
                "env_vars": ["GOOGLE_API_KEY", "FIXOPS_GOOGLE_KEY"],
            },
            {
                "name": "deterministic",
                "display_name": "Deterministic (No LLM)",
                "models": [
                    {"id": "heuristic", "name": "Heuristic Rules", "max_tokens": 0},
                ],
                "features": ["no_api_key_required", "fast", "predictable"],
                "env_vars": [],
            },
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/health")
async def llm_health() -> Dict[str, Any]:
    """Health check for LLM service.
    
    Returns the overall health status of the LLM integration including
    which providers are available and working.
    """
    providers_status = []
    
    # Check OpenAI
    openai_key = os.getenv("OPENAI_API_KEY") or os.getenv("FIXOPS_OPENAI_KEY")
    providers_status.append({
        "provider": "openai",
        "available": bool(openai_key),
    })
    
    # Check Anthropic
    anthropic_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("FIXOPS_ANTHROPIC_KEY")
    providers_status.append({
        "provider": "anthropic",
        "available": bool(anthropic_key),
    })
    
    # Check Google
    google_key = os.getenv("GOOGLE_API_KEY") or os.getenv("FIXOPS_GOOGLE_KEY")
    providers_status.append({
        "provider": "google",
        "available": bool(google_key),
    })
    
    any_available = any(p["available"] for p in providers_status)
    
    return {
        "status": "healthy" if any_available else "degraded",
        "providers": providers_status,
        "fallback_available": True,  # Deterministic fallback always available
        "message": (
            "LLM integration operational" if any_available 
            else "No LLM providers configured - using deterministic fallback"
        ),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
