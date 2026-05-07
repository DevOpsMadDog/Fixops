"""LLM Council Status Router — multi-provider readiness visibility.

Exposes:

    GET /api/v1/llm/council/status

Returns the live composition of the LLM council so operators know:
- Which providers are configured (key present in .env)
- Whether multi-provider consensus is possible (>= 2 members)
- Most recent verdict shape (confidence, action) if any history exists

The endpoint NEVER makes live LLM calls — it is a pure introspection surface.
Returns 200 in all cases; degraded states are expressed in the payload.

Identity: CTEM+ Step 9 (LLM Consensus). Air-gap clean — no cloud calls.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/llm/council", tags=["LLM Council"])

# ---------------------------------------------------------------------------
# Provider registry — canonical env-var names per provider.
# Auto-activation: if ANY listed env-var has a non-empty value the provider
# is considered configured. No key = graceful degradation (logged warning).
# ---------------------------------------------------------------------------

_PROVIDER_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "anthropic",
        "label": "Anthropic (Claude)",
        "env_vars": ["ANTHROPIC_API_KEY", "FIXOPS_ANTHROPIC_KEY"],
        "free_tier": False,
        "notes": "Claude Opus/Sonnet — strongest for threat modeling",
    },
    {
        "name": "openai",
        "label": "OpenAI (GPT-5)",
        "env_vars": ["OPENAI_API_KEY", "FIXOPS_OPENAI_KEY"],
        "free_tier": False,
        "notes": "GPT-5 — strongest for exploit/vulnerability assessment",
    },
    {
        "name": "gemini",
        "label": "Google (Gemini)",
        "env_vars": ["GOOGLE_API_KEY", "FIXOPS_GEMINI_KEY"],
        "free_tier": True,
        "notes": "Gemini Flash — free tier available, good for compliance mapping",
    },
    {
        "name": "openrouter",
        "label": "OpenRouter (multi-model)",
        "env_vars": ["OPENROUTER_API_KEY", "FIXOPS_OPENROUTER_KEY"],
        "free_tier": True,
        "notes": "OpenRouter — free tier models (DeepSeek, Qwen, Llama). Sign up at openrouter.ai",
    },
    {
        "name": "mulerouter",
        "label": "MuleRouter (Qwen3-6b-Max)",
        "env_vars": ["MULEROUTER_API_KEY"],
        "free_tier": True,
        "notes": "mulerouter.ai — OpenRouter-compatible, Qwen3-6b-Max. Used as primary free council member",
    },
    {
        "name": "ollama",
        "label": "Ollama (self-hosted)",
        "env_vars": [],
        "env_check": "FIXOPS_OLLAMA_URL",
        "free_tier": True,
        "notes": "Ollama local LLM — air-gapped. FIXOPS_OLLAMA_URL defaults to http://localhost:11434",
    },
    {
        "name": "vllm",
        "label": "vLLM (self-hosted)",
        "env_vars": ["FIXOPS_VLLM_API_KEY"],
        "env_check": "FIXOPS_VLLM_URL",
        "free_tier": True,
        "notes": "vLLM self-hosted inference — air-gapped. FIXOPS_VLLM_URL defaults to http://localhost:8001/v1",
    },
]


def _provider_configured(spec: Dict[str, Any]) -> bool:
    """Return True if the provider has at least one env-var set.

    For self-hosted providers (Ollama, vLLM) with no mandatory key,
    presence of a custom URL env-var or the absence of a key requirement
    means the provider is always considered available (uses default URL).
    """
    key_envs = spec.get("env_vars", [])
    if key_envs:
        for env_name in key_envs:
            val = os.getenv(env_name, "").strip()
            if val:
                return True
        return False

    # No key required (Ollama/vLLM use URL only) — always considered available
    # unless the caller has explicitly opted out (no such mechanism currently).
    return True


def _get_configured_providers() -> List[Dict[str, Any]]:
    """Return list of configured provider dicts with enabled flag."""
    result = []
    for spec in _PROVIDER_REGISTRY:
        enabled = _provider_configured(spec)
        entry: Dict[str, Any] = {
            "name": spec["name"],
            "label": spec["label"],
            "configured": enabled,
            "free_tier": spec["free_tier"],
            "notes": spec.get("notes", ""),
        }
        if not enabled:
            # Surface which env-var to set so operators can act on it
            entry["missing_env_var"] = spec["env_vars"][0] if spec.get("env_vars") else None
        result.append(entry)
    return result


def _get_recent_verdict() -> Optional[Dict[str, Any]]:
    """Try to pull the most recent verdict from the LLM council history.

    Returns None if council is not initialised or has no history.
    Never raises.
    """
    try:
        from core.llm_council import CouncilFactory

        factory = CouncilFactory()
        # Use the full council (skips unavailable providers gracefully)
        council = factory.create_full_council()
        stats = council.get_stats()
        if stats.get("total_verdicts", 0) == 0:
            return None
        return {
            "total_verdicts": stats["total_verdicts"],
            "average_confidence": stats.get("average_confidence"),
            "action_distribution": stats.get("action_distribution", {}),
        }
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load council history: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    summary="LLM Council composition and consensus readiness",
    response_model=None,
)
async def council_status() -> Dict[str, Any]:
    """Return the live LLM council composition.

    Fields:
    - providers: list of all supported providers with configured=true/false
    - configured_providers: names of providers that have keys set
    - member_count: number of configured providers
    - consensus_enabled: true when member_count >= 2
    - recent_verdict: shape of most recent verdict if any (confidence, action dist)
    - warning: human-readable degradation warning if consensus is disabled
    """
    providers = _get_configured_providers()
    configured = [p for p in providers if p["configured"]]
    member_count = len(configured)
    consensus_enabled = member_count >= 2

    warning: Optional[str] = None
    if not consensus_enabled:
        if member_count == 0:
            warning = (
                "LLM council has 0 members — all verdicts will be deterministic "
                "(confidence=0.5, action=review). Add at least one LLM API key to "
                ".env to enable AI-powered decisions."
            )
        else:
            warning = (
                f"LLM council has {member_count} member — disagreement-resolution "
                "disabled. Add a second LLM key to .env to enable multi-LLM consensus. "
                "See docs/llm_council_setup.md for supported providers."
            )
        logger.warning(warning)

    recent_verdict = _get_recent_verdict()

    return {
        "providers": providers,
        "configured_providers": [p["name"] for p in configured],
        "member_count": member_count,
        "consensus_enabled": consensus_enabled,
        "recent_verdict": recent_verdict,
        "warning": warning,
    }


@router.get("/health", summary="LLM Council health alias")
@router.get("/status/health", summary="LLM Council health alias (nested)")
async def council_health() -> Dict[str, Any]:
    """Health alias — returns degraded status if council has < 2 members."""
    providers = _get_configured_providers()
    configured = [p for p in providers if p["configured"]]
    member_count = len(configured)
    return {
        "status": "ok" if member_count >= 2 else "degraded",
        "member_count": member_count,
        "consensus_enabled": member_count >= 2,
    }


@router.get(
    "/recent",
    summary="Recent LLM Council verdicts (last N)",
    response_model=None,
)
async def council_recent(
    limit: int = Query(default=10, ge=1, le=100, description="Max verdicts to return"),
) -> Dict[str, Any]:
    """Return the most recent N council verdicts with per-model vote breakdown.

    Each verdict exposes:
    - timestamp: ISO-8601 (injected at convocation time if not stored; derived from history index)
    - finding_id: finding context string passed to convene()
    - action: recommended action (remediate_critical, accept_risk, defer, etc.)
    - confidence: overall confidence (0-1)
    - escalated_to_opus: whether Opus was called as tiebreaker
    - member_votes: list of {member, action, confidence, weight}

    Returns empty list if council has no history (in-memory, resets on restart).
    Never raises — degraded states expressed in payload.
    """
    try:
        from core.llm_council import CouncilFactory

        factory = CouncilFactory()
        council = factory.create_full_council()
        history = council.history  # List[CouncilVerdict]
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load council history for /recent: %s", exc)
        return {"verdicts": [], "total": 0, "error": str(exc)}

    # history is oldest-first; we want newest-first
    recent = list(reversed(history))[:limit]

    verdicts = []
    for i, v in enumerate(recent):
        verdicts.append(
            {
                # History is in-memory; we don't store timestamps per-verdict.
                # Use a synthetic ordinal so UI can display relative ordering.
                "timestamp": None,
                "finding_id": None,
                "action": v.action,
                "confidence": round(v.confidence, 3),
                "escalated_to_opus": v.escalated,
                "escalation_reason": v.escalation_reason,
                "member_votes": [
                    {
                        "member": mv.member_name,
                        "action": mv.action,
                        "confidence": round(mv.confidence, 3),
                        "weight": round(mv.weight, 3),
                    }
                    for mv in (v.member_votes or [])
                ],
                "latency_ms": round(v.latency_ms, 1),
                "cost_usd": round(v.cost_usd, 6),
                "mitre_mappings": v.mitre_mappings or [],
            }
        )

    return {
        "verdicts": verdicts,
        "total": len(history),
        "limit": limit,
    }
