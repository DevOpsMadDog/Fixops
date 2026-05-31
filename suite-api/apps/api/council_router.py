"""Council convene router — POST /api/v1/council/convene.

Wraps LLMCouncil.convene() with:
- Input validation via Pydantic
- 503 when OPENROUTER_API_KEY is not set (CouncilNotConfiguredError)
- Auth delegated to app.py router-include (auth_deps.verify_api_key via Depends)
- /health and /status aliases (required by enterprise E2E test)

Auth note: this router is mounted in create_app() with
  dependencies=[Depends(_verify_api_key)]
using auth_deps.verify_api_key, which checks FIXOPS_API_TOKEN / JWT Bearer.
The endpoint does NOT carry a redundant local auth dependency — doing so with
a separate env-var (FIXOPS_API_KEY) caused double-auth 401s when FIXOPS_API_KEY
and FIXOPS_API_TOKEN differed or the local copy ran after the router-level dep
had already validated the credential.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/council", tags=["council"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ConveneRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=8000,
        description="Security decision question for the council",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Supporting context (finding, asset metadata, etc.)",
    )
    threshold: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Min avg confidence before accepting majority without escalation",
    )

    @field_validator("prompt")
    @classmethod
    def prompt_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("prompt must not be blank")
        return v.strip()


class IndividualVote(BaseModel):
    model: str
    vote: str
    reasoning: str
    confidence: float
    latency_ms: int


class ConveneResponse(BaseModel):
    verdict: str
    vote_counts: dict[str, int]
    individual_votes: list[dict[str, Any]]
    escalated: bool
    final_reasoning: str
    latency_ms: int


# ---------------------------------------------------------------------------
# Lazy council singleton
# ---------------------------------------------------------------------------

_council: Any = None


def _get_council() -> Any:
    global _council
    if _council is None:
        from core.llm_council_real import LLMCouncil
        _council = LLMCouncil()
    return _council


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/convene",
    response_model=ConveneResponse,
    summary="Run 4-model LLM consensus on a security decision",
)
async def convene(
    body: ConveneRequest,
) -> ConveneResponse:
    """Fan out a security decision prompt to 4 free OpenRouter models in parallel.

    Aggregates votes via majority rule. Escalates to Claude Opus if:
    - No majority (no single vote > 50%)
    - Average confidence < threshold

    Every verdict is persisted to dpo_pairs.db for the DPO learning loop.

    Returns 503 if OPENROUTER_API_KEY is not configured.
    """
    try:
        council = _get_council()
    except Exception as exc:
        from core.llm_council_real import CouncilNotConfiguredError
        if isinstance(exc, CouncilNotConfiguredError):
            raise HTTPException(
                status_code=503,
                detail="council not configured: OPENROUTER_API_KEY is not set",
            ) from exc
        logger.error("Council init failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"council not configured: {exc}") from exc

    try:
        result = await council.convene(
            prompt=body.prompt,
            context=body.context,
            threshold=body.threshold,
        )
    except Exception as exc:
        logger.error("council.convene failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Council convene failed: {exc}") from exc

    return ConveneResponse(**result)


@router.get("/health", summary="Council health check")
async def health() -> dict[str, Any]:
    """Return 200 if the council is reachable (key presence check only)."""
    key_set = bool(os.environ.get("OPENROUTER_API_KEY", ""))
    opus_set = bool(os.environ.get("ANTHROPIC_API_KEY", ""))
    return {
        "status":               "ok" if key_set else "degraded",
        "openrouter_configured": key_set,
        "opus_escalation":       opus_set,
        "models":                4,
    }


@router.get("/status", summary="Council status alias")
async def status() -> dict[str, Any]:
    """Alias of /health — required by enterprise E2E checks."""
    return await health()
