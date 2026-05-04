"""Guardrails AI Router — ALDECI.

Wraps ``core.guardrails_engine.GuardrailsEngine`` and exposes the Guardrails
Server REST surface under ``/api/v1/guardrails``:

  - GET  /                                         capability summary
  - POST /v1/validate                              ad-hoc validate
  - GET  /v1/specs                                 list registered specs
  - GET  /v1/specs/{spec_name}                     spec detail
  - POST /v1/spec                                  register custom spec (201)
  - POST /v1/guards/{guard_name}/validate          validate against named guard
  - POST /v1/openai/chat/completions               guarded OpenAI passthrough
  - GET  /v1/health                                upstream health probe

NO MOCKS rule
-------------
* When GUARDRAILS_API_KEY is unset:
    - Capability summary surfaces ``status="unavailable"`` (HTTP 200).
    - All other endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/guardrails",
    tags=["Guardrails AI"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.guardrails_engine import get_guardrails_engine

    return get_guardrails_engine()


def _serve(callable_):
    """Run a Guardrails call, translating engine errors to HTTP responses.

    GuardrailsUnavailableError -> 503
    ValueError                 -> 422
    """
    from core.guardrails_engine import GuardrailsUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except GuardrailsUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


_DEFAULT_ENDPOINTS: List[str] = [
    "/v1/validate",
    "/v1/specs",
    "/v1/spec",
    "/v1/guards/{guard_name}/validate",
    "/v1/openai/chat/completions",
]


class CapabilityResponse(BaseModel):
    service: str = "Guardrails AI"
    endpoints: List[str] = Field(default_factory=lambda: list(_DEFAULT_ENDPOINTS))
    guardrails_api_key_present: bool = False
    guardrails_base_url: str = "https://api.guardrailsai.com"
    status: str = "unavailable"  # ok | empty | unavailable


class GuardSpec(BaseModel):
    name: str
    kwargs: Optional[Dict[str, Any]] = None
    on_fail: Optional[str] = "exception"  # exception|filter|fix|noop|reask|refrain


class ValidateRequest(BaseModel):
    prompt: str = Field(..., description="LLM input or output to validate")
    response: Optional[str] = Field(
        default=None, description="Pre-computed LLM response (optional)"
    )
    guards: List[GuardSpec] = Field(..., min_length=1)
    llm_callable: Optional[str] = None
    llm_kwargs: Optional[Dict[str, Any]] = None
    num_reasks: Optional[int] = None


class CreateSpecRequest(BaseModel):
    name: str
    description: str = ""
    guards: List[GuardSpec] = Field(..., min_length=1)
    schema_def: Optional[Dict[str, Any]] = Field(default=None, alias="schema")

    model_config = {"populate_by_name": True}


class GuardValidateRequest(BaseModel):
    value: Union[str, Dict[str, Any], List[Any]]
    kwargs: Optional[Dict[str, Any]] = None
    num_reasks: Optional[int] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Capability summary — surfaces env-key presence + base URL + status."""
    engine = _engine()
    key_present = engine.api_key_present()
    base_url = engine.base_url()
    if not key_present:
        status = "unavailable"
    else:
        # If the key is present but no specs reachable, callers can interpret
        # status="empty"; here we only ping cheap state — say "ok".
        status = "ok"
    return CapabilityResponse(
        service="Guardrails AI",
        endpoints=list(_DEFAULT_ENDPOINTS),
        guardrails_api_key_present=key_present,
        guardrails_base_url=base_url,
        status=status,
    )


@router.post("/v1/validate")
async def validate(req: ValidateRequest) -> Dict[str, Any]:
    """POST /v1/validate — run guard validation on a prompt/response."""
    guards = [g.model_dump(exclude_none=True) for g in req.guards]
    return _serve(
        lambda: _engine().validate(
            prompt=req.prompt,
            guards=guards,
            response=req.response,
            llm_callable=req.llm_callable,
            llm_kwargs=req.llm_kwargs,
            num_reasks=req.num_reasks,
        )
    )


@router.get("/v1/specs")
async def list_specs() -> Dict[str, Any]:
    return _serve(lambda: _engine().list_specs())


@router.get("/v1/specs/{spec_name}")
async def get_spec(
    spec_name: str = Path(..., min_length=1),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().get_spec(spec_name))


@router.post("/v1/spec", status_code=201)
async def create_spec(req: CreateSpecRequest) -> Dict[str, Any]:
    """POST /v1/spec — register a custom guard spec → 201."""
    guards = [g.model_dump(exclude_none=True) for g in req.guards]
    return _serve(
        lambda: _engine().create_spec(
            name=req.name,
            description=req.description,
            guards=guards,
            schema=req.schema_def,
        )
    )


@router.post("/v1/guards/{guard_name}/validate")
async def validate_guard(
    req: GuardValidateRequest,
    guard_name: str = Path(..., min_length=1),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().validate_guard(
            guard_name=guard_name,
            value=req.value,
            kwargs=req.kwargs,
            num_reasks=req.num_reasks,
        )
    )


@router.post("/v1/openai/chat/completions")
async def openai_chat_completions(
    body: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    """Guarded OpenAI passthrough — body is OpenAI chat-completion + ``guards``."""
    return _serve(lambda: _engine().openai_chat_completions(body))


@router.get("/v1/health")
async def health() -> Dict[str, Any]:
    """Delegate health-check to upstream Guardrails server."""
    return _serve(lambda: _engine().health())
