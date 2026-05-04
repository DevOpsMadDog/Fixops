"""ALDECI Microsoft PyRIT bridge router.

Pass-through to a separate PyRIT runner service (``PYRIT_RUNNER_URL``) — PyRIT
itself requires GPU + heavy ML deps so it is NOT embedded in the ALDECI process.

Endpoints (mounted at ``/api/v1/pyrit``)
----------------------------------------
GET  /                                     — capability summary
POST /api/v1/attacks/run                   — submit an attack run (orchestrator + prompts)
GET  /api/v1/runs/{run_id}                 — run summary (status, counters, scores)
GET  /api/v1/runs/{run_id}/results         — paginated per-prompt results
GET  /api/v1/converters                    — built-in/registered prompt converters
GET  /api/v1/scorers                       — built-in/registered scorers
GET  /api/v1/orchestrators                 — built-in/registered orchestrators
GET  /api/v1/datasets/seed-prompts         — built-in adversarial prompt datasets

When ``PYRIT_RUNNER_URL`` is unset the capability summary reports
``status="unavailable"`` and *action* endpoints (attacks/run, runs/...) respond
with HTTP 503. *Catalog* endpoints (converters/scorers/orchestrators) still
return their built-in (informational) catalog so the UI can render the form.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/pyrit", tags=["pyrit"])


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.pyrit_engine import get_pyrit_engine

    return get_pyrit_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    pyrit_runner_url_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class TargetSpec(BaseModel):
    name: str = Field(
        ...,
        description=(
            "OpenAIChatTarget | AzureOpenAIChatTarget | AzureMLChatTarget | "
            "HuggingFaceChatTarget | ClaudeChatTarget | GroqChatTarget | "
            "OllamaChatTarget | HTTPTarget"
        ),
    )
    params: Dict[str, Any] = Field(default_factory=dict)


class PromptSpec(BaseModel):
    value: str
    data_type: str = Field("text", description="text | image_path | audio_path | url")
    name: Optional[str] = None
    role: Optional[str] = Field(None, description="user | system | assistant")
    metadata: Optional[Dict[str, Any]] = None


class ConverterSpec(BaseModel):
    name: str
    params: Dict[str, Any] = Field(default_factory=dict)


class ScorerSpec(BaseModel):
    name: str
    params: Dict[str, Any] = Field(default_factory=dict)


class AttackRunRequest(BaseModel):
    orchestrator: str = Field(
        ...,
        description=(
            "PromptSendingOrchestrator | RedTeamingOrchestrator | XPIAOrchestrator | "
            "ScoringOrchestrator | TreeOfAttacksOrchestrator | FuzzerOrchestrator | "
            "CrescendoOrchestrator | PAIROrchestrator"
        ),
    )
    target: TargetSpec
    prompts: List[PromptSpec] = Field(default_factory=list)
    converters: Optional[List[ConverterSpec]] = None
    scorers: Optional[List[ScorerSpec]] = None
    memory_labels: Optional[Dict[str, Any]] = None
    max_attacks: Optional[int] = Field(None, ge=1, le=100000)
    max_iterations: Optional[int] = Field(None, ge=1, le=10000)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "pyrit_unavailable",
            "message": "PYRIT_RUNNER_URL environment variable is not configured",
        },
    )


def _map_pyrit_error(exc: Exception) -> HTTPException:
    """Translate a PyRITHTTPError (or unavailable) into an HTTPException."""
    from core.pyrit_engine import PyRITHTTPError, PyRITUnavailable

    if isinstance(exc, PyRITUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "pyrit_unavailable", "message": str(exc)},
        )
    if isinstance(exc, PyRITHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "pyrit_upstream_error",
                "upstream_status": exc.status_code,
                "message": str(exc),
                "payload": exc.payload,
            },
        )
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="Microsoft PyRIT capability summary",
)
def capability_summary() -> CapabilitySummary:
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


@router.post(
    "/api/v1/attacks/run",
    summary="Submit a PyRIT attack run (orchestrator + target + prompts)",
)
def submit_attack(req: AttackRunRequest) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.submit_attack(req.model_dump(exclude_none=True))
    except Exception as exc:
        raise _map_pyrit_error(exc) from exc


@router.get(
    "/api/v1/runs/{run_id}",
    summary="PyRIT run summary",
)
def get_run(run_id: str) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_run(run_id)
    except Exception as exc:
        raise _map_pyrit_error(exc) from exc


@router.get(
    "/api/v1/runs/{run_id}/results",
    summary="Paginated per-prompt PyRIT run results",
)
def get_run_results(
    run_id: str,
    include_history: bool = Query(False),
    limit: Optional[int] = Query(None, ge=1, le=10000),
    offset: Optional[int] = Query(None, ge=0),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_run_results(
            run_id,
            include_history=include_history,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise _map_pyrit_error(exc) from exc


@router.get(
    "/api/v1/converters",
    summary="List available PyRIT prompt converters",
)
def list_converters() -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.list_converters()
    except Exception as exc:
        raise _map_pyrit_error(exc) from exc


@router.get(
    "/api/v1/scorers",
    summary="List available PyRIT scorers",
)
def list_scorers() -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.list_scorers()
    except Exception as exc:
        raise _map_pyrit_error(exc) from exc


@router.get(
    "/api/v1/orchestrators",
    summary="List available PyRIT orchestrators",
)
def list_orchestrators() -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.list_orchestrators()
    except Exception as exc:
        raise _map_pyrit_error(exc) from exc


@router.get(
    "/api/v1/datasets/seed-prompts",
    summary="List built-in adversarial seed-prompt datasets",
)
def list_seed_prompts(
    dataset_name: Optional[str] = Query(None),
    limit: Optional[int] = Query(None, ge=1, le=10000),
    offset: Optional[int] = Query(None, ge=0),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_seed_prompts(
            dataset_name=dataset_name, limit=limit, offset=offset
        )
    except Exception as exc:
        raise _map_pyrit_error(exc) from exc
