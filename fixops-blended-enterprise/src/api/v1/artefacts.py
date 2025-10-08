"""Unified artefact ingestion endpoint."""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping

from fastapi import APIRouter, Depends, HTTPException, status

from pydantic import BaseModel, Field

from src.api.dependencies import authenticate
from src.services import run_registry
from src.services.id_allocator import ensure_ids

router = APIRouter(tags=["artefacts"])


class ArtefactSubmission(BaseModel):
    type: str = Field(min_length=1)
    payload: Dict[str, Any] | None = None
    app_id: str | None = None
    run_id: str | None = None


class ArtefactResponse(BaseModel):
    app_id: str
    run_id: str
    stored_as: str


_INPUT_FILE_MAP: Dict[str, str] = {
    "requirements": "requirements-input.json",
    "design": "design-input.json",
    "sbom": "sbom.json",
    "sarif": "scanner.sarif",
    "tfplan": "tfplan.json",
    "ops": "ops-telemetry.json",
    "tests": "tests-input.json",
    "decision": "decision-input.json",
}

Processor = Callable[[Mapping[str, Any], run_registry.RunContext], None]


def _resolve_context(
    submission: ArtefactSubmission,
    artefact_type: str,
    payload: Mapping[str, Any],
) -> run_registry.RunContext:
    if submission.run_id:
        try:
            return run_registry.reopen_run(submission.app_id, submission.run_id)
        except FileNotFoundError as exc:  # pragma: no cover - validated through API tests
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found") from exc
    app_hint = submission.app_id
    if artefact_type == "design":
        app_hint = str(payload.get("app_id") or app_hint)
    return run_registry.resolve_run(app_hint)


def _process_design(payload: Mapping[str, Any], context: run_registry.RunContext) -> None:
    manifest = dict(payload)
    manifest["design_risk_score"] = _design_risk_score(payload)
    context.write_output("design.manifest.json", manifest)


def _design_risk_score(payload: Mapping[str, Any]) -> float:
    components = payload.get("components") if isinstance(payload, Mapping) else []
    score = 0.5
    if isinstance(components, list):
        if any(str(item.get("exposure")).lower() == "internet" for item in components if isinstance(item, Mapping)):
            score += 0.2
        if any(bool(item.get("pii")) for item in components if isinstance(item, Mapping)):
            score += 0.08
    return round(min(score, 0.99), 2)


_PROCESSORS: Dict[str, Processor] = {
    "design": _process_design,
}


@router.post("", response_model=ArtefactResponse, status_code=status.HTTP_201_CREATED)
async def submit_artefact(
    submission: ArtefactSubmission,
    _: None = Depends(authenticate),
) -> ArtefactResponse:
    artefact_type = submission.type.lower()
    if artefact_type not in _INPUT_FILE_MAP:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported artefact type")

    payload: Mapping[str, Any] | Dict[str, Any] = submission.payload or {}
    if artefact_type == "design":
        if not isinstance(payload, Mapping):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Design payload must be an object")
        payload = ensure_ids(payload)

    context = _resolve_context(submission, artefact_type, payload if isinstance(payload, Mapping) else {})
    filename = _INPUT_FILE_MAP[artefact_type]
    stored_path = context.save_input(filename, payload)
    processor = _PROCESSORS.get(artefact_type)
    if processor and isinstance(payload, Mapping):
        processor(payload, context)
    relative = stored_path.relative_to(context.run_path)
    return ArtefactResponse(app_id=context.app_id, run_id=context.run_id, stored_as=str(relative))
