"""Unified artefact ingestion endpoint backed by the stage runner."""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from core.stage_runner import StageRunner
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from src.api.dependencies import authenticate
from src.services import id_allocator, signing
from src.services.run_registry import RunRegistry

router = APIRouter(tags=["artefacts"])


class ArtefactSummary(BaseModel):
    stage: str = Field(..., description="Stage that was processed")
    app_id: str = Field(..., description="Resolved application identifier")
    run_id: str = Field(..., description="Allocated run identifier")
    output_file: str = Field(..., description="Canonical output file path")
    outputs_dir: str = Field(
        ..., description="Folder containing all outputs for the run"
    )
    signed_manifests: list[str] = Field(default_factory=list)
    transparency_index: Optional[str] = None
    evidence_bundle: Optional[str] = None
    verified: Optional[bool] = Field(
        default=None, description="Signature verification result when requested"
    )


def _bool_from_form(value: bool | str | None) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"true", "1", "yes", "on"}
    return False


@router.post("", response_model=ArtefactSummary, status_code=status.HTTP_201_CREATED)
async def ingest_artefact(
    artefact_type: str = Form(..., alias="type"),
    payload: UploadFile | None = File(default=None),
    app_name: str | None = Form(default=None),
    mode: str = Form(default="demo"),
    sign: bool | str | None = Form(default=False),
    verify: bool | str | None = Form(default=False),
    _: None = Depends(authenticate),
) -> ArtefactSummary:
    stage = artefact_type.lower().strip()
    if stage not in {
        "requirements",
        "design",
        "build",
        "test",
        "deploy",
        "operate",
        "decision",
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported artefact type"
        )

    temp_path: Path | None = None
    if payload is not None:
        try:
            contents = await payload.read()
        except Exception as exc:  # pragma: no cover - runtime protection
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc
        suffix = Path(payload.filename or f"{stage}.dat").suffix or ".json"
        handle = NamedTemporaryFile(delete=False, suffix=suffix)
        try:
            handle.write(contents)
        finally:
            handle.close()
        temp_path = Path(handle.name)

    runner = StageRunner(RunRegistry(), id_allocator, signing)

    try:
        result = runner.run_stage(
            stage,
            temp_path,
            app_name=app_name,
            app_id=None,
            mode=mode,
            sign=_bool_from_form(sign),
            verify=_bool_from_form(verify),
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:  # pragma: no cover - best effort cleanup
                pass

    summary = ArtefactSummary(
        stage=result.stage,
        app_id=result.app_id,
        run_id=result.run_id,
        output_file=str(result.output_file),
        outputs_dir=str(result.outputs_dir),
        signed_manifests=[str(path) for path in result.signatures],
        transparency_index=(
            str(result.transparency_index) if result.transparency_index else None
        ),
        evidence_bundle=str(result.bundle) if result.bundle else None,
        verified=result.verified,
    )
    return summary


__all__ = ["router"]
