from __future__ import annotations

import csv
import io
import logging
from contextlib import suppress
from pathlib import Path
from tempfile import SpooledTemporaryFile
from types import SimpleNamespace
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from fixops.configuration import OverlayConfig, load_overlay
from fixops.paths import ensure_secure_directory, verify_allowlisted_path
from fixops.storage import ArtefactArchive
from fixops.feedback import FeedbackRecorder

from .normalizers import InputNormalizer, NormalizedCVEFeed, NormalizedSARIF, NormalizedSBOM
from .pipeline import PipelineOrchestrator

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create the FastAPI application with file-upload ingestion endpoints."""

    app = FastAPI(title="FixOps Ingestion Demo API", version="0.1.0")
    if not hasattr(app, "state"):
        app.state = SimpleNamespace()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    normalizer = InputNormalizer()
    orchestrator = PipelineOrchestrator()
    overlay = load_overlay()

    # API authentication setup
    auth_strategy = overlay.auth.get("strategy", "").lower()
    header_name = overlay.auth.get("header", "X-API-Key")
    api_key_header = APIKeyHeader(name=header_name, auto_error=False)
    expected_tokens = overlay.auth_tokens if auth_strategy == "token" else tuple()

    async def _verify_api_key(api_key: Optional[str] = Depends(api_key_header)) -> None:
        if auth_strategy != "token":
            return
        if not api_key or api_key not in expected_tokens:
            raise HTTPException(status_code=401, detail="Invalid or missing API token")

    allowlist = overlay.allowed_data_roots or (Path("data").resolve(),)
    for directory in overlay.data_directories.values():
        secure_path = verify_allowlisted_path(directory, allowlist)
        ensure_secure_directory(secure_path)

    archive_dir = overlay.data_directories.get("archive_dir")
    if archive_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        archive_dir = (root / "archive" / overlay.mode).resolve()
    archive_dir = verify_allowlisted_path(archive_dir, allowlist)
    archive = ArtefactArchive(archive_dir, allowlist=allowlist)

    app.state.normalizer = normalizer
    app.state.orchestrator = orchestrator
    app.state.artifacts: Dict[str, Any] = {}
    app.state.overlay = overlay
    app.state.archive = archive
    app.state.archive_records: Dict[str, Dict[str, Any]] = {}
    app.state.feedback = (
        FeedbackRecorder(overlay)
        if overlay.toggles.get("capture_feedback")
        else None
    )

    _CHUNK_SIZE = 1024 * 1024
    _RAW_BYTES_THRESHOLD = 4 * 1024 * 1024

    async def _read_limited(file: UploadFile, stage: str) -> Tuple[SpooledTemporaryFile, int]:
        """Stream an upload into a spooled file respecting the configured limit."""

        limit = overlay.upload_limit(stage)
        total = 0
        buffer = SpooledTemporaryFile(max_size=_CHUNK_SIZE, mode="w+b")
        try:
            while total < limit:
                remaining = limit - total
                chunk = await file.read(min(_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise HTTPException(
                        status_code=413,
                        detail={
                            "message": f"Upload for stage '{stage}' exceeded limit",
                            "max_bytes": limit,
                        },
                    )
                buffer.write(chunk)
        except Exception:
            buffer.close()
            raise
        buffer.seek(0)
        return buffer, total

    def _maybe_materialise_raw(
        buffer: SpooledTemporaryFile, total: int, *, threshold: int = _RAW_BYTES_THRESHOLD
    ) -> Optional[bytes]:
        if total > threshold:
            return None
        buffer.seek(0)
        data = buffer.read()
        buffer.seek(0)
        return data

    def _validate_content_type(file: UploadFile, expected: tuple[str, ...]) -> None:
        if file.content_type and file.content_type not in expected:
            raise HTTPException(
                status_code=415,
                detail={
                    "message": "Unsupported content type",
                    "received": file.content_type,
                    "expected": list(expected),
                },
            )

    def _store(
        stage: str,
        payload: Any,
        *,
        original_filename: Optional[str] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> None:
        logger.debug("Storing stage %s", stage)
        app.state.artifacts[stage] = payload
        try:
            record = app.state.archive.persist(
                stage,
                payload,
                original_filename=original_filename,
                raw_bytes=raw_bytes,
            )
        except Exception as exc:  # pragma: no cover - persistence must not break ingestion
            logger.exception("Failed to persist artefact stage %s", stage)
            record = {"stage": stage, "error": str(exc)}
        app.state.archive_records[stage] = record

    @app.post("/inputs/design", dependencies=[Depends(_verify_api_key)])
    async def ingest_design(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(file, ("text/csv", "application/vnd.ms-excel", "application/csv"))
        buffer, total = await _read_limited(file, "design")
        try:
            text_stream = io.TextIOWrapper(buffer, encoding="utf-8", errors="ignore", newline="")
            try:
                reader = csv.DictReader(text_stream)
                rows = [
                    row
                    for row in reader
                    if any((value or "").strip() for value in row.values())
                ]
                columns = reader.fieldnames or []
            finally:
                buffer = text_stream.detach()

            if not rows:
                raise HTTPException(status_code=400, detail="Design CSV contained no rows")

            dataset = {"columns": columns, "rows": rows}
            raw_bytes = _maybe_materialise_raw(buffer, total)
            _store("design", dataset, original_filename=file.filename, raw_bytes=raw_bytes)
            return {
                "stage": "design",
                "input_filename": file.filename,
                "row_count": len(rows),
                "columns": dataset["columns"],
                "data": dataset,
            }
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/sbom", dependencies=[Depends(_verify_api_key)])
    async def ingest_sbom(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/zip",
                "application/x-zip-compressed",
                "application/gzip",
            ),
        )
        buffer, total = await _read_limited(file, "sbom")
        try:
            sbom: NormalizedSBOM = normalizer.load_sbom(buffer)
        except Exception as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("SBOM normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse SBOM: {exc}") from exc
        else:
            raw_bytes = _maybe_materialise_raw(buffer, total)
            _store("sbom", sbom, original_filename=file.filename, raw_bytes=raw_bytes)
            return {
                "stage": "sbom",
                "input_filename": file.filename,
                "metadata": sbom.metadata,
                "component_preview": [
                    component.to_dict() for component in sbom.components[:5]
                ],
            }
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/cve", dependencies=[Depends(_verify_api_key)])
    async def ingest_cve(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/zip",
                "application/x-zip-compressed",
                "application/gzip",
            ),
        )
        buffer, total = await _read_limited(file, "cve")
        try:
            cve_feed: NormalizedCVEFeed = normalizer.load_cve_feed(buffer)
        except Exception as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("CVE feed normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse CVE feed: {exc}") from exc
        else:
            raw_bytes = _maybe_materialise_raw(buffer, total)
            _store("cve", cve_feed, original_filename=file.filename, raw_bytes=raw_bytes)
            return {
                "stage": "cve",
                "input_filename": file.filename,
                "record_count": cve_feed.metadata.get("record_count", 0),
                "validation_errors": cve_feed.errors,
            }
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/sarif", dependencies=[Depends(_verify_api_key)])
    async def ingest_sarif(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/zip",
                "application/x-zip-compressed",
                "application/gzip",
            ),
        )
        buffer, total = await _read_limited(file, "sarif")
        try:
            sarif: NormalizedSARIF = normalizer.load_sarif(buffer)
        except Exception as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("SARIF normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse SARIF: {exc}") from exc
        else:
            raw_bytes = _maybe_materialise_raw(buffer, total)
            _store("sarif", sarif, original_filename=file.filename, raw_bytes=raw_bytes)
            return {
                "stage": "sarif",
                "input_filename": file.filename,
                "metadata": sarif.metadata,
                "tools": sarif.tool_names,
            }
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/pipeline/run", dependencies=[Depends(_verify_api_key)])
    async def run_pipeline() -> Dict[str, Any]:
        overlay: OverlayConfig = app.state.overlay
        required = overlay.required_inputs
        missing = [stage for stage in required if stage not in app.state.artifacts]
        if missing:
            raise HTTPException(
                status_code=400,
                detail={"message": "Missing required artefacts", "missing": missing},
            )

        if overlay.toggles.get("enforce_ticket_sync") and not overlay.jira.get("project_key"):
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Ticket synchronisation enforced but Jira project_key missing",
                    "integration": overlay.jira,
                },
            )

        result = orchestrator.run(
            design_dataset=app.state.artifacts.get("design", {"columns": [], "rows": []}),
            sbom=app.state.artifacts["sbom"],
            sarif=app.state.artifacts["sarif"],
            cve=app.state.artifacts["cve"],
            overlay=overlay,
        )
        if app.state.archive_records:
            result["artifact_archive"] = ArtefactArchive.summarise(app.state.archive_records)
            app.state.archive_records = {}
        if overlay.toggles.get("auto_attach_overlay_metadata", True):
            result["overlay"] = overlay.to_sanitised_dict()
            result["overlay"]["required_inputs"] = list(required)
        return result

    @app.post("/feedback", dependencies=[Depends(_verify_api_key)])
    async def submit_feedback(payload: Dict[str, Any]) -> Dict[str, Any]:
        recorder: Optional[FeedbackRecorder] = app.state.feedback
        if recorder is None:
            raise HTTPException(status_code=400, detail="Feedback capture disabled in this profile")
        try:
            entry = recorder.record(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return entry

    return app
