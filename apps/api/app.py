from __future__ import annotations

import csv
import io
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta
from contextlib import suppress
from pathlib import Path
from tempfile import SpooledTemporaryFile
from types import SimpleNamespace
from typing import Any, Dict, Mapping, Optional, Tuple

import jwt
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from core.analytics import AnalyticsStore
from core.configuration import OverlayConfig, load_overlay
from core.paths import ensure_secure_directory, verify_allowlisted_path
from core.storage import ArtefactArchive
from core.feedback import FeedbackRecorder

from .normalizers import (
    InputNormalizer,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
)
from .pipeline import PipelineOrchestrator

logger = logging.getLogger(__name__)

JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = int(os.getenv("FIXOPS_JWT_EXP_MINUTES", "120"))
JWT_SECRET = os.getenv("FIXOPS_JWT_SECRET") or secrets.token_hex(32)


def generate_access_token(data: Dict[str, Any]) -> str:
    """Generate a signed JWT access token with an expiry."""

    exp = datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES)
    payload = {**data, "exp": exp}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token."""

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:  # pragma: no cover - depends on wall clock
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    return payload


def create_app() -> FastAPI:
    """Create the FastAPI application with file-upload ingestion endpoints."""

    app = FastAPI(title="FixOps Ingestion Demo API", version="0.1.0")
    if not hasattr(app, "state"):
        app.state = SimpleNamespace()
    origins_env = os.getenv("FIXOPS_ALLOWED_ORIGINS", "")
    origins = [origin.strip() for origin in origins_env.split(",") if origin.strip()]
    if not origins:
        origins = ["https://core.ai"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    normalizer = InputNormalizer()
    orchestrator = PipelineOrchestrator()
    try:
        overlay = load_overlay(allow_demo_token_fallback=True)
    except TypeError:
        overlay = load_overlay()

    # API authentication setup
    auth_strategy = overlay.auth.get("strategy", "").lower()
    header_name = overlay.auth.get(
        "header", "X-API-Key" if auth_strategy != "jwt" else "Authorization"
    )
    api_key_header = APIKeyHeader(name=header_name, auto_error=False)
    expected_tokens = overlay.auth_tokens if auth_strategy == "token" else tuple()

    async def _verify_api_key(api_key: Optional[str] = Depends(api_key_header)) -> None:
        if auth_strategy == "token":
            if not api_key or api_key not in expected_tokens:
                raise HTTPException(
                    status_code=401, detail="Invalid or missing API token"
                )
            return
        if auth_strategy == "jwt":
            if not api_key:
                raise HTTPException(
                    status_code=401, detail="Missing Authorization header"
                )
            token = api_key
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            decode_access_token(token)

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

    analytics_dir = overlay.data_directories.get("analytics_dir")
    if analytics_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        analytics_dir = (root / "analytics" / overlay.mode).resolve()
    analytics_dir = verify_allowlisted_path(analytics_dir, allowlist)
    analytics_store = AnalyticsStore(analytics_dir, allowlist=allowlist)

    app.state.normalizer = normalizer
    app.state.orchestrator = orchestrator
    app.state.artifacts: Dict[str, Any] = {}
    app.state.overlay = overlay
    app.state.archive = archive
    app.state.archive_records: Dict[str, Dict[str, Any]] = {}
    app.state.analytics_store = analytics_store
    app.state.feedback = (
        FeedbackRecorder(overlay, analytics_store=analytics_store)
        if overlay.toggles.get("capture_feedback")
        else None
    )

    _CHUNK_SIZE = 1024 * 1024
    _RAW_BYTES_THRESHOLD = 4 * 1024 * 1024

    async def _read_limited(
        file: UploadFile, stage: str
    ) -> Tuple[SpooledTemporaryFile, int]:
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
        buffer: SpooledTemporaryFile,
        total: int,
        *,
        threshold: int = _RAW_BYTES_THRESHOLD,
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
        except (
            Exception
        ) as exc:  # pragma: no cover - persistence must not break ingestion
            logger.exception("Failed to persist artefact stage %s", stage)
            record = {"stage": stage, "error": str(exc)}
        app.state.archive_records[stage] = record

    @app.post("/inputs/design", dependencies=[Depends(_verify_api_key)])
    async def ingest_design(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file, ("text/csv", "application/vnd.ms-excel", "application/csv")
        )
        buffer, total = await _read_limited(file, "design")
        try:
            text_stream = io.TextIOWrapper(
                buffer, encoding="utf-8", errors="ignore", newline=""
            )
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
                raise HTTPException(
                    status_code=400, detail="Design CSV contained no rows"
                )

            dataset = {"columns": columns, "rows": rows}
            raw_bytes = _maybe_materialise_raw(buffer, total)
            _store(
                "design", dataset, original_filename=file.filename, raw_bytes=raw_bytes
            )
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
        except (
            Exception
        ) as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("SBOM normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse SBOM: {exc}"
            ) from exc
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
        except (
            Exception
        ) as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("CVE feed normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse CVE feed: {exc}"
            ) from exc
        else:
            raw_bytes = _maybe_materialise_raw(buffer, total)
            _store(
                "cve", cve_feed, original_filename=file.filename, raw_bytes=raw_bytes
            )
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
        except (
            Exception
        ) as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("SARIF normalisation failed")
            raise HTTPException(
                status_code=400, detail=f"Failed to parse SARIF: {exc}"
            ) from exc
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

        if overlay.toggles.get("enforce_ticket_sync") and not overlay.jira.get(
            "project_key"
        ):
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Ticket synchronisation enforced but Jira project_key missing",
                    "integration": overlay.jira,
                },
            )

        run_id = uuid.uuid4().hex

        result = orchestrator.run(
            design_dataset=app.state.artifacts.get(
                "design", {"columns": [], "rows": []}
            ),
            sbom=app.state.artifacts["sbom"],
            sarif=app.state.artifacts["sarif"],
            cve=app.state.artifacts["cve"],
            overlay=overlay,
        )
        result["run_id"] = run_id
        analytics_store = getattr(app.state, "analytics_store", None)
        if analytics_store is not None:
            try:
                persistence = analytics_store.persist_run(run_id, result)
            except (
                Exception
            ):  # pragma: no cover - analytics persistence must not block pipeline
                logger.exception(
                    "Failed to persist analytics artefacts for run %s", run_id
                )
                persistence = {}
            if persistence:
                result["analytics_persistence"] = persistence
                analytics_section = result.get("analytics")
                if isinstance(analytics_section, dict):
                    analytics_section["persistence"] = persistence
        if app.state.archive_records:
            result["artifact_archive"] = ArtefactArchive.summarise(
                app.state.archive_records
            )
            app.state.archive_records = {}
        if overlay.toggles.get("auto_attach_overlay_metadata", True):
            result["overlay"] = overlay.to_sanitised_dict()
            result["overlay"]["required_inputs"] = list(required)
        return result

    @app.get("/analytics/dashboard", dependencies=[Depends(_verify_api_key)])
    async def analytics_dashboard(limit: int = 10) -> Dict[str, Any]:
        store: Optional[AnalyticsStore] = getattr(app.state, "analytics_store", None)
        if store is None:
            raise HTTPException(
                status_code=404,
                detail="Analytics persistence disabled for this profile",
            )
        try:
            return store.load_dashboard(limit=limit)
        except ValueError as exc:  # pragma: no cover - defensive guard
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/analytics/runs/{run_id}", dependencies=[Depends(_verify_api_key)])
    async def analytics_run(run_id: str) -> Dict[str, Any]:
        store: Optional[AnalyticsStore] = getattr(app.state, "analytics_store", None)
        if store is None:
            raise HTTPException(
                status_code=404,
                detail="Analytics persistence disabled for this profile",
            )
        try:
            data = store.load_run(run_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        has_content = bool(
            data.get("forecasts")
            or data.get("exploit_snapshots")
            or data.get("ticket_metrics")
        )
        feedback_section = data.get("feedback")
        if isinstance(feedback_section, Mapping):
            has_content = has_content or bool(
                feedback_section.get("events") or feedback_section.get("outcomes")
            )
        if not has_content:
            raise HTTPException(
                status_code=404, detail="No analytics persisted for run"
            )
        return data

    @app.post("/feedback", dependencies=[Depends(_verify_api_key)])
    async def submit_feedback(payload: Dict[str, Any]) -> Dict[str, Any]:
        recorder: Optional[FeedbackRecorder] = app.state.feedback
        if recorder is None:
            raise HTTPException(
                status_code=400, detail="Feedback capture disabled in this profile"
            )
        try:
            entry = recorder.record(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return entry

    return app
