from __future__ import annotations

import asyncio
import csv
import io
import logging
import os
import uuid
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import SpooledTemporaryFile
from types import SimpleNamespace
from typing import Any, Dict, Mapping, Optional, Tuple

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from fixops.analytics import AnalyticsStore
from fixops.configuration import OverlayConfig, load_overlay
from fixops.paths import ensure_secure_directory, verify_allowlisted_path
from fixops.storage import ArtefactArchive
from fixops.feedback import FeedbackRecorder

from .normalizers import InputNormalizer, NormalizedCVEFeed, NormalizedSARIF, NormalizedSBOM
from .pipeline import PipelineOrchestrator

logger = logging.getLogger(__name__)


@dataclass
class _SessionState:
    run_id: str
    artifacts: Dict[str, Any] = field(default_factory=dict)
    archive_records: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class SessionHandle:
    run_id: str
    state: _SessionState
    lock: asyncio.Lock


class SessionRegistry:
    """Coordinate access to in-flight ingestion sessions."""

    def __init__(self) -> None:
        self._sessions: Dict[str, _SessionState] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._registry_lock = asyncio.Lock()

    async def acquire(self, run_id: str) -> SessionHandle:
        async with self._registry_lock:
            session = self._sessions.get(run_id)
            if session is None:
                session = _SessionState(run_id=run_id)
                self._sessions[run_id] = session
                self._locks[run_id] = asyncio.Lock()
            lock = self._locks[run_id]
        return SessionHandle(run_id=run_id, state=session, lock=lock)

    async def clear(self, run_id: str) -> None:
        async with self._registry_lock:
            if self._locks.get(run_id) and self._locks[run_id].locked():
                return
            self._sessions.pop(run_id, None)
            self._locks.pop(run_id, None)


_RUN_ID_HEADER = "X-Fixops-Run-Id"
_CORS_ENV = "FIXOPS_CORS_ALLOW_ORIGINS"
_SESSION_ALLOWED_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


def _parse_origins(raw: Optional[str]) -> list[str]:
    if not raw:
        return []
    return [origin.strip() for origin in raw.split(",") if origin and origin.strip()]


def create_app() -> FastAPI:
    """Create the FastAPI application with file-upload ingestion endpoints."""

    overlay = load_overlay()

    app = FastAPI(title="FixOps Ingestion Demo API", version="0.1.0")
    if not hasattr(app, "state"):
        app.state = SimpleNamespace()
    app.state.sessions = SessionRegistry()

    cors_settings = dict(overlay.cors_settings)
    env_override = _parse_origins(os.getenv(_CORS_ENV))
    if env_override:
        cors_settings["allow_origins"] = env_override

    allow_origins = cors_settings.get("allow_origins", [])
    if allow_origins:
        if "*" in allow_origins and overlay.mode != "demo":
            raise RuntimeError(
                "Wildcard CORS origins are not permitted outside demo mode. Set explicit origins via FIXOPS_CORS_ALLOW_ORIGINS or overlay api.cors.allow_origins."
            )
        allow_credentials = bool(cors_settings.get("allow_credentials", False))
        if "*" in allow_origins:
            allow_credentials = False
        allow_methods = cors_settings.get("allow_methods") or ["GET", "POST", "OPTIONS"]
        allow_headers = cors_settings.get("allow_headers") or [
            "Authorization",
            "Content-Type",
            "Accept",
            "X-Requested-With",
        ]
        max_age = int(cors_settings.get("max_age", 600))
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allow_origins,
            allow_credentials=allow_credentials,
            allow_methods=allow_methods,
            allow_headers=allow_headers,
            max_age=max_age,
        )

    normalizer = InputNormalizer()
    orchestrator = PipelineOrchestrator()

    # API authentication setup
    auth_strategy = overlay.auth.get("strategy", "").lower()
    header_name = overlay.auth.get("header", "X-API-Key")
    expected_tokens = overlay.auth_tokens if auth_strategy == "token" else tuple()

    def _verify_api_key(provided: Optional[str]) -> None:
        if auth_strategy != "token":
            return
        if not provided or provided not in expected_tokens:
            raise HTTPException(status_code=401, detail="Invalid or missing API token")

    async def _get_session(run_id: Optional[str]) -> tuple[SessionHandle, bool]:
        issued = False
        if run_id is None:
            token = uuid.uuid4().hex
            issued = True
        else:
            token = run_id.strip()
            if not token:
                raise HTTPException(
                    status_code=400,
                    detail={"message": f"{_RUN_ID_HEADER} header cannot be empty"},
                )
            if any(character not in _SESSION_ALLOWED_CHARS for character in token):
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": (
                            f"{_RUN_ID_HEADER} may only contain alphanumeric characters, '-' or '_'"
                        )
                    },
                )
        registry: SessionRegistry = app.state.sessions
        handle = await registry.acquire(token)
        return handle, issued

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
    app.state.overlay = overlay
    app.state.archive = archive
    app.state.analytics_store = analytics_store
    app.state.feedback = (
        FeedbackRecorder(overlay, analytics_store=analytics_store)
        if overlay.toggles.get("capture_feedback")
        else None
    )

    _CHUNK_SIZE = 1024 * 1024
    _RAW_BYTES_THRESHOLD = 4 * 1024 * 1024

    async def _read_limited(file: UploadFile, stage: str) -> Tuple[SpooledTemporaryFile, int]:
        """Stream an upload into a spooled file respecting the configured limit."""

        limit = overlay.upload_limit(stage)
        timeout_seconds = max(1, overlay.upload_read_timeout(stage))
        total = 0
        buffer = SpooledTemporaryFile(max_size=_CHUNK_SIZE, mode="w+b")
        try:
            while total < limit:
                remaining = limit - total
                try:
                    chunk = await asyncio.wait_for(
                        file.read(min(_CHUNK_SIZE, remaining)), timeout=timeout_seconds
                    )
                except asyncio.TimeoutError as exc:
                    raise HTTPException(
                        status_code=408,
                        detail={
                            "message": f"Upload for stage '{stage}' timed out",
                            "timeout_seconds": timeout_seconds,
                        },
                    ) from exc
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

    async def _store(
        session: SessionHandle,
        stage: str,
        payload: Any,
        *,
        original_filename: Optional[str] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> None:
        async with session.lock:
            if stage in session.state.artifacts:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "message": f"Stage '{stage}' has already been uploaded for this run",
                        "run_id": session.run_id,
                        "stage": stage,
                    },
                )
            logger.debug("Storing stage %s for run %s", stage, session.run_id)
            session.state.artifacts[stage] = payload
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
        async with session.lock:
            session.state.archive_records[stage] = record

    @app.post("/inputs/design")
    async def ingest_design(
        file: UploadFile = File(...),
        run_id: Optional[str] = Header(default=None, alias=_RUN_ID_HEADER),
        api_key: Optional[str] = Header(default=None, alias=header_name),
    ) -> Dict[str, Any]:
        _verify_api_key(api_key)
        session, issued = await _get_session(run_id)
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
            await _store(
                session,
                "design",
                dataset,
                original_filename=file.filename,
                raw_bytes=raw_bytes,
            )
            return {
                "stage": "design",
                "input_filename": file.filename,
                "row_count": len(rows),
                "columns": dataset["columns"],
                "data": dataset,
                "session_id": session.run_id,
                "issued_session": issued,
            }
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/sbom")
    async def ingest_sbom(
        file: UploadFile = File(...),
        run_id: Optional[str] = Header(default=None, alias=_RUN_ID_HEADER),
        api_key: Optional[str] = Header(default=None, alias=header_name),
    ) -> Dict[str, Any]:
        _verify_api_key(api_key)
        session, issued = await _get_session(run_id)
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
            await _store(
                session,
                "sbom",
                sbom,
                original_filename=file.filename,
                raw_bytes=raw_bytes,
            )
            return {
                "stage": "sbom",
                "input_filename": file.filename,
                "metadata": sbom.metadata,
                "component_preview": [
                    component.to_dict() for component in sbom.components[:5]
                ],
                "session_id": session.run_id,
                "issued_session": issued,
            }
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/cve")
    async def ingest_cve(
        file: UploadFile = File(...),
        run_id: Optional[str] = Header(default=None, alias=_RUN_ID_HEADER),
        api_key: Optional[str] = Header(default=None, alias=header_name),
    ) -> Dict[str, Any]:
        _verify_api_key(api_key)
        session, issued = await _get_session(run_id)
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
            await _store(
                session,
                "cve",
                cve_feed,
                original_filename=file.filename,
                raw_bytes=raw_bytes,
            )
            return {
                "stage": "cve",
                "input_filename": file.filename,
                "record_count": cve_feed.metadata.get("record_count", 0),
                "validation_errors": cve_feed.errors,
                "session_id": session.run_id,
                "issued_session": issued,
            }
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/sarif")
    async def ingest_sarif(
        file: UploadFile = File(...),
        run_id: Optional[str] = Header(default=None, alias=_RUN_ID_HEADER),
        api_key: Optional[str] = Header(default=None, alias=header_name),
    ) -> Dict[str, Any]:
        _verify_api_key(api_key)
        session, issued = await _get_session(run_id)
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
            await _store(
                session,
                "sarif",
                sarif,
                original_filename=file.filename,
                raw_bytes=raw_bytes,
            )
            return {
                "stage": "sarif",
                "input_filename": file.filename,
                "metadata": sarif.metadata,
                "tools": sarif.tool_names,
                "session_id": session.run_id,
                "issued_session": issued,
            }
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/pipeline/run")
    async def run_pipeline(
        run_id: Optional[str] = Header(default=None, alias=_RUN_ID_HEADER),
        api_key: Optional[str] = Header(default=None, alias=header_name),
    ) -> Dict[str, Any]:
        _verify_api_key(api_key)
        session, issued = await _get_session(run_id)
        if issued:
            raise HTTPException(
                status_code=400,
                detail={"message": f"{_RUN_ID_HEADER} header is required"},
            )
        overlay: OverlayConfig = app.state.overlay
        required = overlay.required_inputs
        async with session.lock:
            missing = [stage for stage in required if stage not in session.state.artifacts]
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

        run_id = uuid.uuid4().hex

        registry: SessionRegistry = app.state.sessions

        try:
            async with session.lock:
                result = orchestrator.run(
                    design_dataset=session.state.artifacts.get("design", {"columns": [], "rows": []}),
                    sbom=session.state.artifacts["sbom"],
                    sarif=session.state.artifacts["sarif"],
                    cve=session.state.artifacts["cve"],
                    overlay=overlay,
                )
                session_id = session.run_id
                archive_records = dict(session.state.archive_records)
                session.state.archive_records = {}
                session.state.artifacts.clear()
            result["run_id"] = run_id
            result["session_id"] = session_id
            analytics_store = getattr(app.state, "analytics_store", None)
            if analytics_store is not None:
                try:
                    persistence = analytics_store.persist_run(run_id, result)
                except Exception:  # pragma: no cover - analytics persistence must not block pipeline
                    logger.exception("Failed to persist analytics artefacts for run %s", run_id)
                    persistence = {}
                if persistence:
                    result["analytics_persistence"] = persistence
                    analytics_section = result.get("analytics")
                    if isinstance(analytics_section, dict):
                        analytics_section["persistence"] = persistence
            if archive_records:
                result["artifact_archive"] = ArtefactArchive.summarise(archive_records)
            if overlay.toggles.get("auto_attach_overlay_metadata", True):
                result["overlay"] = overlay.to_sanitised_dict()
                result["overlay"]["required_inputs"] = list(required)
            return result
        finally:
            await registry.clear(session.run_id)

    @app.get("/analytics/dashboard")
    async def analytics_dashboard(
        limit: int = 10,
        api_key: Optional[str] = Header(default=None, alias=header_name),
    ) -> Dict[str, Any]:
        _verify_api_key(api_key)
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

    @app.get("/analytics/runs/{run_id}")
    async def analytics_run(
        run_id: str, api_key: Optional[str] = Header(default=None, alias=header_name)
    ) -> Dict[str, Any]:
        _verify_api_key(api_key)
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
            data.get("forecasts") or data.get("exploit_snapshots") or data.get("ticket_metrics")
        )
        feedback_section = data.get("feedback")
        if isinstance(feedback_section, Mapping):
            has_content = has_content or bool(
                feedback_section.get("events") or feedback_section.get("outcomes")
            )
        if not has_content:
            raise HTTPException(status_code=404, detail="No analytics persisted for run")
        return data

    @app.post("/feedback")
    async def submit_feedback(
        payload: Dict[str, Any],
        api_key: Optional[str] = Header(default=None, alias=header_name),
    ) -> Dict[str, Any]:
        _verify_api_key(api_key)
        recorder: Optional[FeedbackRecorder] = app.state.feedback
        if recorder is None:
            raise HTTPException(status_code=400, detail="Feedback capture disabled in this profile")
        try:
            entry = recorder.record(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return entry

    return app
