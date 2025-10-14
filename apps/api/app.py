from __future__ import annotations

import csv
import io
import importlib.util
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta
from contextlib import suppress
import json
import shutil
from pathlib import Path
from tempfile import SpooledTemporaryFile
from types import SimpleNamespace
from typing import Any, Dict, Mapping, Optional, Tuple

import jwt
from fastapi import Body, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from core.analytics import AnalyticsStore
from core.configuration import OverlayConfig, load_overlay
from core.paths import ensure_secure_directory, verify_allowlisted_path
from core.storage import ArtefactArchive
from core.feedback import FeedbackRecorder
from core.enhanced_decision import EnhancedDecisionEngine

from backend.api.provenance import router as provenance_router
from backend.api.risk import router as risk_router
from backend.api.graph import router as graph_router
from backend.api.evidence import router as evidence_router
from telemetry import configure as configure_telemetry

if importlib.util.find_spec("opentelemetry.instrumentation.fastapi"):
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
else:  # pragma: no cover - fallback when instrumentation is unavailable
    from telemetry.fastapi_noop import FastAPIInstrumentor

from .normalizers import (
    InputNormalizer,
    NormalizedBusinessContext,
    NormalizedCNAPP,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    NormalizedVEX,
)
from .pipeline import PipelineOrchestrator
from .routes.enhanced import router as enhanced_router
from .upload_manager import ChunkUploadManager

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

    configure_telemetry(service_name="fixops-api")
    app = FastAPI(title="FixOps Ingestion Demo API", version="0.1.0")
    FastAPIInstrumentor.instrument_app(app)
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
            if not api_key:
                raise HTTPException(
                    status_code=401, detail="Missing API token"
                )
            if api_key not in expected_tokens:
                raise HTTPException(
                    status_code=403, detail="Invalid API token"
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

    provenance_dir = overlay.data_directories.get("provenance_dir")
    if provenance_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        provenance_dir = (root / "artifacts" / "attestations" / overlay.mode).resolve()
    provenance_dir = verify_allowlisted_path(provenance_dir, allowlist)
    provenance_dir = ensure_secure_directory(provenance_dir)

    risk_dir = overlay.data_directories.get("risk_dir")
    if risk_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        risk_dir = (root / "artifacts").resolve()
    risk_dir = verify_allowlisted_path(risk_dir, allowlist)
    risk_dir = ensure_secure_directory(risk_dir)

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
    app.state.enhanced_engine = EnhancedDecisionEngine(
        overlay.enhanced_decision_settings
    )
    sbom_dir = overlay.data_directories.get("sbom_dir")
    if sbom_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        sbom_dir = (root / "artifacts" / "sbom").resolve()
    sbom_dir = verify_allowlisted_path(sbom_dir, allowlist)
    sbom_dir = ensure_secure_directory(sbom_dir)

    graph_dir = overlay.data_directories.get("graph_dir")
    if graph_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        graph_dir = (root / "analysis").resolve()
    graph_dir = verify_allowlisted_path(graph_dir, allowlist)
    graph_dir = ensure_secure_directory(graph_dir)

    evidence_dir = overlay.data_directories.get("evidence_dir")
    if evidence_dir is None:
        root = allowlist[0]
        root = verify_allowlisted_path(root, allowlist)
        evidence_dir = (root / "evidence").resolve()
    evidence_dir = verify_allowlisted_path(evidence_dir, allowlist)
    evidence_dir = ensure_secure_directory(evidence_dir)
    evidence_manifest_dir = ensure_secure_directory(evidence_dir / "manifests")
    evidence_bundle_dir = ensure_secure_directory(evidence_dir / "bundles")

    app.state.provenance_dir = provenance_dir
    app.state.risk_dir = risk_dir
    app.state.sbom_dir = sbom_dir
    app.state.graph_config = {
        "repo_path": Path(".").resolve(),
        "attestation_dir": provenance_dir,
        "sbom_dir": sbom_dir,
        "risk_dir": risk_dir,
        "releases_path": graph_dir / "releases.json",
    }
    app.state.evidence_manifest_dir = evidence_manifest_dir
    app.state.evidence_bundle_dir = evidence_bundle_dir
    uploads_dir = overlay.data_directories.get("uploads_dir")
    if uploads_dir is None:
        root = allowlist[0]
        uploads_dir = (root / "uploads" / overlay.mode).resolve()
    uploads_dir = verify_allowlisted_path(uploads_dir, allowlist)
    upload_manager = ChunkUploadManager(uploads_dir)
    app.state.upload_manager = upload_manager

    app.include_router(enhanced_router, dependencies=[Depends(_verify_api_key)])
    app.include_router(provenance_router, dependencies=[Depends(_verify_api_key)])
    app.include_router(risk_router, dependencies=[Depends(_verify_api_key)])
    app.include_router(graph_router, dependencies=[Depends(_verify_api_key)])
    app.include_router(evidence_router, dependencies=[Depends(_verify_api_key)])

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

    supported_stages = {
        "design",
        "sbom",
        "sarif",
        "cve",
        "vex",
        "cnapp",
        "context",
    }

    def _process_design(buffer: SpooledTemporaryFile, total: int, filename: str) -> Dict[str, Any]:
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
            raise HTTPException(status_code=400, detail="Design CSV contained no rows")
        dataset = {"columns": columns, "rows": rows}
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("design", dataset, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "stage": "design",
            "input_filename": filename,
            "row_count": len(rows),
            "columns": columns,
            "data": dataset,
        }

    def _process_sbom(buffer: SpooledTemporaryFile, total: int, filename: str) -> Dict[str, Any]:
        try:
            sbom: NormalizedSBOM = normalizer.load_sbom(buffer)
        except Exception as exc:  # pragma: no cover - pass to FastAPI
            logger.exception("SBOM normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse SBOM: {exc}") from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("sbom", sbom, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "stage": "sbom",
            "input_filename": filename,
            "metadata": sbom.metadata,
            "component_preview": [component.to_dict() for component in sbom.components[:5]],
            "format": sbom.format,
        }

    def _process_cve(buffer: SpooledTemporaryFile, total: int, filename: str) -> Dict[str, Any]:
        try:
            cve_feed: NormalizedCVEFeed = normalizer.load_cve_feed(buffer)
        except Exception as exc:  # pragma: no cover - FastAPI serialises
            logger.exception("CVE feed normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse CVE feed: {exc}") from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("cve", cve_feed, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "stage": "cve",
            "input_filename": filename,
            "record_count": cve_feed.metadata.get("record_count", 0),
            "validation_errors": cve_feed.errors,
        }

    def _process_vex(buffer: SpooledTemporaryFile, total: int, filename: str) -> Dict[str, Any]:
        try:
            vex_doc: NormalizedVEX = normalizer.load_vex(buffer)
        except Exception as exc:
            logger.exception("VEX normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse VEX document: {exc}") from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("vex", vex_doc, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "stage": "vex",
            "input_filename": filename,
            "assertions": vex_doc.metadata.get("assertion_count", 0),
            "not_affected": len(vex_doc.suppressed_refs),
        }

    def _process_cnapp(buffer: SpooledTemporaryFile, total: int, filename: str) -> Dict[str, Any]:
        try:
            cnapp_payload: NormalizedCNAPP = normalizer.load_cnapp(buffer)
        except Exception as exc:
            logger.exception("CNAPP normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse CNAPP payload: {exc}") from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("cnapp", cnapp_payload, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "stage": "cnapp",
            "input_filename": filename,
            "asset_count": cnapp_payload.metadata.get("asset_count", len(cnapp_payload.assets)),
            "finding_count": cnapp_payload.metadata.get("finding_count", len(cnapp_payload.findings)),
        }

    def _process_sarif(buffer: SpooledTemporaryFile, total: int, filename: str) -> Dict[str, Any]:
        try:
            sarif: NormalizedSARIF = normalizer.load_sarif(buffer)
        except Exception as exc:
            logger.exception("SARIF normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse SARIF: {exc}") from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("sarif", sarif, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "stage": "sarif",
            "input_filename": filename,
            "metadata": sarif.metadata,
            "tools": sarif.tool_names,
        }

    def _process_context(buffer: SpooledTemporaryFile, total: int, filename: str, content_type: Optional[str] = None) -> Dict[str, Any]:
        try:
            context: NormalizedBusinessContext = normalizer.load_business_context(buffer, content_type=content_type)
        except Exception as exc:
            logger.exception("Business context normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse business context: {exc}") from exc
        raw_bytes = _maybe_materialise_raw(buffer, total)
        _store("context", context, original_filename=filename, raw_bytes=raw_bytes)
        return {
            "stage": "context",
            "input_filename": filename,
            "format": context.format,
            "ssvc_factors": context.ssvc,
            "components": context.components,
        }

    def _process_from_buffer(stage: str, buffer: SpooledTemporaryFile, total: int, filename: str, content_type: Optional[str] = None) -> Dict[str, Any]:
        if stage == "design":
            return _process_design(buffer, total, filename)
        if stage == "sbom":
            return _process_sbom(buffer, total, filename)
        if stage == "cve":
            return _process_cve(buffer, total, filename)
        if stage == "vex":
            return _process_vex(buffer, total, filename)
        if stage == "cnapp":
            return _process_cnapp(buffer, total, filename)
        if stage == "sarif":
            return _process_sarif(buffer, total, filename)
        if stage == "context":
            return _process_context(buffer, total, filename, content_type)
        raise HTTPException(status_code=400, detail=f"Unsupported stage '{stage}'")

    def _process_from_path(stage: str, path: Path, filename: str, content_type: Optional[str] = None) -> Dict[str, Any]:
        buffer = SpooledTemporaryFile(max_size=_CHUNK_SIZE, mode="w+b")
        try:
            with path.open("rb") as handle:
                shutil.copyfileobj(handle, buffer)
            total = buffer.tell()
            buffer.seek(0)
            return _process_from_buffer(stage, buffer, total, filename, content_type)
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/design", dependencies=[Depends(_verify_api_key)])
    async def ingest_design(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file, ("text/csv", "application/vnd.ms-excel", "application/csv")
        )
        buffer, total = await _read_limited(file, "design")
        try:
            return _process_design(buffer, total, file.filename or "design.csv")
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
            return _process_sbom(buffer, total, file.filename or "sbom.json")
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
            return _process_cve(buffer, total, file.filename or "cve.json")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/vex", dependencies=[Depends(_verify_api_key)])
    async def ingest_vex(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(file, ("application/json", "text/json"))
        buffer, total = await _read_limited(file, "vex")
        try:
            return _process_vex(buffer, total, file.filename or "vex.json")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/cnapp", dependencies=[Depends(_verify_api_key)])
    async def ingest_cnapp(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(file, ("application/json", "text/json"))
        buffer, total = await _read_limited(file, "cnapp")
        try:
            return _process_cnapp(buffer, total, file.filename or "cnapp.json")
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
            return _process_sarif(buffer, total, file.filename or "scan.sarif")
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/context", dependencies=[Depends(_verify_api_key)])
    async def ingest_context(file: UploadFile = File(...)) -> Dict[str, Any]:
        _validate_content_type(
            file,
            (
                "application/json",
                "text/json",
                "application/x-yaml",
                "text/yaml",
                "application/yaml",
                "text/plain",
            ),
        )
        buffer, total = await _read_limited(file, "context")
        try:
            return _process_context(buffer, total, file.filename or "context.yaml", file.content_type)
        finally:
            with suppress(Exception):
                buffer.close()

    @app.post("/inputs/{stage}/chunks/start", dependencies=[Depends(_verify_api_key)])
    async def initialise_chunk_upload(stage: str, payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(status_code=404, detail=f"Stage '{stage}' not recognised")
        filename = str(payload.get("file_name") or payload.get("filename") or f"{stage}.bin")
        try:
            total_bytes = int(payload.get("total_size")) if payload.get("total_size") is not None else None
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="total_size must be an integer")
        checksum = payload.get("checksum")
        content_type = payload.get("content_type")
        session = upload_manager.create_session(
            stage,
            filename=filename,
            total_bytes=total_bytes,
            checksum=checksum,
            content_type=content_type,
        )
        return {"status": "initialised", "session": session.to_dict()}

    @app.put("/inputs/{stage}/chunks/{session_id}", dependencies=[Depends(_verify_api_key)])
    async def upload_chunk(stage: str, session_id: str, chunk: UploadFile = File(...), offset: Optional[int] = None) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(status_code=404, detail=f"Stage '{stage}' not recognised")
        data = await chunk.read()
        try:
            session = upload_manager.append_chunk(session_id, data, offset=offset)
        except KeyError:
            raise HTTPException(status_code=404, detail="Upload session not found")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"status": "chunk_received", "session": session.to_dict()}

    @app.post("/inputs/{stage}/chunks/{session_id}/complete", dependencies=[Depends(_verify_api_key)])
    async def complete_upload(stage: str, session_id: str) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(status_code=404, detail=f"Stage '{stage}' not recognised")
        try:
            session = upload_manager.finalise(session_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Upload session not found")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        path = session.path
        if path is None:
            raise HTTPException(status_code=500, detail="Upload payload missing")
        response = _process_from_path(stage, path, session.filename, session.content_type)
        response["upload_session"] = session.to_dict()
        return response

    @app.get("/inputs/{stage}/chunks/{session_id}", dependencies=[Depends(_verify_api_key)])
    async def upload_status(stage: str, session_id: str) -> Dict[str, Any]:
        if stage not in supported_stages:
            raise HTTPException(status_code=404, detail=f"Stage '{stage}' not recognised")
        try:
            session = upload_manager.status(session_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Upload session not found")
        return {"status": "ok", "session": session.to_dict()}

    @app.api_route(
        "/pipeline/run",
        methods=["GET", "POST"],
        dependencies=[Depends(_verify_api_key)],
    )
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
            vex=app.state.artifacts.get("vex"),
            cnapp=app.state.artifacts.get("cnapp"),
            context=app.state.artifacts.get("context"),
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
