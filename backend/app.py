from __future__ import annotations

import csv
import io
import logging
from typing import Any, Dict

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from fixops.configuration import OverlayConfig, load_overlay

from .normalizers import InputNormalizer, NormalizedCVEFeed, NormalizedSARIF, NormalizedSBOM
from .pipeline import PipelineOrchestrator

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create the FastAPI application with file-upload ingestion endpoints."""

    app = FastAPI(title="FixOps Ingestion Demo API", version="0.1.0")
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

    for directory in overlay.data_directories.values():
        directory.mkdir(parents=True, exist_ok=True)

    app.state.normalizer = normalizer
    app.state.orchestrator = orchestrator
    app.state.artifacts: Dict[str, Any] = {}
    app.state.overlay = overlay

    def _store(stage: str, payload: Any) -> None:
        logger.debug("Storing stage %s", stage)
        app.state.artifacts[stage] = payload

    @app.post("/inputs/design")
    async def ingest_design(file: UploadFile = File(...)) -> Dict[str, Any]:
        raw_bytes = await file.read()
        text = raw_bytes.decode("utf-8", errors="ignore")
        reader = csv.DictReader(io.StringIO(text))
        rows = [row for row in reader if any((value or "").strip() for value in row.values())]

        if not rows:
            raise HTTPException(status_code=400, detail="Design CSV contained no rows")

        dataset = {"columns": reader.fieldnames or [], "rows": rows}
        _store("design", dataset)
        return {
            "stage": "design",
            "input_filename": file.filename,
            "row_count": len(rows),
            "columns": dataset["columns"],
            "data": dataset,
        }

    @app.post("/inputs/sbom")
    async def ingest_sbom(file: UploadFile = File(...)) -> Dict[str, Any]:
        raw_bytes = await file.read()
        try:
            sbom: NormalizedSBOM = normalizer.load_sbom(raw_bytes)
        except Exception as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("SBOM normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse SBOM: {exc}") from exc

        _store("sbom", sbom)
        return {
            "stage": "sbom",
            "input_filename": file.filename,
            "metadata": sbom.metadata,
            "component_preview": [
                component.to_dict() for component in sbom.components[:5]
            ],
        }

    @app.post("/inputs/cve")
    async def ingest_cve(file: UploadFile = File(...)) -> Dict[str, Any]:
        raw_bytes = await file.read()
        try:
            cve_feed: NormalizedCVEFeed = normalizer.load_cve_feed(raw_bytes)
        except Exception as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("CVE feed normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse CVE feed: {exc}") from exc

        _store("cve", cve_feed)
        return {
            "stage": "cve",
            "input_filename": file.filename,
            "record_count": cve_feed.metadata.get("record_count", 0),
            "validation_errors": cve_feed.errors,
        }

    @app.post("/inputs/sarif")
    async def ingest_sarif(file: UploadFile = File(...)) -> Dict[str, Any]:
        raw_bytes = await file.read()
        try:
            sarif: NormalizedSARIF = normalizer.load_sarif(raw_bytes)
        except Exception as exc:  # pragma: no cover - FastAPI will serialise the message
            logger.exception("SARIF normalisation failed")
            raise HTTPException(status_code=400, detail=f"Failed to parse SARIF: {exc}") from exc

        _store("sarif", sarif)
        return {
            "stage": "sarif",
            "input_filename": file.filename,
            "metadata": sarif.metadata,
            "tools": sarif.tool_names,
        }

    @app.post("/pipeline/run")
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
        )
        if overlay.toggles.get("auto_attach_overlay_metadata", True):
            result["overlay"] = overlay.to_sanitised_dict()
            result["overlay"]["required_inputs"] = list(required)
        return result

    return app
