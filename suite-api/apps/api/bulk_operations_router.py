"""
Bulk Finding Import/Export API Router.

Endpoints:
  POST /api/v1/bulk/import          — import findings (CSV/JSON/SARIF/CycloneDX)
  POST /api/v1/bulk/validate        — dry-run validation without storing
  POST /api/v1/bulk/export          — export findings (CSV/JSON/SARIF)
  GET  /api/v1/bulk/import-history  — import history for org
  GET  /api/v1/bulk/export-history  — export history for org
  GET  /api/v1/bulk/field-mapping/{format} — field mapping reference
  GET  /api/v1/bulk/stats           — bulk operation stats

Auth is applied via _verify_api_key dependency on each route.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

from apps.api.auth_deps import api_key_auth as _verify_api_key

# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------

_engine: Optional[Any] = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.bulk_operations import BulkOperationsEngine
        _engine = BulkOperationsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ImportRequest(BaseModel):
    content: str = Field(..., description="Raw file content (CSV, JSON, SARIF, or CycloneDX)")
    format: str = Field(..., description="Import format: csv, json, sarif, cyclonedx")
    org_id: str = Field(..., min_length=1, description="Organisation ID")
    source: str = Field("bulk_import", description="Source label attached to findings")


class ValidateRequest(BaseModel):
    content: str = Field(..., description="Raw file content to validate")
    format: str = Field(..., description="Import format: csv, json, sarif, cyclonedx")


class ExportRequest(BaseModel):
    org_id: str = Field(..., min_length=1)
    format: str = Field("json", description="Export format: csv, json, sarif")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Filter findings by field values")


class ScheduleExportRequest(BaseModel):
    org_id: str = Field(..., min_length=1)
    format: str = Field("json")
    filters: Dict[str, Any] = Field(default_factory=dict)
    frequency: str = Field("daily", description="Frequency: hourly, daily, weekly")


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/bulk", tags=["bulk-operations"])


@router.post("/import", dependencies=[Depends(_verify_api_key)])
def import_findings(req: ImportRequest):
    """Import findings from CSV, JSON, SARIF, or CycloneDX content."""
    from core.bulk_operations import ImportFormat

    try:
        fmt = ImportFormat(req.format.lower())
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported import format '{req.format}'. Supported: csv, json, sarif, cyclonedx",
        )

    try:
        result = _get_engine().import_findings(
            content=req.content,
            format=fmt,
            org_id=req.org_id,
            source=req.source,
        )
    except Exception as exc:
        logger.exception("Import failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Import failed: {exc}")

    return result.model_dump()


@router.post("/validate", dependencies=[Depends(_verify_api_key)])
def validate_import(req: ValidateRequest):
    """Dry-run validation — returns errors without storing findings."""
    from core.bulk_operations import ImportFormat

    try:
        fmt = ImportFormat(req.format.lower())
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported format '{req.format}'",
        )

    try:
        errors = _get_engine().validate_import(content=req.content, format=fmt)
    except Exception as exc:
        logger.exception("Validation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Validation failed: {exc}")

    return {
        "valid": len(errors) == 0,
        "error_count": len(errors),
        "errors": [e.model_dump() for e in errors],
    }


@router.post("/export", dependencies=[Depends(_verify_api_key)])
def export_findings(req: ExportRequest):
    """Export org findings to CSV, JSON, or SARIF."""
    from core.bulk_operations import ExportFormat

    try:
        fmt = ExportFormat(req.format.lower())
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported export format '{req.format}'. Supported: csv, json, sarif",
        )

    try:
        result = _get_engine().export_findings(
            org_id=req.org_id,
            format=fmt,
            filters=req.filters,
        )
    except Exception as exc:
        logger.exception("Export failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Export failed: {exc}")

    return result.model_dump()


@router.get("/import-history", dependencies=[Depends(_verify_api_key)])
def get_import_history(org_id: str = Query(..., description="Organisation ID")):
    """Return all import operations for the given org."""
    try:
        history = _get_engine().get_import_history(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to fetch import history: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    return [h.model_dump() for h in history]


@router.get("/export-history", dependencies=[Depends(_verify_api_key)])
def get_export_history(org_id: str = Query(..., description="Organisation ID")):
    """Return all export operations for the given org."""
    try:
        history = _get_engine().get_export_history(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to fetch export history: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    return [h.model_dump() for h in history]


@router.get("/field-mapping/{format}", dependencies=[Depends(_verify_api_key)])
def get_field_mapping(format: str):
    """Return expected field mapping for the requested import/export format."""
    mapping = _get_engine().get_field_mapping(format)
    if not mapping:
        raise HTTPException(
            status_code=404,
            detail=f"No field mapping found for format '{format}'. Supported: csv, json, sarif, cyclonedx",
        )
    return {"format": format, "mapping": mapping}


@router.get("/stats", dependencies=[Depends(_verify_api_key)])
def get_bulk_stats(org_id: str = Query(..., description="Organisation ID")):
    """Return aggregate bulk operation stats for the given org."""
    try:
        stats = _get_engine().get_bulk_stats(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to fetch bulk stats: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    return stats


@router.post("/schedule-export", dependencies=[Depends(_verify_api_key)])
def schedule_export(req: ScheduleExportRequest):
    """Schedule a recurring export for the given org."""
    from core.bulk_operations import ExportFormat

    try:
        fmt = ExportFormat(req.format.lower())
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported export format '{req.format}'",
        )

    try:
        schedule_id = _get_engine().schedule_export(
            org_id=req.org_id,
            format=fmt,
            filters=req.filters,
            frequency=req.frequency,
        )
    except Exception as exc:
        logger.exception("Failed to schedule export: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return {"schedule_id": schedule_id, "org_id": req.org_id, "format": fmt.value, "frequency": req.frequency}
