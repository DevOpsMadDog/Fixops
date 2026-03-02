"""
ALdeci Scanner Ingest Router — Universal scanner output ingestion API.

Accepts output from 25+ security scanners via upload, webhook, or auto-detect.
Plugs into the Brain Pipeline via NormalizerRegistry.

Endpoints:
  POST /api/v1/scanner-ingest/upload         — File upload (multipart)
  POST /api/v1/scanner-ingest/webhook/{type}  — Webhook receiver (raw body)
  POST /api/v1/scanner-ingest/detect          — Auto-detect scanner type
  GET  /api/v1/scanner-ingest/supported       — List supported scanners
  GET  /api/v1/scanner-ingest/stats           — Ingestion statistics

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V7 (MCP-Native), V9 (Air-Gapped)
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/scanner-ingest",
    tags=["scanner-ingest"],
)

# ── Security constants ──────────────────────────────────────────────
# Maximum upload size: 100 MB (prevents zip bombs and memory exhaustion)
_MAX_UPLOAD_BYTES = 100 * 1024 * 1024
# Maximum body size for webhook ingestion: 50 MB
_MAX_WEBHOOK_BYTES = 50 * 1024 * 1024
# Allowed file extensions for scanner output uploads
_ALLOWED_EXTENSIONS = frozenset({
    ".json", ".xml", ".html", ".csv", ".sarif",
    ".nessus", ".nmap", ".txt", ".log", ".yaml", ".yml",
    ".cdx", ".spdx", ".vex",
})
# Valid scanner type characters (alphanumeric + hyphens/underscores only)
import re as _re
_SCANNER_TYPE_RE = _re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _validate_scanner_type(scanner_type: str) -> str:
    """Validate scanner type to prevent injection attacks."""
    s = scanner_type.strip().lower()
    if not _SCANNER_TYPE_RE.match(s):
        raise HTTPException(
            status_code=422,
            detail="Invalid scanner type format: must be alphanumeric/hyphens/underscores, 1-64 chars",
        )
    return s


def _validate_filename(filename: Optional[str]) -> Optional[str]:
    """Validate uploaded filename to prevent path traversal."""
    if not filename:
        return None
    # Strip directory components (path traversal defense)
    import os
    # Check raw string BEFORE using os.path.basename
    if ".." in filename or "/" in filename or "\\" in filename:
        logger.warning("Path traversal attempt in filename: %r", filename[:100])
        # Still extract just the base name safely
        return os.path.basename(filename.replace("\\", "/"))
    return os.path.basename(filename)


def _validate_upload_size(content: bytes, max_bytes: int = _MAX_UPLOAD_BYTES) -> None:
    """Validate upload size to prevent DoS / zip bomb attacks."""
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Upload too large: {len(content)} bytes exceeds {max_bytes} byte limit",
        )
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")


# In-memory stats (shared per-process)
_ingest_stats: Dict[str, Any] = {
    "total_files_processed": 0,
    "total_findings_parsed": 0,
    "by_scanner": {},
    "last_ingest_at": None,
    "errors": 0,
}


def _get_scanner_parsers():
    """Lazy import to avoid circular imports."""
    try:
        from core.scanner_parsers import (
            SCANNER_NORMALIZERS,
            auto_detect_scanner,
            get_supported_scanners,
            parse_scanner_output,
        )
        return {
            "SCANNER_NORMALIZERS": SCANNER_NORMALIZERS,
            "auto_detect_scanner": auto_detect_scanner,
            "get_supported_scanners": get_supported_scanners,
            "parse_scanner_output": parse_scanner_output,
        }
    except ImportError as e:
        logger.warning(f"scanner_parsers not available: {e}")
        return None


def _serialize_findings(findings: list) -> List[Dict]:
    """Convert findings (UnifiedFinding or dict) to JSON-safe dicts."""
    result = []
    for f in findings:
        if hasattr(f, "model_dump"):
            d = f.model_dump(exclude_none=True)
        elif hasattr(f, "dict"):
            d = f.dict(exclude_none=True)
        elif isinstance(f, dict):
            d = {k: v for k, v in f.items() if v is not None}
        else:
            d = {"raw": str(f)}
        # Stringify any non-serializable values
        for k, v in d.items():
            if hasattr(v, "value"):  # enums
                d[k] = v.value
            elif isinstance(v, datetime):
                d[k] = v.isoformat()
        result.append(d)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# POST /upload — File upload (multipart form-data)
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/upload")
async def upload_scanner_output(
    file: UploadFile = File(...),
    scanner_type: Optional[str] = Form(None),
    app_id: str = Form(""),
    component: str = Form(""),
    pipeline: bool = Form(False),
):
    """
    Upload a scanner output file for ingestion.

    Supports: ZAP, Burp, Nessus, OpenVAS, Bandit, Checkmarx, SonarQube,
    Fortify, Veracode, Nikto, Nuclei, Nmap, Snyk, Prowler, Checkov.
    Plus existing: SARIF, CycloneDX, SPDX, VEX, Trivy, Grype, Semgrep, Dependabot.

    If scanner_type is not provided, auto-detection is used.
    Set pipeline=true to push findings into the Brain Pipeline immediately.
    """
    parsers = _get_scanner_parsers()
    if not parsers:
        raise HTTPException(status_code=503, detail="Scanner parser module not available")

    # Security: validate filename (path traversal defense)
    safe_filename = _validate_filename(file.filename)

    # Security: validate file extension
    if safe_filename:
        import os
        ext = os.path.splitext(safe_filename)[1].lower()
        if ext and ext not in _ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=415,
                detail=f"Unsupported file extension: {ext}. Allowed: {sorted(_ALLOWED_EXTENSIONS)}",
            )

    content = await file.read()
    # Security: validate upload size (zip bomb / DoS prevention)
    _validate_upload_size(content, _MAX_UPLOAD_BYTES)

    t0 = time.time()

    # Security: validate scanner_type if provided
    if scanner_type:
        scanner_type = _validate_scanner_type(scanner_type)

    # Auto-detect if not specified
    detected = scanner_type or parsers["auto_detect_scanner"](content)
    if not detected:
        raise HTTPException(
            status_code=422,
            detail="Cannot auto-detect scanner type. Provide scanner_type parameter.",
        )

    try:
        findings = parsers["parse_scanner_output"](
            content=content,
            scanner_type=detected,
            app_id=app_id,
            component=component,
        )
    except Exception as e:
        _ingest_stats["errors"] += 1
        # Security: don't leak internal error details — only expose type
        logger.error("Parse error for %s: %s", detected, e)
        raise HTTPException(
            status_code=422,
            detail=f"Parse error ({type(e).__name__}): could not parse {detected} output",
        )

    elapsed = time.time() - t0

    # Update stats
    _ingest_stats["total_files_processed"] += 1
    _ingest_stats["total_findings_parsed"] += len(findings)
    _ingest_stats["last_ingest_at"] = datetime.now(timezone.utc).isoformat()
    scanner_stats = _ingest_stats["by_scanner"].setdefault(detected, {"files": 0, "findings": 0})
    scanner_stats["files"] += 1
    scanner_stats["findings"] += len(findings)

    # Optionally push to brain pipeline
    pipeline_result = None
    if pipeline and findings:
        try:
            from core.brain_pipeline import BrainPipeline, PipelineInput

            bp = BrainPipeline()
            findings_dicts = _serialize_findings(findings)
            pipe_input = PipelineInput(
                findings=findings_dicts,
                assets=[],
                options={"source": f"scanner-ingest:{detected}"},
            )
            pipeline_result = bp.run(pipe_input)
            if hasattr(pipeline_result, "model_dump"):
                pipeline_result = pipeline_result.model_dump(exclude_none=True)
            elif hasattr(pipeline_result, "__dict__"):
                pipeline_result = pipeline_result.__dict__
        except Exception as e:
            logger.warning(f"Pipeline execution failed: {e}")
            pipeline_result = {"error": str(e)}

    return {
        "status": "success",
        "scanner": detected,
        "file_name": safe_filename or file.filename,
        "findings_count": len(findings),
        "parse_time_ms": round(elapsed * 1000, 1),
        "app_id": app_id or None,
        "component": component or None,
        "findings": _serialize_findings(findings[:100]),  # Cap response at 100
        "total_findings": len(findings),
        "pipeline_result": pipeline_result,
    }


# ═══════════════════════════════════════════════════════════════════════════
# POST /webhook/{scanner_type} — Webhook receiver
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/webhook/{scanner_type}")
async def webhook_ingest(
    scanner_type: str,
    request: Request,
    app_id: str = Query(""),
    component: str = Query(""),
    pipeline: bool = Query(False),
):
    """
    Receive scanner output via webhook (raw body).

    Set up your CI/CD to POST scanner output directly:
      curl -X POST https://aldeci/api/v1/scanner-ingest/webhook/zap \\
        -H "X-API-Key: $KEY" \\
        -H "Content-Type: application/json" \\
        --data-binary @zap-report.json
    """
    parsers = _get_scanner_parsers()
    if not parsers:
        raise HTTPException(status_code=503, detail="Scanner parser module not available")

    content = await request.body()
    # Security: validate body size (DoS prevention)
    _validate_upload_size(content, _MAX_WEBHOOK_BYTES)

    # Security: validate scanner_type path param (injection prevention)
    scanner = _validate_scanner_type(scanner_type)
    if scanner not in parsers["SCANNER_NORMALIZERS"]:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scanner type: {scanner}. Use GET /supported for list.",
        )

    t0 = time.time()
    try:
        findings = parsers["parse_scanner_output"](
            content=content,
            scanner_type=scanner,
            app_id=app_id,
            component=component,
        )
    except Exception as e:
        _ingest_stats["errors"] += 1
        # Security: don't leak internal error details
        logger.error("Parse error for webhook %s: %s", scanner, e)
        raise HTTPException(
            status_code=422,
            detail=f"Parse error ({type(e).__name__}): could not parse {scanner} output",
        )

    elapsed = time.time() - t0

    _ingest_stats["total_files_processed"] += 1
    _ingest_stats["total_findings_parsed"] += len(findings)
    _ingest_stats["last_ingest_at"] = datetime.now(timezone.utc).isoformat()
    scanner_stats = _ingest_stats["by_scanner"].setdefault(scanner, {"files": 0, "findings": 0})
    scanner_stats["files"] += 1
    scanner_stats["findings"] += len(findings)

    # Optionally push to brain pipeline
    pipeline_result = None
    if pipeline and findings:
        try:
            from core.brain_pipeline import BrainPipeline, PipelineInput

            bp = BrainPipeline()
            findings_dicts = _serialize_findings(findings)
            pipe_input = PipelineInput(
                findings=findings_dicts,
                assets=[],
                options={"source": f"webhook:{scanner}"},
            )
            pipeline_result = bp.run(pipe_input)
            if hasattr(pipeline_result, "model_dump"):
                pipeline_result = pipeline_result.model_dump(exclude_none=True)
            elif hasattr(pipeline_result, "__dict__"):
                pipeline_result = pipeline_result.__dict__
        except Exception as e:
            pipeline_result = {"error": str(e)}

    return {
        "status": "success",
        "scanner": scanner,
        "findings_count": len(findings),
        "parse_time_ms": round(elapsed * 1000, 1),
        "app_id": app_id or None,
        "findings": _serialize_findings(findings[:100]),
        "total_findings": len(findings),
        "pipeline_result": pipeline_result,
    }


# ═══════════════════════════════════════════════════════════════════════════
# POST /detect — Auto-detect scanner type from content
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/detect")
async def detect_scanner_type(
    file: UploadFile = File(...),
):
    """
    Detect scanner type from uploaded file without processing.
    Returns the detected scanner type and confidence score.
    """
    parsers = _get_scanner_parsers()
    if not parsers:
        raise HTTPException(status_code=503, detail="Scanner parser module not available")

    content = await file.read()
    # Security: validate upload size for detection endpoint too
    _validate_upload_size(content, _MAX_UPLOAD_BYTES)

    # Run all detectors and return scores
    from core.scanner_parsers import SCANNER_NORMALIZERS, NormalizerConfig

    scores = {}
    for name, cls in SCANNER_NORMALIZERS.items():
        try:
            config = NormalizerConfig(name=name, enabled=True, priority=50)
            normalizer = cls(config)
            score = normalizer.can_handle(content)
            if score > 0:
                scores[name] = round(score, 3)
        except Exception:
            continue

    # Sort by score descending
    sorted_scores = dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))
    best = next(iter(sorted_scores), None)

    return {
        "detected": best,
        "confidence": sorted_scores.get(best, 0.0) if best else 0.0,
        "all_scores": sorted_scores,
        "file_name": file.filename,
        "file_size_bytes": len(content),
    }


# ═══════════════════════════════════════════════════════════════════════════
# GET /supported — List supported scanners
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/supported")
async def list_supported_scanners():
    """
    List all supported scanner types grouped by category.

    Returns 25+ scanner types across SAST, DAST, SCA, infrastructure, cloud.
    """
    parsers = _get_scanner_parsers()
    if not parsers:
        # Still return the known list even if module isn't loaded
        return {
            "scanners": {
                "sast": ["checkmarx", "sonarqube", "bandit", "fortify", "veracode", "semgrep"],
                "dast": ["zap", "burp", "nikto", "nuclei"],
                "sca": ["snyk", "trivy", "grype", "dependabot"],
                "infrastructure": ["nessus", "openvas", "nmap"],
                "cloud": ["prowler", "checkov"],
                "universal": ["sarif", "cyclonedx", "spdx", "vex"],
            },
            "total": 25,
            "ingestion_methods": ["upload", "webhook", "auto-detect"],
        }

    supported = parsers["get_supported_scanners"]()
    return {
        "scanners": supported,
        "total_new_parsers": len(parsers["SCANNER_NORMALIZERS"]),
        "total_with_builtins": len(parsers["SCANNER_NORMALIZERS"]) + 10,
        "ingestion_methods": [
            {"method": "upload", "endpoint": "POST /api/v1/scanner-ingest/upload", "format": "multipart/form-data"},
            {"method": "webhook", "endpoint": "POST /api/v1/scanner-ingest/webhook/{type}", "format": "raw body"},
            {"method": "auto-detect", "endpoint": "POST /api/v1/scanner-ingest/detect", "format": "multipart/form-data"},
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════
# GET /stats — Ingestion statistics
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/stats")
async def ingestion_stats():
    """Return scanner ingestion statistics."""
    return {
        "stats": _ingest_stats,
        "uptime_note": "Stats are per-process (reset on restart)",
    }


@router.get("/health")
async def scanner_ingest_health():
    """Scanner ingest service health check."""
    return {
        "status": "healthy",
        "engine": "scanner-ingest",
        "version": "1.0.0",
        "total_ingested": _ingest_stats.get("total_ingested", 0),
    }


@router.get("/status")
async def scanner_ingest_status():
    """Scanner ingest service status (alias for /health)."""
    return await scanner_ingest_health()
