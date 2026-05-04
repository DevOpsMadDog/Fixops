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

from apps.api.dependencies import get_org_id
from apps.api.endpoint_rate_limit import enforce as _rl_enforce
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
)

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


def _promote_findings_to_issues(
    findings_dicts: List[Dict[str, Any]],
    scanner: str,
    org_id: str,
) -> int:
    """Promote ingested scanner findings to /api/v1/issues queue.

    Bridges scanner-ingest output into SecurityFindingsEngine — the table
    the unified Issues federation reads from. Each finding becomes an open
    row deduped by correlation_key (scanner|rule_or_cve|asset). Returns
    the number of findings successfully promoted (best-effort: never raises;
    individual record failures are skipped).
    """
    if not findings_dicts:
        return 0
    try:
        from core.security_findings_engine import SecurityFindingsEngine
    except ImportError:
        logger.warning("issue promotion skipped — security_findings_engine unavailable")
        return 0

    engine = SecurityFindingsEngine()
    promoted = 0
    for f in findings_dicts:
        try:
            title = (f.get("title") or f.get("rule_id") or f.get("id") or "scanner-finding")[:500]
            description = (f.get("description") or "")[:2000]
            severity = str(f.get("severity") or "medium").lower()
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "medium"
            cvss = f.get("cvss_score") or f.get("cvss") or 0.0
            try:
                cvss = float(cvss)
            except (TypeError, ValueError):
                cvss = 0.0
            asset_id = (
                f.get("asset_id")
                or f.get("file_path")
                or f.get("package_name")
                or f.get("component")
                or scanner
            )
            asset_type = (
                f.get("asset_type")
                or ("dependency" if f.get("package_name") else "code")
            )
            finding_type = (
                f.get("finding_type")
                or ("vulnerability" if f.get("cve_id") else "weakness")
            )
            remediation = (
                f.get("recommendation")
                or f.get("remediation")
                or ""
            )[:1000]
            corr_key = (
                f.get("correlation_key")
                or f"{scanner}|{f.get('rule_id') or f.get('cve_id') or title}|{asset_id}"
            )
            engine.record_finding(
                org_id=org_id or "default",
                title=title,
                finding_type=str(finding_type),
                source_tool=scanner,
                severity=severity,
                cvss_score=cvss,
                asset_id=str(asset_id),
                asset_type=str(asset_type),
                description=description,
                remediation=remediation,
                correlation_key=corr_key,
            )
            promoted += 1
        except (TypeError, ValueError, KeyError, RuntimeError, OSError) as e:
            logger.debug("issue promotion record failed for one finding: %s", type(e).__name__)
            continue

    if promoted:
        # Bump federation refresh epoch so /api/v1/issues sees new rows.
        try:
            from core.event_bus import EventType, get_event_bus
            bus = get_event_bus()
            if hasattr(bus, "publish"):
                bus.publish(
                    EventType.FINDINGS_INDEX_REFRESH,
                    {"source": f"scanner-ingest:{scanner}", "findings_mirrored": promoted},
                )
        except (ImportError, AttributeError, RuntimeError):
            pass  # bridge is best-effort
    return promoted


def _dedupe_findings(
    findings_dicts: List[Dict[str, Any]],
    org_id: str,
) -> Dict[str, Any]:
    """Run SmartDedup over serialized findings; return canonical-only list.

    Collapses cross-scanner duplicates (exact CVE / file:line / fuzzy title /
    package@version) before findings hit the storage layer. Returns a dict
    with: canonical (surviving findings), duplicate_count, groups (count of
    dedup groups created). Falls back to no-op on engine errors.
    """
    if not findings_dicts:
        return {"canonical": findings_dicts, "duplicate_count": 0, "groups": 0}
    try:
        from core.smart_dedup import SmartDedup
    except ImportError:
        return {"canonical": findings_dicts, "duplicate_count": 0, "groups": 0}
    try:
        engine = SmartDedup()
        result = engine.deduplicate(findings_dicts, org_id=org_id or "")
        canonical = result.get("canonical_findings") or findings_dicts
        return {
            "canonical": canonical,
            "duplicate_count": int(result.get("duplicate_count", 0)),
            "groups": len(result.get("groups", []) or []),
        }
    except (RuntimeError, ValueError, KeyError, OSError, AttributeError) as e:
        logger.warning("smart-dedup at ingest failed: %s", type(e).__name__)
        return {"canonical": findings_dicts, "duplicate_count": 0, "groups": 0}


# ═══════════════════════════════════════════════════════════════════════════
# POST /upload — File upload (multipart form-data)
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/")
async def list_scanner_ingest(org_id: str = Depends(get_org_id)):
    """List supported scanners and ingestion stats."""
    return {"org_id": org_id, "status": "ok", "supported_scanners": ["semgrep", "trivy", "grype", "snyk", "bandit", "checkov", "nuclei", "zap"]}


@router.post("/upload")
async def upload_scanner_output(
    request: Request,
    file: UploadFile = File(...),
    scanner_type: Optional[str] = Form(None),
    app_id: str = Form(""),
    component: str = Form(""),
    pipeline: bool = Form(False),
    org_id: str = Depends(get_org_id),
):
    """
    Upload a scanner output file for ingestion.

    Supports: ZAP, Burp, Nessus, OpenVAS, Bandit, Checkmarx, SonarQube,
    Fortify, Veracode, Nikto, Nuclei, Nmap, Snyk, Prowler, Checkov, Gitleaks.
    Plus existing: SARIF, CycloneDX, SPDX, VEX, Trivy, Grype, Semgrep, Dependabot.

    If scanner_type is not provided, auto-detection is used.
    Set pipeline=true to push findings into the Brain Pipeline immediately.
    """
    _rl_enforce(request, limit_key="ingest:upload", max_per_minute=30)
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
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
        _ingest_stats["errors"] += 1
        # Security: don't leak internal error details — only expose type
        logger.error("Parse error for %s: %s", detected, type(e).__name__, exc_info=True)
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

    # Gap 4: cross-scanner dedup at storage layer — collapse exact CVE,
    # file:line, fuzzy-title, and package@version overlaps before findings
    # are persisted. Falls back to no-op when the engine is unavailable.
    findings_dicts_full = _serialize_findings(findings) if findings else []
    dedup_summary = _dedupe_findings(findings_dicts_full, org_id)
    canonical_dicts = dedup_summary["canonical"]

    # Gap 2: promote canonical findings to /api/v1/issues federation by
    # writing them into SecurityFindingsEngine (security_findings table).
    promoted_count = _promote_findings_to_issues(canonical_dicts, detected, org_id)

    # Optionally push to brain pipeline
    pipeline_result = None
    if pipeline and findings:
        try:
            from core.brain_pipeline import BrainPipeline, PipelineInput

            bp = BrainPipeline()
            pipe_input = PipelineInput(
                findings=canonical_dicts,
                assets=[],
                source=f"scanner-ingest:{detected}",
            )
            pipeline_result = bp.run(pipe_input)
            if hasattr(pipeline_result, "model_dump"):
                pipeline_result = pipeline_result.model_dump(exclude_none=True)
            elif hasattr(pipeline_result, "__dict__"):
                pipeline_result = pipeline_result.__dict__
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("Pipeline execution failed: %s", type(e).__name__)
            pipeline_result = {"error": type(e).__name__}

    # TrustGraph async indexing (fire-and-forget, non-blocking)
    try:
        from core.trustgraph_event_bus import EVENT_FINDING_CREATED, get_event_bus
        bus = get_event_bus()
        if bus and bus.enabled and findings:
            import asyncio
            asyncio.ensure_future(bus.emit(EVENT_FINDING_CREATED, {
                "finding_id": f"scanner-upload-{detected}-{app_id or 'default'}",
                "type": "scanner_finding",
                "severity": "medium",
                "source": f"scanner_ingest_router:{detected}",
                "scanner": detected,
                "findings_count": len(findings),
                "app_id": app_id or None,
            }))
    except Exception:
        pass  # event bus is best-effort
    return {
        "status": "success",
        "org_id": org_id,
        "scanner": detected,
        "file_name": safe_filename or file.filename,
        "findings_count": len(findings),
        "parse_time_ms": round(elapsed * 1000, 1),
        "app_id": app_id or None,
        "component": component or None,
        "findings": _serialize_findings(findings[:100]),  # Cap response at 100
        "total_findings": len(findings),
        "deduped_count": len(canonical_dicts),
        "duplicates_removed": dedup_summary["duplicate_count"],
        "promoted_to_issues": promoted_count,
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
    org_id: str = Depends(get_org_id),
):
    """
    Receive scanner output via webhook (raw body).

    Set up your CI/CD to POST scanner output directly:
      curl -X POST https://aldeci/api/v1/scanner-ingest/webhook/zap \\
        -H "X-API-Key: $KEY" \\
        -H "Content-Type: application/json" \\
        --data-binary @zap-report.json
    """
    _rl_enforce(request, limit_key="ingest:webhook", max_per_minute=30)
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
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
        _ingest_stats["errors"] += 1
        # Security: don't leak internal error details
        logger.error("Parse error for webhook %s: %s", scanner, type(e).__name__, exc_info=True)
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

    # Gap 4: cross-scanner dedup at storage layer (webhook path).
    findings_dicts_full = _serialize_findings(findings) if findings else []
    dedup_summary = _dedupe_findings(findings_dicts_full, org_id)
    canonical_dicts = dedup_summary["canonical"]

    # Gap 2: promote canonical findings to /api/v1/issues federation.
    promoted_count = _promote_findings_to_issues(canonical_dicts, scanner, org_id)

    # Optionally push to brain pipeline
    pipeline_result = None
    if pipeline and findings:
        try:
            from core.brain_pipeline import BrainPipeline, PipelineInput

            bp = BrainPipeline()
            pipe_input = PipelineInput(
                findings=canonical_dicts,
                assets=[],
                source=f"webhook:{scanner}",
            )
            pipeline_result = bp.run(pipe_input)
            if hasattr(pipeline_result, "model_dump"):
                pipeline_result = pipeline_result.model_dump(exclude_none=True)
            elif hasattr(pipeline_result, "__dict__"):
                pipeline_result = pipeline_result.__dict__
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("Webhook pipeline failed: %s", type(e).__name__)
            pipeline_result = {"error": type(e).__name__}

    # TrustGraph async indexing (fire-and-forget, non-blocking)
    try:
        from core.trustgraph_event_bus import EVENT_FINDING_CREATED, get_event_bus
        bus = get_event_bus()
        if bus and bus.enabled and findings:
            import asyncio
            asyncio.ensure_future(bus.emit(EVENT_FINDING_CREATED, {
                "finding_id": f"scanner-webhook-{scanner}-{app_id or 'default'}",
                "type": "scanner_finding",
                "severity": "medium",
                "source": f"scanner_ingest_router:webhook:{scanner}",
                "scanner": scanner,
                "findings_count": len(findings),
                "app_id": app_id or None,
            }))
    except Exception:
        pass  # event bus is best-effort
    return {
        "status": "success",
        "org_id": org_id,
        "scanner": scanner,
        "findings_count": len(findings),
        "parse_time_ms": round(elapsed * 1000, 1),
        "app_id": app_id or None,
        "findings": _serialize_findings(findings[:100]),
        "total_findings": len(findings),
        "deduped_count": len(canonical_dicts),
        "duplicates_removed": dedup_summary["duplicate_count"],
        "promoted_to_issues": promoted_count,
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
        except (TypeError, AttributeError, ValueError, KeyError, UnicodeDecodeError):
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
                "secrets": ["gitleaks"],
                "cloud": ["prowler", "checkov"],
                "universal": ["sarif", "cyclonedx", "spdx", "vex"],
            },
            "total": 26,
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

def _get_db_ingest_stats() -> Dict[str, Any]:
    """Read real ingestion stats from the analytics database."""
    try:
        import sqlite3
        from pathlib import Path

        db_path = Path("data/analytics.db")
        if not db_path.exists():
            return None

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            # Total findings ingested
            cursor.execute("SELECT COUNT(*) as total FROM findings")
            total_findings = cursor.fetchone()[0]

            # Findings by source (scanner)
            cursor.execute(
                "SELECT source, COUNT(*) as count, MAX(created_at) as last_at "
                "FROM findings GROUP BY source ORDER BY count DESC"
            )
            by_source = {}
            last_ingest_at = None
            for row in cursor.fetchall():
                src = row[0] or "unknown"
                # Skip pure test entries from the counts
                if src == "test":
                    continue
                by_source[src] = {"findings": row[1]}
                if row[2] and (last_ingest_at is None or row[2] > last_ingest_at):
                    last_ingest_at = row[2]

            # Files processed: count distinct (source, created_at day) groups as proxy
            cursor.execute(
                "SELECT COUNT(DISTINCT source) as scanners FROM findings WHERE source != 'test'"
            )
            distinct_scanners = cursor.fetchone()[0]

            return {
                "total_findings_ingested": total_findings,
                "distinct_scanners": distinct_scanners,
                "by_source": by_source,
                "last_ingest_at": last_ingest_at,
            }
        finally:
            conn.close()
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.warning("Could not read analytics DB for ingest stats: %s", type(e).__name__)
        return None


@router.get("/stats")
async def ingestion_stats():
    """Return scanner ingestion statistics from the analytics database."""
    db_stats = _get_db_ingest_stats()
    if db_stats:
        return {
            "status": "ok",
            "total_findings_ingested": db_stats["total_findings_ingested"],
            "distinct_scanners": db_stats["distinct_scanners"],
            "by_source": db_stats["by_source"],
            "last_ingest_at": db_stats["last_ingest_at"],
            "in_session": {
                "files_processed": _ingest_stats["total_files_processed"],
                "findings_parsed": _ingest_stats["total_findings_parsed"],
                "errors": _ingest_stats["errors"],
                "note": "Per-process counters since last server start",
            },
        }
    return {
        "status": "ok",
        "total_findings_ingested": _ingest_stats["total_findings_parsed"],
        "by_source": _ingest_stats["by_scanner"],
        "last_ingest_at": _ingest_stats["last_ingest_at"],
        "in_session": {
            "files_processed": _ingest_stats["total_files_processed"],
            "findings_parsed": _ingest_stats["total_findings_parsed"],
            "errors": _ingest_stats["errors"],
        },
    }


@router.get("/health")
async def scanner_ingest_health():
    """Scanner ingest service health check."""
    db_stats = _get_db_ingest_stats()
    total = db_stats["total_findings_ingested"] if db_stats else _ingest_stats["total_findings_parsed"]
    last_at = db_stats["last_ingest_at"] if db_stats else _ingest_stats["last_ingest_at"]
    return {
        "status": "healthy",
        "engine": "scanner-ingest",
        "version": "1.0.0",
        "total_ingested": total,
        "last_ingest_at": last_at,
        "scanners_active": db_stats["distinct_scanners"] if db_stats else 0,
    }


@router.get("/status")
async def scanner_ingest_status():
    """Scanner ingest service status with real ingestion data."""
    db_stats = _get_db_ingest_stats()
    total = db_stats["total_findings_ingested"] if db_stats else _ingest_stats["total_findings_parsed"]
    last_at = db_stats["last_ingest_at"] if db_stats else _ingest_stats["last_ingest_at"]
    by_source = db_stats["by_source"] if db_stats else _ingest_stats["by_scanner"]
    parsers = _get_scanner_parsers()
    supported_count = len(parsers["SCANNER_NORMALIZERS"]) + 10 if parsers else 25
    return {
        "status": "healthy",
        "engine": "scanner-ingest",
        "version": "1.0.0",
        "total_ingested": total,
        "last_ingest_at": last_at,
        "scanners_active": db_stats["distinct_scanners"] if db_stats else 0,
        "supported_scanners": supported_count,
        "by_source": by_source,
        "ingestion_methods": ["upload", "webhook", "auto-detect"],
    }


# ═══════════════════════════════════════════════════════════════════════════
# Alias router: POST /api/v1/scanners/ingest
# The canonical prefix is /api/v1/scanner-ingest but the demo path and
# several UI calls use /api/v1/scanners/ingest (plural, with /ingest suffix).
# This second router provides that alias without changing the canonical routes.
# ═══════════════════════════════════════════════════════════════════════════

from pydantic import BaseModel as _BaseModel, Field as _Field  # noqa: E402, F401

scanners_alias_router = APIRouter(
    prefix="/api/v1/scanners",
    tags=["scanner-ingest"],
)

# _IngestBody — hardened with Pydantic Field constraints (security: input validation)
_scanner_type_field = _Field(None, min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")
_app_id_field = _Field("", max_length=255)
_org_id_field = _Field("default", min_length=1, max_length=128)
_findings_field = _Field(None, max_length=10000)


class _IngestBody(_BaseModel):
    scanner_type: Optional[str] = _scanner_type_field
    app_id: str = _app_id_field
    org_id: str = _org_id_field
    findings: Optional[List[Dict[str, Any]]] = _findings_field
    raw: Optional[Dict[str, Any]] = None


@scanners_alias_router.post(
    "/ingest",
    summary="Ingest scanner findings (JSON alias for POST /api/v1/scanner-ingest/upload)",
    description=(
        "Accepts a JSON body with pre-parsed scanner findings or raw scanner output. "
        "Alias for the canonical /api/v1/scanner-ingest endpoints — provided for "
        "demo-path compatibility and UI callers that POST JSON rather than multipart."
    ),
)
async def scanners_ingest_alias(body: _IngestBody, org_id: str = Depends(get_org_id)):
    """JSON-body ingest alias. Promotes findings to issues queue and records stats."""
    findings = body.findings or []
    scanner = body.scanner_type or "unknown"
    effective_org = body.org_id or org_id
    now = datetime.now(timezone.utc).isoformat()

    # Promote to SecurityFindingsEngine (same path as upload handler)
    promoted = _promote_findings_to_issues(findings, scanner, effective_org)

    # Update in-memory stats
    _ingest_stats["total_findings_parsed"] += len(findings)
    scanner_stats = _ingest_stats["by_scanner"].setdefault(scanner, {"files": 0, "findings": 0})
    if isinstance(scanner_stats, dict):
        scanner_stats["findings"] = scanner_stats.get("findings", 0) + len(findings)
    _ingest_stats["last_ingest_at"] = now

    return {
        "status": "ok",
        "scanner_type": scanner,
        "findings_received": len(findings),
        "findings_promoted": promoted,
        "org_id": effective_org,
        "ingested_at": now,
        "canonical_endpoint": "/api/v1/scanner-ingest/upload",
    }
