"""ALdeci SAST Router — Static Application Security Testing API.

Endpoints:
  POST /api/v1/sast/scan            — trigger SAST scan (repo path or file list)
  POST /api/v1/sast/scan/code       — scan a single code snippet
  POST /api/v1/sast/scan/files      — scan multiple files
  GET  /api/v1/sast/findings        — SAST findings with severity and CWE filters
  GET  /api/v1/sast/rules           — active rules by language
  POST /api/v1/sast/rules/custom    — add custom Semgrep-format YAML rule
  GET  /api/v1/sast/languages       — supported languages with rule counts
  GET  /api/v1/sast/summary         — scan summary (findings by language, severity, CWE)
  GET  /api/v1/sast/status          — engine status / health check
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.sast_engine import SAST_RULES, _EXTRA_RULES, get_sast_engine, parse_semgrep_yaml, SASTEngine
from fastapi import APIRouter, HTTPException, Depends
from apps.api.dependencies import get_org_id
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Severity mapping from SAST engine values to analytics DB enum values
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}

router = APIRouter(prefix="/api/v1/sast", tags=["SAST"])


_MAX_CODE_LENGTH = 500_000  # 500KB max per code snippet
_MAX_FILES = 50  # Max files per batch scan
_MAX_FILENAME_LENGTH = 255


class ScanCodeRequest(BaseModel):
    code: str = Field(..., description="Source code to scan", max_length=_MAX_CODE_LENGTH)
    filename: str = Field(
        "input.py",
        description="Filename for language detection",
        max_length=_MAX_FILENAME_LENGTH,
    )
    language: str = Field(None, description="Language hint (optional)")
    app_id: str = Field(None, description="Application ID (optional)", max_length=128)


class ScanFilesRequest(BaseModel):
    files: Dict[str, str] = Field(..., description="Map of filename → code content")


class ScanRequest(BaseModel):
    """Unified scan request — provide either repo_path or file_list."""
    repo_path: Optional[str] = Field(
        None,
        description="Absolute path to the repository root to scan",
        max_length=1024,
    )
    file_list: Optional[List[str]] = Field(
        None,
        description="Explicit list of file paths to scan",
        max_length=_MAX_FILES,
    )
    incremental: bool = Field(
        False, description="Skip files whose content hash is unchanged since last scan"
    )


class CustomRuleRequest(BaseModel):
    yaml_text: str = Field(
        ...,
        description="Semgrep-format YAML rule(s) to add",
        max_length=100_000,
    )


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename while preserving safe relative paths for scanner context."""
    normalized = filename.replace("\\", "/")
    cleaned = "".join(c for c in normalized if c.isprintable() and c != "\x00")

    safe_parts: List[str] = []
    for part in cleaned.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            continue
        safe_part = "".join(
            ch if ch.isalnum() or ch in "._-" else "_" for ch in part
        )
        if safe_part:
            safe_parts.append(safe_part)

    safe = "/".join(safe_parts)
    if len(safe) > _MAX_FILENAME_LENGTH:
        safe = safe[-_MAX_FILENAME_LENGTH:]
    return safe or "input.txt"


_SEVERITY_TO_CVSS = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0}


def _persist_sast_findings(
    findings: list,
    app_id: str | None = None,
    org_id: str | None = None,
    scan_id: str | None = None,
) -> int:
    """Persist SAST findings to BOTH stores so the customer dashboard populates.

    Writes to:
    1. ``AnalyticsDB`` (existing) — feeds the analytics/triage pipeline.
    2. ``SecurityFindingsEngine.record_finding`` (NEW, GAP from onboarding bug #4)
       — populates the primary customer-facing dashboard at
       ``/api/v1/security-findings/findings``.

    Without (2) the Brain Pipeline reports `completed` but the UI shows empty.
    Returns the number of findings successfully written to BOTH stores.
    """
    if not findings:
        return 0

    persisted_analytics = 0
    persisted_findings_engine = 0

    # 1. AnalyticsDB write (existing path)
    try:
        from core.analytics_db import AnalyticsDB
        from core.analytics_models import Finding, FindingSeverity, FindingStatus

        db = AnalyticsDB()
        for f in findings:
            sev_val = f.get("severity", "medium").lower()
            try:
                severity = FindingSeverity(sev_val)
            except ValueError:
                severity = FindingSeverity.MEDIUM
            finding = Finding(
                id=f.get("finding_id", str(uuid.uuid4())),
                application_id=app_id,
                service_id=None,
                rule_id=f.get("rule_id", "SAST-UNKNOWN"),
                severity=severity,
                status=FindingStatus.OPEN,
                title=f.get("title", "SAST Finding"),
                description=f.get("message", f.get("title", "")),
                source="sast_scanner",
                cve_id=f.get("cwe_id"),
                cvss_score=None,
                epss_score=None,
                exploitable=False,
                metadata={
                    "file_path": f.get("file_path", ""),
                    "line_number": f.get("line_number", 0),
                    "column": f.get("column", 0),
                    "snippet": f.get("snippet", ""),
                    "language": f.get("language", ""),
                    "fix_suggestion": f.get("fix_suggestion", ""),
                    "confidence": f.get("confidence", 0.0),
                },
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.create_finding(finding)
            persisted_analytics += 1
    except (OSError, ValueError, KeyError, RuntimeError):
        logger.exception("Failed to persist SAST findings to analytics DB")
        # fall through to SecurityFindingsEngine — partial persistence > nothing

    # 2. SecurityFindingsEngine write (NEW — primary customer dashboard)
    if org_id:
        try:
            from core.security_findings_engine import SecurityFindingsEngine
            sfe = SecurityFindingsEngine()
            for f in findings:
                sev = (f.get("severity") or "medium").lower()
                cvss = _SEVERITY_TO_CVSS.get(sev, 5.0)
                file_path = f.get("file_path") or "unknown"
                line = f.get("line_number") or 0
                # Stable correlation key so re-scans dedup + lifecycle works
                corr_key = f"sast|{f.get('rule_id', 'SAST-UNKNOWN')}|{file_path}:{line}"
                sfe.record_finding(
                    org_id=org_id,
                    title=f.get("title") or f.get("message") or "SAST Finding",
                    finding_type="sast",
                    source_tool="sast_scanner",
                    severity=sev,
                    cvss_score=cvss,
                    asset_id=file_path,
                    asset_type="source_file",
                    description=f.get("message", f.get("title", "")),
                    remediation=f.get("fix_suggestion", ""),
                    correlation_key=corr_key,
                    scan_id=scan_id,
                )
                persisted_findings_engine += 1
        except (OSError, ValueError, KeyError, RuntimeError):
            logger.exception(
                "Failed to mirror SAST findings to SecurityFindingsEngine "
                "(dashboard will show empty for org_id=%s)",
                org_id,
            )

    if persisted_analytics == 0 and persisted_findings_engine == 0:
        return -1  # Distinguish error from zero findings
    return max(persisted_analytics, persisted_findings_engine)


@router.post("/scan")
async def trigger_scan(req: ScanRequest, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Trigger a SAST scan by repo path or explicit file list.

    - Supply ``repo_path`` to scan all supported files under that directory.
    - Supply ``file_list`` to scan specific files (must be absolute paths).
    - Set ``incremental=true`` to skip files unchanged since last scan.
    """
    import os

    engine = get_sast_engine()

    if req.repo_path is None and req.file_list is None:
        raise HTTPException(400, "Provide repo_path or file_list")

    if req.repo_path is not None:
        # Security: repo_path must be an existing directory
        safe_path = os.path.realpath(req.repo_path)
        if not os.path.isdir(safe_path):
            raise HTTPException(400, f"repo_path is not a valid directory: {req.repo_path}")
        result = engine.scan_path(safe_path, incremental=req.incremental)
    else:
        # file_list mode: read each file and scan
        file_contents: Dict[str, str] = {}
        for fp in (req.file_list or []):
            safe_fp = os.path.realpath(fp)
            if not os.path.isfile(safe_fp):
                continue
            try:
                with open(safe_fp, encoding="utf-8", errors="replace") as fh:
                    content = fh.read(engine.MAX_CODE_SIZE)
                file_contents[safe_fp] = content
            except OSError:
                continue
        if not file_contents:
            raise HTTPException(400, "No readable files found in file_list")
        result = engine.scan_files(file_contents, incremental=req.incremental)

    result_dict = result.to_dict()
    persisted = _persist_sast_findings(
        result_dict.get("findings", []),
        org_id=org_id,
        scan_id=result_dict.get("scan_id"),
    )
    result_dict["persisted_count"] = persisted
    # TrustGraph explicit indexing (fire-and-forget)
    try:
        from core.trustgraph_event_bus import EVENT_FINDING_CREATED, get_event_bus as _get_eb
        _bus = _get_eb()
        if _bus and _bus.enabled:
            import asyncio as _asyncio
            _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                "finding_id": f"sast-scan-{result_dict.get('total_findings', 0)}",
                "type": "sast_finding", "severity": "medium",
                "source": "sast_router", "data": result_dict,
            }))
    except Exception:
        pass
    return result_dict


@router.get("/languages")
async def list_languages() -> Dict[str, Any]:
    """Return supported languages with rule counts and file extensions."""
    langs = SASTEngine.get_supported_languages()
    return {
        "languages": langs,
        "total_languages": len(langs),
    }


@router.get("/summary")
async def scan_summary(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return summary of the most recent scan: findings by language, severity, CWE."""
    engine = get_sast_engine()
    summary = engine.get_summary()
    return summary


@router.post("/rules/custom")
async def add_custom_rule(req: CustomRuleRequest) -> Dict[str, Any]:
    """Add one or more custom Semgrep-format YAML rules to the engine."""
    if not req.yaml_text.strip():
        raise HTTPException(400, "Empty yaml_text provided")
    engine = get_sast_engine()
    try:
        added = engine.add_semgrep_rules(req.yaml_text)
    except Exception as exc:
        logger.exception("Failed to parse custom Semgrep rules")
        raise HTTPException(400, f"Failed to parse YAML rules: {exc}") from exc
    return {
        "added": len(added),
        "rules": [r.to_dict() for r in added],
    }


@router.post("/scan/code")
async def scan_code(req: ScanCodeRequest, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Scan a single code snippet for vulnerabilities."""
    if not req.code.strip():
        raise HTTPException(400, "Empty code provided")
    safe_filename = _sanitize_filename(req.filename)
    engine = get_sast_engine()
    result = engine.scan_code(req.code, safe_filename)
    result_dict = result.to_dict()
    # Persist findings to analytics DB for triage/risk pipeline + customer dashboard
    persisted = _persist_sast_findings(
        result_dict.get("findings", []),
        app_id=req.app_id,
        org_id=org_id,
        scan_id=result_dict.get("scan_id"),
    )
    result_dict["persisted_count"] = persisted
    # TrustGraph explicit indexing (fire-and-forget)
    try:
        from core.trustgraph_event_bus import EVENT_FINDING_CREATED, get_event_bus as _get_eb
        _bus = _get_eb()
        if _bus and _bus.enabled:
            import asyncio as _asyncio
            _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                "finding_id": f"sast-code-{req.filename}",
                "type": "sast_finding", "severity": "medium",
                "source": "sast_router", "data": result_dict,
            }))
    except Exception:
        pass
    return result_dict


@router.post("/scan/files")
async def scan_files(req: ScanFilesRequest, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Scan multiple files for vulnerabilities."""
    if not req.files:
        raise HTTPException(400, "No files provided")
    if len(req.files) > _MAX_FILES:
        raise HTTPException(
            400, f"Too many files: {len(req.files)} (max {_MAX_FILES})"
        )
    # Sanitize all filenames and enforce size limits
    sanitized: Dict[str, str] = {}
    for fname, content in req.files.items():
        if len(content) > _MAX_CODE_LENGTH:
            raise HTTPException(
                400,
                f"File '{fname}' exceeds max size ({len(content)} > {_MAX_CODE_LENGTH})",
            )
        sanitized[_sanitize_filename(fname)] = content
    engine = get_sast_engine()
    result = engine.scan_files(sanitized)
    result_dict = result.to_dict()
    # Persist findings to analytics DB for triage/risk pipeline + customer dashboard
    persisted = _persist_sast_findings(
        result_dict.get("findings", []),
        org_id=org_id,
        scan_id=result_dict.get("scan_id"),
    )
    result_dict["persisted_count"] = persisted
    # TrustGraph explicit indexing (fire-and-forget)
    try:
        from core.trustgraph_event_bus import EVENT_FINDING_CREATED, get_event_bus as _get_eb
        _bus = _get_eb()
        if _bus and _bus.enabled:
            import asyncio as _asyncio
            _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                "finding_id": f"sast-files-{len(sanitized)}",
                "type": "sast_finding", "severity": "medium",
                "source": "sast_router", "data": result_dict,
            }))
    except Exception:
        pass
    return result_dict


@router.get("/findings")
async def list_sast_findings(
    severity: str = None,
    cwe: str = None,
    language: str = None,
    limit: int = 100,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List SAST findings from the most recent scan, with optional filters.

    Query parameters:
    - ``severity``: Filter by severity (critical/high/medium/low/info)
    - ``cwe``: Filter by CWE ID (e.g. CWE-89)
    - ``language``: Filter by language (e.g. python, javascript)
    - ``limit``: Maximum number of results (default 100)
    """
    engine = get_sast_engine()
    findings = engine.get_all_findings(severity=severity, cwe=cwe, language=language)
    findings = findings[:limit]
    return {
        "findings": findings,
        "total": len(findings),
        "scanner": "ALdeci SAST Engine",
        "filters": {"severity": severity, "cwe": cwe, "language": language},
    }


@router.get("/rules")
async def list_rules(language: str = None) -> Dict[str, Any]:
    """List active SAST rules, optionally filtered by language.

    Query parameters:
    - ``language``: Return only rules that apply to this language
      (e.g. python, javascript, typescript, go, java, c, cpp, rust, ruby, php)
    """
    all_rules = list(SAST_RULES) + list(_EXTRA_RULES)
    # Also include any custom Semgrep rules
    engine = get_sast_engine()
    custom_rules = engine.get_custom_rules()

    rules = []
    for r in all_rules:
        rid, title, sev, cwe, pat, msg, fix, langs = r
        if language and language.lower() not in langs:
            continue
        rules.append({
            "rule_id": rid,
            "title": title,
            "severity": sev,
            "cwe_id": cwe,
            "message": msg,
            "fix_suggestion": fix,
            "languages": langs,
            "source": "builtin",
        })
    for cr in custom_rules:
        if language and language.lower() not in cr.languages:
            continue
        rules.append({
            "rule_id": cr.rule_id,
            "title": cr.rule_id,
            "severity": cr.severity,
            "cwe_id": cr.cwe or "CWE-0",
            "message": cr.message,
            "fix_suggestion": cr.fix or "",
            "languages": cr.languages,
            "source": "custom",
        })

    return {
        "rules": rules,
        "total": len(rules),
        "filter": {"language": language},
    }


@router.get("/status")
async def sast_status() -> Dict[str, Any]:
    """SAST engine status."""
    return {
        "status": "healthy",
        "engine": "ALdeci SAST Engine",
        "rules_count": len(SAST_RULES),
        "languages": ["python", "javascript", "java", "go", "ruby", "php", "csharp"],
        "capabilities": ["pattern_matching", "taint_analysis", "cwe_mapping"],
    }


@router.get("/health")
async def sast_health() -> Dict[str, Any]:
    """SAST engine health check (alias for /status)."""
    return await sast_status()
