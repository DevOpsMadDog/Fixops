"""ALdeci SAST Router — Static Application Security Testing API.

Endpoints:
  POST /api/v1/sast/scan/code      — scan a single code snippet
  POST /api/v1/sast/scan/files     — scan multiple files
  GET  /api/v1/sast/rules          — list all SAST rules
  GET  /api/v1/sast/status         — engine status
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from core.sast_engine import SAST_RULES, get_sast_engine
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


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and injection."""
    import os

    # Strip directory components — only keep the basename
    safe = os.path.basename(filename)
    # Remove any null bytes or control characters
    safe = "".join(c for c in safe if c.isprintable() and c != "\x00")
    # Enforce length limit
    if len(safe) > _MAX_FILENAME_LENGTH:
        safe = safe[:_MAX_FILENAME_LENGTH]
    return safe or "input.txt"


def _persist_sast_findings(findings: list, app_id: str | None = None) -> int:
    """Persist SAST findings to AnalyticsDB so they appear in triage/risk.

    Returns the number of findings successfully persisted.
    """
    if not findings:
        return 0
    try:
        from core.analytics_db import AnalyticsDB
        from core.analytics_models import Finding, FindingSeverity, FindingStatus

        db = AnalyticsDB()
        persisted = 0
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
            persisted += 1
        return persisted
    except Exception:
        logger.exception("Failed to persist SAST findings to analytics DB")
        return 0


@router.post("/scan/code")
async def scan_code(req: ScanCodeRequest) -> Dict[str, Any]:
    """Scan a single code snippet for vulnerabilities."""
    if not req.code.strip():
        raise HTTPException(400, "Empty code provided")
    safe_filename = _sanitize_filename(req.filename)
    engine = get_sast_engine()
    result = engine.scan_code(req.code, safe_filename)
    result_dict = result.to_dict()
    # Persist findings to analytics DB for triage/risk pipeline
    persisted = _persist_sast_findings(result_dict.get("findings", []), app_id=req.app_id)
    result_dict["persisted_count"] = persisted
    return result_dict


@router.post("/scan/files")
async def scan_files(req: ScanFilesRequest) -> Dict[str, Any]:
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
    # Persist findings to analytics DB for triage/risk pipeline
    persisted = _persist_sast_findings(result_dict.get("findings", []))
    result_dict["persisted_count"] = persisted
    return result_dict


@router.get("/findings")
async def list_sast_findings(
    severity: str = None,
    limit: int = 100,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List SAST scan findings."""
    try:
        from core.analytics_db import AnalyticsDB
        db = AnalyticsDB()
        findings = db.list_findings(limit=limit)
        sast_findings = []
        for f in findings:
            src = getattr(f, 'source', '') or ''
            if 'sast' in src.lower() or 'static' in src.lower():
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                if severity and sev.lower() != severity.lower():
                    continue
                sast_findings.append({
                    'id': f.id,
                    'title': getattr(f, 'title', 'SAST Finding'),
                    'severity': sev,
                    'status': f.status.value if hasattr(f.status, 'value') else str(f.status),
                    'source': src,
                    'created_at': f.created_at.isoformat() if hasattr(f, 'created_at') and f.created_at else None,
                })
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
        sast_findings = []
    return {
        'findings': sast_findings,
        'total': len(sast_findings),
        'scanner': 'ALdeci SAST Engine',
    }


@router.get("/rules")
async def list_rules() -> List[Dict[str, Any]]:
    """List all SAST rules."""
    rules = []
    for r in SAST_RULES:
        rid, title, sev, cwe, pat, msg, fix, langs = r
        rules.append(
            {
                "rule_id": rid,
                "title": title,
                "severity": sev,
                "cwe_id": cwe,
                "message": msg,
                "fix_suggestion": fix,
                "languages": langs,
            }
        )
    return rules


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
