"""IDE Integration API router.

Provides inline SAST scanning endpoints for VS Code / JetBrains plugins:
- Scan a file or diff for security findings
- Get fix suggestions
- Session management (register, heartbeat, list, stats)
- Pattern catalogue

All endpoints require API key authentication.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy singleton — graceful degradation if core is unavailable
# ---------------------------------------------------------------------------

_integration = None


def _get_integration():
    global _integration
    if _integration is None:
        from core.ide_integration import IDEIntegration  # noqa: PLC0415
        db_path = os.getenv("ALDECI_IDE_DB", "")
        _integration = IDEIntegration(db_path=db_path or ":memory:")
    return _integration


def _ide_finding_cls():
    from core.ide_integration import IDEFinding  # noqa: PLC0415
    return IDEFinding

router = APIRouter(
    prefix="/api/v1/ide",
    tags=["ide"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ScanFileRequest(BaseModel):
    content: str
    file_path: str
    language: str = "python"


class ScanDiffRequest(BaseModel):
    diff_text: str


class GetFixRequest(BaseModel):
    file_path: str
    line_start: int
    line_end: int
    severity: str
    title: str
    description: str
    fix_suggestion: Optional[str] = None
    cwe_id: Optional[str] = None
    rule_id: str


class RegisterSessionRequest(BaseModel):
    user_email: str
    ide_type: str
    project_path: str
    org_id: str


class FindingsForFileRequest(BaseModel):
    content: str
    file_path: str
    language: str = "python"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/")
def get_ide_status() -> Dict[str, Any]:
    """IDE integration health and capability summary."""
    integration = _get_integration()
    patterns = integration.get_patterns()
    return {
        "status": "ok",
        "supported_languages": ["python", "typescript", "javascript"],
        "pattern_count": len(patterns),
        "endpoints": [
            "POST /scan/file",
            "POST /scan/diff",
            "POST /fix",
            "POST /sessions/register",
            "POST /sessions/{session_id}/heartbeat",
            "GET  /sessions",
            "GET  /stats",
            "GET  /patterns",
            "POST /findings/file",
            "POST /project/summary",
        ],
    }


@router.post("/scan/file")
def scan_file(request: ScanFileRequest) -> Dict[str, Any]:
    """Scan a file's content for SAST findings."""
    integration = _get_integration()
    findings = integration.scan_file(request.content, request.file_path, request.language)
    return {
        "file_path": request.file_path,
        "findings": [f.model_dump() for f in findings],
        "count": len(findings),
    }


@router.post("/scan/diff")
def scan_diff(request: ScanDiffRequest) -> Dict[str, Any]:
    """Scan a unified diff for SAST findings in added lines only."""
    integration = _get_integration()
    findings = integration.scan_diff(request.diff_text)
    return {
        "findings": [f.model_dump() for f in findings],
        "count": len(findings),
    }


@router.post("/fix")
def get_fix(request: GetFixRequest) -> Dict[str, Any]:
    """Get a fix suggestion for a specific finding."""
    integration = _get_integration()
    finding = _ide_finding_cls()(
        file_path=request.file_path,
        line_start=request.line_start,
        line_end=request.line_end,
        severity=request.severity,
        title=request.title,
        description=request.description,
        fix_suggestion=request.fix_suggestion,
        cwe_id=request.cwe_id,
        rule_id=request.rule_id,
    )
    return integration.get_fix_for_finding(finding)


@router.post("/sessions/register")
def register_session(request: RegisterSessionRequest) -> Dict[str, Any]:
    """Register a new IDE session."""
    integration = _get_integration()
    session = integration.register_session(
        user_email=request.user_email,
        ide_type=request.ide_type,
        project_path=request.project_path,
        org_id=request.org_id,
    )
    return session.model_dump()


@router.post("/sessions/{session_id}/heartbeat")
def heartbeat(session_id: str) -> Dict[str, Any]:
    """Send a heartbeat to keep a session active."""
    integration = _get_integration()
    integration.heartbeat(session_id)
    return {"session_id": session_id, "status": "ok"}


@router.get("/sessions")
def get_active_sessions(
    org_id: str = Query(..., description="Organisation ID to filter sessions"),
) -> Dict[str, Any]:
    """List active IDE sessions for an organisation."""
    integration = _get_integration()
    sessions = integration.get_active_sessions(org_id)
    return {"sessions": sessions, "count": len(sessions)}


@router.get("/stats")
def get_stats(
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    """Get aggregate IDE usage statistics for an organisation."""
    integration = _get_integration()
    return integration.get_ide_stats(org_id)


@router.get("/patterns")
def get_patterns() -> Dict[str, Any]:
    """List all supported SAST detection patterns."""
    integration = _get_integration()
    patterns = integration.get_patterns()
    return {"patterns": patterns, "count": len(patterns)}


@router.post("/findings/file")
def findings_for_file(request: FindingsForFileRequest) -> Dict[str, Any]:
    """Return all findings for a given file (alias for scan/file with richer metadata)."""
    integration = _get_integration()
    findings = integration.scan_file(request.content, request.file_path, request.language)
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")
    return {
        "file_path": request.file_path,
        "findings": [f.model_dump() for f in findings],
        "count": len(findings),
        "severity_summary": {"high": high, "medium": medium, "low": low},
    }


@router.post("/project/summary")
def project_summary(
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    """Return a project-level summary combining session stats and pattern catalogue."""
    integration = _get_integration()
    stats = integration.get_ide_stats(org_id)
    patterns = integration.get_patterns()
    return {
        "org_id": org_id,
        "stats": stats,
        "supported_patterns": len(patterns),
        "pattern_severities": {
            "high": sum(1 for p in patterns if p["severity"] == "HIGH"),
            "medium": sum(1 for p in patterns if p["severity"] == "MEDIUM"),
            "low": sum(1 for p in patterns if p["severity"] == "LOW"),
        },
    }
