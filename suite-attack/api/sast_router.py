"""ALdeci SAST Router — Static Application Security Testing API.

Endpoints:
  POST /api/v1/sast/scan/code      — scan a single code snippet
  POST /api/v1/sast/scan/files     — scan multiple files
  GET  /api/v1/sast/rules          — list all SAST rules
  GET  /api/v1/sast/status         — engine status
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.sast_engine import SAST_RULES, get_sast_engine
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

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


@router.post("/scan/code")
async def scan_code(req: ScanCodeRequest) -> Dict[str, Any]:
    """Scan a single code snippet for vulnerabilities."""
    if not req.code.strip():
        raise HTTPException(400, "Empty code provided")
    safe_filename = _sanitize_filename(req.filename)
    engine = get_sast_engine()
    result = engine.scan_code(req.code, safe_filename)
    return result.to_dict()


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
    return result.to_dict()


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
