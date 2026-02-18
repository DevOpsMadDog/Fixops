"""ALdeci SAST Router — Static Application Security Testing API.

Endpoints:
  POST /api/v1/sast/scan/code      — scan a single code snippet
  POST /api/v1/sast/scan/files     — scan multiple files
  GET  /api/v1/sast/rules          — list all SAST rules
  GET  /api/v1/sast/status         — engine status
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.sast_engine import SAST_RULES, get_sast_engine

router = APIRouter(prefix="/api/v1/sast", tags=["SAST"])


class ScanCodeRequest(BaseModel):
    code: str = Field(..., description="Source code to scan")
    filename: str = Field("input.py", description="Filename for language detection")


class ScanFilesRequest(BaseModel):
    files: Dict[str, str] = Field(..., description="Map of filename → code content")


@router.post("/scan/code")
async def scan_code(req: ScanCodeRequest) -> Dict[str, Any]:
    """Scan a single code snippet for vulnerabilities."""
    engine = get_sast_engine()
    result = engine.scan_code(req.code, req.filename)
    return result.to_dict()


@router.post("/scan/files")
async def scan_files(req: ScanFilesRequest) -> Dict[str, Any]:
    """Scan multiple files for vulnerabilities."""
    if not req.files:
        raise HTTPException(400, "No files provided")
    engine = get_sast_engine()
    result = engine.scan_files(req.files)
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
