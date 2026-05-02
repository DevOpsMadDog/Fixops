"""AI Code Guardian API — /api/v1/guardian

Detect risks in AI-generated code. Apiiro Guardian Agent parity.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict

from core.ai_code_guardian import (
    RiskCategory,
    Severity,
    get_ai_code_guardian,
)
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/guardian", tags=["AI Code Guardian"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    code: str = Field(..., description="Source code to scan")
    filename: str = Field(default="unknown", description="Filename (used for language detection)")
    language: str = Field(default="auto", description="Language (auto-detect from filename if 'auto')")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan")
async def scan_code(req: ScanRequest) -> Dict[str, Any]:
    """Scan code for AI-generation indicators and security risks."""
    guardian = get_ai_code_guardian()
    result = guardian.scan_code(
        code=req.code,
        filename=req.filename,
        language=req.language,
    )
    return {
        "scan_id": result.scan_id,
        "filename": result.filename,
        "language": result.language,
        "scanned_at": result.scanned_at,
        "lines_scanned": result.lines_scanned,
        "ai_detection": asdict(result.ai_detection),
        "findings": [asdict(f) for f in result.findings],
        "risk_score": result.risk_score,
        "summary": result.summary,
    }


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str) -> Dict[str, Any]:
    """Retrieve a previous scan result."""
    guardian = get_ai_code_guardian()
    result = guardian.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return {
        "scan_id": result.scan_id,
        "filename": result.filename,
        "language": result.language,
        "scanned_at": result.scanned_at,
        "lines_scanned": result.lines_scanned,
        "ai_detection": asdict(result.ai_detection),
        "findings": [asdict(f) for f in result.findings],
        "risk_score": result.risk_score,
        "summary": result.summary,
    }


@router.get("/stats")
async def get_stats() -> Dict[str, Any]:
    """Get Guardian scanning statistics."""
    guardian = get_ai_code_guardian()
    return guardian.get_stats()


@router.get("/categories")
async def list_categories() -> Dict[str, Any]:
    """List all risk categories detected by Guardian."""
    return {
        "categories": [c.value for c in RiskCategory],
        "severities": [s.value for s in Severity],
    }


@router.get("/status")
async def status() -> Dict[str, Any]:
    """Guardian engine health/status."""
    guardian = get_ai_code_guardian()
    stats = guardian.get_stats()
    return {
        "status": "operational",
        "engine": "AICodeGuardian",
        "version": "1.0.0",
        "capabilities": [
            "ai_code_detection",
            "secret_scanning",
            "insecure_default_detection",
            "injection_sink_detection",
            "insecure_crypto_detection",
            "entropy_analysis",
            "structural_uniformity_analysis",
        ],
        **stats,
    }

