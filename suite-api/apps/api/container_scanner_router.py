"""Container Security Scanner API router.

6 endpoints under /api/v1/containers/* for Dockerfile security analysis,
scan history, statistics, and available checks catalogue.

All endpoints require API key authentication.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/containers",
    tags=["container-security"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Singleton scanner
# ---------------------------------------------------------------------------

_scanner = None


def _get_scanner():
    global _scanner
    if _scanner is None:
        from core.container_scanner import ContainerSecurityScanner
        db_path = os.getenv("ALDECI_CONTAINER_SCANNER_DB", "")
        _scanner = ContainerSecurityScanner(db_path=db_path or None)
    return _scanner


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScanDockerfileRequest(BaseModel):
    """Request body for scanning a Dockerfile."""

    content: str = Field(..., description="Raw Dockerfile content to analyse")
    file_path: str = Field("Dockerfile", description="Logical path for reporting")
    org_id: str = Field("default", description="Organisation identifier for history scoping")


class FindingSummary(BaseModel):
    id: str
    check_id: str
    title: str
    severity: str
    category: str
    line_number: Optional[int] = None
    remediation: str


class ScanResponse(BaseModel):
    id: str
    file_path: str
    base_image: str
    user: str
    exposed_ports: List[int]
    total_layers: int
    score: float
    org_id: str
    findings_count: int
    findings: List[FindingSummary]
    scanned_at: str


class CheckInfo(BaseModel):
    id: str
    category: str
    severity: str
    title: str


class StatsResponse(BaseModel):
    total_scans: int
    avg_score: float
    total_findings: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=ScanResponse, summary="Scan a Dockerfile for security issues")
def scan_dockerfile(body: ScanDockerfileRequest) -> ScanResponse:
    """Analyse a Dockerfile and return all security findings with a 0-100 score."""
    if not body.content.strip():
        raise HTTPException(status_code=400, detail="content must not be empty")

    scanner = _get_scanner()
    try:
        analysis = scanner.scan_dockerfile(
            content=body.content,
            file_path=body.file_path,
            org_id=body.org_id,
        )
    except Exception as exc:
        logger.exception("Dockerfile scan failed")
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    return ScanResponse(
        id=analysis.id,
        file_path=analysis.file_path,
        base_image=analysis.base_image,
        user=analysis.user,
        exposed_ports=analysis.exposed_ports,
        total_layers=analysis.total_layers,
        score=analysis.score,
        org_id=analysis.org_id,
        findings_count=len(analysis.findings),
        findings=[
            FindingSummary(
                id=f.id,
                check_id=f.check_id,
                title=f.title,
                severity=f.severity.value,
                category=f.category.value,
                line_number=f.line_number,
                remediation=f.remediation,
            )
            for f in analysis.findings
        ],
        scanned_at=analysis.scanned_at.isoformat(),
    )


@router.get("/checks", response_model=List[CheckInfo], summary="List all available security checks")
def list_checks() -> List[CheckInfo]:
    """Return the catalogue of all 20+ built-in Dockerfile security checks."""
    scanner = _get_scanner()
    checks = scanner.get_checks()
    return [
        CheckInfo(
            id=c["id"],
            category=c["category"].value if hasattr(c["category"], "value") else str(c["category"]),
            severity=c["severity"].value if hasattr(c["severity"], "value") else str(c["severity"]),
            title=c["title"],
        )
        for c in checks
    ]


@router.get("/history", response_model=List[ScanResponse], summary="Scan history for an org")
def get_history(
    org_id: str = Query("default", description="Organisation ID"),
    limit: int = Query(50, ge=1, le=500, description="Maximum results to return"),
) -> List[ScanResponse]:
    """Return past Dockerfile analyses for *org_id*, most-recent first."""
    scanner = _get_scanner()
    history = scanner.get_scan_history(org_id=org_id)
    result = []
    for analysis in history[:limit]:
        result.append(ScanResponse(
            id=analysis.id,
            file_path=analysis.file_path,
            base_image=analysis.base_image,
            user=analysis.user,
            exposed_ports=analysis.exposed_ports,
            total_layers=analysis.total_layers,
            score=analysis.score,
            org_id=analysis.org_id,
            findings_count=len(analysis.findings),
            findings=[
                FindingSummary(
                    id=f.id,
                    check_id=f.check_id,
                    title=f.title,
                    severity=f.severity.value,
                    category=f.category.value,
                    line_number=f.line_number,
                    remediation=f.remediation,
                )
                for f in analysis.findings
            ],
            scanned_at=analysis.scanned_at.isoformat(),
        ))
    return result


@router.get("/stats", response_model=StatsResponse, summary="Aggregate statistics for an org")
def get_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> StatsResponse:
    """Return aggregate scan statistics (counts, average score, breakdown by severity/category)."""
    scanner = _get_scanner()
    stats = scanner.get_scanner_stats(org_id=org_id)
    return StatsResponse(**stats)


@router.get("/score", summary="Quick security score for a Dockerfile")
def quick_score(
    content: str = Query(..., description="Raw Dockerfile content"),
    file_path: str = Query("Dockerfile"),
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Scan a Dockerfile (via query param) and return only the score and finding counts."""
    if not content.strip():
        raise HTTPException(status_code=400, detail="content must not be empty")
    scanner = _get_scanner()
    try:
        analysis = scanner.scan_dockerfile(content=content, file_path=file_path, org_id=org_id)
    except Exception as exc:
        logger.exception("Quick score scan failed")
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    by_severity: Dict[str, int] = {}
    for f in analysis.findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    return {
        "score": analysis.score,
        "findings_count": len(analysis.findings),
        "by_severity": by_severity,
        "base_image": analysis.base_image,
        "file_path": analysis.file_path,
    }


@router.delete("/history", summary="Clear scan history for an org")
def clear_history(
    org_id: str = Query("default", description="Organisation ID to clear"),
) -> Dict[str, Any]:
    """Delete all scan history for *org_id*. Irreversible."""
    import sqlite3

    scanner = _get_scanner()
    try:
        conn = sqlite3.connect(scanner._db_path)
        cur = conn.execute(
            "DELETE FROM container_analyses WHERE org_id = ?", (org_id,)
        )
        deleted = cur.rowcount
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.exception("Clear history failed")
        raise HTTPException(status_code=500, detail=f"Clear failed: {exc}") from exc

    return {"deleted": deleted, "org_id": org_id}
