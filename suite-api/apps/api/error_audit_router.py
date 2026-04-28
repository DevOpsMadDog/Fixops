"""Error Handling Audit Router — ALDECI.

Static analysis endpoints that scan the codebase for poor exception handling
patterns and return structured findings.

Routes:
  GET /api/v1/error-audit/scan      — scan suite-core/ + suite-api/, return full report
  GET /api/v1/error-audit/report    — full categorized report (same as scan, cached)
  GET /api/v1/error-audit/critical  — only files with 5+ bare except handlers
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "error_audit_router: auth_deps not available, "
        "relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.error_handling_auditor import ErrorHandlingAuditor

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/error-audit",
    tags=["error-audit"],
    dependencies=_AUTH_DEP,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Resolve repo root relative to this file:
#   suite-api/apps/api/error_audit_router.py  →  ../../..  →  repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCAN_DIRS = [
    str(_REPO_ROOT / "suite-core"),
    str(_REPO_ROOT / "suite-api"),
]


def _build_auditor() -> ErrorHandlingAuditor:
    return ErrorHandlingAuditor(root_dir=str(_REPO_ROOT))


def _multi_dir_report() -> dict[str, Any]:
    """Scan suite-core/ and suite-api/ and merge results."""
    all_findings: list[dict[str, Any]] = []
    for scan_dir in _SCAN_DIRS:
        if Path(scan_dir).exists():
            auditor = _build_auditor()
            all_findings.extend(auditor.scan_directory(path=scan_dir))

    # Build combined report using a fresh auditor instance
    combined = _build_auditor()
    combined._findings = all_findings  # inject pre-scanned findings
    categorized = combined.categorize_findings(all_findings)

    total = len(all_findings)
    n_critical = len(categorized["by_severity"].get("critical", []))
    n_high = len(categorized["by_severity"].get("high", []))
    n_medium = len(categorized["by_severity"].get("medium", []))

    file_counts = {
        f: len(items) for f, items in categorized["by_file"].items()
    }
    top_offenders = [
        {"file": f, "count": c}
        for f, c in sorted(file_counts.items(), key=lambda x: -x[1])[:10]
    ]

    recommendations: list[str] = []
    if n_critical:
        recommendations.append(
            f"Fix {n_critical} bare `except:` clauses — they swallow "
            "KeyboardInterrupt and SystemExit."
        )
    if n_high:
        recommendations.append(
            f"Address {n_high} silently-swallowed or print-logged exceptions."
        )
    if n_medium:
        recommendations.append(
            f"Review {n_medium} handlers that log but never re-raise."
        )

    return {
        "summary": {
            "total": total,
            "critical": n_critical,
            "high": n_high,
            "medium": n_medium,
        },
        "top_offenders": top_offenders,
        "categorized": categorized,
        "recommendations": recommendations,
        "findings": all_findings,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/scan", summary="Scan for poor error handling patterns")
def scan() -> Dict[str, Any]:
    """Run a live scan of suite-core/ and suite-api/.

    Returns a full JSON report with summary counts, top offenders, and every
    individual finding grouped by severity.
    """
    try:
        return _multi_dir_report()
    except Exception as exc:
        logger.exception("error_audit_router: scan failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/report", summary="Full categorized error handling report")
def report() -> Dict[str, Any]:
    """Alias for /scan — returns the full audit report."""
    try:
        return _multi_dir_report()
    except Exception as exc:
        logger.exception("error_audit_router: report failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/critical", summary="Files with 5+ bare except handlers")
def critical_files() -> Dict[str, Any]:
    """Return only the files that have 5 or more bare ``except:`` handlers.

    These are the highest-priority targets for remediation.
    """
    try:
        all_findings: list[dict[str, Any]] = []
        for scan_dir in _SCAN_DIRS:
            if Path(scan_dir).exists():
                auditor = _build_auditor()
                all_findings.extend(auditor.scan_directory(path=scan_dir))

        combined = _build_auditor()
        combined._findings = all_findings
        critical = combined.get_critical_files()

        return {
            "critical_files": critical,
            "count": len(critical),
        }
    except Exception as exc:
        logger.exception("error_audit_router: critical lookup failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
