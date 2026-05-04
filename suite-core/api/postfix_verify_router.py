"""
FixOps MPTE Post-Fix Verification Router.

Provides the critical "Find → Fix → VERIFY" loop that differentiates FixOps
from competitors like Snyk Agent Fix and Aikido AutoFix.

After AutoFix generates a patch this router re-runs:
  - Static pattern analysis (regex + AST)
  - Regression / new-CWE detection
  - Dependency safety check
  - MPTE exploit re-test (does the exploit still succeed?)
  - Code style preservation check
  - Test coverage impact estimate

Endpoints:
  POST /api/v1/verify/fix              — Verify a single fix
  POST /api/v1/verify/bulk             — Verify multiple fixes in batch
  POST /api/v1/verify/regression       — Regression-only check
  POST /api/v1/verify/mpte-retest      — MPTE exploit re-run only
  GET  /api/v1/verify/history          — Verification history
  GET  /api/v1/verify/stats            — Verification statistics
  GET  /api/v1/verify/supported-languages — Supported languages
  GET  /api/v1/verify/health           — Health check

Auth: X-API-Key header (same pattern as autofix_router).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/verify", tags=["Post-Fix Verification"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class VerifyFixRequest(BaseModel):
    """Request body for POST /api/v1/verify/fix.

    Accepts the finding metadata, the original vulnerable code, and the
    proposed fixed code.  language is required; all other fields have
    sensible defaults so callers can omit optional context.
    """

    finding_id: str = Field(
        default="",
        description="Identifier of the original finding (e.g. FIND-0042)",
    )
    finding_type: str = Field(
        default="unknown",
        description=(
            "Vulnerability category: sql_injection | xss | buffer_overflow | "
            "path_traversal | command_injection | deserialization | ssrf | "
            "open_redirect | xxe | ldap_injection | xpath_injection | ..."
        ),
    )
    severity: str = Field(
        default="high",
        description="Finding severity: critical | high | medium | low",
    )
    original_code: str = Field(
        ...,
        description="The vulnerable code before the fix was applied",
        max_length=500_000,
    )
    fixed_code: str = Field(
        ...,
        description="The proposed fixed code to verify",
        max_length=500_000,
    )
    language: str = Field(
        ...,
        description=(
            "Source language: python | javascript | typescript | java | "
            "go | c | csharp | ruby | php | rust"
        ),
    )
    file_path: Optional[str] = Field(
        None,
        description="Optional file path for additional context",
        max_length=4096,
    )
    context_code: Optional[str] = Field(
        None,
        description="Optional surrounding code for richer analysis",
        max_length=500_000,
    )
    dep_changes: Optional[Dict[str, str]] = Field(
        None,
        description="Optional dependency changes {package: new_version} introduced by the fix",
    )

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low"}
        v = v.lower().strip()
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v

    @field_validator("language")
    @classmethod
    def _normalise_language(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator("finding_type")
    @classmethod
    def _normalise_finding_type(cls, v: str) -> str:
        return v.lower().strip().replace("-", "_").replace(" ", "_")


class BulkVerifyRequest(BaseModel):
    """Request body for POST /api/v1/verify/bulk.

    Up to 20 fix verifications in a single request.
    """

    fixes: List[VerifyFixRequest] = Field(
        ...,
        description="List of fix verification requests (max 20)",
        min_length=1,
        max_length=20,
    )
    fail_fast: bool = Field(
        False,
        description="Stop on first failed verification",
    )


class RegressionCheckRequest(BaseModel):
    """Request body for POST /api/v1/verify/regression.

    Runs only the regression-detection suite (Suite 2) without the
    full MPTE re-test or dependency check.
    """

    original_code: str = Field(..., max_length=500_000)
    fixed_code: str = Field(..., max_length=500_000)
    language: str = Field(...)
    finding_id: str = Field(default="")

    @field_validator("language")
    @classmethod
    def _normalise(cls, v: str) -> str:
        return v.lower().strip()


class MPTERetestRequest(BaseModel):
    """Request body for POST /api/v1/verify/mpte-retest.

    Re-runs only the MPTE exploit simulation against the fixed code.
    """

    original_code: str = Field(..., max_length=500_000)
    fixed_code: str = Field(..., max_length=500_000)
    language: str = Field(...)
    finding_type: str = Field(...)
    finding_id: str = Field(default="")

    @field_validator("language")
    @classmethod
    def _normalise_lang(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator("finding_type")
    @classmethod
    def _normalise_type(cls, v: str) -> str:
        return v.lower().strip().replace("-", "_").replace(" ", "_")


# ---------------------------------------------------------------------------
# Engine accessor
# ---------------------------------------------------------------------------


def _get_engine():
    """Return the module-level PostFixVerifier singleton.

    Lazy-imported to avoid circular imports at module load time.
    """
    from core.postfix_verifier import get_postfix_verifier

    return get_postfix_verifier()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/fix", summary="Verify a single post-fix")
async def verify_fix(req: VerifyFixRequest) -> Dict[str, Any]:
    """
    Run the full MPTE post-fix verification suite against a proposed fix.

    Performs six verification suites:
    1. **Static analysis** — regex + AST pattern removal check
    2. **Regression check** — new CWE / anti-pattern detection
    3. **Dependency safety** — version range validation
    4. **MPTE re-scan** — simulated exploit re-run
    5. **Style preservation** — indentation + naming convention check
    6. **Test coverage** — test density impact estimate

    Returns a `VerificationReport` with:
    - `verified` (bool) — did the fix pass all checks?
    - `confidence` (float 0–1) — aggregate confidence score
    - `mpte_retest_result` — exploit_blocked / exploit_still_possible / inconclusive
    - `safe_to_deploy` — enterprise deployment recommendation
    - `detailed_checks` — per-check pass/fail with explanations
    """
    engine = _get_engine()
    try:
        report = engine.verify(
            finding_id=req.finding_id or f"FIND-{hash(req.original_code) % 10000:04d}",
            finding_type=req.finding_type,
            severity=req.severity,
            original_code=req.original_code,
            fixed_code=req.fixed_code,
            language=req.language,
            file_path=req.file_path,
            context_code=req.context_code,
            dep_changes=req.dep_changes,
        )
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("postfix_verifier error: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail=f"Verification error: {type(exc).__name__}") from exc

    return {
        "status": "ok",
        "report": report.to_dict(),
    }


@router.post("/bulk", summary="Batch-verify multiple fixes")
async def verify_bulk(req: BulkVerifyRequest) -> Dict[str, Any]:
    """
    Run post-fix verification for up to 20 fixes in a single request.

    Each fix is verified independently.  If `fail_fast` is true the batch
    stops at the first failed verification.

    Returns an array of VerificationReport objects plus aggregate summary.
    """
    engine = _get_engine()
    reports = []
    total_verified = 0
    total_safe = 0
    failed_at: Optional[int] = None

    for idx, fix_req in enumerate(req.fixes[:20]):
        try:
            report = engine.verify(
                finding_id=fix_req.finding_id or f"BULK-{idx:03d}",
                finding_type=fix_req.finding_type,
                severity=fix_req.severity,
                original_code=fix_req.original_code,
                fixed_code=fix_req.fixed_code,
                language=fix_req.language,
                file_path=fix_req.file_path,
                context_code=fix_req.context_code,
                dep_changes=fix_req.dep_changes,
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("bulk verify item %d error: %s", idx, type(exc).__name__)
            reports.append({
                "index": idx,
                "error": type(exc).__name__,
                "finding_id": fix_req.finding_id,
            })
            continue

        r_dict = report.to_dict()
        r_dict["index"] = idx
        reports.append(r_dict)

        if report.verified:
            total_verified += 1
        if report.safe_to_deploy:
            total_safe += 1

        if req.fail_fast and not report.verified:
            failed_at = idx
            break

    return {
        "status": "ok",
        "count": len(reports),
        "total_verified": total_verified,
        "total_safe_to_deploy": total_safe,
        "failed_at_index": failed_at,
        "reports": reports,
    }


@router.post("/regression", summary="Check fix for regression patterns only")
async def check_regression(req: RegressionCheckRequest) -> Dict[str, Any]:
    """
    Run only the regression-detection suite (Suite 2) against a proposed fix.

    Checks for:
    - Anti-patterns introduced by the fix (swallowed exceptions, linter suppressions)
    - Security controls removed by the fix (auth checks, CSRF, rate limiting)
    - Code size / bloat regression

    Returns a lightweight report with just the regression checks.
    """
    engine = _get_engine()
    try:
        # Run only the regression suite directly
        checks = engine._run_regression_check(
            original=req.original_code,
            fixed=req.fixed_code,
            language=req.language,
        )
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("regression check error: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail=f"Regression check error: {type(exc).__name__}") from exc

    passed = [c for c in checks if c.status.value == "passed"]
    failed = [c for c in checks if c.status.value == "failed"]
    warnings = [c for c in checks if c.status.value == "warning"]
    overall_clean = len(failed) == 0

    return {
        "status": "ok",
        "finding_id": req.finding_id,
        "language": req.language,
        "regression_clean": overall_clean,
        "checks_passed": len(passed),
        "checks_failed": len(failed),
        "checks_warning": len(warnings),
        "checks": [
            {
                "check_name": c.check_name,
                "status": c.status.value,
                "description": c.description,
                "severity": c.severity,
                "cwe": c.cwe,
            }
            for c in checks
        ],
    }


@router.post("/mpte-retest", summary="Re-run MPTE exploit simulation after fix")
async def mpte_retest(req: MPTERetestRequest) -> Dict[str, Any]:
    """
    Re-run the MPTE exploit simulation (Suite 4) against the fixed code.

    Simulates whether the previously identified exploit payload would still
    succeed against the patched code by:
    1. Checking if vulnerable code patterns are still present
    2. Checking if the correct fix mitigation pattern was applied
    3. Comparing exploit indicators in original vs fixed code

    Returns:
    - `mpte_retest_result`: "exploit_blocked" | "exploit_still_possible" | "inconclusive" | "not_applicable"
    - `check`: detailed CheckResult with explanation
    - `exploit_blocked`: bool shorthand
    """
    engine = _get_engine()
    try:
        check, result = engine._run_mpte_retest(
            original=req.original_code,
            fixed=req.fixed_code,
            language=req.language,
            finding_type=req.finding_type,
        )
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("mpte retest error: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail=f"MPTE re-test error: {type(exc).__name__}") from exc

    return {
        "status": "ok",
        "finding_id": req.finding_id,
        "finding_type": req.finding_type,
        "language": req.language,
        "mpte_retest_result": result.value,
        "exploit_blocked": result.value == "exploit_blocked",
        "check": {
            "check_name": check.check_name,
            "status": check.status.value,
            "description": check.description,
            "details": check.details,
            "cwe": check.cwe,
            "severity": check.severity,
            "duration_ms": round(check.duration_ms, 2),
        },
    }


@router.get("/history", summary="Get verification history")
async def get_history(
    limit: int = Query(100, ge=1, le=1000, description="Max records to return"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type"),
    language: Optional[str] = Query(None, description="Filter by language"),
    verified_only: bool = Query(False, description="Return only verified results"),
) -> Dict[str, Any]:
    """
    Get the post-fix verification history for this engine instance.

    History is in-memory and resets on service restart.  For persistent
    history integrate with your data store.
    """
    engine = _get_engine()
    records = engine.get_history(limit=limit)

    # Apply filters
    if finding_type:
        records = [r for r in records if r.get("finding_type") == finding_type.lower()]
    if language:
        records = [r for r in records if r.get("language") == language.lower()]
    if verified_only:
        records = [r for r in records if r.get("verified")]

    return {
        "status": "ok",
        "count": len(records),
        "history": records,
    }


@router.get("/stats", summary="Verification statistics")
async def get_stats() -> Dict[str, Any]:
    """
    Get aggregate post-fix verification statistics.

    Returns counts of verified/failed verifications, per-language and
    per-finding-type breakdown, safe-to-deploy rates, and MPTE re-test
    pass rates.
    """
    engine = _get_engine()
    stats = engine.get_stats()

    return {
        "status": "ok",
        "stats": {
            **stats,
            "engine": "postfix_verifier",
            "version": "1.0.0",
            "description": "MPTE Post-Fix Verification Engine — Find → Fix → VERIFY",
        },
    }


@router.get("/supported-languages", summary="List supported languages")
async def supported_languages() -> Dict[str, Any]:
    """
    List all programming languages supported by the post-fix verification engine.

    For each language, returns the number of vulnerability patterns in the
    detection library.
    """
    from core.postfix_verifier import _FIX_REGRESSION_PATTERNS, _VULN_PATTERNS

    result = {}
    for lang in sorted(_VULN_PATTERNS.keys()):
        result[lang] = {
            "vuln_patterns": len(_VULN_PATTERNS[lang]),
            "regression_patterns": len(_FIX_REGRESSION_PATTERNS.get(lang, [])),
        }

    return {
        "status": "ok",
        "supported_languages": result,
        "total_languages": len(result),
        "total_vuln_patterns": sum(v["vuln_patterns"] for v in result.values()),
    }


@router.get("/health", summary="Health check")
async def health() -> Dict[str, Any]:
    """
    Health check for the MPTE Post-Fix Verification engine.

    Returns engine status, version, and key capability flags.
    """
    engine = _get_engine()
    stats = engine.get_stats()

    return {
        "status": "healthy",
        "engine": "postfix_verifier",
        "version": "1.0.0",
        "capabilities": {
            "static_analysis": True,
            "ast_analysis_python": True,
            "regression_check": True,
            "dependency_safety": True,
            "mpte_retest": True,
            "style_preservation": True,
            "test_coverage_impact": True,
        },
        "supported_languages": engine.supported_languages(),
        "total_verifications": stats.get("total_verifications", 0),
        "air_gapped": True,
        "external_api_calls": False,
    }
