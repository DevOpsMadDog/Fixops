"""Material Change Detection Router for FixOps.

Provides FastAPI endpoints for the Material Change Detection engine.
All endpoints use real analysis logic from :mod:`core.material_change_detector`
— no mocks or dummy returns.

Prefix: ``/api/v1/changes``
Tags:   ``Material Change Detection``

Endpoints
---------
POST /analyze-diff
    Analyze a unified diff for security-material changes.

POST /analyze-pr
    Full PR/MR risk assessment from multiple file diffs.

GET  /risk-profile/{repo}
    Historical risk profile (weekly buckets, top files, velocity).

POST /classify
    Classify a set of file changes as BREAKING / MATERIAL / COSMETIC.

GET  /velocity/{repo}
    Change velocity metrics and security-debt-acceleration alert.

POST /review-checklist
    Generate a targeted security review checklist from diffs.

GET  /health
    Health check endpoint.
"""

from __future__ import annotations

import logging
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from apps.api.dependencies import get_org_id
from pydantic import BaseModel, Field, validator

# Import the core engine — supports air-gapped / offline deployments
try:
    from core.material_change_detector import (
        ChangeCategory,
        ChangeClassification,
        SeverityLevel,
        analyze_diff as _analyze_diff,
        analyze_pr as _analyze_pr,
        classify_changes as _classify_changes,
        generate_checklist as _generate_checklist,
        get_pr_analyzer,
        get_risk_profile as _get_risk_profile,
        get_velocity as _get_velocity,
        get_velocity_tracker,
        material_change_to_dict,
    )

    _ENGINE_AVAILABLE = True
except ImportError as _import_err:
    _ENGINE_AVAILABLE = False
    _IMPORT_ERROR_MSG = str(_import_err)
    logger_pre = logging.getLogger(__name__)
    logger_pre.error("material_change_detector import failed: %s", _import_err)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/changes",
    tags=["Material Change Detection"],
)

# ---------------------------------------------------------------------------
# Pydantic Models — Requests
# ---------------------------------------------------------------------------


class FileDiffEntry(BaseModel):
    """A single file diff entry submitted for analysis.

    Attributes:
        path: Relative path of the changed file within the repository.
        diff: Unified diff text for this file (``git diff`` output).
    """

    path: str = Field(..., description="Relative file path in the repository", min_length=1)
    diff: str = Field(
        "",
        description="Unified diff text (output of git diff) for this file",
    )

    @validator("path")
    def path_not_empty(cls, v: str) -> str:  # noqa: N805
        v = v.strip()
        if not v:
            raise ValueError("path must not be empty")
        return v


class AnalyzeDiffRequest(BaseModel):
    """Request body for POST /analyze-diff.

    Attributes:
        diff: Raw unified diff text to analyze (full ``git diff`` output).
        historical_vuln_density: Optional map of file_path → historical
            vulnerability density (0.0–1.0) for risk boosting.
        include_cosmetic: If True, cosmetic changes are included in the
            response (default False — only material/breaking returned).
        repo: Optional repository identifier for telemetry/logging.
    """

    diff: str = Field(..., description="Raw unified diff text (git diff output)", min_length=1)
    historical_vuln_density: Optional[Dict[str, float]] = Field(
        None,
        description="Per-file historical vulnerability density (0.0–1.0)",
    )
    include_cosmetic: bool = Field(
        False,
        description="Whether to include COSMETIC-classified changes in the response",
    )
    repo: Optional[str] = Field(None, description="Repository identifier for telemetry")


class AnalyzePRRequest(BaseModel):
    """Request body for POST /analyze-pr.

    Attributes:
        pr_id: Pull/merge request identifier (e.g. GitHub PR number, GitLab MR IID).
        repo: Repository identifier for velocity tracking.
        file_diffs: List of per-file diff entries.
        historical_vuln_density: Optional per-file historical vuln density.
        record_velocity: Whether to record results in the velocity tracker.
    """

    pr_id: str = Field(..., description="PR/MR identifier", min_length=1)
    repo: str = Field(..., description="Repository identifier (owner/name)", min_length=1)
    file_diffs: List[FileDiffEntry] = Field(
        ...,
        description="List of per-file diff entries",
        min_items=1,
    )
    historical_vuln_density: Optional[Dict[str, float]] = Field(
        None,
        description="Per-file historical vulnerability density override",
    )
    record_velocity: bool = Field(
        True,
        description="Record results in velocity tracker for trend analysis",
    )


class ClassifyRequest(BaseModel):
    """Request body for POST /classify.

    Attributes:
        file_diffs: List of file diff entries to classify.
    """

    file_diffs: List[FileDiffEntry] = Field(
        ...,
        description="List of file diffs to classify",
        min_items=1,
    )


class ReviewChecklistRequest(BaseModel):
    """Request body for POST /review-checklist.

    Attributes:
        file_diffs: File diffs from which to derive the checklist.
        pr_id: Optional PR identifier for context in the response.
        repo: Optional repository name for context.
    """

    file_diffs: List[FileDiffEntry] = Field(
        ...,
        description="File diffs to generate checklist from",
        min_items=1,
    )
    pr_id: Optional[str] = Field(None, description="Optional PR/MR identifier")
    repo: Optional[str] = Field(None, description="Optional repository identifier")


# ---------------------------------------------------------------------------
# Pydantic Models — Responses
# ---------------------------------------------------------------------------


class APIResponseMeta(BaseModel):
    """Standard metadata block included in every response.

    Attributes:
        request_id: Unique identifier for this request (UUID4).
        analyzed_at: ISO-8601 timestamp of analysis completion.
        engine_version: Engine version string.
        duration_ms: Analysis duration in milliseconds.
        status: 'ok' or 'error'.
    """

    request_id: str
    analyzed_at: str
    engine_version: str = "1.0.0"
    duration_ms: float
    status: str = "ok"


class AnalyzeDiffResponse(BaseModel):
    """Response from POST /analyze-diff.

    Attributes:
        status: 'ok' or 'error'.
        data: Analysis results dict.
        metadata: Request metadata.
    """

    status: str
    data: Dict[str, Any]
    metadata: APIResponseMeta


class AnalyzePRResponse(BaseModel):
    """Response from POST /analyze-pr."""

    status: str
    data: Dict[str, Any]
    metadata: APIResponseMeta


class RiskProfileResponse(BaseModel):
    """Response from GET /risk-profile/{repo}."""

    status: str
    data: Dict[str, Any]
    metadata: APIResponseMeta


class ClassifyResponse(BaseModel):
    """Response from POST /classify."""

    status: str
    data: Dict[str, Any]
    metadata: APIResponseMeta


class VelocityResponse(BaseModel):
    """Response from GET /velocity/{repo}."""

    status: str
    data: Dict[str, Any]
    metadata: APIResponseMeta


class ReviewChecklistResponse(BaseModel):
    """Response from POST /review-checklist."""

    status: str
    data: Dict[str, Any]
    metadata: APIResponseMeta


class HealthResponse(BaseModel):
    """Response from GET /health."""

    status: str
    engine_available: bool
    version: str
    timestamp: str
    checks: Dict[str, Any]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _make_meta(start_time: float, status: str = "ok") -> APIResponseMeta:
    """Construct a response metadata block.

    Args:
        start_time: ``time.perf_counter()`` value from request start.
        status: 'ok' or 'error'.

    Returns:
        Populated APIResponseMeta instance.
    """
    return APIResponseMeta(
        request_id=str(uuid.uuid4()),
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
        status=status,
    )


def _file_diffs_to_list(file_diffs: List[FileDiffEntry]) -> List[Dict[str, str]]:
    """Convert Pydantic FileDiffEntry list to plain dicts for the engine.

    Args:
        file_diffs: List of FileDiffEntry objects.

    Returns:
        List of plain dicts with 'path' and 'diff' keys.
    """
    return [{"path": fd.path, "diff": fd.diff} for fd in file_diffs]


def _require_engine() -> None:
    """Raise HTTP 503 if the core engine failed to import.

    Raises:
        HTTPException: 503 Service Unavailable with import error detail.
    """
    if not _ENGINE_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Material Change Detection engine unavailable",
                "reason": _IMPORT_ERROR_MSG if not _ENGINE_AVAILABLE else "unknown",
            },
        )


def _severity_filter(severity_str: Optional[str]) -> Optional[str]:
    """Validate and normalize a severity filter query parameter.

    Args:
        severity_str: Raw severity string from query params.

    Returns:
        Normalized uppercase severity string, or None if not provided.

    Raises:
        HTTPException: 400 if the value is not a valid SeverityLevel.
    """
    if severity_str is None:
        return None
    upper = severity_str.upper()
    valid = {s.value for s in SeverityLevel}
    if upper not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity filter '{severity_str}'. Valid values: {sorted(valid)}",
        )
    return upper


def _classification_filter(cls_str: Optional[str]) -> Optional[str]:
    """Validate and normalize a classification filter query parameter.

    Args:
        cls_str: Raw classification string from query params.

    Returns:
        Normalized uppercase classification string, or None.

    Raises:
        HTTPException: 400 if value is not a valid ChangeClassification.
    """
    if cls_str is None:
        return None
    upper = cls_str.upper()
    valid = {c.value for c in ChangeClassification}
    if upper not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid classification filter '{cls_str}'. Valid values: {sorted(valid)}",
        )
    return upper


# ---------------------------------------------------------------------------
# Endpoint 1: POST /analyze-diff
# ---------------------------------------------------------------------------


@router.post(
    "/analyze-diff",
    response_model=AnalyzeDiffResponse,
    summary="Analyze a unified diff for security-material changes",
    description=(
        "Parses a raw unified git diff and detects security-material changes across "
        "six categories: Auth/AuthZ, Crypto, Data Flow, API Surface, Dependencies, "
        "and Infrastructure. Returns risk-scored and classified changes with "
        "explanations and reviewer recommendations."
    ),
    response_description="Analysis results with material changes, risk scores, and classification",
)
async def analyze_diff_endpoint(
    request: AnalyzeDiffRequest,
    min_risk_score: Optional[float] = Query(
        None,
        ge=0.0,
        le=100.0,
        description="Only return changes with risk_score >= this value",
    ),
    org_id: str = Depends(get_org_id),
    classification: Optional[str] = Query(
        None,
        description="Filter by classification: BREAKING, MATERIAL, or COSMETIC",
    ),
    severity: Optional[str] = Query(
        None,
        description="Filter by minimum severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO",
    ),
) -> AnalyzeDiffResponse:
    """Analyze a single unified diff for security-material changes.

    Accepts a raw ``git diff`` output and runs the full detection pipeline:
    regex pattern matching, Python AST analysis (for .py files), risk scoring,
    semantic classification, and reviewer recommendation.

    Returns a filtered, scored list of material changes along with aggregate
    statistics.
    """
    _require_engine()
    start = time.perf_counter()

    cls_filter = _classification_filter(classification)
    sev_filter = _severity_filter(severity)

    # Severity ordering for filtering
    sev_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    try:
        changes = _analyze_diff(
            request.diff,
            historical_vuln_density=request.historical_vuln_density,
        )
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("analyze_diff failed: %s\n%s", exc, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Analysis error: {exc}") from exc

    # Apply filters
    filtered = changes
    if not request.include_cosmetic:
        filtered = [c for c in filtered if c.get("classification") != "COSMETIC"]
    if cls_filter:
        filtered = [c for c in filtered if c.get("classification") == cls_filter]
    if min_risk_score is not None:
        filtered = [c for c in filtered if c.get("risk_score", 0) >= min_risk_score]
    if sev_filter:
        min_sev_idx = sev_order.index(sev_filter)
        filtered = [
            c for c in filtered
            if sev_order.index(c.get("severity", "INFO")) >= min_sev_idx
        ]

    # Aggregate stats
    risk_scores = [c.get("risk_score", 0) for c in filtered]
    categories_seen = list({c.get("category", "unknown") for c in filtered})
    classification_counts: Dict[str, int] = {"BREAKING": 0, "MATERIAL": 0, "COSMETIC": 0}
    for c in filtered:
        k = c.get("classification", "COSMETIC")
        classification_counts[k] = classification_counts.get(k, 0) + 1

    overall_risk = 0.0
    if risk_scores:
        max_score = max(risk_scores)
        avg_score = sum(risk_scores) / len(risk_scores)
        overall_risk = round(0.60 * max_score + 0.40 * avg_score, 2)

    # Determine overall classification
    if classification_counts["BREAKING"] > 0:
        overall_cls = "BREAKING"
    elif classification_counts["MATERIAL"] > 0:
        overall_cls = "MATERIAL"
    else:
        overall_cls = "COSMETIC"

    # Gather all recommended reviewers from changes
    all_reviewers: List[str] = []
    seen_reviewers: set = set()
    for c in filtered:
        for r in c.get("recommended_reviewers", []):
            if r not in seen_reviewers:
                seen_reviewers.add(r)
                all_reviewers.append(r)

    data: Dict[str, Any] = {
        "overall_risk_score": overall_risk,
        "overall_classification": overall_cls,
        "total_changes_detected": len(changes),
        "filtered_changes_returned": len(filtered),
        "classification_breakdown": classification_counts,
        "categories_detected": categories_seen,
        "recommended_reviewers": all_reviewers,
        "changes": filtered,
        "repo": request.repo,
    }

    return AnalyzeDiffResponse(
        status="ok",
        data=data,
        metadata=_make_meta(start),
    )


# ---------------------------------------------------------------------------
# Endpoint 2: POST /analyze-pr
# ---------------------------------------------------------------------------


@router.post(
    "/analyze-pr",
    response_model=AnalyzePRResponse,
    summary="Full PR/MR risk assessment",
    description=(
        "Analyzes an entire pull/merge request by processing multiple file diffs. "
        "Produces an overall risk score, per-file summaries, reviewer recommendations, "
        "security review checklist, and change velocity recording."
    ),
    response_description="Full PR risk assessment with aggregated scores and detailed findings",
)
async def analyze_pr_endpoint(request: AnalyzePRRequest) -> AnalyzePRResponse:
    """Perform a full Pull/Merge Request risk assessment.

    Processes all file diffs in the PR, aggregates risk scores, identifies
    the highest-risk areas, and generates a comprehensive security review
    package for human reviewers.

    If ``record_velocity`` is True, results are recorded in the velocity
    tracker keyed by the ``repo`` field for later trend analysis.
    """
    _require_engine()
    start = time.perf_counter()

    file_diffs_plain = _file_diffs_to_list(request.file_diffs)

    try:
        assessment = _analyze_pr(
            pr_id=request.pr_id,
            file_diffs=file_diffs_plain,
            historical_vuln_density=request.historical_vuln_density,
            record_velocity=request.record_velocity,
            repo=request.repo,
        )
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("analyze_pr failed for PR %s: %s\n%s", request.pr_id, exc, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"PR analysis error: {exc}") from exc

    # Enrich assessment with action priorities
    breaking = [c for c in assessment.get("material_changes", []) if c.get("classification") == "BREAKING"]
    material = [c for c in assessment.get("material_changes", []) if c.get("classification") == "MATERIAL"]

    assessment["action_required"] = len(breaking) > 0 or assessment.get("overall_risk_score", 0) >= 70
    assessment["priority_items"] = [
        {
            "priority": "CRITICAL" if c.get("severity") == "CRITICAL" else "HIGH",
            "file": c.get("file_path"),
            "category": c.get("category"),
            "summary": c.get("summary"),
            "risk_score": c.get("risk_score"),
        }
        for c in breaking[:5]  # Top 5 breaking changes
    ]
    assessment["material_change_count"] = len(material)
    assessment["breaking_change_count"] = len(breaking)

    return AnalyzePRResponse(
        status="ok",
        data=assessment,
        metadata=_make_meta(start),
    )


# ---------------------------------------------------------------------------
# Endpoint 3: GET /risk-profile/{repo}
# ---------------------------------------------------------------------------


@router.get(
    "/risk-profile/{repo:path}",
    response_model=RiskProfileResponse,
    summary="Historical risk profile for a repository",
    description=(
        "Returns a time-windowed historical risk profile for the specified repository. "
        "Includes weekly change buckets, category distribution, top-risk files, "
        "and current velocity snapshot. Useful for audit trails and security posture trends."
    ),
    response_description="Historical risk profile with time-bucketed change data",
)
async def get_risk_profile_endpoint(
    repo: str,
    window_days: int = Query(
        90,
        ge=1,
        le=365,
        description="Historical window in days (1–365, default 90)",
    ),
) -> RiskProfileResponse:
    """Retrieve the historical risk profile for a repository.

    Returns time-bucketed material change data over the specified window,
    enabling trend identification, audit reporting, and baseline establishment.

    The repository must have had changes recorded via POST /analyze-pr with
    ``record_velocity=true`` for data to be available.
    """
    _require_engine()
    start = time.perf_counter()

    try:
        profile = _get_risk_profile(repo=repo, window_days=window_days)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("get_risk_profile failed for repo %s: %s", repo, exc)
        raise HTTPException(status_code=500, detail=f"Risk profile error: {exc}") from exc

    # Enrich with risk trend assessment
    weekly_buckets = profile.get("weekly_buckets", [])
    if len(weekly_buckets) >= 2:
        recent_risk = weekly_buckets[-1].get("avg_risk", 0) if weekly_buckets else 0
        earlier_risk = weekly_buckets[-2].get("avg_risk", 0) if len(weekly_buckets) > 1 else 0
        if earlier_risk > 0:
            risk_trend = round((recent_risk - earlier_risk) / earlier_risk * 100, 1)
            trend_direction = "increasing" if risk_trend > 5 else ("decreasing" if risk_trend < -5 else "stable")
        else:
            risk_trend = 0.0
            trend_direction = "stable"
    else:
        risk_trend = 0.0
        trend_direction = "insufficient_data"

    profile["risk_trend_pct"] = risk_trend
    profile["risk_trend_direction"] = trend_direction
    profile["window_days_requested"] = window_days

    return RiskProfileResponse(
        status="ok",
        data=profile,
        metadata=_make_meta(start),
    )


# ---------------------------------------------------------------------------
# Endpoint 4: POST /classify
# ---------------------------------------------------------------------------


@router.post(
    "/classify",
    response_model=ClassifyResponse,
    summary="Classify changes as BREAKING / MATERIAL / COSMETIC",
    description=(
        "Lightweight endpoint that classifies each provided file diff without producing "
        "the full analysis output. Returns BREAKING, MATERIAL, or COSMETIC for each file "
        "plus aggregate counts. Suitable for CI/CD gate decisions."
    ),
    response_description="Classification results per file and aggregate summary",
)
async def classify_endpoint(
    request: ClassifyRequest,
    fail_on_breaking: bool = Query(
        False,
        description="If True, return HTTP 422 when any BREAKING change is detected",
    ),
    org_id: str = Depends(get_org_id),
) -> ClassifyResponse:
    """Classify a set of file diffs as BREAKING, MATERIAL, or COSMETIC.

    Designed as a fast CI/CD gate: returns a simple classification per file
    and an aggregate summary. When ``fail_on_breaking=true``, the endpoint
    returns HTTP 422 Unprocessable Entity if any BREAKING changes are found,
    which can block a merge pipeline.
    """
    _require_engine()
    start = time.perf_counter()

    file_diffs_plain = _file_diffs_to_list(request.file_diffs)

    try:
        result = _classify_changes(file_diffs_plain)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("classify_changes failed: %s\n%s", exc, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Classification error: {exc}") from exc

    # Determine if gate should block
    summary = result.get("classification_summary", {})
    breaking_count = summary.get("BREAKING", 0)
    gate_passed = breaking_count == 0

    result["gate_passed"] = gate_passed
    result["gate_status"] = "PASS" if gate_passed else "BLOCK"

    if fail_on_breaking and not gate_passed:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "BREAKING security changes detected — merge blocked",
                "breaking_change_count": breaking_count,
                "classification_summary": summary,
                "results": result.get("results", []),
            },
        )

    return ClassifyResponse(
        status="ok",
        data=result,
        metadata=_make_meta(start),
    )


# ---------------------------------------------------------------------------
# Endpoint 5: GET /velocity/{repo}
# ---------------------------------------------------------------------------


@router.get(
    "/velocity/{repo:path}",
    response_model=VelocityResponse,
    summary="Change velocity metrics for a repository",
    description=(
        "Returns change velocity metrics for the specified repository over a configurable "
        "time window. Detects 'security debt acceleration' — when the rate of material "
        "changes significantly exceeds the historical baseline."
    ),
    response_description="Velocity snapshot with acceleration metric and debt alert flag",
)
async def get_velocity_endpoint(
    repo: str,
    window_days: int = Query(
        7,
        ge=1,
        le=90,
        description="Measurement window in days (1–90, default 7)",
    ),
    include_detail: bool = Query(
        False,
        description="If True, includes per-category velocity breakdown",
    ),
) -> VelocityResponse:
    """Retrieve change velocity metrics for a repository.

    Computes the rate of material security changes over the specified window
    and compares to the historical baseline.  An acceleration ratio >= 2.0
    (configurable) triggers a ``debt_acceleration_alert``.

    The ``acceleration`` field represents current_velocity / baseline_velocity:
    - 1.0 = same rate as baseline
    - >1.0 = faster than baseline (potential concern)
    - <1.0 = slower than baseline (improving posture)
    """
    _require_engine()
    start = time.perf_counter()

    try:
        snapshot = _get_velocity(repo=repo, window_days=window_days)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("get_velocity failed for repo %s: %s", repo, exc)
        raise HTTPException(status_code=500, detail=f"Velocity error: {exc}") from exc

    # Interpret acceleration for humans
    acc = snapshot.get("acceleration", 1.0)
    if acc >= 3.0:
        acceleration_label = "CRITICAL — Change rate far exceeds baseline"
    elif acc >= 2.0:
        acceleration_label = "HIGH — Change rate significantly exceeds baseline"
    elif acc >= 1.5:
        acceleration_label = "ELEVATED — Change rate moderately above baseline"
    elif acc >= 0.8:
        acceleration_label = "NORMAL — Change rate within baseline range"
    else:
        acceleration_label = "LOW — Change rate below baseline (improving)"

    snapshot["acceleration_label"] = acceleration_label

    # Optional per-category detail
    if include_detail:
        try:
            tracker = get_velocity_tracker()
            record = tracker._repos.get(repo)
            if record and record.change_log:
                now = time.time()
                window_start = now - (window_days * 86400)
                window_entries = [e for e in record.change_log if e["ts"] >= window_start]
                cat_breakdown: Dict[str, Dict[str, Any]] = {}
                for entry in window_entries:
                    cat = entry.get("category", "unknown")
                    if cat not in cat_breakdown:
                        cat_breakdown[cat] = {"count": 0, "breaking": 0, "avg_risk": 0.0, "_risks": []}
                    cat_breakdown[cat]["count"] += 1
                    if entry.get("classification") == "BREAKING":
                        cat_breakdown[cat]["breaking"] += 1
                    cat_breakdown[cat]["_risks"].append(entry.get("risk_score", 0))
                # Compute avg risk per category
                for cat_data in cat_breakdown.values():
                    risks = cat_data.pop("_risks", [])
                    cat_data["avg_risk"] = round(sum(risks) / len(risks), 2) if risks else 0.0
                snapshot["category_breakdown"] = cat_breakdown
            else:
                snapshot["category_breakdown"] = {}
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.warning("category breakdown failed: %s", exc)
            snapshot["category_breakdown"] = {}

    return VelocityResponse(
        status="ok",
        data=snapshot,
        metadata=_make_meta(start),
    )


# ---------------------------------------------------------------------------
# Endpoint 6: POST /review-checklist
# ---------------------------------------------------------------------------


@router.post(
    "/review-checklist",
    response_model=ReviewChecklistResponse,
    summary="Generate a security review checklist from changes",
    description=(
        "Analyzes the provided file diffs, detects security change categories, "
        "and generates a targeted review checklist. The checklist covers all detected "
        "categories (Auth, Crypto, Data Flow, API Surface, Dependencies, Infrastructure) "
        "plus universal security review items."
    ),
    response_description="Targeted security review checklist with category attribution",
)
async def review_checklist_endpoint(
    request: ReviewChecklistRequest,
    group_by_category: bool = Query(
        False,
        description="If True, group checklist items by security category",
    ),
    org_id: str = Depends(get_org_id),
) -> ReviewChecklistResponse:
    """Generate a security review checklist from a set of file diffs.

    Analyzes the diffs to identify which security categories are touched,
    then synthesizes a focused checklist covering only the relevant areas.
    Avoids overwhelming reviewers with irrelevant checks.

    The ``group_by_category`` flag returns the checklist organized by
    security domain rather than as a flat list, which is useful for
    assigning checklist sections to different reviewers.
    """
    _require_engine()
    start = time.perf_counter()

    file_diffs_plain = _file_diffs_to_list(request.file_diffs)

    try:
        checklist = _generate_checklist(file_diffs_plain)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("generate_checklist failed: %s\n%s", exc, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Checklist generation error: {exc}") from exc

    # Detect categories for metadata
    try:
        from core.material_change_detector import (
            MaterialChangeDetector,
            ChangeClassification,
            _CHECKLIST_TEMPLATES,
        )
        detector = MaterialChangeDetector()
        categories_seen: List[str] = []
        for fd in file_diffs_plain:
            changes = detector.analyze_diff(fd.get("diff", ""))
            for c in changes:
                cat_val = c.category.value if hasattr(c.category, "value") else str(c.category)
                if c.classification != ChangeClassification.COSMETIC and cat_val not in categories_seen:
                    categories_seen.append(cat_val)
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
        categories_seen = []

    # Group by category if requested
    grouped: Dict[str, List[str]] = {}
    if group_by_category:
        try:
            from core.material_change_detector import _CHECKLIST_TEMPLATES, ChangeCategory
            # General items (first 4 are always general)
            grouped["general"] = checklist[:4]
            offset = 4
            for cat in ChangeCategory:
                template_items = _CHECKLIST_TEMPLATES.get(cat, [])
                cat_items = [item for item in checklist[offset:] if item in template_items]
                if cat_items:
                    grouped[cat.value] = cat_items
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            grouped = {"general": checklist}

    data: Dict[str, Any] = {
        "pr_id": request.pr_id,
        "repo": request.repo,
        "checklist": checklist,
        "total_items": len(checklist),
        "categories_covered": categories_seen,
        "category_count": len(categories_seen),
    }
    if group_by_category:
        data["grouped_checklist"] = grouped

    return ReviewChecklistResponse(
        status="ok",
        data=data,
        metadata=_make_meta(start),
    )


# ---------------------------------------------------------------------------
# Endpoint 7: GET /health
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check for the Material Change Detection service",
    description=(
        "Returns the operational status of the Material Change Detection engine. "
        "Checks engine availability, pattern library initialization, AST analyzer, "
        "and velocity tracker state."
    ),
    response_description="Health status with subsystem checks",
)
async def health_endpoint() -> HealthResponse:
    """Health check for the Material Change Detection engine.

    Performs lightweight subsystem checks without executing any actual
    analysis (suitable for load balancer probes and readiness checks).

    Returns HTTP 200 with status='ok' when all subsystems are healthy,
    or HTTP 503 with status='degraded' when the engine is unavailable.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    checks: Dict[str, Any] = {}

    if not _ENGINE_AVAILABLE:
        checks["engine_import"] = {
            "status": "FAIL",
            "detail": _IMPORT_ERROR_MSG if not _ENGINE_AVAILABLE else "unknown",
        }
        return HealthResponse(
            status="degraded",
            engine_available=False,
            version="1.0.0",
            timestamp=timestamp,
            checks=checks,
        )

    # Check 1: Pattern library
    try:
        from core.material_change_detector import PatternLibrary
        lib = PatternLibrary()
        all_patterns = lib.get_all_patterns()
        pattern_count = len(all_patterns)
        checks["pattern_library"] = {
            "status": "OK",
            "pattern_count": pattern_count,
        }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        checks["pattern_library"] = {"status": "FAIL", "detail": str(exc)}

    # Check 2: Diff parser smoke test
    try:
        from core.material_change_detector import DiffParser
        parser = DiffParser()
        _test_diff = (
            "diff --git a/test.py b/test.py\n"
            "--- a/test.py\n"
            "+++ b/test.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-old_line\n"
            "+new_line\n"
        )
        parsed = parser.parse(_test_diff)
        checks["diff_parser"] = {
            "status": "OK",
            "test_files_parsed": len(parsed),
        }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        checks["diff_parser"] = {"status": "FAIL", "detail": str(exc)}

    # Check 3: AST analyzer
    try:
        from core.material_change_detector import PythonASTAnalyzer
        analyzer = PythonASTAnalyzer()
        findings = analyzer.analyze_added_code("import os\neval('test')\n")
        checks["ast_analyzer"] = {
            "status": "OK",
            "test_findings": len(findings),
        }
    except ImportError as exc:
        checks["ast_analyzer"] = {"status": "FAIL", "detail": str(exc)}

    # Check 4: Risk scorer
    try:
        from core.material_change_detector import RiskScorer, ChangeCategory, SeverityLevel
        scorer = RiskScorer()
        score = scorer.score(
            category=ChangeCategory.AUTH,
            severity=SeverityLevel.HIGH,
            churn=10,
            file_path="auth/login.py",
            confidence=0.9,
        )
        checks["risk_scorer"] = {
            "status": "OK",
            "test_score": score,
        }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        checks["risk_scorer"] = {"status": "FAIL", "detail": str(exc)}

    # Check 5: Velocity tracker
    try:
        tracker = get_velocity_tracker()
        repos = tracker.list_repos()
        checks["velocity_tracker"] = {
            "status": "OK",
            "tracked_repos": len(repos),
        }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
        checks["velocity_tracker"] = {"status": "FAIL", "detail": str(exc)}

    # Overall health
    all_ok = all(v.get("status") == "OK" for v in checks.values())
    overall_status = "ok" if all_ok else "degraded"

    return HealthResponse(
        status=overall_status,
        engine_available=True,
        version="1.0.0",
        timestamp=timestamp,
        checks=checks,
    )
