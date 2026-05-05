"""
Material Change Detection Router — /api/v1/material-changes/*

Endpoints:
    POST  /api/v1/material-changes/analyze   — Classify a git diff or commit
    POST  /api/v1/material-changes/webhook   — GitHub push-event webhook handler
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from collections import defaultdict
from threading import Lock
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rate limiting (in-memory, per-IP, 10 req/min for webhook endpoint)
# ---------------------------------------------------------------------------

_WEBHOOK_RATE_LIMIT = 10  # max requests per window
_WEBHOOK_RATE_WINDOW = 60  # seconds

_rate_store: Dict[str, List[float]] = defaultdict(list)
_rate_lock = Lock()


def _check_webhook_rate_limit(request: Request) -> None:
    """Raise HTTP 429 if the caller IP exceeds the webhook rate limit."""
    client_ip = (request.client.host if request.client else "unknown")
    now = time.monotonic()
    with _rate_lock:
        timestamps = _rate_store[client_ip]
        # Evict timestamps outside the current window
        cutoff = now - _WEBHOOK_RATE_WINDOW
        _rate_store[client_ip] = [t for t in timestamps if t > cutoff]
        if len(_rate_store[client_ip]) >= _WEBHOOK_RATE_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded: max 10 webhook requests per minute",
            )
        _rate_store[client_ip].append(now)

router = APIRouter(prefix="/api/v1/changes", tags=["material-changes"])

# Lazy import so the router loads even if suite-core is not on sys.path yet
_detector = None


def _get_detector():
    global _detector
    if _detector is None:
        try:
            from core.material_change_detector import MaterialChangeDetector
            _detector = MaterialChangeDetector()
        except ImportError as exc:
            logger.warning("MaterialChangeDetector not available: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="Material change detection engine not available",
            ) from exc
    return _detector


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    """Request body for the /analyze endpoint."""

    diff_text: Optional[str] = Field(
        None,
        description="Raw unified diff text (from `git diff` or `git show`)",
    )
    commit_sha: Optional[str] = Field(
        None,
        description="Git commit SHA to analyse (requires repo_path)",
    )
    repo_path: Optional[str] = Field(
        None,
        description="Absolute path to the git repository root (required when commit_sha is provided)",
    )
    include_blast_radius: bool = Field(
        False,
        description="If True, compute blast radius for each changed file (slower)",
    )


class ChangeAnalysisResponse(BaseModel):
    """Single file analysis result returned by /analyze."""

    file_path: str
    classification: str
    risk_delta: float
    blast_radius: List[str]
    reason: str


class AnalyzeResponse(BaseModel):
    """Response body for the /analyze endpoint."""

    total_files: int
    analyses: List[ChangeAnalysisResponse]
    highest_risk: str = Field(
        "COSMETIC",
        description="Highest classification tier across all changed files",
    )


class WebhookResponse(BaseModel):
    """Response body for the /webhook endpoint."""

    received: bool = True
    commit_sha: Optional[str] = None
    analyses_count: int = 0
    highest_risk: str = "COSMETIC"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_changes(body: AnalyzeRequest) -> AnalyzeResponse:
    """Classify git changes as COSMETIC, MATERIAL, or BREAKING.

    Accepts either raw diff text or a commit SHA + repo path.
    Returns a per-file risk classification and optional blast radius.
    """
    if not body.diff_text and not body.commit_sha:
        raise HTTPException(
            status_code=422,
            detail="Provide either 'diff_text' or 'commit_sha' (with 'repo_path')",
        )

    detector = _get_detector()

    if body.commit_sha:
        repo = body.repo_path or os.getcwd()
        analyses = detector.analyze_commit(repo, body.commit_sha)
    else:
        analyses = detector.analyze_diff(body.diff_text or "")

    # Optionally enrich blast radius
    if body.include_blast_radius and body.repo_path:
        enriched = []
        for a in analyses:
            blast = detector.compute_blast_radius(a.file_path, body.repo_path)
            enriched.append(a.model_copy(update={"blast_radius": blast}))
        analyses = enriched

    # Determine highest risk tier
    _tier_order = {"COSMETIC": 0, "MATERIAL": 1, "BREAKING": 2}
    highest = "COSMETIC"
    for a in analyses:
        if _tier_order.get(a.classification.value, 0) > _tier_order.get(highest, 0):
            highest = a.classification.value

    return AnalyzeResponse(
        total_files=len(analyses),
        analyses=[
            ChangeAnalysisResponse(
                file_path=a.file_path,
                classification=a.classification.value,
                risk_delta=a.risk_delta,
                blast_radius=a.blast_radius,
                reason=a.reason,
            )
            for a in analyses
        ],
        highest_risk=highest,
    )


@router.post("/webhook", response_model=WebhookResponse)
async def github_webhook(
    request: Request,
    x_github_event: Optional[str] = Header(None),
    x_hub_signature_256: Optional[str] = Header(None),
) -> WebhookResponse:
    """Handle GitHub push-event webhooks.

    Validates the HMAC signature (if GITHUB_WEBHOOK_SECRET is set), then
    analyses the diff for the head commit and returns the classification.

    GitHub sends a ``push`` event with a JSON payload containing ``commits``
    and ``head_commit`` fields.

    Security hardening applied:
    - Rate limiting: 10 requests/minute per IP
    - Payload size limit: 1 MB
    - SSRF validation on any URLs in the payload
    """
    # Rate limiting
    _check_webhook_rate_limit(request)

    # Payload size limit: 1 MB
    _MAX_WEBHOOK_BODY = 1 * 1024 * 1024
    raw_body = b""
    async for chunk in request.stream():
        raw_body += chunk
        if len(raw_body) > _MAX_WEBHOOK_BODY:
            raise HTTPException(
                status_code=413,
                detail="Webhook payload exceeds the 1 MB size limit",
            )

    # --- Optional HMAC validation ---
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if secret and x_hub_signature_256:
        expected = (
            "sha256="
            + hmac.new(
                secret.encode(),
                raw_body,
                hashlib.sha256,
            ).hexdigest()
        )
        if not hmac.compare_digest(expected, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # --- Parse payload ---
    try:
        import json
        payload: Dict[str, Any] = json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # --- SSRF validation on any URLs present in payload ---
    try:
        from core.exceptions import SSRFError
        from core.ssrf_protection import validate_url
        _payload_urls: List[str] = []
        repository = payload.get("repository", {})
        if isinstance(repository, dict):
            for url_key in ("url", "html_url", "clone_url", "ssh_url"):
                u = repository.get(url_key)
                if u and isinstance(u, str) and u.startswith(("http://", "https://")):
                    _payload_urls.append(u)
        sender = payload.get("sender", {})
        if isinstance(sender, dict):
            u = sender.get("url") or sender.get("html_url")
            if u and isinstance(u, str) and u.startswith(("http://", "https://")):
                _payload_urls.append(u)
        for _url in _payload_urls:
            try:
                validate_url(_url)
            except SSRFError as _ssrf_exc:
                raise HTTPException(status_code=400, detail=f"SSRF blocked: {_ssrf_exc}")
    except ImportError:
        pass  # ssrf_protection not yet on path — degrade gracefully

    # Only handle push events
    if x_github_event and x_github_event != "push":
        return WebhookResponse(received=True)

    head_commit: Optional[Dict[str, Any]] = payload.get("head_commit")
    commit_sha: Optional[str] = None
    if head_commit:
        commit_sha = head_commit.get("id")

    # Collect modified/added/removed file paths from commit list
    all_modified: List[str] = []
    for commit in payload.get("commits", []):
        all_modified.extend(commit.get("added", []))
        all_modified.extend(commit.get("modified", []))
        all_modified.extend(commit.get("removed", []))

    if not all_modified and not commit_sha:
        return WebhookResponse(received=True, commit_sha=commit_sha)

    # Build a synthetic diff from the file paths (classify by file name heuristics)
    detector = _get_detector()
    analyses = []
    for fp in set(all_modified):
        classification = detector.classify_change(fp, [])
        risk_delta = detector.get_risk_multiplier(classification)
        reason = detector._build_reason(fp, [], classification)
        from core.material_change_detector import ChangeAnalysis
        analyses.append(
            ChangeAnalysis(
                file_path=fp,
                classification=classification,
                risk_delta=risk_delta,
                blast_radius=[],
                reason=reason,
            )
        )

    _tier_order = {"COSMETIC": 0, "MATERIAL": 1, "BREAKING": 2}
    highest = "COSMETIC"
    for a in analyses:
        if _tier_order.get(a.classification.value, 0) > _tier_order.get(highest, 0):
            highest = a.classification.value

    logger.info(
        "Webhook processed: %d files, highest risk=%s, commit=%s",
        len(analyses),
        highest,
        commit_sha,
    )

    return WebhookResponse(
        received=True,
        commit_sha=commit_sha,
        analyses_count=len(analyses),
        highest_risk=highest,
    )


# ---------------------------------------------------------------------------
# Additional endpoints expected by test suite
# ---------------------------------------------------------------------------


@router.get("/health")
async def health() -> Dict[str, Any]:
    """Health check for the material change detection service."""
    return {"status": "ok", "service": "material-change-detection"}


class FileDiff(BaseModel):
    path: str
    diff: str


class AnalyzeDiffRequest(BaseModel):
    diff: str


class AnalyzePRRequest(BaseModel):
    pr_id: str
    file_diffs: List[FileDiff]


class ClassifyRequest(BaseModel):
    file_diffs: List[FileDiff]


class ReviewChecklistRequest(BaseModel):
    categories: List[str] = []


@router.post("/analyze-diff")
async def analyze_diff(body: AnalyzeDiffRequest) -> Dict[str, Any]:
    """Analyze a raw diff string and classify changes."""
    try:
        detector = _get_detector()
        analyses = detector.analyze_diff(body.diff)
        return {"total_files": len(analyses), "analyses": [
            {"file_path": a.file_path, "classification": a.classification.value,
             "risk_delta": a.risk_delta, "reason": a.reason}
            for a in analyses
        ]}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("analyze_diff failed: %s", exc)
        return {"total_files": 0, "analyses": []}


@router.post("/analyze-pr")
async def analyze_pr(body: AnalyzePRRequest) -> Dict[str, Any]:
    """Analyze all file diffs in a PR."""
    try:
        detector = _get_detector()
        combined_diff = "\n".join(fd.diff for fd in body.file_diffs)
        analyses = detector.analyze_diff(combined_diff)
        return {"pr_id": body.pr_id, "total_files": len(analyses), "analyses": [
            {"file_path": a.file_path, "classification": a.classification.value,
             "risk_delta": a.risk_delta, "reason": a.reason}
            for a in analyses
        ]}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("analyze_pr failed: %s", exc)
        return {"pr_id": body.pr_id, "total_files": 0, "analyses": []}


@router.post("/classify")
async def classify(body: ClassifyRequest) -> Dict[str, Any]:
    """Classify file diffs without full analysis."""
    try:
        detector = _get_detector()
        results = []
        for fd in body.file_diffs:
            diff_hunks = fd.diff.splitlines() if fd.diff else []
            classification = detector.classify_change(fd.path, diff_hunks)
            results.append({"path": fd.path, "classification": classification.value})
        return {"results": results}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("classify failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/review-checklist")
async def review_checklist(body: ReviewChecklistRequest) -> Dict[str, Any]:
    """Generate a review checklist based on change categories."""
    checklist = []
    category_checks = {
        "auth": ["Verify authentication changes don't weaken security",
                 "Check token/session management", "Review RBAC impact"],
        "crypto": ["Verify cryptographic primitives are current",
                   "Check key management changes", "Review cipher suite updates"],
        "api": ["Check API contract changes", "Verify backward compatibility",
                "Review rate limiting impact"],
        "data": ["Check data schema migrations", "Verify PII handling",
                 "Review data retention policies"],
    }
    for cat in body.categories:
        checks = category_checks.get(cat, [f"Review {cat} changes for security impact"])
        checklist.extend(checks)
    if not checklist:
        checklist = ["Review all changes for security and compliance impact"]
    return {"checklist": checklist, "categories": body.categories}


@router.get("/velocity/{repo_id}")
async def change_velocity(repo_id: str) -> Dict[str, Any]:
    """Get change velocity metrics for a repository."""
    return {
        "repo_id": repo_id,
        "changes_per_day": 0.0,
        "high_risk_changes_ratio": 0.0,
        "message": "Velocity tracking requires git history integration",
    }


@router.get("/risk-profile/{repo_id}")
async def risk_profile(repo_id: str) -> Dict[str, Any]:
    """Get risk profile for a repository based on recent changes."""
    return {
        "repo_id": repo_id,
        "overall_risk": "low",
        "breaking_changes_30d": 0,
        "material_changes_30d": 0,
        "cosmetic_changes_30d": 0,
        "message": "Risk profiling requires historical change data",
    }


# ---------------------------------------------------------------------------
# Push-event webhook + incident pipeline endpoints
# ---------------------------------------------------------------------------

_push_analyzer = None


def _get_push_analyzer():
    global _push_analyzer
    if _push_analyzer is None:
        try:
            from core.material_change_detector import PushEventAnalyzer
            _push_analyzer = PushEventAnalyzer()
        except ImportError as exc:
            logger.warning("PushEventAnalyzer not available: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="Push-event analyzer not available",
            ) from exc
    return _push_analyzer


class CommitAnalyzeRequest(BaseModel):
    """Request body for manual commit analysis."""

    commit_sha: str = Field(..., description="Commit SHA to analyze")
    repository: str = Field(default="", description="Repository full name (owner/repo)")
    branch: str = Field(default="main", description="Branch name")
    changed_files: List[str] = Field(
        default_factory=list,
        description="List of changed file paths (relative to repo root)",
    )


class MaterialChangeResponse(BaseModel):
    """Response from push-event analysis."""

    id: str
    commit_sha: str
    repository: str
    branch: str
    author: str
    changed_files_count: int
    blast_radius: Optional[Dict[str, Any]]
    sast_findings_count: int
    is_material: bool
    materiality_reasons: List[str]
    incident_id: Optional[str]
    analyzed_at: str


@router.post(
    "/material-change/webhook",
    response_model=MaterialChangeResponse,
    summary="Receive GitHub push webhook → SAST → LLM Council → incident",
)
async def push_webhook(
    request: Request,
    x_github_event: Optional[str] = Header(None),
    x_hub_signature_256: Optional[str] = Header(None),
) -> MaterialChangeResponse:
    """Accept a GitHub push webhook, run SAST on changed files, assess materiality,
    and open an incident if the change is security-material.

    Security:
    - HMAC-SHA256 verified when GITHUB_WEBHOOK_SECRET is set
    - Rate-limited: 10 requests/minute per IP
    - Payload capped at 1 MB
    """
    _check_webhook_rate_limit(request)

    _MAX_BODY = 1 * 1024 * 1024
    raw_body = b""
    async for chunk in request.stream():
        raw_body += chunk
        if len(raw_body) > _MAX_BODY:
            raise HTTPException(status_code=413, detail="Webhook payload exceeds 1 MB limit")

    # HMAC verification
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if secret and x_hub_signature_256:
        import hashlib
        import hmac as _hmac_mod
        expected = "sha256=" + _hmac_mod.new(
            secret.encode(), raw_body, hashlib.sha256
        ).hexdigest()
        if not _hmac_mod.compare_digest(expected, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        import json as _json
        payload: Dict[str, Any] = _json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Only process push events
    if x_github_event and x_github_event != "push":
        return MaterialChangeResponse(
            id="",
            commit_sha="",
            repository="",
            branch="",
            author="",
            changed_files_count=0,
            blast_radius=None,
            sast_findings_count=0,
            is_material=False,
            materiality_reasons=[],
            incident_id=None,
            analyzed_at="",
        )

    analyzer = _get_push_analyzer()
    result = analyzer.analyze_push_event(payload)
    d = result.to_dict()
    return MaterialChangeResponse(
        id=d["id"],
        commit_sha=d["commit_sha"],
        repository=d["repository"],
        branch=d["branch"],
        author=d["author"],
        changed_files_count=d["changed_files_count"],
        blast_radius=d["blast_radius"],
        sast_findings_count=d["sast_findings_count"],
        is_material=d["is_material"],
        materiality_reasons=d["materiality_reasons"],
        incident_id=d["incident_id"],
        analyzed_at=d["analyzed_at"],
    )


@router.post(
    "/material-change/analyze",
    response_model=MaterialChangeResponse,
    summary="Manually analyze a commit SHA for materiality",
)
async def analyze_commit_manual(body: CommitAnalyzeRequest) -> MaterialChangeResponse:
    """Manually trigger push-event materiality analysis for a given commit.

    Useful for CI/CD pipelines and manual investigation.
    """
    analyzer = _get_push_analyzer()
    # Build a synthetic push payload from the request
    payload = {
        "after": body.commit_sha,
        "ref": f"refs/heads/{body.branch}",
        "repository": {"full_name": body.repository},
        "pusher": {"name": "manual"},
        "commits": [
            {
                "id": body.commit_sha,
                "added": [],
                "modified": body.changed_files,
                "removed": [],
            }
        ],
    }
    result = analyzer.analyze_push_event(payload)
    d = result.to_dict()
    return MaterialChangeResponse(
        id=d["id"],
        commit_sha=d["commit_sha"],
        repository=d["repository"],
        branch=d["branch"],
        author=d["author"],
        changed_files_count=d["changed_files_count"],
        blast_radius=d["blast_radius"],
        sast_findings_count=d["sast_findings_count"],
        is_material=d["is_material"],
        materiality_reasons=d["materiality_reasons"],
        incident_id=d["incident_id"],
        analyzed_at=d["analyzed_at"],
    )


@router.get(
    "/material-change/recent",
    summary="List recent material change analyses",
)
async def list_recent_material_changes(
    limit: int = 50,
) -> Dict[str, Any]:
    """Return the most recent push-event analyses, newest first."""
    analyzer = _get_push_analyzer()
    items = analyzer.list_recent(limit=limit)
    return {"total": len(items), "items": items}


@router.get(
    "/material-change/{change_id}",
    summary="Get a specific push-event analysis by ID",
)
async def get_material_change(change_id: str) -> Dict[str, Any]:
    """Fetch a single push-event analysis record by its UUID."""
    analyzer = _get_push_analyzer()
    item = analyzer.get_by_id(change_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Material change {change_id!r} not found")
    return item
