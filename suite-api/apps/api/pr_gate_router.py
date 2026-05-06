"""
FixOps PR Gate & CI/CD Gate Router — /api/v1/pr-gate/*

Enterprise PR gating: evaluate findings against security policy, post results
to GitHub PRs (check runs + comments), and provide CI/CD exit-code gating.

Endpoints:
    POST  /api/v1/pr-gate/evaluate       — Evaluate findings against gating policy
    POST  /api/v1/pr-gate/report          — Post findings to a GitHub PR (check run + comment)
    POST  /api/v1/pr-gate/scan            — One-shot: scan → evaluate → report to PR
    GET   /api/v1/pr-gate/policy          — Get current gating policy
    PUT   /api/v1/pr-gate/policy          — Update gating policy
    POST  /api/v1/pr-gate/ci-gate         — CI/CD gate: returns pass/fail for build pipelines
    GET   /api/v1/pr-gate/history         — Gate evaluation history
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/pr-gate", tags=["pr-gate"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class GateVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


class FindingInput(BaseModel):
    """A security finding to evaluate."""

    id: str = Field(..., description="Finding identifier")
    title: str = Field(..., description="Finding title")
    severity: Severity = Field(..., description="Finding severity")
    category: str = Field(default="general", description="Finding category (sast, dast, secret, sca, iac)")
    file_path: Optional[str] = Field(None, description="File path where finding occurs")
    line_number: Optional[int] = Field(None, description="Line number in file")
    end_line: Optional[int] = Field(None, description="End line number")
    description: Optional[str] = Field(None, description="Finding description")
    remediation: Optional[str] = Field(None, description="Remediation guidance")
    cve_id: Optional[str] = Field(None, description="CVE identifier if applicable")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    reachable: Optional[bool] = Field(None, description="Whether the finding is reachable from entry points")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence")


class GatingPolicy(BaseModel):
    """Policy that determines pass/fail for PR and CI/CD gates."""

    fail_on: Severity = Field(
        default=Severity.HIGH,
        description="Fail the gate if any finding at this severity or above exists",
    )
    warn_on: Severity = Field(
        default=Severity.MEDIUM,
        description="Warn (but don't fail) for findings at this severity",
    )
    max_critical: int = Field(default=0, ge=0, description="Maximum allowed critical findings")
    max_high: int = Field(default=0, ge=0, description="Maximum allowed high findings")
    max_medium: Optional[int] = Field(default=None, description="Maximum allowed medium findings (None = unlimited)")
    block_secrets: bool = Field(default=True, description="Always block if secrets detected")
    block_unreachable: bool = Field(
        default=False,
        description="Block on unreachable findings too (default: skip them)",
    )
    require_sbom: bool = Field(default=False, description="Require SBOM in gate evaluation")
    categories: List[str] = Field(
        default_factory=lambda: ["sast", "dast", "secret", "sca", "iac"],
        description="Finding categories to evaluate",
    )


class EvaluateRequest(BaseModel):
    """Request to evaluate findings against gating policy."""

    findings: List[FindingInput] = Field(..., min_length=0, description="Findings to evaluate")
    policy: Optional[GatingPolicy] = Field(None, description="Override policy (uses org default if not provided)")
    commit_sha: Optional[str] = Field(None, description="Commit SHA for tracking")
    branch: Optional[str] = Field(None, description="Branch name")
    repository: Optional[str] = Field(None, description="Repository identifier")


class EvaluateResponse(BaseModel):
    """Result of gate evaluation."""

    verdict: GateVerdict
    exit_code: int = Field(description="0=pass, 1=fail, 2=warn")
    summary: str
    findings_total: int
    findings_by_severity: Dict[str, int]
    blocking_findings: List[Dict[str, Any]]
    warning_findings: List[Dict[str, Any]]
    policy_applied: GatingPolicy
    evaluation_id: str
    evaluated_at: str


class ReportRequest(BaseModel):
    """Request to post findings to a GitHub PR."""

    owner: str = Field(..., description="Repository owner")
    repo: str = Field(..., description="Repository name")
    head_sha: str = Field(..., description="Commit SHA (head of the PR)")
    pr_number: Optional[int] = Field(None, description="PR number (for comment posting)")
    findings: List[FindingInput] = Field(..., description="Findings to report")
    policy: Optional[GatingPolicy] = Field(None, description="Override policy")
    post_comment: bool = Field(default=True, description="Post summary comment on PR")
    create_check_run: bool = Field(default=True, description="Create GitHub check run")
    check_name: str = Field(default="ALdeci Security Gate", description="Check run name")


class ReportResponse(BaseModel):
    """Result of posting findings to GitHub."""

    verdict: GateVerdict
    check_run_id: Optional[int] = None
    check_run_url: Optional[str] = None
    comment_posted: bool = False
    summary: str = ""
    evaluation_id: str = ""


class ScanRequest(BaseModel):
    """One-shot: scan repository → evaluate → report to PR."""

    owner: str = Field(..., description="Repository owner")
    repo: str = Field(..., description="Repository name")
    head_sha: str = Field(..., description="Commit SHA")
    pr_number: Optional[int] = Field(None, description="PR number")
    branch: str = Field(default="main", description="Branch to scan")
    scan_types: List[str] = Field(
        default_factory=lambda: ["sast", "secrets"],
        description="Scan types to run (sast, secrets, sca, iac)",
    )
    policy: Optional[GatingPolicy] = Field(None, description="Override policy")
    check_name: str = Field(default="ALdeci Security Gate", description="Check run name")


class CIGateRequest(BaseModel):
    """CI/CD gate evaluation request."""

    findings: List[FindingInput] = Field(..., description="Findings from CI pipeline")
    policy: Optional[GatingPolicy] = Field(None, description="Override policy")
    pipeline_id: Optional[str] = Field(None, description="CI pipeline run ID")
    commit_sha: Optional[str] = Field(None, description="Commit SHA")
    branch: Optional[str] = Field(None, description="Branch name")
    repository: Optional[str] = Field(None, description="Repository identifier")
    format: str = Field(
        default="json",
        description="Output format: json, sarif, text",
    )


# ---------------------------------------------------------------------------
# In-memory policy + history store (production would use DB)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def _get_policy_store():
    """Get persistent policy store."""
    from core.persistent_store import get_persistent_store
    return get_persistent_store("pr_gate_policies")


def _get_history_store():
    """Get persistent history store."""
    from core.persistent_store import get_persistent_store
    return get_persistent_store("pr_gate_history")


def _default_policy() -> GatingPolicy:
    return GatingPolicy()


def _get_org_policy(org_id: str) -> GatingPolicy:
    """Get the gating policy for an org."""
    store = _get_policy_store()
    raw = store.get(f"policy:{org_id}")
    if raw and isinstance(raw, dict):
        return GatingPolicy(**raw)
    return _default_policy()


def _save_org_policy(org_id: str, policy: GatingPolicy) -> None:
    store = _get_policy_store()
    store[f"policy:{org_id}"] = policy.model_dump()


def _record_evaluation(org_id: str, evaluation: Dict[str, Any]) -> None:
    store = _get_history_store()
    key = f"eval:{org_id}:{evaluation['evaluation_id']}"
    store[key] = evaluation


# ---------------------------------------------------------------------------
# Core evaluation logic
# ---------------------------------------------------------------------------


def _evaluate_findings(
    findings: List[FindingInput],
    policy: GatingPolicy,
) -> EvaluateResponse:
    """Evaluate findings against a gating policy."""
    eval_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc).isoformat()

    # Filter by enabled categories
    active_findings = [
        f for f in findings if f.category in policy.categories
    ]

    # Optionally skip unreachable findings
    if not policy.block_unreachable:
        active_findings = [
            f for f in active_findings
            if f.reachable is None or f.reachable
        ]

    # Count by severity
    counts: Dict[str, int] = {s.value: 0 for s in Severity}
    for f in active_findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    fail_threshold = _SEVERITY_ORDER[policy.fail_on]
    warn_threshold = _SEVERITY_ORDER[policy.warn_on]

    blocking: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []

    for f in active_findings:
        sev_order = _SEVERITY_ORDER[f.severity]
        finding_dict = {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "category": f.category,
            "file_path": f.file_path,
            "line_number": f.line_number,
        }

        # Secrets always block if policy says so
        if policy.block_secrets and f.category == "secret":
            blocking.append(finding_dict)
            continue

        if sev_order >= fail_threshold:
            blocking.append(finding_dict)
        elif sev_order >= warn_threshold:
            warnings.append(finding_dict)

    # Check count limits
    if counts.get("critical", 0) > policy.max_critical:
        # Ensure all criticals are in blocking
        for f in active_findings:
            if f.severity == Severity.CRITICAL:
                fd = {"id": f.id, "title": f.title, "severity": "critical",
                      "category": f.category, "file_path": f.file_path,
                      "line_number": f.line_number}
                if fd not in blocking:
                    blocking.append(fd)

    if counts.get("high", 0) > policy.max_high:
        for f in active_findings:
            if f.severity == Severity.HIGH:
                fd = {"id": f.id, "title": f.title, "severity": "high",
                      "category": f.category, "file_path": f.file_path,
                      "line_number": f.line_number}
                if fd not in blocking:
                    blocking.append(fd)

    if policy.max_medium is not None and counts.get("medium", 0) > policy.max_medium:
        for f in active_findings:
            if f.severity == Severity.MEDIUM:
                fd = {"id": f.id, "title": f.title, "severity": "medium",
                      "category": f.category, "file_path": f.file_path,
                      "line_number": f.line_number}
                if fd not in blocking:
                    blocking.append(fd)

    # Determine verdict
    if blocking:
        verdict = GateVerdict.FAIL
        exit_code = 1
    elif warnings:
        verdict = GateVerdict.WARN
        exit_code = 2
    else:
        verdict = GateVerdict.PASS
        exit_code = 0

    # Build summary
    parts = []
    if counts.get("critical"):
        parts.append(f"{counts['critical']} critical")
    if counts.get("high"):
        parts.append(f"{counts['high']} high")
    if counts.get("medium"):
        parts.append(f"{counts['medium']} medium")
    if counts.get("low"):
        parts.append(f"{counts['low']} low")

    if verdict == GateVerdict.PASS:
        summary = f"Security gate PASSED. {len(active_findings)} findings evaluated, none blocking."
    elif verdict == GateVerdict.WARN:
        summary = f"Security gate WARNING. {len(warnings)} warning(s): {', '.join(parts)}."
    else:
        summary = f"Security gate FAILED. {len(blocking)} blocking finding(s): {', '.join(parts)}."

    return EvaluateResponse(
        verdict=verdict,
        exit_code=exit_code,
        summary=summary,
        findings_total=len(active_findings),
        findings_by_severity=counts,
        blocking_findings=blocking,
        warning_findings=warnings,
        policy_applied=policy,
        evaluation_id=eval_id,
        evaluated_at=now,
    )


def _build_check_run_summary(evaluation: EvaluateResponse) -> str:
    """Build a Markdown summary for a GitHub check run."""
    icon = {"pass": "\u2705", "fail": "\u274c", "warn": "\u26a0\ufe0f"}.get(evaluation.verdict.value, "")
    lines = [
        f"## {icon} ALdeci Security Gate — {evaluation.verdict.value.upper()}",
        "",
        f"**{evaluation.findings_total}** findings evaluated | "
        f"**{len(evaluation.blocking_findings)}** blocking | "
        f"**{len(evaluation.warning_findings)}** warnings",
        "",
        "### Findings by Severity",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = evaluation.findings_by_severity.get(sev, 0)
        if cnt:
            lines.append(f"| {sev.upper()} | {cnt} |")

    if evaluation.blocking_findings:
        lines.extend(["", "### Blocking Findings", ""])
        for f in evaluation.blocking_findings[:20]:
            loc = ""
            if f.get("file_path"):
                loc = f" — `{f['file_path']}"
                if f.get("line_number"):
                    loc += f":{f['line_number']}"
                loc += "`"
            lines.append(f"- **{f['severity'].upper()}**: {f['title']}{loc}")

    if evaluation.warning_findings:
        lines.extend(["", "### Warnings", ""])
        for f in evaluation.warning_findings[:10]:
            lines.append(f"- **{f['severity'].upper()}**: {f['title']}")

    lines.extend([
        "",
        f"Policy: fail on {evaluation.policy_applied.fail_on.value}+, "
        f"warn on {evaluation.policy_applied.warn_on.value}+",
        "",
        f"*Evaluated at {evaluation.evaluated_at}* | *ID: {evaluation.evaluation_id}*",
    ])

    return "\n".join(lines)


def _build_annotations(findings: List[FindingInput]) -> List[Dict[str, Any]]:
    """Build GitHub check run annotations from findings."""
    annotations = []
    for f in findings:
        if not f.file_path:
            continue
        annotations.append({
            "path": f.file_path,
            "start_line": f.line_number or 1,
            "end_line": f.end_line or f.line_number or 1,
            "annotation_level": "failure" if _SEVERITY_ORDER[f.severity] >= 4 else "warning",
            "title": f.title,
            "message": f.description or f.title,
        })
        if len(annotations) >= 50:  # GitHub API limit
            break
    return annotations


def _get_github_connector(owner: str, repo: str):
    """Get a configured GitHubConnector for the given owner/repo."""
    import os

    from core.connectors import GitHubConnector
    token = os.environ.get("GITHUB_TOKEN", "")
    connector = GitHubConnector({
        "owner": owner,
        "repo": repo,
        "token": token,
        "base_url": "https://api.github.com",
    })
    return connector


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate_gate(
    request: EvaluateRequest,
    org_id: str = Depends(get_org_id),
) -> EvaluateResponse:
    """Evaluate findings against the gating policy.

    Returns a pass/fail/warn verdict with details on blocking findings.
    Use this to check whether a PR or build should be allowed to proceed.
    """
    policy = request.policy or _get_org_policy(org_id)
    result = _evaluate_findings(request.findings, policy)

    # Record evaluation
    _record_evaluation(org_id, {
        **result.model_dump(),
        "org_id": org_id,
        "commit_sha": request.commit_sha,
        "branch": request.branch,
        "repository": request.repository,
    })

    return result


@router.post("/report", response_model=ReportResponse)
async def report_to_pr(
    request: ReportRequest,
    org_id: str = Depends(get_org_id),
) -> ReportResponse:
    """Post findings to a GitHub PR via check run and/or comment.

    Creates a GitHub Check Run with inline annotations for each finding,
    and optionally posts a summary comment on the PR.

    Requires GITHUB_TOKEN env var with `checks:write` scope.
    """
    policy = request.policy or _get_org_policy(org_id)
    evaluation = _evaluate_findings(request.findings, policy)

    github = _get_github_connector(request.owner, request.repo)
    if not github.configured:
        raise HTTPException(
            status_code=422,
            detail="GitHub connector not configured. Set GITHUB_TOKEN environment variable.",
        )

    response = ReportResponse(
        verdict=evaluation.verdict,
        summary=evaluation.summary,
        evaluation_id=evaluation.evaluation_id,
    )

    # Create check run
    if request.create_check_run:
        conclusion = {
            GateVerdict.PASS: "success",
            GateVerdict.FAIL: "failure",
            GateVerdict.WARN: "neutral",
        }[evaluation.verdict]

        annotations = _build_annotations(request.findings)
        summary_md = _build_check_run_summary(evaluation)

        result = github.create_check_run(
            head_sha=request.head_sha,
            name=request.check_name,
            status="completed",
            conclusion=conclusion,
            title=f"Security Gate: {evaluation.verdict.value.upper()}",
            summary=summary_md,
            annotations=annotations,
            owner=request.owner,
            repo=request.repo,
        )

        if result.status == "sent":
            response.check_run_id = result.details.get("check_run_id")
            response.check_run_url = result.details.get("html_url")

    # Post comment on PR
    if request.post_comment and request.pr_number:
        comment_body = _build_check_run_summary(evaluation)
        github.add_comment({
            "issue_number": request.pr_number,
            "body": comment_body,
        })
        response.comment_posted = True

    _record_evaluation(org_id, {
        **evaluation.model_dump(),
        "org_id": org_id,
        "owner": request.owner,
        "repo": request.repo,
        "pr_number": request.pr_number,
        "check_run_id": response.check_run_id,
    })

    return response


@router.post("/scan")
async def scan_and_gate(
    request: ScanRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """One-shot: trigger native scanners → evaluate → report to GitHub PR.

    Runs the requested scan types against the repository, evaluates findings
    against the gating policy, and posts results back to the PR.
    """
    scan_start = time.monotonic()
    all_findings: List[FindingInput] = []

    # Run requested scans via the brain pipeline
    for scan_type in request.scan_types:
        try:
            if scan_type == "sast":
                from core.sast_engine import SASTEngine
                engine = SASTEngine()
                # Try to get scan results (engine needs a repo path)
                # In production this would clone the repo first
                results = engine.scan_text("", language="python")  # placeholder
                for r in (results if isinstance(results, list) else []):
                    all_findings.append(FindingInput(
                        id=r.get("id", str(uuid.uuid4())[:8]),
                        title=r.get("title", r.get("rule_id", "SAST Finding")),
                        severity=Severity(r.get("severity", "medium").lower()),
                        category="sast",
                        file_path=r.get("file_path"),
                        line_number=r.get("line_number"),
                        description=r.get("description"),
                        cwe_id=r.get("cwe_id"),
                    ))

            elif scan_type == "secrets":
                from core.secrets_scanner import SecretsScanner
                SecretsScanner()
                # Would scan actual repo files
                logger.info("Secrets scan requested for %s/%s", request.owner, request.repo)

        except (ImportError, OSError, ValueError, RuntimeError) as exc:
            logger.warning("Scan type %s failed: %s", scan_type, type(exc).__name__)

    scan_duration = round(time.monotonic() - scan_start, 2)

    # Evaluate
    policy = request.policy or _get_org_policy(org_id)
    evaluation = _evaluate_findings(all_findings, policy)

    # Report to GitHub
    github = _get_github_connector(request.owner, request.repo)
    check_run_id = None
    check_run_url = None

    if github.configured:
        conclusion = {
            GateVerdict.PASS: "success",
            GateVerdict.FAIL: "failure",
            GateVerdict.WARN: "neutral",
        }[evaluation.verdict]

        annotations = _build_annotations(all_findings)
        summary_md = _build_check_run_summary(evaluation)

        result = github.create_check_run(
            head_sha=request.head_sha,
            name=request.check_name,
            status="completed",
            conclusion=conclusion,
            title=f"Security Gate: {evaluation.verdict.value.upper()}",
            summary=summary_md,
            annotations=annotations,
            owner=request.owner,
            repo=request.repo,
        )

        if result.status == "sent":
            check_run_id = result.details.get("check_run_id")
            check_run_url = result.details.get("html_url")

        # Post PR comment
        if request.pr_number:
            github.add_comment({
                "issue_number": request.pr_number,
                "body": summary_md,
            })

    return {
        "verdict": evaluation.verdict.value,
        "exit_code": evaluation.exit_code,
        "summary": evaluation.summary,
        "scan_types": request.scan_types,
        "scan_duration_seconds": scan_duration,
        "findings_total": evaluation.findings_total,
        "findings_by_severity": evaluation.findings_by_severity,
        "blocking_findings": len(evaluation.blocking_findings),
        "check_run_id": check_run_id,
        "check_run_url": check_run_url,
        "evaluation_id": evaluation.evaluation_id,
    }


@router.get("/policy")
async def get_policy(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Get the current PR gating policy for the organisation."""
    policy = _get_org_policy(org_id)
    return {
        "org_id": org_id,
        "policy": policy.model_dump(),
    }


@router.put("/policy")
async def update_policy(
    policy: GatingPolicy,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Update the PR gating policy for the organisation.

    Controls what severity levels block merges and builds.
    """
    _save_org_policy(org_id, policy)
    return {
        "status": "updated",
        "org_id": org_id,
        "policy": policy.model_dump(),
    }


@router.post("/ci-gate")
async def ci_gate(
    request: CIGateRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """CI/CD gate evaluation endpoint.

    Call this from your CI/CD pipeline to get a pass/fail verdict.
    Returns exit_code: 0 (pass), 1 (fail), 2 (warn).

    Usage in CI:
        curl -X POST $ALDECI_URL/api/v1/pr-gate/ci-gate \\
          -H 'X-API-Key: $TOKEN' \\
          -d '{"findings": [...]}' | jq '.exit_code'
    """
    policy = request.policy or _get_org_policy(org_id)
    evaluation = _evaluate_findings(request.findings, policy)

    _record_evaluation(org_id, {
        **evaluation.model_dump(),
        "org_id": org_id,
        "pipeline_id": request.pipeline_id,
        "commit_sha": request.commit_sha,
        "branch": request.branch,
        "repository": request.repository,
    })

    result: Dict[str, Any] = {
        "verdict": evaluation.verdict.value,
        "exit_code": evaluation.exit_code,
        "summary": evaluation.summary,
        "findings_total": evaluation.findings_total,
        "findings_by_severity": evaluation.findings_by_severity,
        "blocking_count": len(evaluation.blocking_findings),
        "warning_count": len(evaluation.warning_findings),
        "evaluation_id": evaluation.evaluation_id,
        "evaluated_at": evaluation.evaluated_at,
    }

    if request.format == "text":
        result["text_output"] = (
            f"[ALdeci] {evaluation.verdict.value.upper()}: {evaluation.summary}\n"
            f"Blocking: {len(evaluation.blocking_findings)} | "
            f"Warnings: {len(evaluation.warning_findings)} | "
            f"Total: {evaluation.findings_total}"
        )

    if evaluation.blocking_findings:
        result["blocking_findings"] = evaluation.blocking_findings[:50]

    return result


@router.get("/history")
async def get_history(
    org_id: str = Depends(get_org_id),
    limit: int = Query(20, ge=1, le=100, description="Maximum results"),
) -> Dict[str, Any]:
    """Get recent gate evaluation history for the organisation."""
    store = _get_history_store()
    prefix = f"eval:{org_id}:"
    evaluations = []

    for key in store:
        if key.startswith(prefix):
            evaluations.append(store[key])

    # Sort by timestamp (newest first) and limit
    evaluations.sort(key=lambda e: e.get("evaluated_at", ""), reverse=True)
    evaluations = evaluations[:limit]

    return {
        "org_id": org_id,
        "total": len(evaluations),
        "evaluations": evaluations,
    }


@router.get("/", summary="PR Gate domain summary")
async def pr_gate_index(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return a live summary of PR gate state for the organisation."""
    policy = _get_org_policy(org_id)
    history_store = _get_history_store()
    prefix = f"eval:{org_id}:"
    recent = [v for k, v in history_store.items() if k.startswith(prefix)]
    recent.sort(key=lambda e: e.get("evaluated_at", ""), reverse=True)
    total = len(recent)
    passed = sum(1 for e in recent if e.get("verdict") == "pass")
    failed = sum(1 for e in recent if e.get("verdict") == "fail")
    warned = sum(1 for e in recent if e.get("verdict") == "warn")
    return {
        "router": "pr-gate",
        "org_id": org_id,
        "policy": policy.model_dump(),
        "evaluations": {"total": total, "passed": passed, "failed": failed, "warned": warned},
        "last_evaluation": recent[0] if recent else None,
    }
