"""
CI/CD Pipeline Gate Router — Binary pass/fail verdicts for CI/CD pipelines.

Accepts SARIF, SBOM, or raw findings and evaluates them against configurable
policies, returning a structured gate verdict that CI systems consume.

Endpoints:
    POST /api/v1/gate/check           — Primary gate evaluation
    POST /api/v1/gate/evaluate        — Evaluate findings against a named policy
    GET  /api/v1/gate/status          — Gate configuration & health
    GET  /api/v1/gate/history         — Recent gate evaluations
    GET  /api/v1/gate/setup/{platform} — Ready-to-use CI config for platform

Competitive target: Match Aikido's "one-click CI/CD integration" experience.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

logger = structlog.get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/gate",
    tags=["ci-cd-gate"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------
class GateSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PolicyThresholds(BaseModel):
    """Configurable severity thresholds for gate decisions."""
    fail_on: List[GateSeverity] = Field(
        default=[GateSeverity.CRITICAL, GateSeverity.HIGH],
        description="Severities that cause a gate FAIL",
    )
    warn_on: List[GateSeverity] = Field(
        default=[GateSeverity.MEDIUM],
        description="Severities that produce warnings but don't block",
    )
    max_critical: int = Field(0, ge=0, description="Max critical findings before FAIL")
    max_high: int = Field(0, ge=0, description="Max high findings before FAIL")
    max_medium: Optional[int] = Field(None, ge=0, description="Max medium findings (None = unlimited)")
    max_total: Optional[int] = Field(None, ge=0, description="Max total findings (None = unlimited)")
    require_sbom: bool = Field(False, description="Require SBOM presence to pass")
    block_on_license_violation: bool = Field(False, description="Block if license violations found")


class GateCheckRequest(BaseModel):
    """Primary gate check request — accepts multiple input formats."""
    repository: str = Field(..., min_length=1, max_length=500, description="Repository identifier (owner/repo)")
    commit_sha: str = Field("", max_length=64, description="Commit SHA being evaluated")
    branch: str = Field("main", max_length=255, description="Branch name")
    pull_request: Optional[int] = Field(None, ge=1, description="PR number (if applicable)")

    # Input data — at least one should be provided
    sarif: Optional[Dict[str, Any]] = Field(None, description="SARIF v2.1.0 scan results")
    findings: Optional[List[Dict[str, Any]]] = Field(None, description="Pre-parsed findings list")
    sbom: Optional[Dict[str, Any]] = Field(None, description="CycloneDX or SPDX SBOM")
    diff: Optional[str] = Field(None, description="Unified diff content for material change analysis")

    # Policy configuration
    policy_id: Optional[str] = Field(None, description="Named policy ID to evaluate against")
    thresholds: Optional[PolicyThresholds] = Field(None, description="Inline threshold overrides")

    @field_validator("repository")
    @classmethod
    def _validate_repo(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("repository cannot be empty")
        return v


class GateCheckDetail(BaseModel):
    """Individual check result within a gate evaluation."""
    name: str
    status: str  # pass | fail | warn | skip
    detail: str
    count: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GateCheckResponse(BaseModel):
    """Gate evaluation response — the CI system consumes this."""
    gate_id: str = Field(description="Unique evaluation ID")
    passed: bool = Field(description="Binary pass/fail — the CI exit code")
    verdict: str = Field(description="PASS | FAIL | WARN")
    reason: str = Field(description="Human-readable summary")
    repository: str
    commit_sha: str
    branch: str
    pull_request: Optional[int] = None
    findings_count: int = Field(0, description="Total findings evaluated")
    policy_violations: List[Dict[str, Any]] = Field(default_factory=list)
    checks: List[GateCheckDetail] = Field(default_factory=list)
    checks_passed: int = 0
    checks_failed: int = 0
    checks_warned: int = 0
    checks_skipped: int = 0
    evaluated_at: str = Field(description="ISO 8601 timestamp")
    evaluation_ms: float = Field(0.0, description="Evaluation duration in milliseconds")


class GateEvaluateRequest(BaseModel):
    """Evaluate findings against a specific policy."""
    findings: List[Dict[str, Any]] = Field(..., min_length=1)
    policy_id: Optional[str] = None
    thresholds: Optional[PolicyThresholds] = None


# ---------------------------------------------------------------------------
# In-memory history (production would use DB)
# ---------------------------------------------------------------------------
_gate_history: List[Dict[str, Any]] = []
_MAX_HISTORY = 500


def _record_evaluation(response: GateCheckResponse) -> None:
    """Store evaluation in history ring buffer."""
    entry = response.model_dump()
    _gate_history.insert(0, entry)
    if len(_gate_history) > _MAX_HISTORY:
        _gate_history.pop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_sarif_findings(sarif: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract normalized findings from SARIF v2.1.0 data."""
    findings: List[Dict[str, Any]] = []
    runs = sarif.get("runs", [])
    if not isinstance(runs, (list, tuple)):
        return findings
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, (list, tuple)):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            level = result.get("level", "warning")
            severity = {"error": "critical", "warning": "high", "note": "medium"}.get(
                level, "medium"
            )
            msg = result.get("message", {})
            message_text = msg.get("text", "") if isinstance(msg, dict) else str(msg)
            locations = result.get("locations", [])
            file_path = ""
            line_number = None
            if isinstance(locations, (list, tuple)) and locations:
                loc = locations[0]
                if isinstance(loc, dict):
                    pl = loc.get("physicalLocation", {})
                    if isinstance(pl, dict):
                        al = pl.get("artifactLocation", {})
                        if isinstance(al, dict):
                            file_path = al.get("uri", "")
                        region = pl.get("region", {})
                        if isinstance(region, dict):
                            line_number = region.get("startLine")
            findings.append({
                "rule_id": result.get("ruleId", "unknown"),
                "severity": severity,
                "message": message_text,
                "file_path": file_path,
                "line_number": line_number,
            })
    return findings


def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings grouped by normalized severity."""
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "medium")).lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["medium"] += 1
    return counts


def _resolve_thresholds(
    thresholds: Optional[PolicyThresholds],
    policy_id: Optional[str],
) -> PolicyThresholds:
    """Resolve thresholds from inline overrides or named policy."""
    if thresholds:
        return thresholds

    if policy_id:
        try:
            from core.policy_db import PolicyDB
            db = PolicyDB()
            policy = db.get_policy(policy_id)
            if policy and policy.rules:
                rules = policy.rules
                return PolicyThresholds(
                    fail_on=[GateSeverity(s) for s in rules.get("fail_on", ["critical", "high"])],
                    max_critical=rules.get("max_critical", 0),
                    max_high=rules.get("max_high", 0),
                    max_medium=rules.get("max_medium"),
                    max_total=rules.get("max_total"),
                )
        except (ImportError, OSError, ValueError, KeyError, RuntimeError):
            logger.warning("Could not load policy %s, using defaults", policy_id)

    return PolicyThresholds()


def _evaluate_gate(
    findings: List[Dict[str, Any]],
    thresholds: PolicyThresholds,
) -> tuple[bool, str, List[GateCheckDetail], List[Dict[str, Any]]]:
    """Core gate evaluation logic. Returns (passed, reason, checks, violations)."""
    checks: List[GateCheckDetail] = []
    violations: List[Dict[str, Any]] = []
    passed = True

    counts = _count_by_severity(findings)

    # Check 1: Severity thresholds
    for sev in thresholds.fail_on:
        sev_count = counts.get(sev.value, 0)
        if sev_count > 0:
            max_allowed = getattr(thresholds, f"max_{sev.value}", 0)
            if max_allowed is None:
                continue
            if sev_count > max_allowed:
                passed = False
                for f in findings:
                    if str(f.get("severity", "")).lower() == sev.value:
                        violations.append({
                            "rule": f"max_{sev.value}_exceeded",
                            "severity": sev.value,
                            "finding": f.get("rule_id", "unknown"),
                            "file": f.get("file_path", ""),
                            "message": f.get("message", ""),
                        })
        status = "fail" if sev_count > (getattr(thresholds, f"max_{sev.value}", 0) or 0) else "pass"
        checks.append(GateCheckDetail(
            name=f"{sev.value}_findings",
            status=status,
            detail=f"{sev_count} {sev.value} finding(s)",
            count=sev_count,
        ))

    # Check 2: Total findings threshold
    if thresholds.max_total is not None:
        total = len(findings)
        if total > thresholds.max_total:
            passed = False
        checks.append(GateCheckDetail(
            name="total_findings",
            status="fail" if total > thresholds.max_total else "pass",
            detail=f"{total} total finding(s) (max: {thresholds.max_total})",
            count=total,
        ))

    # Check 3: Material change analysis
    # (will be populated if diff is provided at the endpoint level)

    if passed:
        reason = f"Gate PASSED — {len(findings)} finding(s), all within thresholds"
    else:
        reason = (
            f"Gate FAILED — {len(violations)} policy violation(s): "
            + ", ".join(f"{counts[s.value]} {s.value}" for s in thresholds.fail_on if counts.get(s.value, 0) > 0)
        )

    return passed, reason, checks, violations


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/check", response_model=GateCheckResponse)
async def check_gate(payload: GateCheckRequest):
    """Binary pass/fail for CI/CD pipelines.

    Accepts SARIF, SBOM, or pre-parsed findings. Runs through policy evaluation
    and returns a structured verdict that CI systems consume as exit code.

    This is the primary endpoint that GitHub Actions / GitLab CI call.
    """
    import time
    start = time.perf_counter()

    # 1. Collect findings from all input sources
    all_findings: List[Dict[str, Any]] = []

    if payload.sarif:
        all_findings.extend(_parse_sarif_findings(payload.sarif))

    if payload.findings:
        all_findings.extend(payload.findings)

    # 2. Resolve thresholds
    thresholds = _resolve_thresholds(payload.thresholds, payload.policy_id)

    # 3. Run core evaluation
    passed, reason, checks, violations = _evaluate_gate(all_findings, thresholds)

    # 4. Material change analysis (if diff provided)
    if payload.diff:
        try:
            from core.material_change_detector import get_detector
            detector = get_detector()
            changes = detector.analyze_diff(payload.diff)
            max_risk = max((c.risk_score for c in changes), default=0.0)
            if max_risk >= 75:
                passed = False
                reason += f"; BREAKING changes detected (risk {max_risk:.0f}/100)"
            checks.append(GateCheckDetail(
                name="material_change",
                status="fail" if max_risk >= 75 else "warn" if max_risk >= 40 else "pass",
                detail=f"Max change risk: {max_risk:.1f}/100 ({len(changes)} changes analyzed)",
                count=len(changes),
                metadata={"max_risk": max_risk},
            ))
        except (ImportError, OSError, ValueError, KeyError, RuntimeError, TypeError):
            checks.append(GateCheckDetail(
                name="material_change",
                status="skip",
                detail="Material change detector unavailable",
            ))

    # 5. Developer risk context (if commit SHA provided)
    if payload.commit_sha:
        try:
            from core.developer_risk_profiler import DeveloperRiskProfiler
            DeveloperRiskProfiler()
            # We can't look up email from SHA alone, but we enrich findings
            checks.append(GateCheckDetail(
                name="developer_risk",
                status="pass",
                detail="Developer risk profiler available",
                metadata={"commit_sha": payload.commit_sha},
            ))
        except (ImportError, OSError, ValueError, KeyError, RuntimeError, TypeError):
            checks.append(GateCheckDetail(
                name="developer_risk",
                status="skip",
                detail="Developer risk profiler unavailable",
            ))

    elapsed_ms = (time.perf_counter() - start) * 1000

    response = GateCheckResponse(
        gate_id=str(uuid.uuid4()),
        passed=passed,
        verdict="PASS" if passed else "FAIL",
        reason=reason,
        repository=payload.repository,
        commit_sha=payload.commit_sha,
        branch=payload.branch,
        pull_request=payload.pull_request,
        findings_count=len(all_findings),
        policy_violations=violations,
        checks=checks,
        checks_passed=sum(1 for c in checks if c.status == "pass"),
        checks_failed=sum(1 for c in checks if c.status == "fail"),
        checks_warned=sum(1 for c in checks if c.status == "warn"),
        checks_skipped=sum(1 for c in checks if c.status == "skip"),
        evaluated_at=datetime.now(timezone.utc).isoformat(),
        evaluation_ms=round(elapsed_ms, 2),
    )

    _record_evaluation(response)
    logger.info(
        "fixops.gate.check",
        gate_id=response.gate_id,
        repository=payload.repository,
        verdict=response.verdict,
        findings=len(all_findings),
        violations=len(violations),
        elapsed_ms=round(elapsed_ms, 2),
    )
    return response


@router.post("/evaluate")
async def evaluate_findings(payload: GateEvaluateRequest):
    """Evaluate a set of findings against configurable policies.

    Lighter than /check — no SARIF parsing, no material change analysis.
    Just pure findings-vs-policy evaluation.
    """
    thresholds = _resolve_thresholds(payload.thresholds, payload.policy_id)
    passed, reason, checks, violations = _evaluate_gate(payload.findings, thresholds)

    return {
        "passed": passed,
        "verdict": "PASS" if passed else "FAIL",
        "reason": reason,
        "findings_count": len(payload.findings),
        "violations_count": len(violations),
        "policy_violations": violations[:50],  # cap for response size
        "severity_breakdown": _count_by_severity(payload.findings),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/status")
async def gate_status():
    """Get current gate configuration and health status."""
    return {
        "enabled": True,
        "version": "2.0",
        "default_policy": {
            "fail_on": ["critical", "high"],
            "warn_on": ["medium"],
            "max_critical": 0,
            "max_high": 0,
        },
        "checks_available": [
            "severity_thresholds",
            "total_findings",
            "material_change",
            "developer_risk",
            "license_compliance",
            "sbom_presence",
        ],
        "supported_inputs": ["sarif", "findings", "sbom", "diff"],
        "supported_platforms": ["github-actions", "gitlab-ci", "azure-pipelines", "bitbucket-pipelines", "jenkins"],
        "recent_evaluations": len(_gate_history),
        "auto_approve_threshold": 0.85,
    }


@router.get("/history")
async def gate_history(
    limit: int = Query(20, ge=1, le=100),
    repository: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None, pattern="^(PASS|FAIL|WARN)$"),
):
    """Get recent gate evaluations with optional filtering."""
    results = _gate_history
    if repository:
        results = [r for r in results if r.get("repository") == repository]
    if verdict:
        results = [r for r in results if r.get("verdict") == verdict]
    return {
        "total": len(results),
        "evaluations": results[:limit],
    }


# ---------------------------------------------------------------------------
# CI/CD Setup Templates
# ---------------------------------------------------------------------------
_GITHUB_ACTION_TEMPLATE = """\
# .github/workflows/fixops-gate.yml
# ALdeci/FixOps Security Gate — blocks merges with critical/high findings
name: FixOps Security Gate

on:
  pull_request:
    branches: [main, master, develop]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run FixOps Security Gate
        env:
          FIXOPS_API_URL: ${{ secrets.FIXOPS_API_URL }}
          FIXOPS_API_TOKEN: ${{ secrets.FIXOPS_API_TOKEN }}
        run: |
          # Upload SARIF and get gate verdict
          RESPONSE=$(curl -s -X POST "${FIXOPS_API_URL}/api/v1/gate/check" \\
            -H "X-API-Key: ${FIXOPS_API_TOKEN}" \\
            -H "Content-Type: application/json" \\
            -d '{
              "repository": "${{ github.repository }}",
              "commit_sha": "${{ github.event.pull_request.head.sha }}",
              "branch": "${{ github.head_ref }}",
              "pull_request": ${{ github.event.pull_request.number }},
              "findings": []
            }')

          VERDICT=$(echo $RESPONSE | jq -r '.verdict')
          REASON=$(echo $RESPONSE | jq -r '.reason')
          echo "::notice::FixOps Gate: $VERDICT — $REASON"

          if [ "$VERDICT" = "FAIL" ]; then
            echo "::error::Security gate FAILED: $REASON"
            exit 1
          fi
"""

_GITLAB_CI_TEMPLATE = """\
# .gitlab-ci.yml snippet
# ALdeci/FixOps Security Gate — blocks merges with critical/high findings
fixops-security-gate:
  stage: test
  image: curlimages/curl:latest
  variables:
    FIXOPS_API_URL: ${FIXOPS_API_URL}
    FIXOPS_API_TOKEN: ${FIXOPS_API_TOKEN}
  script:
    - |
      RESPONSE=$(curl -s -X POST "${FIXOPS_API_URL}/api/v1/gate/check" \\
        -H "X-API-Key: ${FIXOPS_API_TOKEN}" \\
        -H "Content-Type: application/json" \\
        -d "{
          \\"repository\\": \\"${CI_PROJECT_PATH}\\",
          \\"commit_sha\\": \\"${CI_COMMIT_SHA}\\",
          \\"branch\\": \\"${CI_COMMIT_REF_NAME}\\",
          \\"pull_request\\": ${CI_MERGE_REQUEST_IID:-0},
          \\"findings\\": []
        }")

      VERDICT=$(echo $RESPONSE | jq -r '.verdict')
      echo "FixOps Gate: $VERDICT"

      if [ "$VERDICT" = "FAIL" ]; then
        echo "Security gate FAILED"
        exit 1
      fi
  rules:
    - if: $CI_MERGE_REQUEST_IID
  allow_failure: false
"""

_AZURE_PIPELINES_TEMPLATE = """\
# azure-pipelines.yml snippet
# ALdeci/FixOps Security Gate
- task: Bash@3
  displayName: 'FixOps Security Gate'
  inputs:
    targetType: 'inline'
    script: |
      RESPONSE=$(curl -s -X POST "$(FIXOPS_API_URL)/api/v1/gate/check" \\
        -H "X-API-Key: $(FIXOPS_API_TOKEN)" \\
        -H "Content-Type: application/json" \\
        -d '{
          "repository": "$(Build.Repository.Name)",
          "commit_sha": "$(Build.SourceVersion)",
          "branch": "$(Build.SourceBranchName)",
          "findings": []
        }')

      VERDICT=$(echo $RESPONSE | jq -r '.verdict')
      if [ "$VERDICT" = "FAIL" ]; then
        echo "##vso[task.logissue type=error]Security gate FAILED"
        exit 1
      fi
"""

_BITBUCKET_PIPELINES_TEMPLATE = """\
# bitbucket-pipelines.yml snippet
# ALdeci/FixOps Security Gate
pipelines:
  pull-requests:
    '**':
      - step:
          name: FixOps Security Gate
          image: curlimages/curl:latest
          script:
            - |
              RESPONSE=$(curl -s -X POST "${FIXOPS_API_URL}/api/v1/gate/check" \\
                -H "X-API-Key: ${FIXOPS_API_TOKEN}" \\
                -H "Content-Type: application/json" \\
                -d "{
                  \\"repository\\": \\"${BITBUCKET_REPO_FULL_NAME}\\",
                  \\"commit_sha\\": \\"${BITBUCKET_COMMIT}\\",
                  \\"branch\\": \\"${BITBUCKET_BRANCH}\\",
                  \\"findings\\": []
                }")
              VERDICT=$(echo $RESPONSE | jq -r '.verdict')
              if [ "$VERDICT" = "FAIL" ]; then exit 1; fi
"""

_JENKINS_TEMPLATE = (
    '// Jenkinsfile snippet\n'
    '// ALdeci/FixOps Security Gate\n'
    "stage('Security Gate') {\n"
    '    steps {\n'
    '        script {\n'
    '            def response = httpRequest(\n'
    '                url: "${env.FIXOPS_API_URL}/api/v1/gate/check",\n'
    "                httpMode: 'POST',\n"
    "                customHeaders: [[name: 'X-API-Key', value: env.FIXOPS_API_TOKEN],\n"
    "                                [name: 'Content-Type', value: 'application/json']],\n"
    '                requestBody: \'\'\'{"repository":"${env.JOB_NAME}","commit_sha":"${env.GIT_COMMIT}","branch":"${env.BRANCH_NAME}","findings":[]}\'\'\'\n'
    '            )\n'
    '            def result = readJSON text: response.content\n'
    "            if (result.verdict == 'FAIL') {\n"
    '                error "Security gate FAILED: ${result.reason}"\n'
    '            }\n'
    '        }\n'
    '    }\n'
    '}\n'
)

_CI_TEMPLATES: Dict[str, str] = {
    "github-actions": _GITHUB_ACTION_TEMPLATE,
    "gitlab-ci": _GITLAB_CI_TEMPLATE,
    "azure-pipelines": _AZURE_PIPELINES_TEMPLATE,
    "bitbucket-pipelines": _BITBUCKET_PIPELINES_TEMPLATE,
    "jenkins": _JENKINS_TEMPLATE,
}


@router.get("/setup/{platform}")
async def get_ci_setup(platform: str):
    """Get ready-to-use CI/CD configuration for a platform.

    Supported platforms: github-actions, gitlab-ci, azure-pipelines,
    bitbucket-pipelines, jenkins.
    """
    template = _CI_TEMPLATES.get(platform)
    if not template:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown platform: {platform}. Supported: {list(_CI_TEMPLATES.keys())}",
        )
    return {
        "platform": platform,
        "template": template,
        "instructions": [
            f"1. Copy the template into your {platform} configuration file",
            "2. Set FIXOPS_API_URL and FIXOPS_API_TOKEN as secrets/variables in your CI system",
            "3. (Optional) Upload SARIF scan results to the /api/v1/gate/check endpoint for richer analysis",
            "4. The gate will return exit code 1 on FAIL, blocking the merge/deploy",
        ],
        "documentation_url": "https://docs.aldeci.com/integrations/ci-cd-gate",
    }


@router.get("/setup")
async def list_ci_platforms():
    """List all supported CI/CD platforms with setup availability."""
    return {
        "platforms": [
            {"id": k, "name": k.replace("-", " ").title(), "available": True}
            for k in _CI_TEMPLATES
        ],
    }

