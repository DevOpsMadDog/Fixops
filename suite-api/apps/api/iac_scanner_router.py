"""IaC Security Scanner Router — Infrastructure-as-Code vulnerability detection API.

Endpoints:
    POST /api/v1/iac/scan         — Scan IaC content or repo path
    GET  /api/v1/iac/findings     — All findings with severity/provider filters
    GET  /api/v1/iac/rules        — List active rules (filterable)
    POST /api/v1/iac/rules/custom — Add custom policy-as-code rule
    GET  /api/v1/iac/drift        — Drift detection results
    GET  /api/v1/iac/summary      — Summary stats by provider/severity/rule
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/iac",
    tags=["IaC Security"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy engine import (avoids import-time failure if pyyaml is missing)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.iac_scanner_engine import get_iac_scanner
    return get_iac_scanner()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    content: Optional[str] = Field(None, description="Raw IaC file content to scan")
    filename: str = Field("main.tf", description="Filename hint for format detection")
    repo_path: Optional[str] = Field(None, description="Path to a directory with IaC files")
    scan_id: Optional[str] = Field(None, description="Optional scan correlation ID")


class CustomRuleRequest(BaseModel):
    rule_id: str = Field(..., description="Unique rule identifier (e.g. CUSTOM-001)")
    name: str = Field(..., description="Human-readable rule name")
    description: str = Field(..., description="What this rule detects")
    provider: str = Field(..., description="aws | azure | gcp | kubernetes | docker | generic")
    resource_type: str = Field(..., description="Terraform resource type or * for any")
    property_path: str = Field(..., description="Dot-notation path to the property (e.g. tags.Environment)")
    expected_value: Any = Field(..., description="The value the property should have")
    operator: str = Field("equals", description="equals | not_equals | contains | not_contains | exists | not_exists")
    severity: str = Field("medium", description="critical | high | medium | low | info")
    fix_description: str = Field("", description="Plain-English fix guidance")
    fix_snippet: str = Field("", description="Code snippet showing correct configuration")
    compliance: List[Dict[str, str]] = Field(default_factory=list, description="Compliance framework references")
    enabled: bool = Field(True, description="Whether this rule is active")


class DriftCheckRequest(BaseModel):
    filenames: List[str] = Field(default_factory=list, description="IaC filenames to load from disk for drift check")
    cloud_state: Dict[str, Any] = Field(
        default_factory=dict,
        description="Simulated cloud state: resource_name -> properties dict",
    )


class PolicyRule(BaseModel):
    rule_id: str = Field(..., description="Unique rule identifier (e.g. TF-POLICY-001)")
    name: str = Field(..., description="Human-readable rule name")
    description: str = Field("", description="What this rule detects")
    provider: str = Field("generic", description="aws | azure | gcp | kubernetes | docker | generic")
    resource_type: str = Field("*", description="Terraform/CFN resource type or * for any")
    property_path: str = Field(..., description="Dot-notation path to the property")
    expected_value: Any = Field(None, description="The value the property should have")
    operator: str = Field("equals", description="equals | not_equals | contains | not_contains | exists | not_exists")
    severity: str = Field("medium", description="critical | high | medium | low | info")


class PolicyEvalRequest(BaseModel):
    content: str = Field(..., description="Raw IaC file content (Terraform HCL or CloudFormation JSON/YAML)")
    filename: str = Field("main.tf", description="Filename hint for format detection (e.g. main.tf, template.yaml)")
    policy_id: str = Field("inline-policy", description="Logical name for this policy bundle")
    rules: List[PolicyRule] = Field(..., min_length=1, description="Policy rules to evaluate against the IaC content")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_to_dict(finding) -> Dict[str, Any]:
    """Convert IaCFinding (Pydantic or dataclass) to plain dict."""
    if hasattr(finding, "model_dump"):
        return finding.model_dump()
    if hasattr(finding, "dict"):
        return finding.dict()
    # dataclass fallback
    result = finding.__dict__.copy()
    if hasattr(result.get("fix"), "__dict__"):
        fix = result["fix"]
        fix_dict = fix.__dict__.copy()
        crs = fix_dict.get("compliance_violations", [])
        fix_dict["compliance_violations"] = [c.__dict__ for c in crs]
        result["fix"] = fix_dict
    return result


def _scan_result_to_dict(sr) -> Dict[str, Any]:
    if hasattr(sr, "model_dump"):
        return sr.model_dump()
    if hasattr(sr, "dict"):
        return sr.dict()
    result = sr.__dict__.copy()
    result["findings"] = [_finding_to_dict(f) for f in result.get("findings", [])]
    return result


def _drift_to_dict(dr) -> Dict[str, Any]:
    if hasattr(dr, "model_dump"):
        return dr.model_dump()
    if hasattr(dr, "dict"):
        return dr.dict()
    return dr.__dict__.copy()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan")
async def scan_iac(body: ScanRequest) -> Dict[str, Any]:
    """Scan IaC content for security misconfigurations.

    Accepts either raw ``content`` (with a ``filename`` hint for format detection)
    or a ``repo_path`` to recursively scan a directory of IaC files.
    """
    engine = _get_engine()

    if body.repo_path:
        import os
        if not os.path.exists(body.repo_path):
            raise HTTPException(status_code=400, detail=f"repo_path does not exist: {body.repo_path}")
        results = engine.scan_path(body.repo_path)
        all_findings = []
        for sr in results:
            all_findings.extend([_finding_to_dict(f) for f in sr.findings])
        return {
            "files_scanned": len(results),
            "total_findings": len(all_findings),
            "results": [_scan_result_to_dict(sr) for sr in results],
        }

    if not body.content:
        raise HTTPException(status_code=400, detail="Provide either 'content' or 'repo_path'")

    result = engine.scan_content(
        content=body.content,
        filename=body.filename,
        scan_id=body.scan_id,
    )
    return _scan_result_to_dict(result)


@router.get("/findings")
async def get_findings(
    provider: Optional[str] = Query(None, description="Filter by provider: aws|azure|gcp|kubernetes|docker"),
    severity: Optional[str] = Query(None, description="Filter by severity: critical|high|medium|low|info"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    limit: int = Query(200, ge=1, le=1000, description="Max findings to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> Dict[str, Any]:
    """Return all stored IaC findings with optional filtering."""
    engine = _get_engine()
    findings = engine.get_findings(provider=provider, severity=severity, rule_id=rule_id)
    total = len(findings)
    page = findings[offset: offset + limit]
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "findings": [_finding_to_dict(f) for f in page],
    }


@router.get("/rules")
async def list_rules(
    provider: Optional[str] = Query(None, description="Filter by provider"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
) -> Dict[str, Any]:
    """List all active IaC security rules (built-in + custom)."""
    engine = _get_engine()
    rules = engine.list_rules(provider=provider, severity=severity)
    return {
        "total": len(rules),
        "rules": rules,
    }


@router.post("/rules/custom", status_code=201)
async def add_custom_rule(body: CustomRuleRequest) -> Dict[str, Any]:
    """Add a custom policy-as-code rule in YAML-defined format."""
    engine = _get_engine()

    valid_operators = {"equals", "not_equals", "contains", "not_contains", "exists", "not_exists"}
    if body.operator not in valid_operators:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid operator '{body.operator}'. Must be one of: {sorted(valid_operators)}",
        )

    valid_severities = {"critical", "high", "medium", "low", "info"}
    if body.severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity '{body.severity}'. Must be one of: {sorted(valid_severities)}",
        )

    from core.iac_scanner_engine import CustomRule

    rule = CustomRule(
        rule_id=body.rule_id,
        name=body.name,
        description=body.description,
        provider=body.provider,
        resource_type=body.resource_type,
        property_path=body.property_path,
        expected_value=body.expected_value,
        operator=body.operator,
        severity=body.severity,
        fix_description=body.fix_description,
        fix_snippet=body.fix_snippet,
        compliance=body.compliance,
        enabled=body.enabled,
    )
    engine.add_custom_rule(rule)

    return {
        "message": "Custom rule added successfully",
        "rule_id": body.rule_id,
    }


@router.get("/drift")
async def get_drift(
    status: Optional[str] = Query(None, description="Filter by drift status: in_sync|missing_in_cloud|missing_in_code|property_mismatch"),
) -> Dict[str, Any]:
    """Return drift detection results comparing IaC definitions to cloud state."""
    engine = _get_engine()
    drift_results = engine.get_drift_results()
    if status:
        drift_results = [d for d in drift_results if d.status == status]
    return {
        "total": len(drift_results),
        "drift_results": [_drift_to_dict(d) for d in drift_results],
    }


@router.post("/drift/check")
async def check_drift(body: DriftCheckRequest) -> Dict[str, Any]:
    """Run drift detection between IaC resources and provided cloud state.

    ``cloud_state`` is a dict of resource_name -> properties representing
    the actual deployed configuration (fetched from AWS Config, Azure Resource Graph, etc.).
    """
    engine = _get_engine()

    # Parse provided IaC files
    resources = []
    from pathlib import Path

    for fname in body.filenames:
        try:
            content = Path(fname).read_text(errors="replace")
            from core.iac_scanner_engine import detect_iac_format
            fmt = detect_iac_format(fname, content)
            parsed = engine._parse(content, fname, fmt)
            resources.extend(parsed)
        except Exception as exc:
            _logger.warning("drift_check_file_error", fname=fname, error=str(exc))

    drift_results = engine.detect_drift(resources, cloud_state=body.cloud_state)

    summary = {
        "in_sync": sum(1 for d in drift_results if d.status == "in_sync"),
        "missing_in_cloud": sum(1 for d in drift_results if d.status == "missing_in_cloud"),
        "missing_in_code": sum(1 for d in drift_results if d.status == "missing_in_code"),
        "property_mismatch": sum(1 for d in drift_results if d.status == "property_mismatch"),
    }

    return {
        "total": len(drift_results),
        "summary": summary,
        "drift_results": [_drift_to_dict(d) for d in drift_results],
    }


@router.post("/baselines", status_code=201)
async def create_baseline_snapshot(
    name: str = Query(..., description="Baseline name / label"),
    description: str = Query("", description="Optional description"),
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    """Snapshot the current set of IaC findings as a named baseline.

    Captures finding counts by severity and provider plus the full list of
    finding IDs so future scans can be compared against this point-in-time state.
    """
    engine = _get_engine()
    return engine.create_baseline_snapshot(name=name, description=description, org_id=org_id)


@router.get("/baselines")
async def list_baseline_snapshots(
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    """List all IaC baseline snapshots for an org."""
    engine = _get_engine()
    snapshots = engine.list_baseline_snapshots(org_id=org_id)
    return {"org_id": org_id, "total": len(snapshots), "baselines": snapshots}


@router.get("/baselines/{baseline_id}/snapshot")
async def get_baseline_snapshot(
    baseline_id: str,
    org_id: str = Query("default", description="Organization ID"),
) -> Dict[str, Any]:
    """Return a specific IaC baseline snapshot by ID."""
    engine = _get_engine()
    record = engine.get_baseline_snapshot(baseline_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Baseline snapshot '{baseline_id}' not found")
    if record.get("org_id") != org_id:
        raise HTTPException(status_code=404, detail=f"Baseline snapshot '{baseline_id}' not found")
    return record


@router.get("/summary")
async def get_summary() -> Dict[str, Any]:
    """Return aggregated IaC scan statistics by severity, provider, and rule."""
    engine = _get_engine()
    return engine.get_summary()


@router.post("/policy/eval")
async def evaluate_policy(body: PolicyEvalRequest) -> Dict[str, Any]:
    """Evaluate IaC content (Terraform or CloudFormation) against a policy bundle.

    Parses the supplied ``content`` using the filename hint for format detection,
    then evaluates each policy rule against the parsed resources.  Returns a
    per-rule pass/fail verdict plus a top-level ``passed`` boolean that is
    ``True`` only when every rule passes on every resource.
    """
    from core.iac_scanner_engine import CustomRule, detect_iac_format, evaluate_custom_rule

    valid_operators = {"equals", "not_equals", "contains", "not_contains", "exists", "not_exists"}
    valid_severities = {"critical", "high", "medium", "low", "info"}

    for idx, rule in enumerate(body.rules):
        if rule.operator not in valid_operators:
            raise HTTPException(
                status_code=400,
                detail=f"Rule[{idx}] '{rule.rule_id}': invalid operator '{rule.operator}'",
            )
        if rule.severity not in valid_severities:
            raise HTTPException(
                status_code=400,
                detail=f"Rule[{idx}] '{rule.rule_id}': invalid severity '{rule.severity}'",
            )

    engine = _get_engine()
    fmt = detect_iac_format(body.filename, body.content)
    resources = engine._parse(body.content, body.filename, fmt)

    if not resources:
        return {
            "policy_id": body.policy_id,
            "filename": body.filename,
            "iac_format": fmt.value if hasattr(fmt, "value") else str(fmt),
            "resources_found": 0,
            "passed": True,
            "rules_evaluated": len(body.rules),
            "violations": [],
            "verdict": "pass",
        }

    violations: List[Dict[str, Any]] = []
    rules_passed = 0

    for rule_req in body.rules:
        custom_rule = CustomRule(
            rule_id=rule_req.rule_id,
            name=rule_req.name,
            description=rule_req.description,
            provider=rule_req.provider,
            resource_type=rule_req.resource_type,
            property_path=rule_req.property_path,
            expected_value=rule_req.expected_value,
            operator=rule_req.operator,
            severity=rule_req.severity,
        )

        rule_violations: List[Dict[str, Any]] = []
        for resource in resources:
            result = evaluate_custom_rule(custom_rule, resource)
            if result is not None:
                prop_path, actual, expected = result
                rule_violations.append({
                    "resource_type": resource.resource_type,
                    "resource_name": resource.resource_name,
                    "property_path": prop_path,
                    "actual_value": actual,
                    "expected_value": expected,
                })

        if rule_violations:
            violations.append({
                "rule_id": rule_req.rule_id,
                "name": rule_req.name,
                "severity": rule_req.severity,
                "description": rule_req.description,
                "passed": False,
                "resources_violated": rule_violations,
            })
        else:
            rules_passed += 1

    overall_passed = len(violations) == 0

    _logger.info(
        "iac_policy_eval_complete",
        policy_id=body.policy_id,
        filename=body.filename,
        rules=len(body.rules),
        violations=len(violations),
        passed=overall_passed,
    )

    return {
        "policy_id": body.policy_id,
        "filename": body.filename,
        "iac_format": fmt.value if hasattr(fmt, "value") else str(fmt),
        "resources_found": len(resources),
        "passed": overall_passed,
        "rules_evaluated": len(body.rules),
        "rules_passed": rules_passed,
        "rules_failed": len(violations),
        "violations": violations,
        "verdict": "pass" if overall_passed else "fail",
    }
