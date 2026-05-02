"""WAF Rule Generator Router — REST endpoints for WAF rule management.

Endpoints under /api/v1/waf:
  POST   /generate          — Auto-generate rules from a vulnerability finding
  POST   /virtual-patch     — Generate a virtual patch rule for a CVE
  GET    /rules             — List all stored rules (filterable)
  GET    /rules/{rule_id}   — Fetch a single rule
  PATCH  /rules/{rule_id}/status  — Transition rule lifecycle status
  POST   /rules/{rule_id}/test    — Simulate rule against sample requests
  POST   /export            — Export rules in provider/format of choice
  GET    /templates         — List all available rule templates
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/waf",
    tags=["WAF Rule Generator"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy-import helpers (keep startup fast, avoid import errors on missing deps)
# ---------------------------------------------------------------------------

def _get_gen():
    try:
        from core.waf_generator import get_waf_generator
        return get_waf_generator()
    except Exception as exc:
        _logger.error("WAFRuleGenerator unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=f"WAF engine unavailable: {exc}")


def _vuln_type(val: str):
    from core.waf_generator import VulnType
    try:
        return VulnType(val)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid vuln_type: {val!r}. Valid: {[v.value for v in VulnType]}")


def _provider(val: str):
    from core.waf_generator import WAFProvider
    try:
        return WAFProvider(val)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {val!r}. Valid: {[p.value for p in WAFProvider]}")


def _rule_status(val: str):
    from core.waf_generator import RuleStatus
    try:
        return RuleStatus(val)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {val!r}. Valid: {[s.value for s in RuleStatus]}")


def _export_format(val: str):
    from core.waf_generator import ExportFormat
    try:
        return ExportFormat(val)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid format: {val!r}. Valid: {[f.value for f in ExportFormat]}")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class GenerateRequest(BaseModel):
    finding_id: Optional[str] = None
    title: str
    vuln_type: str = "generic"
    severity: str = "high"
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    method: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    description: str = ""
    attack_payload: Optional[str] = None


class VirtualPatchRequest(BaseModel):
    cve_id: str
    endpoint: str
    attack_vector: str
    description: str = ""


class StatusUpdateRequest(BaseModel):
    status: str  # draft | testing | active | deprecated


class TestRequestItem(BaseModel):
    uri: str
    method: str = "GET"
    query_string: str = ""
    body: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    is_malicious: bool = False


class TestRuleRequest(BaseModel):
    requests: List[TestRequestItem]


class ExportRequest(BaseModel):
    rule_ids: Optional[List[str]] = None   # if None, exports all rules
    provider: str = "aws_waf"
    format: str = "provider_native"        # provider_native | owasp_crs | terraform


class RuleResponse(BaseModel):
    rule_id: str
    name: str
    description: str
    rule_type: str
    vuln_type: str
    status: str
    priority: int
    endpoint: Optional[str]
    parameter: Optional[str]
    cve_id: Optional[str]
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    tags: List[str]
    version: int
    created_at: str
    updated_at: str
    false_positive_rate: Optional[float]
    conditions_count: int


def _rule_to_response(rule) -> RuleResponse:
    return RuleResponse(
        rule_id=rule.rule_id,
        name=rule.name,
        description=rule.description,
        rule_type=rule.rule_type.value,
        vuln_type=rule.vuln_type.value,
        status=rule.status.value,
        priority=rule.priority,
        endpoint=rule.endpoint,
        parameter=rule.parameter,
        cve_id=rule.cve_id,
        cwe_id=rule.cwe_id,
        owasp_category=rule.owasp_category,
        tags=rule.tags,
        version=rule.version,
        created_at=rule.created_at.isoformat(),
        updated_at=rule.updated_at.isoformat(),
        false_positive_rate=rule.false_positive_rate,
        conditions_count=len(rule.conditions),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/generate",
    summary="Auto-generate WAF rules from a vulnerability finding",
    response_model=Dict[str, Any],
)
def generate_rules(body: GenerateRequest):
    """Given a vulnerability finding, generate block + log + rate-limit WAF rules
    using the matching template catalog. Rules are stored in DRAFT status."""
    from core.waf_generator import VulnFinding

    gen = _get_gen()
    finding = VulnFinding(
        title=body.title,
        vuln_type=_vuln_type(body.vuln_type),
        severity=body.severity,
        endpoint=body.endpoint,
        parameter=body.parameter,
        method=body.method,
        cve_id=body.cve_id,
        cwe_id=body.cwe_id,
        description=body.description,
        attack_payload=body.attack_payload,
    )
    if body.finding_id:
        finding.finding_id = body.finding_id

    rules = gen.generate_from_finding(finding)
    return {
        "finding_id": finding.finding_id,
        "generated": len(rules),
        "rules": [_rule_to_response(r).model_dump() for r in rules],
    }


@router.post(
    "/virtual-patch",
    summary="Generate a virtual patch WAF rule for an unpatched CVE",
    response_model=Dict[str, Any],
)
def virtual_patch(body: VirtualPatchRequest):
    """Create a high-priority WAF blocking rule as a temporary mitigation for a CVE
    that cannot be patched immediately. Rule is stored in DRAFT status."""
    gen = _get_gen()
    rule = gen.generate_virtual_patch(
        cve_id=body.cve_id,
        endpoint=body.endpoint,
        attack_vector=body.attack_vector,
        description=body.description,
    )
    return {
        "cve_id": body.cve_id,
        "rule": _rule_to_response(rule).model_dump(),
    }


@router.get(
    "/rules",
    summary="List WAF rules",
    response_model=Dict[str, Any],
)
def list_rules(
    status: Optional[str] = Query(None, description="Filter by status: draft|testing|active|deprecated"),
    vuln_type: Optional[str] = Query(None, description="Filter by vuln type"),
):
    """Return all stored rules, optionally filtered by status and/or vuln_type."""
    gen = _get_gen()
    flt_status = _rule_status(status) if status else None
    flt_vuln = _vuln_type(vuln_type) if vuln_type else None
    rules = gen.list_rules(status=flt_status, vuln_type=flt_vuln)
    return {
        "total": len(rules),
        "rules": [_rule_to_response(r).model_dump() for r in rules],
    }


@router.get(
    "/rules/{rule_id}",
    summary="Fetch a single WAF rule",
    response_model=Dict[str, Any],
)
def get_rule(rule_id: str):
    """Return full rule detail including conditions and history."""
    gen = _get_gen()
    rule = gen.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id!r} not found")
    data = _rule_to_response(rule).model_dump()
    data["conditions"] = [
        {
            "field": c.field,
            "operator": c.operator,
            "value": c.value,
            "negate": c.negate,
            "transform": c.transform,
        }
        for c in rule.conditions
    ]
    data["history"] = rule.history
    data["test_results"] = rule.test_results
    return data


@router.patch(
    "/rules/{rule_id}/status",
    summary="Transition rule lifecycle status",
    response_model=Dict[str, Any],
)
def update_rule_status(rule_id: str, body: StatusUpdateRequest):
    """Move a rule through its lifecycle: draft → testing → active → deprecated.
    Each transition is recorded in the rule's history for audit purposes."""
    gen = _get_gen()
    new_status = _rule_status(body.status)
    rule = gen.update_rule_status(rule_id, new_status)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id!r} not found")
    return {
        "rule_id": rule_id,
        "status": rule.status.value,
        "version": rule.version,
        "history_entries": len(rule.history),
    }


@router.post(
    "/rules/{rule_id}/test",
    summary="Simulate WAF rule against sample requests",
    response_model=Dict[str, Any],
)
def test_rule(rule_id: str, body: TestRuleRequest):
    """Simulate the rule against provided sample requests (malicious and legitimate).
    Returns match results per request and overall false-positive rate."""
    from core.waf_generator import TestRequest as WafTestRequest

    gen = _get_gen()
    rule = gen.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id!r} not found")

    test_reqs = [
        WafTestRequest(
            uri=r.uri,
            method=r.method,
            query_string=r.query_string,
            body=r.body,
            headers=r.headers,
            is_malicious=r.is_malicious,
        )
        for r in body.requests
    ]

    results = gen.test_rule(rule, test_reqs)
    total = len(results)
    correct = sum(1 for r in results if r.correct)
    fp = sum(1 for r in results if r.matched and not r.expected_block)
    fn = sum(1 for r in results if not r.matched and r.expected_block)

    return {
        "rule_id": rule_id,
        "total_requests": total,
        "correct": correct,
        "accuracy": round(correct / total, 4) if total else 0.0,
        "false_positives": fp,
        "false_negatives": fn,
        "false_positive_rate": round(fp / total, 4) if total else 0.0,
        "results": [
            {
                "uri": r.request_uri,
                "matched": r.matched,
                "expected_block": r.expected_block,
                "correct": r.correct,
                "match_condition": r.match_condition,
                "latency_us": r.latency_us,
            }
            for r in results
        ],
    }


@router.post(
    "/export",
    summary="Export WAF rules in provider-native, OWASP CRS, or Terraform format",
    response_model=Dict[str, Any],
)
def export_rules(body: ExportRequest):
    """Export stored rules as AWS WAF JSON, Cloudflare JSON, ModSecurity SecRules,
    NGINX config, Apache config, OWASP CRS JSON, or Terraform HCL."""
    gen = _get_gen()
    provider = _provider(body.provider)
    fmt = _export_format(body.format)

    if body.rule_ids:
        rules = []
        for rid in body.rule_ids:
            r = gen.get_rule(rid)
            if r is None:
                raise HTTPException(status_code=404, detail=f"Rule {rid!r} not found")
            rules.append(r)
    else:
        rules = gen.list_rules()

    if not rules:
        raise HTTPException(status_code=400, detail="No rules to export")

    exported = gen.export_ruleset(rules, provider, fmt)

    return {
        "provider": provider.value,
        "format": fmt.value,
        "rule_count": len(rules),
        "export": exported,
    }


@router.get(
    "/templates",
    summary="List all available WAF rule templates",
    response_model=Dict[str, Any],
)
def list_templates(
    vuln_type: Optional[str] = Query(None, description="Filter by vuln type"),
):
    """Return the built-in template catalog (50+ templates). Optionally filter by
    vulnerability type. Templates can be instantiated via /generate."""
    gen = _get_gen()
    flt_vuln = _vuln_type(vuln_type) if vuln_type else None
    templates = gen.list_templates(vuln_type=flt_vuln)
    return {
        "total": len(templates),
        "templates": [
            {
                "template_id": t.template_id,
                "name": t.name,
                "description": t.description,
                "vuln_type": t.vuln_type.value,
                "rule_type": t.rule_type.value,
                "owasp_category": t.owasp_category,
                "cwe_id": t.cwe_id,
                "tags": t.tags,
                "priority": t.priority,
                "conditions_count": len(t.conditions),
            }
            for t in templates
        ],
    }
