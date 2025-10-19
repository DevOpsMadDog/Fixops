"""Lightweight PSL (Policy Specification Language) shim for explainable policy evaluation.

This module provides a pure Python implementation of PSL rule evaluation without
requiring external PSL libraries. It evaluates rules defined in policy/psl/bundle.psl
and produces structured reasons for PASS/WARN/FAIL verdicts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping

logger = logging.getLogger(__name__)


@dataclass
class PSLRule:
    """Represents a single PSL rule."""

    name: str
    description: str
    conditions: Dict[str, Any]
    verdict: str
    reason: str
    industry_scores_required: List[str] = field(default_factory=list)


@dataclass
class PSLEvaluation:
    """Result of PSL rule evaluation."""

    rule_name: str
    fired: bool
    verdict: str
    reason: str
    industry_scores: Dict[str, Any] = field(default_factory=dict)
    facts_used: Dict[str, Any] = field(default_factory=dict)


def _evaluate_condition(fact_value: Any, operator: str, threshold: Any) -> bool:
    """Evaluate a single condition."""
    if operator == "gte":
        return float(fact_value) >= float(threshold)
    elif operator == "gt":
        return float(fact_value) > float(threshold)
    elif operator == "lte":
        return float(fact_value) <= float(threshold)
    elif operator == "lt":
        return float(fact_value) < float(threshold)
    elif operator == "eq":
        return fact_value == threshold
    elif operator == "ne":
        return fact_value != threshold
    else:
        logger.warning("Unknown operator: %s", operator)
        return False


def _evaluate_rule(rule: PSLRule, facts: Mapping[str, Any]) -> PSLEvaluation:
    """Evaluate a single PSL rule against facts."""
    fired = True
    facts_used = {}

    for fact_name, condition in rule.conditions.items():
        fact_value = facts.get(fact_name)
        if fact_value is None:
            fired = False
            break

        facts_used[fact_name] = fact_value

        if isinstance(condition, dict):
            for operator, threshold in condition.items():
                if not _evaluate_condition(fact_value, operator, threshold):
                    fired = False
                    break
        else:
            if fact_value != condition:
                fired = False
                break

        if not fired:
            break

    industry_scores = {}
    if fired and rule.industry_scores_required:
        for score_name in rule.industry_scores_required:
            if score_name in facts:
                industry_scores[score_name] = facts[score_name]

    return PSLEvaluation(
        rule_name=rule.name,
        fired=fired,
        verdict=rule.verdict if fired else "NONE",
        reason=rule.reason if fired else "",
        industry_scores=industry_scores,
        facts_used=facts_used,
    )


DEFAULT_RULES = [
    PSLRule(
        name="CriticalKEVUnpatched",
        description="Block releases with KEV vulnerabilities and CVSS >= 9",
        conditions={"kev": True, "cvss": {"gte": 9.0}, "patched": False},
        verdict="FAIL",
        reason="Critical KEV vulnerability without available patch",
        industry_scores_required=["kev", "cvss", "epss"],
    ),
    PSLRule(
        name="CriticalRiskScore",
        description="Fail on critical FixOps risk score",
        conditions={"fixops_risk": {"gt": 85}},
        verdict="FAIL",
        reason="FixOps risk score exceeds critical threshold (> 85)",
        industry_scores_required=["cvss", "epss", "kev"],
    ),
    PSLRule(
        name="VeryLowCoverage",
        description="Fail on critically low SBOM coverage",
        conditions={"coverage_percent": {"lt": 60}},
        verdict="FAIL",
        reason="SBOM coverage critically low (< 60%)",
    ),
    PSLRule(
        name="ReproMismatch",
        description="Fail when reproducible build verification fails",
        conditions={"repro_match": False},
        verdict="FAIL",
        reason="Reproducible build verification failed",
    ),
    PSLRule(
        name="HighCVSS",
        description="Warn on critical CVSS scores",
        conditions={"cvss": {"gte": 9.0}},
        verdict="WARN",
        reason="Critical CVSS score (>= 9.0) detected",
        industry_scores_required=["cvss", "epss", "kev"],
    ),
    PSLRule(
        name="LikelyExploit",
        description="Warn on high EPSS scores",
        conditions={"epss": {"gt": 0.5}},
        verdict="WARN",
        reason="High exploit probability (EPSS > 0.5)",
        industry_scores_required=["epss", "cvss", "kev"],
    ),
    PSLRule(
        name="KEVPresent",
        description="Warn on KEV vulnerabilities",
        conditions={"kev": True},
        verdict="WARN",
        reason="Vulnerability in CISA Known Exploited Vulnerabilities catalog",
        industry_scores_required=["kev", "cvss", "epss"],
    ),
    PSLRule(
        name="LowCoverage",
        description="Warn on low SBOM coverage",
        conditions={"coverage_percent": {"lt": 80}},
        verdict="WARN",
        reason="SBOM coverage below 80% threshold",
    ),
    PSLRule(
        name="HighRiskScore",
        description="Warn on high FixOps risk score",
        conditions={"fixops_risk": {"gt": 70}},
        verdict="WARN",
        reason="FixOps risk score exceeds warning threshold (> 70)",
        industry_scores_required=["cvss", "epss", "kev"],
    ),
    PSLRule(
        name="MissingProvenance",
        description="Warn on missing provenance attestations",
        conditions={"attestation_count": {"lt": 1}},
        verdict="WARN",
        reason="No provenance attestations found",
    ),
    PSLRule(
        name="InternetExposedHighRisk",
        description="Warn on internet-exposed high-risk components",
        conditions={"exposure": "internet", "fixops_risk": {"gt": 60}},
        verdict="WARN",
        reason="Internet-exposed component with elevated risk (> 60)",
        industry_scores_required=["cvss", "epss", "kev"],
    ),
    PSLRule(
        name="Pass",
        description="All checks passed",
        conditions={
            "coverage_percent": {"gte": 80},
            "fixops_risk": {"lte": 70},
            "repro_match": True,
            "attestation_count": {"gte": 1},
        },
        verdict="PASS",
        reason="All policy checks passed",
    ),
]


def evaluate_policy(
    facts: Mapping[str, Any], rules: List[PSLRule] | None = None
) -> Dict[str, Any]:
    """Evaluate PSL rules against facts and return structured results.

    Args:
        facts: Dictionary of facts to evaluate (e.g., cvss, epss, kev, coverage_percent)
        rules: Optional list of PSL rules (defaults to DEFAULT_RULES)

    Returns:
        Dictionary containing:
        - policy_status: Overall status (PASS|WARN|FAIL)
        - rules_fired: List of rules that fired
        - reasons: List of reasons for the verdict
        - industry_scores: Dictionary of industry scores used
    """
    if rules is None:
        rules = DEFAULT_RULES

    evaluations = []
    for rule in rules:
        evaluation = _evaluate_rule(rule, facts)
        if evaluation.fired:
            evaluations.append(evaluation)

    overall_status = "PASS"
    if any(e.verdict == "FAIL" for e in evaluations):
        overall_status = "FAIL"
    elif any(e.verdict == "WARN" for e in evaluations):
        overall_status = "WARN"

    rules_fired = [e.rule_name for e in evaluations if e.fired]
    reasons = [e.reason for e in evaluations if e.fired and e.reason]

    all_industry_scores = {}
    for evaluation in evaluations:
        if evaluation.industry_scores:
            all_industry_scores.update(evaluation.industry_scores)

    return {
        "policy_status": overall_status,
        "rules_fired": sorted(rules_fired),
        "reasons": reasons,
        "industry_scores": all_industry_scores,
        "evaluations": [
            {
                "rule": e.rule_name,
                "fired": e.fired,
                "verdict": e.verdict,
                "reason": e.reason,
                "industry_scores": e.industry_scores,
                "facts_used": e.facts_used,
            }
            for e in evaluations
            if e.fired
        ],
    }


def build_facts_from_evidence(
    sbom_quality: Mapping[str, Any] | None = None,
    risk_report: Mapping[str, Any] | None = None,
    repro_attestation: Mapping[str, Any] | None = None,
    provenance_attestations: List[Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Build PSL facts from evidence artifacts.

    Args:
        sbom_quality: SBOM quality report
        risk_report: Risk scoring report
        repro_attestation: Reproducibility attestation
        provenance_attestations: List of provenance attestations

    Returns:
        Dictionary of facts for PSL evaluation
    """
    facts: Dict[str, Any] = {}

    if sbom_quality:
        metrics = sbom_quality.get("metrics", {})
        facts["coverage_percent"] = metrics.get("coverage_percent", 0.0)
        facts["license_coverage_percent"] = metrics.get("license_coverage_percent", 0.0)
        facts["resolvability_percent"] = metrics.get("resolvability_percent", 0.0)

    if risk_report:
        summary = risk_report.get("summary", {})
        facts["fixops_risk"] = summary.get("max_risk_score", 0.0)
        facts["cve_count"] = summary.get("cve_count", 0)
        facts["component_count"] = summary.get("component_count", 0)

        components = risk_report.get("components", [])
        max_cvss = 0.0
        max_epss = 0.0
        kev_present = False
        for component in components:
            for vuln in component.get("vulnerabilities", []):
                if vuln.get("kev"):
                    kev_present = True
                cvss = vuln.get("cvss", 0.0)
                if cvss > max_cvss:
                    max_cvss = cvss
                epss = vuln.get("epss", 0.0)
                if epss > max_epss:
                    max_epss = epss

        facts["cvss"] = max_cvss
        facts["epss"] = max_epss
        facts["kev"] = kev_present
        facts["patched"] = False

    if repro_attestation:
        facts["repro_match"] = repro_attestation.get("match", False)

    if provenance_attestations:
        facts["attestation_count"] = len(provenance_attestations)
    else:
        facts["attestation_count"] = 0

    return facts


__all__ = [
    "PSLRule",
    "PSLEvaluation",
    "evaluate_policy",
    "build_facts_from_evidence",
    "DEFAULT_RULES",
]
