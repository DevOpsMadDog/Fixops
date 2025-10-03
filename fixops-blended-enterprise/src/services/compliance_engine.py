"""Lightweight compliance evaluator for production decisioning."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

import structlog

logger = structlog.get_logger()


@dataclass(frozen=True)
class ComplianceRule:
    name: str
    disallow_severities: List[str]
    epss_threshold: float
    kev_must_block: bool
    requires_fix_available: bool
    requires_regression_pass: bool
    high_impact_required: bool


class ComplianceEvaluator:
    """Evaluate compliance requirements against the live decision context."""

    _RULES: Dict[str, ComplianceRule] = {
        "pci-dss": ComplianceRule(
            name="PCI-DSS",
            disallow_severities=["CRITICAL", "HIGH"],
            epss_threshold=0.4,
            kev_must_block=True,
            requires_fix_available=True,
            requires_regression_pass=True,
            high_impact_required=True,
        ),
        "soc2": ComplianceRule(
            name="SOC2",
            disallow_severities=["CRITICAL"],
            epss_threshold=0.35,
            kev_must_block=True,
            requires_fix_available=False,
            requires_regression_pass=True,
            high_impact_required=False,
        ),
        "ffiec": ComplianceRule(
            name="FFIEC",
            disallow_severities=["CRITICAL", "HIGH"],
            epss_threshold=0.3,
            kev_must_block=True,
            requires_fix_available=True,
            requires_regression_pass=True,
            high_impact_required=True,
        ),
        "nist_ssdf": ComplianceRule(
            name="NIST SSDF",
            disallow_severities=["CRITICAL", "HIGH"],
            epss_threshold=0.25,
            kev_must_block=False,
            requires_fix_available=False,
            requires_regression_pass=True,
            high_impact_required=False,
        ),
        "hipaa": ComplianceRule(
            name="HIPAA",
            disallow_severities=["CRITICAL", "HIGH"],
            epss_threshold=0.2,
            kev_must_block=True,
            requires_fix_available=True,
            requires_regression_pass=False,
            high_impact_required=True,
        ),
        "default": ComplianceRule(
            name="Enterprise Baseline",
            disallow_severities=["CRITICAL"],
            epss_threshold=0.5,
            kev_must_block=False,
            requires_fix_available=False,
            requires_regression_pass=False,
            high_impact_required=False,
        ),
    }

    def evaluate(
        self,
        frameworks: Iterable[str],
        business_context: Dict[str, Any],
        findings: Iterable[Dict[str, Any]],
        regression_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        frameworks_list = [fw for fw in frameworks if fw]
        if not frameworks_list:
            return {
                "status": "not_requested",
                "overall_compliant": True,
                "coverage_pct": 100.0,
                "frameworks": {},
                "notes": "No compliance requirements supplied",
            }

        findings_list = list(findings)
        regression_passed = bool(regression_results.get("validation_passed"))
        deployment_frequency = (business_context.get("deployment_frequency") or "").lower()
        data_classification = (business_context.get("data_classification") or "").lower()
        customer_impact = (business_context.get("customer_impact") or "").lower()

        frameworks_result: Dict[str, Any] = {}
        passes = 0

        for raw_framework in frameworks_list:
            framework_key = raw_framework.lower()
            rule = self._RULES.get(framework_key, self._RULES["default"])
            evaluation = self._evaluate_framework(
                rule,
                findings_list,
                regression_passed,
                deployment_frequency,
                data_classification,
                customer_impact,
            )
            frameworks_result[rule.name] = evaluation
            if evaluation["status"] == "pass":
                passes += 1

        total = len(frameworks_result)
        coverage_pct = (passes / total * 100.0) if total else 100.0
        overall = passes == total

        return {
            "status": "evaluated",
            "overall_compliant": overall,
            "coverage_pct": round(coverage_pct, 1),
            "frameworks": frameworks_result,
        }

    @staticmethod
    def _evaluate_framework(
        rule: ComplianceRule,
        findings: List[Dict[str, Any]],
        regression_passed: bool,
        deployment_frequency: str,
        data_classification: str,
        customer_impact: str,
    ) -> Dict[str, Any]:
        violations: List[str] = []
        controls_triggered: List[str] = []

        for finding in findings:
            severity = (finding.get("severity") or "medium").upper()
            if severity in rule.disallow_severities:
                violations.append(
                    f"{rule.name}: severity {severity} finding {finding.get('cve') or finding.get('id')}"
                )
                controls_triggered.append("severity_block")

            epss = float(finding.get("epss_score") or 0.0)
            if epss >= rule.epss_threshold:
                controls_triggered.append("epss_threshold")

            kev = bool(finding.get("kev_flag") or finding.get("kev"))
            if rule.kev_must_block and kev:
                violations.append(
                    f"{rule.name}: KEV-listed CVE {finding.get('cve') or finding.get('id')}"
                )
                controls_triggered.append("kev_flag")

            if rule.requires_fix_available and not finding.get("fix_available"):
                violations.append(
                    f"{rule.name}: remediation guidance missing for {finding.get('cve') or finding.get('id')}"
                )
                controls_triggered.append("fix_plan")

        if rule.requires_regression_pass and not regression_passed:
            violations.append(f"{rule.name}: golden regression suite did not pass")
            controls_triggered.append("regression_failure")

        if rule.high_impact_required:
            if data_classification in {"restricted", "pii", "pii_financial"} or "pci" in data_classification:
                controls_triggered.append("sensitive_data")
            if customer_impact in {"high", "critical"}:
                controls_triggered.append("high_customer_impact")
            if deployment_frequency in {"daily", "continuous"}:
                controls_triggered.append("rapid_deployment")

        status = "pass" if not violations else "fail"
        return {
            "status": status,
            "violations": violations,
            "controls_triggered": list(dict.fromkeys(controls_triggered)),
        }


__all__ = ["ComplianceEvaluator", "ComplianceRule"]
