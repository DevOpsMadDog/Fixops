"""FixOps Compliance Engine - maps risk-adjusted findings to framework posture."""

from typing import Any, Dict, List, Optional
import structlog

logger = structlog.get_logger()


class ComplianceEngine:
    """Evaluate compliance posture using FixOps risk tiers."""

    _SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def __init__(self) -> None:
        self.framework_thresholds: Dict[str, str] = {
            "pci_dss": "HIGH",
            "sox": "HIGH",
            "hipaa": "HIGH",
            "nist": "MEDIUM",
            "gdpr": "MEDIUM",
        }

    def evaluate(
        self,
        frameworks: List[str],
        findings: List[Dict[str, Any]],
        business_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluate one or more frameworks returning a mapping of results."""

        results: Dict[str, Any] = {}
        for framework in frameworks:
            results[framework] = self._evaluate_framework(framework, findings, business_context)
        return results

    def _evaluate_framework(
        self,
        framework: str,
        findings: List[Dict[str, Any]],
        business_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluate a single framework using FixOps severity tiers."""

        normalized_findings: List[Dict[str, Any]] = []
        highest_scanner = "LOW"
        highest_fixops = "LOW"

        for finding in findings:
            scanner_severity = self._normalize_severity(
                finding.get("scanner_severity") or finding.get("severity")
            )
            fixops_severity = self._normalize_severity(
                finding.get("fixops_severity")
                or finding.get("risk_tier")
                or finding.get("severity")
            )

            highest_scanner = self._max_severity(highest_scanner, scanner_severity)
            highest_fixops = self._max_severity(highest_fixops, fixops_severity)

            normalized_findings.append(
                {
                    "id": finding.get("id")
                    or finding.get("cve")
                    or finding.get("rule_id")
                    or finding.get("title"),
                    "scanner_severity": scanner_severity,
                    "fixops_severity": fixops_severity,
                    "risk_adjustment": finding.get("risk_adjustment", 0),
                    "risk_factors": finding.get("risk_factors", []),
                }
            )

        threshold = self.framework_thresholds.get(framework.lower(), "HIGH")
        status = self._determine_status(threshold, highest_fixops)

        result = {
            "framework": framework,
            "status": status,
            "threshold": threshold,
            "highest_scanner_severity": highest_scanner,
            "highest_fixops_severity": highest_fixops,
            "findings": normalized_findings,
        }

        logger.info(
            "Compliance framework evaluated",
            framework=framework,
            status=status,
            highest_scanner=highest_scanner,
            highest_fixops=highest_fixops,
        )

        return result

    def _determine_status(self, threshold: str, highest_fixops: str) -> str:
        threshold_index = self._SEVERITY_ORDER.index(threshold)
        fixops_index = self._SEVERITY_ORDER.index(highest_fixops)

        if fixops_index >= threshold_index:
            return "non_compliant"
        if fixops_index == threshold_index - 1:
            return "needs_review"
        return "compliant"

    def _normalize_severity(self, severity: Optional[str]) -> str:
        if not severity:
            return "LOW"
        value = str(severity).upper()
        if value not in self._SEVERITY_ORDER:
            return "LOW"
        return value

    def _max_severity(self, current: str, other: str) -> str:
        return current if self._SEVERITY_ORDER.index(current) >= self._SEVERITY_ORDER.index(other) else other


compliance_engine = ComplianceEngine()
