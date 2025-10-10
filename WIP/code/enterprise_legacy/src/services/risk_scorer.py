"""Context-aware risk scoring utilities for FixOps."""

from typing import Any, Dict, List, Optional, Tuple


class ContextualRiskScorer:
    """Apply business context aware adjustments to scanner findings."""

    _SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    _SENSITIVE_DATA_CLASSIFICATIONS = {
        "pii",
        "phi",
        "pci",
        "confidential",
        "restricted",
        "secret",
        "financial",
        "customer",
        "internal_high",
    }
    _LOW_DATA_CLASSIFICATIONS = {"public", "test", "non_sensitive"}
    _HIGH_IMPACT_TERMS = {"high", "critical", "mission_critical", "major"}
    _LOW_IMPACT_TERMS = {"low", "minor", "internal", "limited"}
    _FAST_DEPLOYMENT = {"continuous", "hourly", "daily"}
    _SLOW_DEPLOYMENT = {"monthly", "quarterly", "annual", "annually", "rare", "ad-hoc"}

    def apply(
        self,
        findings: List[Dict[str, Any]],
        business_context: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Return findings with context-aware risk adjustments applied."""

        if not findings:
            return []

        adjusted: List[Dict[str, Any]] = []
        for finding in findings:
            adjusted.append(self._adjust_finding(finding, business_context or {}))
        return adjusted

    def _adjust_finding(
        self, finding: Dict[str, Any], business_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        original_severity = self._normalize_severity(
            finding.get("scanner_severity") or finding.get("severity")
        )

        result = dict(finding)
        result["scanner_severity"] = original_severity

        if result.get("fixops_severity"):
            result["fixops_severity"] = self._normalize_severity(result["fixops_severity"])
            result.setdefault("risk_tier", result["fixops_severity"])
            delta = self._severity_index(result["fixops_severity"]) - self._severity_index(
                original_severity
            )
            result.setdefault("risk_adjustment", delta)
            return result

        adjustment, factors = self._calculate_adjustment(business_context)
        base_index = self._severity_index(original_severity)
        adjusted_index = max(0, min(len(self._SEVERITY_ORDER) - 1, base_index + adjustment))
        fixops_severity = self._SEVERITY_ORDER[adjusted_index]

        result["fixops_severity"] = fixops_severity
        result["risk_adjustment"] = adjusted_index - base_index
        if factors:
            result["risk_factors"] = factors
        result.setdefault("risk_tier", fixops_severity)

        return result

    def _calculate_adjustment(
        self, business_context: Dict[str, Any]
    ) -> Tuple[int, List[str]]:
        adjustment = 0
        factors: List[str] = []

        customer_impact = (
            business_context.get("customer_impact")
            or business_context.get("business_criticality")
            or business_context.get("criticality")
            or business_context.get("business_impact")
        )
        if isinstance(customer_impact, str):
            impact_value = customer_impact.lower()
            if impact_value in self._HIGH_IMPACT_TERMS:
                adjustment += 1
                factors.append("high_customer_impact")
            elif impact_value in self._LOW_IMPACT_TERMS:
                adjustment -= 1
                factors.append("low_customer_impact")

        data_classification = business_context.get("data_classification")
        if data_classification:
            if isinstance(data_classification, str):
                data_values = {data_classification.lower()}
            else:
                data_values = {str(v).lower() for v in data_classification if v}

            if data_values & self._SENSITIVE_DATA_CLASSIFICATIONS:
                adjustment += 1
                factors.append("sensitive_data")
            elif data_values and data_values <= self._LOW_DATA_CLASSIFICATIONS:
                adjustment -= 1
                factors.append("non_sensitive_data")

        deployment_frequency = business_context.get("deployment_frequency")
        if isinstance(deployment_frequency, str):
            frequency_value = deployment_frequency.lower()
            if frequency_value in self._FAST_DEPLOYMENT:
                adjustment += 1
                factors.append("rapid_deployment")
            elif frequency_value in self._SLOW_DEPLOYMENT:
                adjustment -= 1
                factors.append("infrequent_deployment")

        if adjustment > 1:
            adjustment = 1
        elif adjustment < -1:
            adjustment = -1

        return adjustment, factors

    def _normalize_severity(self, severity: Optional[str]) -> str:
        if not severity:
            return "MEDIUM"
        severity_upper = str(severity).upper()
        if severity_upper not in self._SEVERITY_ORDER:
            return "MEDIUM"
        return severity_upper

    def _severity_index(self, severity: str) -> int:
        try:
            return self._SEVERITY_ORDER.index(severity)
        except ValueError:
            return 1
