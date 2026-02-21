"""Policy rules for overriding decision verdicts based on critical vulnerability combinations.

This module provides policy-based overrides for the EnhancedDecisionEngine to ensure
that critical vulnerability combinations (e.g., internet-facing SQL injection in
authentication services) receive appropriate verdicts regardless of EPSS scores or
other factors.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


@dataclass
class PolicyOverride:
    """Result of a policy evaluation that may override the base verdict."""

    triggered: bool
    new_verdict: Optional[str] = None
    reason: str = ""
    policy_id: str = ""
    confidence_boost: float = 0.0


class DecisionPolicyEngine:
    """Evaluates policy rules that can override decision verdicts for critical cases."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize policy engine with configuration.

        Parameters
        ----------
        config:
            Optional configuration dictionary with policy settings.
        """
        self.config = dict(config or {})
        policy_config = self.config.get("decision_policy", {})

        self.block_internet_facing_sqli = policy_config.get(
            "block_internet_facing_sqli", True
        )
        self.block_auth_path_sqli = policy_config.get("block_auth_path_sqli", True)
        self.block_critical_internet_facing = policy_config.get(
            "block_critical_internet_facing", True
        )

        self.internet_facing_multiplier = float(
            policy_config.get("internet_facing_multiplier", 3.0)
        )
        self.auth_path_multiplier = float(
            policy_config.get("auth_path_multiplier", 2.0)
        )
        self.critical_service_multiplier = float(
            policy_config.get("critical_service_multiplier", 1.5)
        )

        logger.info(
            "Initialized DecisionPolicyEngine: "
            "block_internet_facing_sqli=%s, block_auth_path_sqli=%s, "
            "internet_facing_multiplier=%.1f",
            self.block_internet_facing_sqli,
            self.block_auth_path_sqli,
            self.internet_facing_multiplier,
        )

    def evaluate_overrides(
        self,
        base_verdict: str,
        base_confidence: float,
        severity: str,
        exposures: Sequence[Mapping[str, Any]],
        context_summary: Optional[Mapping[str, Any]] = None,
        finding_metadata: Optional[Mapping[str, Any]] = None,
    ) -> PolicyOverride:
        """Evaluate policy rules and return override if triggered.

        Parameters
        ----------
        base_verdict:
            The base verdict from the decision engine ("allow", "review", "block").
        base_confidence:
            The base confidence score (0.0-1.0).
        severity:
            The highest severity level ("low", "medium", "high", "critical").
        exposures:
            List of CNAPP exposure findings.
        context_summary:
            Optional context summary with service/environment information.
        finding_metadata:
            Optional metadata about the finding (vulnerability type, location, etc.).

        Returns
        -------
        PolicyOverride:
            Override result indicating if a policy was triggered and what the new verdict should be.
        """
        is_internet_facing = self._is_internet_facing(exposures, context_summary)

        is_auth_path = self._is_auth_path(context_summary, finding_metadata)

        is_sql_injection = self._is_sql_injection(finding_metadata)

        if (
            self.block_internet_facing_sqli
            and is_internet_facing
            and is_sql_injection
            and base_verdict != "block"
        ):
            return PolicyOverride(
                triggered=True,
                new_verdict="block",
                reason="Policy: block internet-facing SQL injection",
                policy_id="block_internet_facing_sqli",
                confidence_boost=0.15,
            )

        if (
            self.block_auth_path_sqli
            and is_auth_path
            and is_sql_injection
            and base_verdict != "block"
        ):
            return PolicyOverride(
                triggered=True,
                new_verdict="block",
                reason="Policy: block SQL injection in authentication service",
                policy_id="block_auth_path_sqli",
                confidence_boost=0.15,
            )

        if (
            self.block_critical_internet_facing
            and is_internet_facing
            and severity == "critical"
            and base_verdict != "block"
        ):
            return PolicyOverride(
                triggered=True,
                new_verdict="block",
                reason="Policy: block critical severity internet-facing vulnerabilities",
                policy_id="block_critical_internet_facing",
                confidence_boost=0.10,
            )

        if (
            is_internet_facing
            and is_auth_path
            and severity in ("high", "critical")
            and base_verdict == "allow"
        ):
            return PolicyOverride(
                triggered=True,
                new_verdict="review",
                reason="Policy: escalate high severity internet-facing authentication vulnerabilities",
                policy_id="escalate_auth_internet_facing",
                confidence_boost=0.08,
            )

        return PolicyOverride(triggered=False)

    def calculate_exposure_multiplier(
        self,
        exposures: Sequence[Mapping[str, Any]],
        context_summary: Optional[Mapping[str, Any]] = None,
        finding_metadata: Optional[Mapping[str, Any]] = None,
    ) -> float:
        """Calculate risk score multiplier based on exposure context.

        Parameters
        ----------
        exposures:
            List of CNAPP exposure findings.
        context_summary:
            Optional context summary with service/environment information.
        finding_metadata:
            Optional metadata about the finding (vulnerability type, location, etc.).

        Returns
        -------
        float:
            Multiplier to apply to base risk score (1.0 = no change, >1.0 = increase risk).
        """
        multiplier = 1.0

        if self._is_internet_facing(exposures, context_summary):
            multiplier *= self.internet_facing_multiplier
            logger.debug("Applied internet-facing multiplier: %.1f", multiplier)

        if self._is_auth_path(context_summary, finding_metadata):
            multiplier *= self.auth_path_multiplier
            logger.debug("Applied auth-path multiplier: %.1f", multiplier)

        if self._is_critical_service(context_summary):
            multiplier *= self.critical_service_multiplier
            logger.debug("Applied critical-service multiplier: %.1f", multiplier)

        return multiplier

    def _is_internet_facing(
        self,
        exposures: Sequence[Mapping[str, Any]],
        context_summary: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Check if the vulnerability is internet-facing."""
        for exposure in exposures:
            if not isinstance(exposure, Mapping):
                continue
            exposure_type = str(exposure.get("type", "")).lower()
            traits = exposure.get("traits", [])
            if "internet" in exposure_type or "public" in exposure_type:
                return True
            if isinstance(traits, list):
                for trait in traits:
                    trait_str = str(trait).lower()
                    if "internet" in trait_str or "public" in trait_str:
                        return True

        if isinstance(context_summary, Mapping):
            exposure_str = str(context_summary.get("exposure", "")).lower()
            if "internet" in exposure_str or "public" in exposure_str:
                return True

            service = context_summary.get("service", {})
            if isinstance(service, Mapping):
                exposure_str = str(service.get("exposure", "")).lower()
                if "internet" in exposure_str or "public" in exposure_str:
                    return True

        return False

    def _is_auth_path(
        self,
        context_summary: Optional[Mapping[str, Any]] = None,
        finding_metadata: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Check if the vulnerability is in an authentication path."""
        if isinstance(finding_metadata, Mapping):
            location = str(finding_metadata.get("location", "")).lower()
            file_path = str(finding_metadata.get("file", "")).lower()
            service_name = str(finding_metadata.get("service", "")).lower()

            auth_keywords = [
                "auth",
                "login",
                "signin",
                "password",
                "credential",
                "token",
            ]
            for keyword in auth_keywords:
                if (
                    keyword in location
                    or keyword in file_path
                    or keyword in service_name
                ):
                    return True

        if isinstance(context_summary, Mapping):
            service_name = str(
                context_summary.get("service_name")
                or context_summary.get("service")
                or ""
            ).lower()
            service_type = str(context_summary.get("service_type", "")).lower()

            auth_keywords = [
                "auth",
                "login",
                "signin",
                "password",
                "credential",
                "token",
            ]
            for keyword in auth_keywords:
                if keyword in service_name or keyword in service_type:
                    return True

        return False

    def _is_sql_injection(
        self, finding_metadata: Optional[Mapping[str, Any]] = None
    ) -> bool:
        """Check if the vulnerability is a SQL injection."""
        if not isinstance(finding_metadata, Mapping):
            return False

        cwe_ids = finding_metadata.get("cwe_ids", [])
        if isinstance(cwe_ids, list):
            for cwe_id in cwe_ids:
                if str(cwe_id).upper() in ("CWE-89", "CWE-564"):
                    return True

        vuln_type = str(finding_metadata.get("type", "")).lower()
        rule_id = str(finding_metadata.get("rule_id", "")).lower()
        message = str(finding_metadata.get("message", "")).lower()

        sql_keywords = ["sql injection", "sqli", "sql-injection", "cwe-89"]
        for keyword in sql_keywords:
            if keyword in vuln_type or keyword in rule_id or keyword in message:
                return True

        return False

    def _is_critical_service(
        self, context_summary: Optional[Mapping[str, Any]] = None
    ) -> bool:
        """Check if the service is marked as critical."""
        if not isinstance(context_summary, Mapping):
            return False

        business_impact = str(context_summary.get("business_impact", "")).lower()
        if "critical" in business_impact or "high" in business_impact:
            return True

        service = context_summary.get("service", {})
        if isinstance(service, Mapping):
            criticality = str(service.get("criticality", "")).lower()
            if "critical" in criticality or "high" in criticality:
                return True

        return False


__all__ = ["DecisionPolicyEngine", "PolicyOverride"]
