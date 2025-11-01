"""Severity promotion with evidence tracking for audit trails."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

logger = logging.getLogger(__name__)

PROMOTION_RULE_VERSION = "1.0.0"


@dataclass
class SeverityPromotionEvidence:
    """Evidence for a severity promotion decision."""

    cve_id: str
    was_promoted: bool
    prior_severity: str
    new_severity: str
    first_seen_at: str  # ISO 8601 timestamp when finding was first recorded
    first_exploit_report_at: Optional[str] = None  # When KEV/exploit was first detected
    evidence_source: Optional[str] = None  # KEV ID, advisory link, EPSS spike note
    promotion_rule_version: str = PROMOTION_RULE_VERSION
    promotion_reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "was_promoted": self.was_promoted,
            "prior_severity": self.prior_severity,
            "new_severity": self.new_severity,
            "first_seen_at": self.first_seen_at,
            "first_exploit_report_at": self.first_exploit_report_at,
            "evidence_source": self.evidence_source,
            "promotion_rule_version": self.promotion_rule_version,
            "promotion_reason": self.promotion_reason,
            "metadata": dict(self.metadata),
        }


@dataclass
class PromotionRule:
    """Rule for promoting severity based on exploit signals."""

    signal_type: str  # "kev", "epss_high", "exploitdb"
    threshold: Optional[float] = None  # For numeric signals like EPSS
    promote_from: List[str] = field(default_factory=list)  # Severities to promote
    promote_to: str = "high"  # Target severity
    evidence_template: str = ""  # Template for evidence_source field

    def applies_to(self, severity: str, signal_value: Any) -> bool:
        """Check if this rule applies to the given severity and signal."""
        if not self.promote_from or severity.lower() in [
            s.lower() for s in self.promote_from
        ]:
            if self.threshold is not None:
                try:
                    return float(signal_value) >= self.threshold
                except (TypeError, ValueError):
                    return False
            return bool(signal_value)
        return False


DEFAULT_PROMOTION_RULES = [
    PromotionRule(
        signal_type="kev",
        promote_from=["low", "medium", "high"],
        promote_to="critical",
        evidence_template="CISA KEV catalog - actively exploited in the wild",
    ),
    PromotionRule(
        signal_type="epss_high",
        threshold=0.7,
        promote_from=["low", "medium"],
        promote_to="high",
        evidence_template="EPSS score >= 0.7 - high exploitation probability",
    ),
]


class SeverityPromotionEngine:
    """Engine for promoting severity with full evidence tracking."""

    def __init__(
        self,
        rules: Optional[List[PromotionRule]] = None,
        enabled: bool = True,
    ):
        """Initialize severity promotion engine.

        Parameters
        ----------
        rules:
            List of promotion rules to apply. Defaults to DEFAULT_PROMOTION_RULES.
        enabled:
            Whether severity promotion is enabled.
        """
        self.rules = rules or DEFAULT_PROMOTION_RULES
        self.enabled = enabled
        self._now = datetime.now(timezone.utc)

    def evaluate_promotion(
        self,
        cve_id: str,
        current_severity: str,
        exploit_signals: Mapping[str, Any],
        first_seen_at: Optional[str] = None,
    ) -> Optional[SeverityPromotionEvidence]:
        """Evaluate if severity should be promoted based on exploit signals.

        Parameters
        ----------
        cve_id:
            CVE identifier.
        current_severity:
            Current severity level (low, medium, high, critical).
        exploit_signals:
            Exploit signals data containing KEV, EPSS, etc.
        first_seen_at:
            ISO 8601 timestamp when finding was first recorded.

        Returns
        -------
        Optional[SeverityPromotionEvidence]
            Promotion evidence if severity should be promoted, None otherwise.
        """
        if not self.enabled:
            return None

        first_seen = first_seen_at or self._now.isoformat()
        cve_upper = cve_id.upper()

        kev_listed = self._check_kev_signal(cve_upper, exploit_signals)
        if kev_listed:
            for rule in self.rules:
                if rule.signal_type == "kev" and rule.applies_to(
                    current_severity, True
                ):
                    kev_date = self._extract_kev_date(cve_upper, exploit_signals)
                    evidence_source = self._build_kev_evidence_source(
                        cve_upper, exploit_signals
                    )
                    return SeverityPromotionEvidence(
                        cve_id=cve_id,
                        was_promoted=True,
                        prior_severity=current_severity.lower(),
                        new_severity=rule.promote_to.lower(),
                        first_seen_at=first_seen,
                        first_exploit_report_at=kev_date or self._now.isoformat(),
                        evidence_source=evidence_source,
                        promotion_rule_version=PROMOTION_RULE_VERSION,
                        promotion_reason=f"KEV-listed: {rule.evidence_template}",
                        metadata={
                            "signal_type": "kev",
                            "rule_applied": "kev_to_critical",
                        },
                    )

        epss_score = self._extract_epss_score(cve_upper, exploit_signals)
        if epss_score is not None:
            for rule in self.rules:
                if rule.signal_type == "epss_high" and rule.applies_to(
                    current_severity, epss_score
                ):
                    return SeverityPromotionEvidence(
                        cve_id=cve_id,
                        was_promoted=True,
                        prior_severity=current_severity.lower(),
                        new_severity=rule.promote_to.lower(),
                        first_seen_at=first_seen,
                        first_exploit_report_at=self._now.isoformat(),
                        evidence_source=f"EPSS score {epss_score:.4f} (threshold: {rule.threshold})",
                        promotion_rule_version=PROMOTION_RULE_VERSION,
                        promotion_reason=rule.evidence_template,
                        metadata={
                            "signal_type": "epss",
                            "epss_score": epss_score,
                            "threshold": rule.threshold,
                            "rule_applied": "epss_high_to_high",
                        },
                    )

        return SeverityPromotionEvidence(
            cve_id=cve_id,
            was_promoted=False,
            prior_severity=current_severity.lower(),
            new_severity=current_severity.lower(),
            first_seen_at=first_seen,
            promotion_rule_version=PROMOTION_RULE_VERSION,
            promotion_reason="No promotion criteria met",
        )

    def _check_kev_signal(
        self, cve_id: str, exploit_signals: Mapping[str, Any]
    ) -> bool:
        """Check if CVE is listed in KEV catalog."""
        if not isinstance(exploit_signals, Mapping):
            return False

        signals = exploit_signals.get("signals", {})
        if isinstance(signals, Mapping):
            kev_signal = signals.get("kev") or signals.get("cisa_kev")
            if isinstance(kev_signal, Mapping):
                matches = kev_signal.get("matches", [])
                if isinstance(matches, list):
                    for match in matches:
                        if isinstance(match, Mapping):
                            match_cve = match.get("cve_id")
                            if (
                                isinstance(match_cve, str)
                                and match_cve.upper() == cve_id
                            ):
                                return True

        kev_data = exploit_signals.get("kev", {})
        if isinstance(kev_data, Mapping):
            vulnerabilities = kev_data.get("vulnerabilities", [])
            if isinstance(vulnerabilities, list):
                for vuln in vulnerabilities:
                    if isinstance(vuln, Mapping):
                        vuln_cve = vuln.get("cveID")
                        if isinstance(vuln_cve, str) and vuln_cve.upper() == cve_id:
                            return True

        return False

    def _extract_kev_date(
        self, cve_id: str, exploit_signals: Mapping[str, Any]
    ) -> Optional[str]:
        """Extract the date when CVE was added to KEV catalog."""
        if not isinstance(exploit_signals, Mapping):
            return None

        kev_data = exploit_signals.get("kev", {})
        if isinstance(kev_data, Mapping):
            vulnerabilities = kev_data.get("vulnerabilities", [])
            if isinstance(vulnerabilities, list):
                for vuln in vulnerabilities:
                    if isinstance(vuln, Mapping):
                        vuln_cve = vuln.get("cveID")
                        if isinstance(vuln_cve, str) and vuln_cve.upper() == cve_id:
                            date_added = vuln.get("dateAdded")
                            if isinstance(date_added, str):
                                return date_added

        return None

    def _build_kev_evidence_source(
        self, cve_id: str, exploit_signals: Mapping[str, Any]
    ) -> str:
        """Build evidence source string for KEV-listed CVE."""
        kev_date = self._extract_kev_date(cve_id, exploit_signals)
        if kev_date:
            return f"CISA KEV catalog (added: {kev_date}) - https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        return "CISA KEV catalog - https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

    def _extract_epss_score(
        self, cve_id: str, exploit_signals: Mapping[str, Any]
    ) -> Optional[float]:
        """Extract EPSS score for CVE."""
        if not isinstance(exploit_signals, Mapping):
            return None

        signals = exploit_signals.get("signals", {})
        if isinstance(signals, Mapping):
            epss_signal = signals.get("epss")
            if isinstance(epss_signal, Mapping):
                matches = epss_signal.get("matches", [])
                if isinstance(matches, list):
                    for match in matches:
                        if isinstance(match, Mapping):
                            match_cve = match.get("cve_id")
                            score = match.get("value")
                            if (
                                isinstance(match_cve, str)
                                and match_cve.upper() == cve_id
                                and isinstance(score, (int, float))
                            ):
                                return float(score)

        epss_data = exploit_signals.get("epss", {})
        if isinstance(epss_data, Mapping):
            score = epss_data.get(cve_id)
            if isinstance(score, (int, float)):
                return float(score)

        return None


__all__ = [
    "SeverityPromotionEvidence",
    "SeverityPromotionEngine",
    "PromotionRule",
    "DEFAULT_PROMOTION_RULES",
    "PROMOTION_RULE_VERSION",
]
