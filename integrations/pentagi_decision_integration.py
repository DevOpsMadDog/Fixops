"""Integration between Pentagi pen testing and FixOps decision engine."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.enhanced_decision import MultiLLMResult
from core.pentagi_db import PentagiDB
from core.pentagi_models import ExploitabilityLevel

from integrations.pentagi_service import AdvancedPentagiService

logger = logging.getLogger(__name__)


class PentagiDecisionIntegration:
    """
    Integrates Pentagi pen testing results with FixOps decision engine.

    Enhances decision-making by incorporating exploitability data from
    automated penetration testing.
    """

    def __init__(
        self,
        pentagi_service: Optional[AdvancedPentagiService] = None,
        db: Optional[PentagiDB] = None,
    ):
        """
        Initialize integration.

        Args:
            pentagi_service: Advanced Pentagi service instance
            db: Database manager instance
        """
        self.pentagi_service = pentagi_service
        self.db = db or PentagiDB()

    def enhance_decision_with_exploitability(
        self,
        decision_result: MultiLLMResult,
        finding_id: str,
    ) -> Dict[str, Any]:
        """
        Enhance decision result with exploitability data from pen tests.

        Args:
            decision_result: Result from FixOps decision engine
            finding_id: ID of the finding being evaluated

        Returns:
            Enhanced decision result with exploitability information
        """
        # Get pen test results for this finding
        pen_test_results = self.db.list_results(finding_id=finding_id, limit=10)

        if not pen_test_results:
            # No pen test data available
            return {
                **decision_result.to_dict(),
                "exploitability": {
                    "tested": False,
                    "level": "unknown",
                    "message": "No penetration test data available",
                },
            }

        # Use most recent result
        latest_result = pen_test_results[0]

        # Map exploitability to decision signals
        exploitability_signals = self._map_exploitability_to_signals(
            latest_result.exploitability
        )

        # Enhance recommended action based on exploitability
        enhanced_action = self._enhance_action_with_exploitability(
            decision_result.recommended_action,
            latest_result.exploitability,
            latest_result.exploit_successful,
        )

        # Calculate risk adjustment
        risk_adjustment = self._calculate_risk_adjustment(
            latest_result.exploitability,
            latest_result.exploit_successful,
            latest_result.confidence_score,
        )

        return {
            **decision_result.to_dict(),
            "exploitability": {
                "tested": True,
                "level": latest_result.exploitability.value,
                "exploit_successful": latest_result.exploit_successful,
                "confidence": latest_result.confidence_score,
                "evidence": latest_result.evidence[:500],  # Truncate for response
                "steps_taken": latest_result.steps_taken[:5],  # Limit steps
            },
            "enhanced_action": enhanced_action,
            "risk_adjustment": risk_adjustment,
            "signals": {
                **decision_result.to_dict().get("signals", {}),
                **exploitability_signals,
            },
        }

    def _map_exploitability_to_signals(
        self,
        exploitability: ExploitabilityLevel,
    ) -> Dict[str, Any]:
        """Map exploitability level to decision signals."""
        mapping = {
            ExploitabilityLevel.CONFIRMED_EXPLOITABLE: {
                "exploitability_score": 1.0,
                "urgency": "critical",
                "requires_immediate_action": True,
            },
            ExploitabilityLevel.LIKELY_EXPLOITABLE: {
                "exploitability_score": 0.75,
                "urgency": "high",
                "requires_immediate_action": True,
            },
            ExploitabilityLevel.INCONCLUSIVE: {
                "exploitability_score": 0.5,
                "urgency": "medium",
                "requires_immediate_action": False,
            },
            ExploitabilityLevel.UNEXPLOITABLE: {
                "exploitability_score": 0.25,
                "urgency": "low",
                "requires_immediate_action": False,
            },
            ExploitabilityLevel.BLOCKED: {
                "exploitability_score": 0.0,
                "urgency": "low",
                "requires_immediate_action": False,
            },
        }
        return mapping.get(exploitability, {})

    def _enhance_action_with_exploitability(
        self,
        original_action: str,
        exploitability: ExploitabilityLevel,
        exploit_successful: bool,
    ) -> str:
        """Enhance recommended action based on exploitability."""
        if exploitability == ExploitabilityLevel.CONFIRMED_EXPLOITABLE:
            if "block" not in original_action.lower():
                return f"BLOCK - {original_action} (Confirmed exploitable)"
        elif exploitability == ExploitabilityLevel.LIKELY_EXPLOITABLE:
            if "review" not in original_action.lower():
                return f"URGENT REVIEW - {original_action} (Likely exploitable)"
        elif exploitability == ExploitabilityLevel.UNEXPLOITABLE:
            if "allow" not in original_action.lower():
                return f"ALLOW - {original_action} (Not exploitable)"

        return original_action

    def _calculate_risk_adjustment(
        self,
        exploitability: ExploitabilityLevel,
        exploit_successful: bool,
        confidence: float,
    ) -> Dict[str, Any]:
        """Calculate risk adjustment based on exploitability."""
        base_scores = {
            ExploitabilityLevel.CONFIRMED_EXPLOITABLE: 1.0,
            ExploitabilityLevel.LIKELY_EXPLOITABLE: 0.75,
            ExploitabilityLevel.INCONCLUSIVE: 0.5,
            ExploitabilityLevel.UNEXPLOITABLE: 0.25,
            ExploitabilityLevel.BLOCKED: 0.0,
        }

        base_score = base_scores.get(exploitability, 0.5)
        adjusted_score = base_score * confidence

        if exploit_successful:
            adjusted_score = min(1.0, adjusted_score * 1.2)

        return {
            "base_score": base_score,
            "adjusted_score": adjusted_score,
            "multiplier": 1.2 if exploit_successful else 1.0,
            "confidence_factor": confidence,
        }

    def should_trigger_pen_test(
        self,
        finding_severity: str,
        finding_source: str,
        internet_facing: bool,
    ) -> bool:
        """
        Determine if a pen test should be automatically triggered.

        Args:
            finding_severity: Severity of the finding
            finding_source: Source of the finding (SAST, CVE, etc.)
            internet_facing: Whether the target is internet-facing

        Returns:
            True if pen test should be triggered
        """
        # Always test critical/high severity findings
        if finding_severity in ["critical", "high"]:
            return True

        # Test internet-facing medium severity findings
        if finding_severity == "medium" and internet_facing:
            return True

        # Test CVE findings with high EPSS scores
        if finding_source == "CVE":
            return True

        return False

    def get_exploitability_summary(
        self,
        finding_ids: List[str],
    ) -> Dict[str, Any]:
        """
        Get exploitability summary for multiple findings.

        Args:
            finding_ids: List of finding IDs

        Returns:
            Summary statistics
        """
        all_results = []
        for finding_id in finding_ids:
            results = self.db.list_results(finding_id=finding_id, limit=1)
            if results:
                all_results.append(results[0])

        if not all_results:
            return {
                "total_tested": 0,
                "exploitable": 0,
                "not_exploitable": 0,
                "inconclusive": 0,
            }

        summary = {
            "total_tested": len(all_results),
            "exploitable": sum(
                1
                for r in all_results
                if r.exploitability
                in [
                    ExploitabilityLevel.CONFIRMED_EXPLOITABLE,
                    ExploitabilityLevel.LIKELY_EXPLOITABLE,
                ]
            ),
            "not_exploitable": sum(
                1
                for r in all_results
                if r.exploitability == ExploitabilityLevel.UNEXPLOITABLE
            ),
            "inconclusive": sum(
                1
                for r in all_results
                if r.exploitability == ExploitabilityLevel.INCONCLUSIVE
            ),
            "blocked": sum(
                1
                for r in all_results
                if r.exploitability == ExploitabilityLevel.BLOCKED
            ),
            "exploit_successful_count": sum(
                1 for r in all_results if r.exploit_successful
            ),
        }

        return summary
