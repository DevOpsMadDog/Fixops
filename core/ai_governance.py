"""AI Model Governance & System Cards.

This module implements "System Cards" and Model Governance artifacts aligned with
ISO/IEC 42001 (AI Management Systems) and NIST AI RMF.

It generates human-readable and machine-parseable reports detailing:
1. Intended Purpose & Limitations
2. Fairness & Bias Checks
3. Safety & Performance Metrics
4. Human Oversight Controls
"""

from __future__ import annotations

import datetime
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.ai_bom import ModelCard

logger = logging.getLogger(__name__)


@dataclass
class FairnessCheck:
    """Fairness assessment results."""
    metric_name: str
    group_attribute: str  # e.g., "gender", "age"
    parity_difference: float
    threshold: float
    passed: bool


@dataclass
class SafetyEval:
    """Safety evaluation results."""
    test_name: str  # e.g., "hallucination_rate", "jailbreak_resistance"
    score: float
    threshold: float
    passed: bool
    details: str


@dataclass
class SystemCard:
    """System Card for a deployed AI system (Model + Context)."""
    
    system_id: str
    system_name: str
    model_card: ModelCard
    
    # ISO 42001 Controls
    human_oversight_measures: List[str] = field(default_factory=list)
    data_governance_policy: str = "Standard Enterprise Policy"
    
    # Validation Results
    fairness_checks: List[FairnessCheck] = field(default_factory=list)
    safety_evals: List[SafetyEval] = field(default_factory=list)
    
    # Operational Metrics
    deployment_date: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    status: str = "active"  # active, deprecated, testing

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "system_name": self.system_name,
            "model_metadata": {
                "name": self.model_card.name,
                "version": self.model_card.version,
                "type": self.model_card.model_type
            },
            "governance": {
                "human_oversight": self.human_oversight_measures,
                "data_policy": self.data_governance_policy,
                "iso_42001_alignment": True
            },
            "validation": {
                "fairness": [
                    {
                        "metric": f.metric_name,
                        "group": f.group_attribute,
                        "diff": f.parity_difference,
                        "passed": f.passed
                    }
                    for f in self.fairness_checks
                ],
                "safety": [
                    {
                        "test": s.test_name,
                        "score": s.score,
                        "passed": s.passed,
                        "details": s.details
                    }
                    for s in self.safety_evals
                ]
            },
            "status": self.status,
            "generated_at": self.deployment_date
        }

    def generate_markdown(self) -> str:
        """Generate a human-readable System Card report."""
        md = [
            f"# System Card: {self.system_name}",
            f"**ID**: {self.system_id} | **Status**: {self.status.upper()}",
            "---",
            "## 1. Model Overview",
            f"- **Model**: {self.model_card.name} (v{self.model_card.version})",
            f"- **Type**: {self.model_card.model_type}",
            f"- **Description**: {self.model_card.description}",
            "",
            "## 2. Intended Use & Limitations",
            "**Intended Use**:",
            *[f"- {use}" for use in self.model_card.intended_use],
            "",
            "**Limitations**:",
            *[f"- {limit}" for limit in self.model_card.limitations],
            "",
            "## 3. Governance & Oversight (ISO 42001)",
            "**Human Oversight Measures**:",
            *[f"- {measure}" for measure in self.human_oversight_measures],
            "",
            "## 4. Safety & Fairness Validation",
        ]

        if self.fairness_checks:
            md.append("### Fairness Checks")
            md.append("| Metric | Group | Parity Diff | Status |")
            md.append("|---|---|---|---|")
            for f in self.fairness_checks:
                status = "✅ PASS" if f.passed else "❌ FAIL"
                md.append(f"| {f.metric_name} | {f.group_attribute} | {f.parity_difference:.3f} | {status} |")
            md.append("")

        if self.safety_evals:
            md.append("### Safety Evaluations")
            md.append("| Test | Score | Threshold | Status |")
            md.append("|---|---|---|---|")
            for s in self.safety_evals:
                status = "✅ PASS" if s.passed else "❌ FAIL"
                md.append(f"| {s.test_name} | {s.score:.2f} | {s.threshold:.2f} | {status} |")

        return "\n".join(md)


class GovernanceEngine:
    """Orchestrates the creation and validation of System Cards."""

    def __init__(self, organization: str = "FixOps"):
        self.organization = organization

    def create_system_card(
        self,
        system_name: str,
        model_card: ModelCard,
        safety_results: List[SafetyEval],
        fairness_results: List[FairnessCheck],
        oversight_measures: List[str]
    ) -> SystemCard:
        """Create a full System Card."""
        return SystemCard(
            system_id=f"sys-{model_card.name.lower().replace(' ', '-')}-{model_card.version}",
            system_name=system_name,
            model_card=model_card,
            safety_evals=safety_results,
            fairness_checks=fairness_results,
            human_oversight_measures=oversight_measures
        )
