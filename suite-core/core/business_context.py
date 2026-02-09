"""FixOps Business Context Engine

Automatic data classification, business criticality scoring, and exposure analysis.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class DataClassification(Enum):
    """Data classification levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class BusinessCriticality(Enum):
    """Business criticality levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    MISSION_CRITICAL = "mission_critical"


@dataclass
class DataClassificationResult:
    """Data classification result."""

    classification: DataClassification
    confidence: float
    indicators: List[str] = field(default_factory=list)
    reasoning: str = ""


@dataclass
class BusinessCriticalityResult:
    """Business criticality result."""

    criticality: BusinessCriticality
    score: float  # 0.0 to 1.0
    factors: Dict[str, float] = field(default_factory=dict)
    reasoning: str = ""


@dataclass
class ExposureAnalysis:
    """Exposure analysis result."""

    exposure_level: str  # internet, public, partner, internal, controlled
    exposure_score: float  # 0.0 to 1.0
    exposure_vectors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class DataClassificationEngine:
    """Proprietary data classification engine."""

    def __init__(self):
        """Initialize data classification engine."""
        self.patterns = self._build_classification_patterns()

    def _build_classification_patterns(
        self,
    ) -> Dict[DataClassification, List[Dict[str, Any]]]:
        """Build proprietary classification patterns."""
        return {
            DataClassification.TOP_SECRET: [
                {
                    "keywords": ["top secret", "classified", "ts//sci"],
                    "weight": 1.0,
                },
                {
                    "patterns": [r"ssn.*\d{3}-\d{2}-\d{4}", r"passport.*\d{9}"],
                    "weight": 0.9,
                },
            ],
            DataClassification.RESTRICTED: [
                {
                    "keywords": ["restricted", "confidential", "proprietary"],
                    "weight": 0.8,
                },
                {
                    "patterns": [r"credit.*card", r"cvv", r"cvc"],
                    "weight": 0.9,
                },
            ],
            DataClassification.CONFIDENTIAL: [
                {
                    "keywords": ["confidential", "private", "sensitive"],
                    "weight": 0.7,
                },
                {
                    "patterns": [r"email.*@", r"phone.*\d{10}"],
                    "weight": 0.6,
                },
            ],
            DataClassification.INTERNAL: [
                {
                    "keywords": ["internal", "employee", "staff"],
                    "weight": 0.5,
                },
            ],
            DataClassification.PUBLIC: [
                {
                    "keywords": ["public", "published", "blog"],
                    "weight": 0.3,
                },
            ],
        }

    def classify_data(
        self, content: str, metadata: Optional[Dict[str, Any]] = None
    ) -> DataClassificationResult:
        """Classify data automatically."""
        scores = {dc: 0.0 for dc in DataClassification}
        indicators = []

        content_lower = content.lower()

        for classification, patterns in self.patterns.items():
            for pattern_config in patterns:
                weight = pattern_config.get("weight", 0.5)

                # Check keywords
                if "keywords" in pattern_config:
                    for keyword in pattern_config["keywords"]:
                        if keyword in content_lower:
                            scores[classification] += weight
                            indicators.append(f"{classification.value}: {keyword}")

                # Check regex patterns
                if "patterns" in pattern_config:
                    for pattern in pattern_config["patterns"]:
                        if re.search(pattern, content, re.IGNORECASE):
                            scores[classification] += weight
                            indicators.append(f"{classification.value}: pattern match")

        # Determine classification
        max_score = max(scores.values())
        if max_score == 0:
            classification = DataClassification.INTERNAL  # Default
            confidence = 0.5
        else:
            classification = max(scores.items(), key=lambda x: x[1])[0]
            confidence = min(1.0, max_score / 2.0)  # Normalize

        return DataClassificationResult(
            classification=classification,
            confidence=confidence,
            indicators=indicators,
            reasoning=f"Classified as {classification.value} based on {len(indicators)} indicators",
        )


class BusinessCriticalityEngine:
    """Proprietary business criticality scoring engine."""

    def __init__(self):
        """Initialize business criticality engine."""
        self.factors = self._build_criticality_factors()

    def _build_criticality_factors(self) -> Dict[str, Dict[str, float]]:
        """Build criticality scoring factors."""
        return {
            "data_classification": {
                "top_secret": 1.0,
                "restricted": 0.9,
                "confidential": 0.7,
                "internal": 0.5,
                "public": 0.2,
            },
            "user_count": {
                "millions": 1.0,
                "hundreds_of_thousands": 0.8,
                "thousands": 0.6,
                "hundreds": 0.4,
                "tens": 0.2,
            },
            "revenue_impact": {
                "critical": 1.0,
                "high": 0.8,
                "medium": 0.5,
                "low": 0.2,
            },
            "compliance_requirements": {
                "pci_dss": 1.0,
                "hipaa": 0.9,
                "gdpr": 0.8,
                "soc2": 0.7,
                "none": 0.1,
            },
        }

    def calculate_criticality(
        self,
        component_data: Dict[str, Any],
        data_classification: Optional[DataClassification] = None,
    ) -> BusinessCriticalityResult:
        """Calculate business criticality."""
        factors = {}
        total_score = 0.0

        # Data classification factor
        if data_classification:
            classification_score = self.factors["data_classification"].get(
                data_classification.value, 0.5
            )
            factors["data_classification"] = classification_score
            total_score += classification_score * 0.3

        # User count factor
        user_count = component_data.get("user_count", "unknown")
        if isinstance(user_count, str):
            user_count_score = self.factors["user_count"].get(user_count, 0.5)
        else:
            # Numeric user count
            if user_count >= 1_000_000:
                user_count_score = 1.0
            elif user_count >= 100_000:
                user_count_score = 0.8
            elif user_count >= 10_000:
                user_count_score = 0.6
            elif user_count >= 1_000:
                user_count_score = 0.4
            else:
                user_count_score = 0.2

        factors["user_count"] = user_count_score
        total_score += user_count_score * 0.25

        # Revenue impact factor
        revenue_impact = component_data.get("revenue_impact", "medium")
        revenue_score = self.factors["revenue_impact"].get(revenue_impact, 0.5)
        factors["revenue_impact"] = revenue_score
        total_score += revenue_score * 0.25

        # Compliance factor
        compliance = component_data.get("compliance_requirements", [])
        if isinstance(compliance, str):
            compliance = [compliance]

        max_compliance_score = max(
            (
                self.factors["compliance_requirements"].get(c.lower(), 0.1)
                for c in compliance
            ),
            default=0.1,
        )
        factors["compliance"] = max_compliance_score
        total_score += max_compliance_score * 0.2

        # Determine criticality level
        if total_score >= 0.9:
            criticality = BusinessCriticality.MISSION_CRITICAL
        elif total_score >= 0.75:
            criticality = BusinessCriticality.CRITICAL
        elif total_score >= 0.6:
            criticality = BusinessCriticality.HIGH
        elif total_score >= 0.4:
            criticality = BusinessCriticality.MEDIUM
        else:
            criticality = BusinessCriticality.LOW

        return BusinessCriticalityResult(
            criticality=criticality,
            score=total_score,
            factors=factors,
            reasoning=f"Criticality: {criticality.value} (score: {total_score:.2f})",
        )


class ExposureAnalyzer:
    """Proprietary exposure analysis engine."""

    def analyze_exposure(
        self,
        component_data: Dict[str, Any],
        network_config: Optional[Dict[str, Any]] = None,
    ) -> ExposureAnalysis:
        """Analyze component exposure."""
        exposure_vectors = []
        exposure_score = 0.0

        # Check network exposure
        if network_config:
            if network_config.get("public_ip"):
                exposure_vectors.append("Public IP address")
                exposure_score += 0.4

            if network_config.get("open_ports"):
                open_ports = network_config["open_ports"]
                exposure_vectors.append(
                    f"Open ports: {', '.join(map(str, open_ports))}"
                )
                exposure_score += 0.2 * len(open_ports)

            if network_config.get("internet_facing"):
                exposure_vectors.append("Internet-facing")
                exposure_score += 0.3

        # Check authentication
        if not component_data.get("requires_authentication", True):
            exposure_vectors.append("No authentication required")
            exposure_score += 0.3

        # Check data exposure
        if component_data.get("exposes_sensitive_data", False):
            exposure_vectors.append("Exposes sensitive data")
            exposure_score += 0.2

        # Determine exposure level
        if exposure_score >= 0.8:
            exposure_level = "internet"
        elif exposure_score >= 0.6:
            exposure_level = "public"
        elif exposure_score >= 0.4:
            exposure_level = "partner"
        elif exposure_score >= 0.2:
            exposure_level = "internal"
        else:
            exposure_level = "controlled"

        # Generate recommendations
        recommendations = []
        if exposure_score >= 0.6:
            recommendations.append("Restrict network access")
            recommendations.append("Implement authentication")
        if exposure_vectors:
            recommendations.append("Review exposure vectors")

        return ExposureAnalysis(
            exposure_level=exposure_level,
            exposure_score=min(1.0, exposure_score),
            exposure_vectors=exposure_vectors,
            recommendations=recommendations,
        )


class BusinessContextEngine:
    """FixOps Business Context Engine - Proprietary business context integration."""

    def __init__(self):
        """Initialize business context engine."""
        self.data_classifier = DataClassificationEngine()
        self.criticality_engine = BusinessCriticalityEngine()
        self.exposure_analyzer = ExposureAnalyzer()

    def analyze_component(
        self,
        component_data: Dict[str, Any],
        code_content: Optional[str] = None,
        network_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Comprehensive business context analysis."""
        # Data classification
        data_classification = None
        if code_content:
            classification_result = self.data_classifier.classify_data(code_content)
            data_classification = classification_result.classification

        # Business criticality
        criticality_result = self.criticality_engine.calculate_criticality(
            component_data, data_classification
        )

        # Exposure analysis
        exposure_result = self.exposure_analyzer.analyze_exposure(
            component_data, network_config
        )

        return {
            "data_classification": {
                "level": data_classification.value
                if data_classification
                else "unknown",
                "confidence": classification_result.confidence if code_content else 0.0,
            },
            "business_criticality": {
                "level": criticality_result.criticality.value,
                "score": criticality_result.score,
                "factors": criticality_result.factors,
            },
            "exposure": {
                "level": exposure_result.exposure_level,
                "score": exposure_result.exposure_score,
                "vectors": exposure_result.exposure_vectors,
            },
            "risk_adjustment": self._calculate_risk_adjustment(
                criticality_result, exposure_result
            ),
        }

    def _calculate_risk_adjustment(
        self, criticality: BusinessCriticalityResult, exposure: ExposureAnalysis
    ) -> float:
        """Calculate risk adjustment factor."""
        # Higher criticality + higher exposure = higher risk
        base_risk = criticality.score * 0.6 + exposure.exposure_score * 0.4

        # Adjust for critical combinations
        if (
            criticality.criticality == BusinessCriticality.MISSION_CRITICAL
            and exposure.exposure_level == "internet"
        ):
            return min(2.0, base_risk * 1.5)  # 50% boost

        return base_risk
