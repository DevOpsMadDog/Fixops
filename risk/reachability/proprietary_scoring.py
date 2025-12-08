"""Proprietary FixOps risk scoring algorithm - no OSS dependencies.

This is FixOps' proprietary scoring algorithm that doesn't rely on
any open source scoring libraries. Built from scratch using proprietary
mathematical models.
"""

from __future__ import annotations

import logging
import math
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional

logger = logging.getLogger(__name__)


@dataclass
class ProprietaryRiskFactors:
    """Proprietary risk factor calculation."""
    
    exploitability: float  # 0.0 to 1.0
    impact: float  # 0.0 to 1.0
    exposure: float  # 0.0 to 1.0
    reachability: float  # 0.0 to 1.0
    temporal: float  # 0.0 to 1.0
    environmental: float  # 0.0 to 1.0


class ProprietaryScoringEngine:
    """Proprietary risk scoring engine - custom algorithms."""
    
    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize proprietary scoring engine."""
        self.config = config or {}
        
        # Proprietary weights (tuned from real-world data)
        self.weights = {
            "exploitability": 0.35,
            "impact": 0.25,
            "exposure": 0.15,
            "reachability": 0.15,  # Proprietary addition
            "temporal": 0.05,
            "environmental": 0.05,
        }
        
        # Proprietary decay functions
        self.decay_functions = self._build_decay_functions()
    
    def _build_decay_functions(self) -> Dict[str, callable]:
        """Build proprietary decay functions for temporal factors."""
        return {
            "exponential": lambda x, rate: math.exp(-rate * x),
            "linear": lambda x, max_val: max(0, 1 - (x / max_val)),
            "logarithmic": lambda x, scale: 1 / (1 + math.log(1 + x / scale)),
        }
    
    def calculate_proprietary_score(
        self,
        cve_data: Mapping[str, Any],
        component_data: Mapping[str, Any],
        reachability_data: Optional[Mapping[str, Any]] = None,
        epss_score: Optional[float] = None,
        kev_listed: bool = False,
    ) -> Dict[str, Any]:
        """Proprietary risk score calculation."""
        
        # Calculate proprietary risk factors
        factors = self._calculate_risk_factors(
            cve_data, component_data, reachability_data, epss_score, kev_listed
        )
        
        # Apply proprietary scoring formula
        base_score = self._proprietary_formula(factors)
        
        # Apply proprietary adjustments
        adjusted_score = self._apply_proprietary_adjustments(
            base_score, factors, cve_data, component_data
        )
        
        # Calculate confidence
        confidence = self._calculate_confidence(factors, reachability_data)
        
        return {
            "fixops_proprietary_score": round(adjusted_score, 2),
            "base_score": round(base_score, 2),
            "confidence": round(confidence, 3),
            "factors": {
                "exploitability": round(factors.exploitability, 3),
                "impact": round(factors.impact, 3),
                "exposure": round(factors.exposure, 3),
                "reachability": round(factors.reachability, 3),
                "temporal": round(factors.temporal, 3),
                "environmental": round(factors.environmental, 3),
            },
            "weights": self.weights,
            "metadata": {
                "algorithm_version": "2.0",
                "calculated_at": datetime.now(timezone.utc).isoformat(),
                "has_reachability": reachability_data is not None,
            },
        }
    
    def _calculate_risk_factors(
        self,
        cve_data: Mapping[str, Any],
        component_data: Mapping[str, Any],
        reachability_data: Optional[Mapping[str, Any]],
        epss_score: Optional[float],
        kev_listed: bool,
    ) -> ProprietaryRiskFactors:
        """Calculate proprietary risk factors."""
        
        # Exploitability (proprietary calculation)
        exploitability = self._calculate_exploitability(
            cve_data, epss_score, kev_listed
        )
        
        # Impact (proprietary calculation)
        impact = self._calculate_impact(cve_data, component_data)
        
        # Exposure (proprietary calculation)
        exposure = self._calculate_exposure(component_data)
        
        # Reachability (proprietary - unique to FixOps)
        reachability = self._calculate_reachability(reachability_data)
        
        # Temporal (proprietary decay model)
        temporal = self._calculate_temporal(cve_data)
        
        # Environmental (proprietary context model)
        environmental = self._calculate_environmental(component_data)
        
        return ProprietaryRiskFactors(
            exploitability=exploitability,
            impact=impact,
            exposure=exposure,
            reachability=reachability,
            temporal=temporal,
            environmental=environmental,
        )
    
    def _calculate_exploitability(
        self,
        cve_data: Mapping[str, Any],
        epss_score: Optional[float],
        kev_listed: bool,
    ) -> float:
        """Proprietary exploitability calculation."""
        
        # Base from EPSS if available
        if epss_score is not None:
            base = float(epss_score)
        else:
            # Proprietary fallback calculation
            base = 0.1
        
        # KEV boost (proprietary multiplier)
        if kev_listed:
            base = min(1.0, base * 1.5)  # 50% boost for KEV
        
        # CWE-based adjustments (proprietary mapping)
        cwe_ids = cve_data.get("cwe_ids", [])
        for cwe_id in cwe_ids:
            if "CWE-89" in str(cwe_id):  # SQL Injection
                base = min(1.0, base * 1.2)
            elif "CWE-78" in str(cwe_id):  # Command Injection
                base = min(1.0, base * 1.3)
            elif "CWE-79" in str(cwe_id):  # XSS
                base = min(1.0, base * 1.1)
        
        return min(1.0, max(0.0, base))
    
    def _calculate_impact(
        self, cve_data: Mapping[str, Any], component_data: Mapping[str, Any]
    ) -> float:
        """Proprietary impact calculation."""
        
        # CVSS-based if available
        cvss_score = cve_data.get("cvss_score")
        if cvss_score is not None:
            base = float(cvss_score) / 10.0
        else:
            # Proprietary severity mapping
            severity = cve_data.get("severity", "medium").lower()
            severity_map = {
                "critical": 0.9,
                "high": 0.7,
                "medium": 0.5,
                "low": 0.3,
            }
            base = severity_map.get(severity, 0.5)
        
        # Component criticality adjustment (proprietary)
        criticality = component_data.get("criticality", "unknown").lower()
        criticality_multiplier = {
            "mission_critical": 1.2,
            "critical": 1.1,
            "high": 1.0,
            "medium": 0.9,
            "low": 0.8,
        }.get(criticality, 1.0)
        
        impact = base * criticality_multiplier
        return min(1.0, max(0.0, impact))
    
    def _calculate_exposure(self, component_data: Mapping[str, Any]) -> float:
        """Proprietary exposure calculation."""
        
        exposure_flags = component_data.get("exposure_flags", [])
        if not exposure_flags:
            return 0.3  # Default: unknown
        
        # Proprietary exposure scoring
        exposure_map = {
            "internet": 1.0,
            "public": 0.9,
            "partner": 0.7,
            "internal": 0.5,
            "controlled": 0.4,
            "unknown": 0.3,
        }
        
        # Take highest exposure
        max_exposure = max(
            (exposure_map.get(flag.lower(), 0.3) for flag in exposure_flags),
            default=0.3,
        )
        
        return max_exposure
    
    def _calculate_reachability(
        self, reachability_data: Optional[Mapping[str, Any]]
    ) -> float:
        """Proprietary reachability calculation - unique to FixOps."""
        
        if not reachability_data:
            return 0.5  # Unknown: neutral
        
        is_reachable = reachability_data.get("is_reachable", False)
        confidence = reachability_data.get("confidence_score", 0.0)
        
        if is_reachable:
            # Higher confidence = higher reachability score
            return 0.5 + (confidence * 0.5)  # 0.5 to 1.0
        else:
            # Not reachable: lower score based on confidence
            return (1.0 - confidence) * 0.5  # 0.0 to 0.5
    
    def _calculate_temporal(self, cve_data: Mapping[str, Any]) -> float:
        """Proprietary temporal factor calculation."""
        
        # Age-based decay (proprietary model)
        published_date = cve_data.get("published_date")
        if published_date:
            try:
                pub_dt = datetime.fromisoformat(
                    published_date.replace("Z", "+00:00")
                )
                age_days = (datetime.now(timezone.utc) - pub_dt).days
                
                # Proprietary exponential decay
                decay_rate = 0.001  # Tuned parameter
                temporal = self.decay_functions["exponential"](age_days, decay_rate)
                return min(1.0, max(0.0, temporal))
            except Exception:
                pass
        
        # Default: recent vulnerabilities are more relevant
        return 0.8
    
    def _calculate_environmental(
        self, component_data: Mapping[str, Any]
    ) -> float:
        """Proprietary environmental factor calculation."""
        
        # Data classification impact (proprietary)
        data_classification = component_data.get("data_classification", [])
        if isinstance(data_classification, str):
            data_classification = [data_classification]
        
        data_weights = {
            "pii": 1.0,
            "phi": 1.0,
            "pci": 0.9,
            "financial": 0.9,
            "confidential": 0.8,
            "internal": 0.6,
            "public": 0.4,
        }
        
        max_data_weight = max(
            (
                data_weights.get(str(dc).lower(), 0.5)
                for dc in data_classification
            ),
            default=0.5,
        )
        
        return max_data_weight
    
    def _proprietary_formula(
        self, factors: ProprietaryRiskFactors
    ) -> float:
        """Proprietary scoring formula - custom mathematical model."""
        
        # Weighted sum with non-linear adjustments
        weighted_sum = (
            factors.exploitability * self.weights["exploitability"]
            + factors.impact * self.weights["impact"]
            + factors.exposure * self.weights["exposure"]
            + factors.reachability * self.weights["reachability"]
            + factors.temporal * self.weights["temporal"]
            + factors.environmental * self.weights["environmental"]
        )
        
        # Proprietary non-linear transformation
        # Uses sigmoid-like function for better distribution
        score = 100 * (
            1 / (1 + math.exp(-10 * (weighted_sum - 0.5)))
        )  # Sigmoid transformation
        
        return score
    
    def _apply_proprietary_adjustments(
        self,
        base_score: float,
        factors: ProprietaryRiskFactors,
        cve_data: Mapping[str, Any],
        component_data: Mapping[str, Any],
    ) -> float:
        """Apply proprietary adjustments to base score."""
        
        adjusted = base_score
        
        # Multiplicative adjustments for high-risk combinations
        if factors.exploitability > 0.7 and factors.reachability > 0.7:
            # High exploitability + high reachability = critical
            adjusted *= 1.3
        
        if factors.impact > 0.8 and factors.exposure > 0.8:
            # High impact + high exposure = critical
            adjusted *= 1.2
        
        # Additive adjustments
        if cve_data.get("exploited", False):
            adjusted += 10  # Bonus for exploited vulnerabilities
        
        # Clamp to 0-100
        return min(100.0, max(0.0, adjusted))
    
    def _calculate_confidence(
        self,
        factors: ProprietaryRiskFactors,
        reachability_data: Optional[Mapping[str, Any]],
    ) -> float:
        """Proprietary confidence calculation."""
        
        confidence = 0.5  # Base confidence
        
        # More data = higher confidence
        if reachability_data:
            confidence += 0.2
        
        if factors.exploitability > 0:
            confidence += 0.1
        
        if factors.reachability > 0:
            confidence += 0.1
        
        # Factor consistency = higher confidence
        factor_values = [
            factors.exploitability,
            factors.impact,
            factors.exposure,
            factors.reachability,
        ]
        if len(factor_values) > 1:
            std_dev = statistics.stdev(factor_values)
            consistency = 1.0 - min(1.0, std_dev)
            confidence += consistency * 0.1
        
        return min(1.0, max(0.0, confidence))
