"""Differential Privacy mechanisms for threat intelligence sharing.

This module implements localized differential privacy (LDP) algorithms to anonymize
statistical data before sharing it with central threat intelligence feeds.
It allows enterprises to contribute to global security without leaking proprietary details.
"""

from __future__ import annotations

import math
import random
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Union


@dataclass
class DPConfig:
    """Configuration for Differential Privacy."""
    epsilon: float = 1.0  # Privacy budget (lower is more private)
    randomize_response: bool = True
    noise_mechanism: str = "laplace"  # laplace, randomized_response


class DifferentialPrivacyEngine:
    """Engine for applying differential privacy to sensitive metrics."""

    def __init__(self, config: Optional[DPConfig] = None):
        self.config = config or DPConfig()

    def randomized_response(self, value: bool) -> bool:
        """Apply Randomized Response mechanism for boolean values (e.g., 'is vulnerable').
        
        Args:
            value: The true boolean value.
            
        Returns:
            The potentially flipped value.
        """
        if not self.config.randomize_response:
            return value

        # p = probability of telling the truth
        # For epsilon, p = e^ε / (1 + e^ε)
        e_eps = math.exp(self.config.epsilon)
        p = e_eps / (1 + e_eps)

        # Flip a coin (cryptographically secure)
        if secrets.SystemRandom().random() < p:
            return value  # Tell the truth
        else:
            return not value  # Lie

    def add_laplace_noise(self, value: float, sensitivity: float = 1.0) -> float:
        """Add Laplace noise to numerical values (e.g., vulnerability counts).
        
        Args:
            value: The true value.
            sensitivity: Maximum amount the value can change by adding/removing one individual.
            
        Returns:
            Value with added noise.
        """
        scale = sensitivity / self.config.epsilon
        # Generate Laplace noise: L(0, scale)
        # Using inverse transform sampling
        u = secrets.SystemRandom().random() - 0.5
        noise = -scale * math.copysign(1.0, u) * math.log(1 - 2 * abs(u))
        
        return value + noise

    def anonymize_exploit_stats(self, stats: Dict[str, Union[int, float]]) -> Dict[str, Union[int, float]]:
        """Anonymize a dictionary of exploit statistics.
        
        Args:
            stats: Dictionary like {"cve_count": 10, "avg_cvss": 7.5}
            
        Returns:
            Anonymized dictionary suitable for sharing.
        """
        anonymized = {}
        
        # Count data gets Laplace noise
        if "cve_count" in stats:
            # Cast to int but keep noise (or round if integer counts required)
            anonymized["cve_count"] = max(0, round(self.add_laplace_noise(float(stats["cve_count"]))))
            
        # Averages get Laplace noise
        if "avg_cvss" in stats:
            # Sensitivity of average depends on dataset size, assuming sensitivity=1 for simplicity here
            anonymized["avg_cvss"] = min(10.0, max(0.0, self.add_laplace_noise(float(stats["avg_cvss"]), sensitivity=0.1)))
            
        # Booleans get Randomized Response
        if "has_critical_vulns" in stats:
            val = bool(stats["has_critical_vulns"])
            anonymized["has_critical_vulns"] = self.randomized_response(val)
            
        return anonymized

    def encode_histogram(self, buckets: Dict[str, int]) -> Dict[str, int]:
        """Apply DP to a histogram (e.g., vulns per severity)."""
        return {
            k: max(0, round(self.add_laplace_noise(v)))
            for k, v in buckets.items()
        }
