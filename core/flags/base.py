"""Base abstractions for feature flag system.

This module provides the core interfaces for feature flag evaluation,
supporting pluggable backends (local overlay, LaunchDarkly, etc.).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class EvaluationContext:
    """Context for feature flag evaluation with targeting attributes.

    This context is threaded through the pipeline to enable sophisticated
    targeting rules (per-tenant, per-environment, per-plan, etc.).
    """

    tenant_id: Optional[str] = None
    user_email: Optional[str] = None

    environment: Optional[str] = None  # demo, enterprise, staging, production
    mode: Optional[str] = None  # Alias for environment
    region: Optional[str] = None  # us-east-1, eu-west-1, etc.

    plan: Optional[str] = None  # demo, enterprise, premium

    service_name: Optional[str] = None  # API service name
    request_id: Optional[str] = None  # Correlation ID

    cve_id: Optional[str] = None
    component_id: Optional[str] = None

    custom: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for LaunchDarkly or logging."""
        result = {
            "tenant_id": self.tenant_id,
            "user_email": self.user_email,
            "environment": self.environment or self.mode,
            "region": self.region,
            "plan": self.plan,
            "service_name": self.service_name,
            "request_id": self.request_id,
            "cve_id": self.cve_id,
            "component_id": self.component_id,
        }
        result = {k: v for k, v in result.items() if v is not None}
        result.update(self.custom)
        return result


class FeatureFlagProvider(ABC):
    """Abstract base class for feature flag providers.

    Implementations include:
    - LocalOverlayProvider: Reads from config/fixops.overlay.yml
    - LaunchDarklyProvider: Wraps LaunchDarkly SDK
    - CombinedProvider: LD first → local fallback → defaults
    """

    @abstractmethod
    def bool(
        self,
        key: str,
        default: bool,
        context: Optional[EvaluationContext] = None,
    ) -> bool:
        """Evaluate a boolean flag.

        Parameters
        ----------
        key:
            Flag key (e.g., "fixops.module.guardrails.enabled")
        default:
            Default value if flag not found
        context:
            Evaluation context for targeting

        Returns
        -------
        bool
            Flag value
        """

    @abstractmethod
    def string(
        self,
        key: str,
        default: str,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Evaluate a string flag.

        Parameters
        ----------
        key:
            Flag key
        default:
            Default value if flag not found
        context:
            Evaluation context for targeting

        Returns
        -------
        str
            Flag value
        """

    @abstractmethod
    def number(
        self,
        key: str,
        default: float,
        context: Optional[EvaluationContext] = None,
    ) -> float:
        """Evaluate a numeric flag.

        Parameters
        ----------
        key:
            Flag key
        default:
            Default value if flag not found
        context:
            Evaluation context for targeting

        Returns
        -------
        float
            Flag value
        """

    @abstractmethod
    def json(
        self,
        key: str,
        default: Dict[str, Any],
        context: Optional[EvaluationContext] = None,
    ) -> Dict[str, Any]:
        """Evaluate a JSON flag.

        Parameters
        ----------
        key:
            Flag key
        default:
            Default value if flag not found
        context:
            Evaluation context for targeting

        Returns
        -------
        Dict[str, Any]
            Flag value
        """

    @abstractmethod
    def variant(
        self,
        key: str,
        default: str,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Evaluate a multi-variant flag for A/B testing.

        Parameters
        ----------
        key:
            Flag key
        default:
            Default variant if flag not found
        context:
            Evaluation context for targeting (used for consistent hashing)

        Returns
        -------
        str
            Variant name (e.g., "control", "treatment", "variant_a")
        """


__all__ = [
    "EvaluationContext",
    "FeatureFlagProvider",
]
