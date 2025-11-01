"""Feature flag system for FixOps.

Provides a comprehensive, LaunchDarkly-compatible feature flag system with:
- Pluggable providers (local overlay, LaunchDarkly, combined)
- Evaluation context for sophisticated targeting
- Percentage-based rollouts with consistent hashing
- Multi-variant experiments for A/B testing
- Typed flag registry with metadata
"""

from core.flags.base import EvaluationContext, FeatureFlagProvider
from core.flags.combined import CombinedProvider
from core.flags.ld_provider import LaunchDarklyProvider
from core.flags.local_provider import LocalOverlayProvider

__all__ = [
    "EvaluationContext",
    "FeatureFlagProvider",
    "LocalOverlayProvider",
    "LaunchDarklyProvider",
    "CombinedProvider",
]
