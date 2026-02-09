"""Combined feature flag provider with fallback chain.

Implements the fallback strategy: LaunchDarkly → Local Overlay → Registry Defaults
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.flags.base import EvaluationContext, FeatureFlagProvider

logger = logging.getLogger(__name__)


class CombinedProvider(FeatureFlagProvider):
    """Combined provider with fallback chain.

    Evaluation order:
    1. LaunchDarkly (if available and not offline)
    2. Local overlay configuration
    3. Registry defaults

    This ensures:
    - Production can use LaunchDarkly for dynamic control
    - Development/CI can use local overlay
    - Always has a fallback to registry defaults
    """

    def __init__(
        self,
        primary: Optional[FeatureFlagProvider] = None,
        fallback: Optional[FeatureFlagProvider] = None,
    ):
        """Initialize combined provider.

        Parameters
        ----------
        primary:
            Primary provider (typically LaunchDarkly)
        fallback:
            Fallback provider (typically LocalOverlayProvider)
        """
        self.primary = primary
        self.fallback = fallback

    def bool(
        self,
        key: str,
        default: bool,
        context: Optional[EvaluationContext] = None,
    ) -> bool:
        """Evaluate a boolean flag with fallback."""
        if self.primary:
            try:
                result = self.primary.bool(key, default, context)
                if result != default:
                    logger.debug(
                        "Flag %s evaluated by primary provider: %s", key, result
                    )
                    return result
                logger.debug(
                    "Flag %s returned default from primary, trying fallback", key
                )
            except Exception as exc:
                logger.warning(
                    "Primary provider failed for %s: %s. Trying fallback.", key, exc
                )

        if self.fallback:
            try:
                result = self.fallback.bool(key, default, context)
                logger.debug("Flag %s evaluated by fallback provider: %s", key, result)
                return result
            except Exception as exc:
                logger.warning(
                    "Fallback provider failed for %s: %s. Using default.", key, exc
                )

        logger.debug("Flag %s using default: %s", key, default)
        return default

    def string(
        self,
        key: str,
        default: str,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Evaluate a string flag with fallback."""
        if self.primary:
            try:
                result = self.primary.string(key, default, context)
                if result != default:
                    logger.debug(
                        "Flag %s evaluated by primary provider: %s", key, result
                    )
                    return result
                logger.debug(
                    "Flag %s returned default from primary, trying fallback", key
                )
            except Exception as exc:
                logger.warning(
                    "Primary provider failed for %s: %s. Trying fallback.", key, exc
                )

        if self.fallback:
            try:
                result = self.fallback.string(key, default, context)
                logger.debug("Flag %s evaluated by fallback provider: %s", key, result)
                return result
            except Exception as exc:
                logger.warning(
                    "Fallback provider failed for %s: %s. Using default.", key, exc
                )

        logger.debug("Flag %s using default: %s", key, default)
        return default

    def number(
        self,
        key: str,
        default: float,
        context: Optional[EvaluationContext] = None,
    ) -> float:
        """Evaluate a numeric flag with fallback."""
        if self.primary:
            try:
                result = self.primary.number(key, default, context)
                if result != default:
                    logger.debug(
                        "Flag %s evaluated by primary provider: %s", key, result
                    )
                    return result
                logger.debug(
                    "Flag %s returned default from primary, trying fallback", key
                )
            except Exception as exc:
                logger.warning(
                    "Primary provider failed for %s: %s. Trying fallback.", key, exc
                )

        if self.fallback:
            try:
                result = self.fallback.number(key, default, context)
                logger.debug("Flag %s evaluated by fallback provider: %s", key, result)
                return result
            except Exception as exc:
                logger.warning(
                    "Fallback provider failed for %s: %s. Using default.", key, exc
                )

        logger.debug("Flag %s using default: %s", key, default)
        return default

    def json(
        self,
        key: str,
        default: Dict[str, Any],
        context: Optional[EvaluationContext] = None,
    ) -> Dict[str, Any]:
        """Evaluate a JSON flag with fallback."""
        if self.primary:
            try:
                result = self.primary.json(key, default, context)
                if result != default:
                    logger.debug("Flag %s evaluated by primary provider", key)
                    return result
                logger.debug(
                    "Flag %s returned default from primary, trying fallback", key
                )
            except Exception as exc:
                logger.warning(
                    "Primary provider failed for %s: %s. Trying fallback.", key, exc
                )

        if self.fallback:
            try:
                result = self.fallback.json(key, default, context)
                logger.debug("Flag %s evaluated by fallback provider", key)
                return result
            except Exception as exc:
                logger.warning(
                    "Fallback provider failed for %s: %s. Using default.", key, exc
                )

        logger.debug("Flag %s using default", key)
        return default

    def variant(
        self,
        key: str,
        default: str,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Evaluate a multi-variant flag with fallback."""
        if self.primary:
            try:
                result = self.primary.variant(key, default, context)
                if result != default:
                    logger.debug(
                        "Flag %s evaluated by primary provider: %s", key, result
                    )
                    return result
                logger.debug(
                    "Flag %s returned default from primary, trying fallback", key
                )
            except Exception as exc:
                logger.warning(
                    "Primary provider failed for %s: %s. Trying fallback.", key, exc
                )

        if self.fallback:
            try:
                result = self.fallback.variant(key, default, context)
                logger.debug("Flag %s evaluated by fallback provider: %s", key, result)
                return result
            except Exception as exc:
                logger.warning(
                    "Fallback provider failed for %s: %s. Using default.", key, exc
                )

        logger.debug("Flag %s using default: %s", key, default)
        return default


__all__ = ["CombinedProvider"]
