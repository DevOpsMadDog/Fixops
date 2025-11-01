"""Factory for creating and initializing feature flag providers.

Handles provider initialization with proper fallback chain:
LaunchDarkly → Local Overlay → Registry Defaults
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from core.flags.base import FeatureFlagProvider
from core.flags.combined import CombinedProvider
from core.flags.ld_provider import LaunchDarklyProvider
from core.flags.local_provider import LocalOverlayProvider

logger = logging.getLogger(__name__)


def create_flag_provider(
    overlay_config: Dict[str, Any],
    enable_launchdarkly: bool = True,
) -> FeatureFlagProvider:
    """Create feature flag provider with fallback chain.

    Parameters
    ----------
    overlay_config:
        Overlay configuration dictionary
    enable_launchdarkly:
        If True, attempt to initialize LaunchDarkly provider

    Returns
    -------
    FeatureFlagProvider
        Combined provider with fallback chain
    """
    local_provider = LocalOverlayProvider(overlay_config)
    logger.info("Initialized LocalOverlayProvider")

    ld_provider: Optional[FeatureFlagProvider] = None
    if enable_launchdarkly:
        ld_disabled = os.getenv("LAUNCHDARKLY_DISABLED", "").lower() in (
            "1",
            "true",
            "yes",
        )
        if ld_disabled:
            logger.info(
                "LaunchDarkly disabled via LAUNCHDARKLY_DISABLED environment variable"
            )
        else:
            try:
                ld_provider = LaunchDarklyProvider()
                if not ld_provider.offline:
                    logger.info("Initialized LaunchDarklyProvider")
                else:
                    logger.info("LaunchDarkly running in offline mode")
                    ld_provider = None  # Don't use offline LD provider
            except Exception as exc:
                logger.warning("Failed to initialize LaunchDarkly provider: %s", exc)

    if ld_provider:
        provider = CombinedProvider(primary=ld_provider, fallback=local_provider)
        logger.info("Using CombinedProvider: LaunchDarkly → Local Overlay → Defaults")
    else:
        provider = CombinedProvider(primary=None, fallback=local_provider)
        logger.info("Using CombinedProvider: Local Overlay → Defaults")

    return provider


__all__ = ["create_flag_provider"]
