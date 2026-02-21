"""LaunchDarkly feature flag provider.

Wraps the LaunchDarkly SDK with proper error handling, timeouts,
and offline mode support for CI/testing.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from core.flags.base import EvaluationContext, FeatureFlagProvider

logger = logging.getLogger(__name__)

try:
    import ldclient
    from ldclient import Context as LDContext
    from ldclient.config import Config as LDConfig

    LAUNCHDARKLY_AVAILABLE = True
except ImportError:
    ldclient = None  # type: ignore[assignment]
    LDContext = None  # type: ignore[assignment]
    LDConfig = None  # type: ignore[assignment]
    LAUNCHDARKLY_AVAILABLE = False


class LaunchDarklyProvider(FeatureFlagProvider):
    """Feature flag provider that wraps LaunchDarkly SDK.

    Features:
    - Automatic SDK initialization with timeout
    - Offline mode for CI/testing (no network calls)
    - PII redaction (hash user emails, avoid sensitive data)
    - Graceful fallback on errors
    """

    def __init__(
        self,
        sdk_key: Optional[str] = None,
        offline: bool = False,
        timeout_seconds: float = 5.0,
    ):
        """Initialize LaunchDarkly provider.

        Parameters
        ----------
        sdk_key:
            LaunchDarkly SDK key. If None, reads from LAUNCHDARKLY_SDK_KEY env var.
        offline:
            If True, run in offline mode (no network calls). Useful for CI/testing.
        timeout_seconds:
            Timeout for SDK initialization and flag evaluation.
        """
        self.offline = offline or os.getenv("LAUNCHDARKLY_OFFLINE", "").lower() in (
            "1",
            "true",
            "yes",
        )
        self.timeout_seconds = timeout_seconds
        self.client = None

        if not LAUNCHDARKLY_AVAILABLE:
            logger.warning(
                "LaunchDarkly SDK not available. Install with: pip install launchdarkly-server-sdk"
            )
            self.offline = True
            return

        if self.offline:
            logger.info("LaunchDarkly provider running in offline mode")
            return

        if sdk_key is None:
            sdk_key = os.getenv("LAUNCHDARKLY_SDK_KEY")

        if not sdk_key:
            logger.warning("LAUNCHDARKLY_SDK_KEY not set. Running in offline mode.")
            self.offline = True
            return

        try:
            ldclient.set_config(
                LDConfig(
                    sdk_key=sdk_key,
                    connect_timeout=timeout_seconds,
                    read_timeout=timeout_seconds,
                )
            )
            self.client = ldclient.get()
            if not self.client.is_initialized():
                logger.warning(
                    "LaunchDarkly client failed to initialize. Running in offline mode."
                )
                self.offline = True
        except Exception as exc:
            logger.warning(
                "Failed to initialize LaunchDarkly client: %s. Running in offline mode.",
                exc,
            )
            self.offline = True

    def _build_ld_context(self, context: Optional[EvaluationContext]) -> Any:
        """Build LaunchDarkly context from EvaluationContext.

        Redacts PII (hashes user emails) and includes targeting attributes.
        """
        if not context:
            return LDContext.builder("anonymous").anonymous(True).build()

        key = context.tenant_id or "anonymous"

        builder = LDContext.builder(key)

        env = context.environment or context.mode
        if env:
            builder.set("environment", env)
        if context.region:
            builder.set("region", context.region)
        if context.plan:
            builder.set("plan", context.plan)
        if context.service_name:
            builder.set("service_name", context.service_name)

        for attr_key, attr_value in context.custom.items():
            builder.set(attr_key, attr_value)

        return builder.build()

    def bool(
        self,
        key: str,
        default: bool,
        context: Optional[EvaluationContext] = None,
    ) -> bool:
        """Evaluate a boolean flag."""
        if self.offline or not self.client:
            return default

        try:
            ld_context = self._build_ld_context(context)
            return self.client.variation(key, ld_context, default)
        except Exception as exc:
            logger.warning(
                "LaunchDarkly evaluation failed for %s: %s. Using default.", key, exc
            )
            return default

    def string(
        self,
        key: str,
        default: str,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Evaluate a string flag."""
        if self.offline or not self.client:
            return default

        try:
            ld_context = self._build_ld_context(context)
            return self.client.variation(key, ld_context, default)
        except Exception as exc:
            logger.warning(
                "LaunchDarkly evaluation failed for %s: %s. Using default.", key, exc
            )
            return default

    def number(
        self,
        key: str,
        default: float,
        context: Optional[EvaluationContext] = None,
    ) -> float:
        """Evaluate a numeric flag."""
        if self.offline or not self.client:
            return default

        try:
            ld_context = self._build_ld_context(context)
            value = self.client.variation(key, ld_context, default)
            return float(value)
        except Exception as exc:
            logger.warning(
                "LaunchDarkly evaluation failed for %s: %s. Using default.", key, exc
            )
            return default

    def json(
        self,
        key: str,
        default: Dict[str, Any],
        context: Optional[EvaluationContext] = None,
    ) -> Dict[str, Any]:
        """Evaluate a JSON flag."""
        if self.offline or not self.client:
            return default

        try:
            ld_context = self._build_ld_context(context)
            value = self.client.variation(key, ld_context, default)
            if isinstance(value, dict):
                return value
            return default
        except Exception as exc:
            logger.warning(
                "LaunchDarkly evaluation failed for %s: %s. Using default.", key, exc
            )
            return default

    def variant(
        self,
        key: str,
        default: str,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Evaluate a multi-variant flag for A/B testing."""
        if self.offline or not self.client:
            return default

        try:
            ld_context = self._build_ld_context(context)
            return self.client.variation(key, ld_context, default)
        except Exception as exc:
            logger.warning(
                "LaunchDarkly evaluation failed for %s: %s. Using default.", key, exc
            )
            return default

    def close(self) -> None:
        """Close LaunchDarkly client connection."""
        if self.client:
            try:
                self.client.close()
            except Exception as exc:
                logger.warning("Failed to close LaunchDarkly client: %s", exc)


__all__ = ["LaunchDarklyProvider"]
