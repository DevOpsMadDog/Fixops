"""Namespace adapter for feature flags to support dynamic product branding.

Allows flags to be accessed using a branded namespace (e.g., "aldeci.*") while
maintaining backward compatibility with the canonical "fixops.*" namespace.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any, Dict, Optional

from core.flags.base import EvaluationContext, FeatureFlagProvider

logger = logging.getLogger(__name__)


def _alt_default(method_name: str, default: Any) -> Any:
    """Generate an alternate default value for two-pass probe.

    Used to distinguish "key not set" from "key explicitly set to default value".
    Returns a value that is guaranteed to differ from the original default.
    """
    if method_name == "bool":
        return not default
    if method_name in ("string", "variant"):
        return f"{default}__ns_probe__" if default else "__ns_probe__"
    if method_name == "number":
        return 9.999999999e307 if default != 9.999999999e307 else -9.999999999e307
    if method_name == "json":
        return {"__ns_probe__": f"1f{uuid.uuid4().hex}"}
    return default


def _derive_brand_namespace(provider: FeatureFlagProvider) -> str:
    """Derive brand namespace from environment or branding flags.

    Precedence:
    1. PRODUCT_NAMESPACE environment variable
    2. Branding flag short_name (lowercased)
    3. Default to "fixops"

    Parameters
    ----------
    provider:
        Flag provider to query for branding information

    Returns
    -------
    str
        Brand namespace slug (lowercased, sanitized)
    """
    env_namespace = os.getenv("PRODUCT_NAMESPACE")
    if env_namespace:
        return env_namespace.lower().strip()

    try:
        branding = provider.json("fixops.branding", {})
        if branding and isinstance(branding, dict):
            short_name = branding.get("short_name", "fixops")
            return short_name.lower().strip()
    except Exception:
        pass

    return "fixops"


class NamespaceAdapterProvider(FeatureFlagProvider):
    """Adapter that adds namespace aliasing to any feature flag provider.

    Allows flags to be accessed using a branded namespace while maintaining
    backward compatibility with the canonical "fixops.*" namespace.

    Example:
        If brand namespace is "aldeci", then:
        - provider.bool("fixops.module.guardrails", False) will try:
          1. "aldeci.module.guardrails" first
          2. "fixops.module.guardrails" as fallback

        This allows users to set flags under "aldeci.*" in LaunchDarkly or
        local overlay while keeping existing "fixops.*" flags working.
    """

    def __init__(
        self,
        wrapped: FeatureFlagProvider,
        brand_namespace: Optional[str] = None,
    ):
        """Initialize namespace adapter.

        Parameters
        ----------
        wrapped:
            Underlying flag provider to wrap
        brand_namespace:
            Brand namespace slug (e.g., "aldeci"). If None, will be derived
            from environment or branding flags.
        """
        self.wrapped = wrapped
        self._brand_namespace = brand_namespace
        self._namespace_cache: Optional[str] = None

    @property
    def brand_namespace(self) -> str:
        """Get cached brand namespace."""
        if self._namespace_cache is None:
            if self._brand_namespace:
                self._namespace_cache = self._brand_namespace
            else:
                self._namespace_cache = _derive_brand_namespace(self.wrapped)
        return self._namespace_cache

    def _try_with_namespace(
        self,
        key: str,
        default: Any,
        context: Optional[EvaluationContext],
        method_name: str,
    ) -> tuple[Any, bool]:
        """Try to evaluate flag with brand namespace first, then canonical.

        Uses a two-pass probe to distinguish "key not set" from "key explicitly
        set to default value". This ensures branded overrides are honored even
        when they equal the default.

        Returns tuple of (value, found) where found indicates if a real
        value was found (not just the default).
        """
        brand_ns = self.brand_namespace

        if brand_ns == "fixops":
            method = getattr(self.wrapped, method_name)
            result = method(key, default, context)
            return result, result != default

        if key.startswith("fixops."):
            brand_key = key.replace("fixops.", f"{brand_ns}.", 1)
            try:
                method = getattr(self.wrapped, method_name)

                result = method(brand_key, default, context)
                if result != default:
                    logger.debug(
                        "Flag %s evaluated with brand namespace %s: %s",
                        key,
                        brand_ns,
                        result,
                    )
                    return result, True

                alt_default = _alt_default(method_name, default)
                result2 = method(brand_key, alt_default, context)

                if result2 != alt_default:
                    logger.debug(
                        "Flag %s explicitly set to default in brand namespace %s: %s",
                        key,
                        brand_ns,
                        result,
                    )
                    return result, True

            except Exception as exc:
                logger.debug(
                    "Brand namespace %s lookup failed for %s: %s",
                    brand_ns,
                    brand_key,
                    exc,
                )

        try:
            method = getattr(self.wrapped, method_name)
            result = method(key, default, context)
            return result, result != default
        except Exception as exc:
            logger.debug("Canonical lookup failed for %s: %s", key, exc)
            return default, False

    def bool(
        self,
        key: str,
        default: bool,
        context: Optional[EvaluationContext] = None,
    ) -> bool:
        """Evaluate boolean flag with namespace aliasing."""
        result, _ = self._try_with_namespace(key, default, context, "bool")
        return result

    def string(
        self,
        key: str,
        default: str,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Evaluate string flag with namespace aliasing."""
        result, _ = self._try_with_namespace(key, default, context, "string")
        return result

    def number(
        self,
        key: str,
        default: float,
        context: Optional[EvaluationContext] = None,
    ) -> float:
        """Evaluate number flag with namespace aliasing."""
        result, _ = self._try_with_namespace(key, default, context, "number")
        return result

    def json(
        self,
        key: str,
        default: Dict[str, Any],
        context: Optional[EvaluationContext] = None,
    ) -> Dict[str, Any]:
        """Evaluate JSON flag with namespace aliasing."""
        result, _ = self._try_with_namespace(key, default, context, "json")
        return result

    def variant(
        self,
        key: str,
        default: str,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Evaluate variant flag with namespace aliasing."""
        result, _ = self._try_with_namespace(key, default, context, "variant")
        return result


__all__ = ["NamespaceAdapterProvider"]
