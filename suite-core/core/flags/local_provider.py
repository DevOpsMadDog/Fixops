"""Local overlay-based feature flag provider.

Reads flags from config/fixops.overlay.yml and supports:
- Simple boolean/string/number/json flags
- Percentage-based rollouts with consistent hashing
- Multi-variant experiments
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Optional

from core.flags.base import EvaluationContext, FeatureFlagProvider

logger = logging.getLogger(__name__)


class LocalOverlayProvider(FeatureFlagProvider):
    """Feature flag provider that reads from overlay configuration.

    Supports:
    - Simple flags: { "key": value }
    - Percentage rollouts: { "key": { "percentage": 50, "value": true } }
    - Multi-variant: { "key": { "variants": {"control": 50, "treatment": 50} } }
    """

    def __init__(self, overlay_config: Dict[str, Any]):
        """Initialize with overlay configuration.

        Parameters
        ----------
        overlay_config:
            Overlay configuration dictionary (typically from fixops.overlay.yml)
        """
        self.config = overlay_config
        self.flags = overlay_config.get("feature_flags", {})

    def _get_flag_config(self, key: str) -> Any:
        """Get flag configuration from overlay.

        Supports nested keys like "fixops.module.guardrails.enabled"
        """
        if key in self.flags:
            return self.flags[key]

        parts = key.split(".")
        current = self.flags
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _evaluate_percentage_rollout(
        self,
        config: Dict[str, Any],
        context: Optional[EvaluationContext],
        default: Any,
    ) -> Any:
        """Evaluate percentage-based rollout with consistent hashing.

        Config format:
        {
            "percentage": 50,  # 0-100
            "value": true,
            "hash_key": "tenant_id"  # Optional, defaults to tenant_id
        }
        """
        percentage = config.get("percentage", 0)
        value = config.get("value", default)
        hash_key_attr = config.get("hash_key", "tenant_id")

        if not context:
            return default

        hash_input = None
        if hash_key_attr == "tenant_id":
            hash_input = context.tenant_id
        elif hash_key_attr == "user_email":
            hash_input = context.user_email
        elif hash_key_attr == "cve_id":
            hash_input = context.cve_id
        elif hash_key_attr == "component_id":
            hash_input = context.component_id
        elif hash_key_attr == "request_id":
            hash_input = context.request_id
        else:
            hash_input = context.custom.get(hash_key_attr)

        if not hash_input:
            return default

        hash_value = int(hashlib.sha256(str(hash_input).encode()).hexdigest(), 16)
        bucket = hash_value % 100

        if bucket < percentage:
            return value
        else:
            return default

    def _evaluate_variant(
        self,
        config: Dict[str, Any],
        context: Optional[EvaluationContext],
        default: str,
    ) -> str:
        """Evaluate multi-variant flag with consistent hashing.

        Config format:
        {
            "variants": {
                "control": 50,
                "treatment": 30,
                "variant_c": 20
            },
            "hash_key": "tenant_id"  # Optional
        }
        """
        variants = config.get("variants", {})
        hash_key_attr = config.get("hash_key", "tenant_id")

        if not variants:
            return default

        if not context:
            return default

        hash_input = None
        if hash_key_attr == "tenant_id":
            hash_input = context.tenant_id
        elif hash_key_attr == "user_email":
            hash_input = context.user_email
        elif hash_key_attr == "cve_id":
            hash_input = context.cve_id
        elif hash_key_attr == "component_id":
            hash_input = context.component_id
        else:
            hash_input = context.custom.get(hash_key_attr)

        if not hash_input:
            return default

        hash_value = int(hashlib.sha256(str(hash_input).encode()).hexdigest(), 16)
        bucket = hash_value % 100

        cumulative = 0
        for variant_name, percentage in variants.items():
            cumulative += percentage
            if bucket < cumulative:
                return variant_name

        return default

    def bool(
        self,
        key: str,
        default: bool,
        context: Optional[EvaluationContext] = None,
    ) -> bool:
        """Evaluate a boolean flag."""
        config = self._get_flag_config(key)

        if config is None:
            return default

        if isinstance(config, bool):
            return config

        if isinstance(config, dict) and "percentage" in config:
            return self._evaluate_percentage_rollout(config, context, default)

        if isinstance(config, dict) and "value" in config:
            return bool(config["value"])

        return bool(config)

    def string(
        self,
        key: str,
        default: str,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Evaluate a string flag."""
        config = self._get_flag_config(key)

        if config is None:
            return default

        if isinstance(config, str):
            return config

        if isinstance(config, dict) and "percentage" in config:
            return self._evaluate_percentage_rollout(config, context, default)

        if isinstance(config, dict) and "value" in config:
            return str(config["value"])

        return str(config)

    def number(
        self,
        key: str,
        default: float,
        context: Optional[EvaluationContext] = None,
    ) -> float:
        """Evaluate a numeric flag."""
        config = self._get_flag_config(key)

        if config is None:
            return default

        if isinstance(config, (int, float)):
            return float(config)

        if isinstance(config, dict) and "percentage" in config:
            return self._evaluate_percentage_rollout(config, context, default)

        if isinstance(config, dict) and "value" in config:
            try:
                return float(config["value"])
            except (ValueError, TypeError):
                return default

        try:
            return float(config)
        except (ValueError, TypeError):
            return default

    def json(
        self,
        key: str,
        default: Dict[str, Any],
        context: Optional[EvaluationContext] = None,
    ) -> Dict[str, Any]:
        """Evaluate a JSON flag."""
        config = self._get_flag_config(key)

        if config is None:
            return default

        if (
            isinstance(config, dict)
            and "percentage" not in config
            and "variants" not in config
        ):
            return config

        if isinstance(config, dict) and "percentage" in config:
            return self._evaluate_percentage_rollout(config, context, default)

        if isinstance(config, dict) and "value" in config:
            value = config["value"]
            if isinstance(value, dict):
                return value

        return default

    def variant(
        self,
        key: str,
        default: str,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Evaluate a multi-variant flag for A/B testing."""
        config = self._get_flag_config(key)

        if config is None:
            return default

        if isinstance(config, str):
            return config

        if isinstance(config, dict) and "variants" in config:
            return self._evaluate_variant(config, context, default)

        if isinstance(config, dict) and "value" in config:
            return str(config["value"])

        return default


__all__ = ["LocalOverlayProvider"]
