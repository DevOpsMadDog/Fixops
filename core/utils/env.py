"""Environment variable utilities with product namespace support."""

from __future__ import annotations

import os
from typing import Optional


def get_env_with_namespace(
    var_name: str,
    default: Optional[str] = None,
    brand_namespace: str = "fixops",
) -> Optional[str]:
    """Get environment variable with brand namespace fallback.

    Tries branded environment variable first, then falls back to FIXOPS_* prefix.

    Example:
        If brand_namespace is "aldeci" and var_name is "API_TOKEN":
        1. Try ALDECI_API_TOKEN first
        2. Fall back to FIXOPS_API_TOKEN
        3. Return default if neither exists

    Parameters
    ----------
    var_name:
        Variable name without prefix (e.g., "API_TOKEN")
    default:
        Default value if neither branded nor canonical variable exists
    brand_namespace:
        Brand namespace slug (e.g., "aldeci")

    Returns
    -------
    Optional[str]
        Environment variable value or default
    """
    if brand_namespace and brand_namespace != "fixops":
        brand_var = f"{brand_namespace.upper()}_{var_name}"
        brand_value = os.getenv(brand_var)
        if brand_value is not None:
            return brand_value

    fixops_var = f"FIXOPS_{var_name}"
    fixops_value = os.getenv(fixops_var)
    if fixops_value is not None:
        return fixops_value

    return default


__all__ = ["get_env_with_namespace"]
