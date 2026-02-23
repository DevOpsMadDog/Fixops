"""Shared TLS configuration for all outbound HTTP calls.

Reads from environment variables:
- ``FIXOPS_TLS_VERIFY``  – "true" (default) or "false"
- ``FIXOPS_CA_BUNDLE``   – path to CA bundle file (optional)

Usage::

    from core.tls_config import tls_verify

    async with httpx.AsyncClient(verify=tls_verify(), timeout=30) as client:
        ...
"""

from __future__ import annotations

import os
from typing import Union


def tls_verify() -> Union[bool, str]:
    """Return the *verify* parameter for ``httpx`` / ``requests`` calls.

    * When ``FIXOPS_TLS_VERIFY`` is ``"false"`` → returns ``False``
    * When ``FIXOPS_CA_BUNDLE`` is set           → returns the bundle path
    * Otherwise                                  → returns ``True`` (system certs)
    """
    env_verify = os.environ.get("FIXOPS_TLS_VERIFY", "true").strip().lower()
    if env_verify == "false":
        return False

    ca_bundle = os.environ.get("FIXOPS_CA_BUNDLE", "").strip()
    if ca_bundle:
        return ca_bundle

    return True


__all__ = ["tls_verify"]
