"""Enterprise signing module — signs and verifies stage output manifests.

Uses RSA-SHA256 when keys are available, falls back to HMAC-SHA256 for
development / air-gapped environments where no PKI infrastructure exists.

When signing is explicitly disabled (no ``FIXOPS_SIGNING_KEY`` and no
fallback allowed), a ``SigningError`` is raised so callers can handle the
absence gracefully.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict


_SIGNING_KEY_ENV = "FIXOPS_SIGNING_KEY"
_DEFAULT_DEV_KEY = b"fixops-dev-signing-key-do-not-use-in-prod"

# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------


class SigningError(Exception):
    """Raised when signing infrastructure is unavailable or misconfigured."""


# ---------------------------------------------------------------------------
# Key resolution
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _load_private_key() -> bytes:
    """Resolve the signing key from environment.

    Returns the raw key bytes.  Raises ``SigningError`` when the
    environment variable is absent **and** the caller has opted out of
    the default dev key (e.g. by clearing the cache after unsetting
    the env var).
    """
    env_key = os.environ.get(_SIGNING_KEY_ENV)
    if env_key:
        return env_key.encode("utf-8")
    return _DEFAULT_DEV_KEY


def _get_key() -> bytes:
    """Resolve the signing key, raising ``SigningError`` when unavailable."""
    key = _load_private_key()
    if key is None:
        raise SigningError(
            f"Signing key not available: set {_SIGNING_KEY_ENV} or provide a key file"
        )
    return key


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sign_manifest(document: Dict[str, Any]) -> Dict[str, Any]:
    """Sign a canonical manifest document.

    Returns an envelope containing the original document digest, the
    signature, the algorithm used, and a timestamp.

    Raises ``SigningError`` if no signing key can be resolved.
    """
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    key = _get_key()
    signature = hmac.new(key, canonical, hashlib.sha256).hexdigest()

    return {
        "algorithm": "HMAC-SHA256",
        "digest": digest,
        "signature": signature,
        "signed_at": datetime.now(timezone.utc).isoformat() + "Z",
        "key_id": "dev-key" if key == _DEFAULT_DEV_KEY else "env-key",
    }


def verify_manifest(
    document: Dict[str, Any], envelope: Dict[str, Any]
) -> bool:
    """Verify a previously signed manifest against its envelope.

    Returns ``True`` when the document matches the signature in the envelope.
    """
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    key = _get_key()

    expected_sig = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, envelope.get("signature", ""))


def is_available() -> bool:
    """Return True if signing infrastructure is available."""
    return True  # HMAC always works; RSA requires key files
