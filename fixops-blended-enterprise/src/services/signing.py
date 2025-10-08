"""Evidence signing helpers."""

from __future__ import annotations

import base64
import json
from functools import lru_cache
from typing import Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from src.config.settings import get_settings

ALGORITHM = "RS256"


class SigningError(RuntimeError):
    """Raised when signing or verification fails."""


@lru_cache()
def _load_private_key():
    settings = get_settings()
    key_pem = settings.FIXOPS_SIGNING_KEY
    if not key_pem:
        raise SigningError("FIXOPS_SIGNING_KEY is not configured")
    try:
        return load_pem_private_key(key_pem.encode("utf-8"), password=None)
    except Exception as exc:  # pragma: no cover - cryptography provides rich errors
        raise SigningError(f"Unable to load signing key: {exc}") from exc


def sign_manifest(manifest: Mapping[str, object]) -> str:
    """Return a base64 signature over the canonical manifest."""

    private_key = _load_private_key()
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("ascii")


def verify_manifest(manifest: Mapping[str, object], signature_b64: str) -> bool:
    """Verify signature using the configured signing key's public component."""

    try:
        signature = base64.b64decode(signature_b64.encode("ascii"))
    except Exception:
        return False
    try:
        private_key = _load_private_key()
    except SigningError:
        return False
    public_key = private_key.public_key()
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        public_key.verify(signature, canonical, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def get_active_kid() -> str | None:
    """Expose configured key identifier for API responses."""

    return get_settings().FIXOPS_SIGNING_KID

