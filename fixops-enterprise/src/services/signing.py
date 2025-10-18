"""Evidence signing helpers."""

from __future__ import annotations

import base64
import hashlib
import json
from functools import lru_cache
from typing import Any, Mapping

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


def _canonical_bytes(manifest: Mapping[str, Any]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return a signing envelope for the manifest.

    The returned mapping matches the demo contract by including the algorithm,
    configured key identifier, detached signature, and canonical digest of the
    unsigned document. Callers are expected to persist the envelope alongside
    the manifest.
    """

    private_key = _load_private_key()
    canonical = _canonical_bytes(manifest)
    digest = hashlib.sha256(canonical).hexdigest()
    signature = private_key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    envelope = {
        "alg": ALGORITHM,
        "kid": get_active_kid(),
        "signature": base64.b64encode(signature).decode("ascii"),
        "digest": {"sha256": digest},
    }
    return envelope


def verify_manifest(
    manifest: Mapping[str, Any], signature_envelope: Mapping[str, Any] | str | None
) -> bool:
    """Verify signature using the configured signing key's public component."""

    if isinstance(signature_envelope, str):
        signature_envelope = {"signature": signature_envelope}
    if not isinstance(signature_envelope, Mapping):
        return False

    signature_b64 = signature_envelope.get("signature")
    if not isinstance(signature_b64, str):
        return False

    expected_digest = None
    digest_section = signature_envelope.get("digest")
    if isinstance(digest_section, Mapping):
        value = digest_section.get("sha256")
        if isinstance(value, str):
            expected_digest = value

    canonical = _canonical_bytes(manifest)
    if expected_digest and hashlib.sha256(canonical).hexdigest() != expected_digest:
        return False

    try:
        signature = base64.b64decode(signature_b64.encode("ascii"))
    except Exception:
        return False
    try:
        private_key = _load_private_key()
    except SigningError:
        return False
    public_key = private_key.public_key()
    try:
        public_key.verify(signature, canonical, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def get_active_kid() -> str | None:
    """Expose configured key identifier for API responses."""

    return get_settings().FIXOPS_SIGNING_KID
