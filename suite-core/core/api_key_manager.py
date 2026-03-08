"""
api_key_manager.py — Enterprise API Key Management for FixOps CTEM+ Platform.

Provides cryptographically secure API key generation, hashing, validation,
JWT token issuance, and key rotation utilities following Stripe-style key
format conventions.

Usage:
    from core.api_key_manager import APIKeyManager

    mgr = APIKeyManager(jwt_secret="your-64-char-hex-secret")
    key = mgr.generate_api_key()
    token = mgr.generate_jwt_token("user@example.com", "admin", ["read", "write"])
    hashed = mgr.hash_api_key(key)
    valid = mgr.validate_key_format(key)
    old_key, new_key = mgr.rotate_key(key)
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import uuid
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Optional JWT support (PyJWT)
# ---------------------------------------------------------------------------
try:
    import jwt as _pyjwt  # type: ignore

    _JWT_AVAILABLE = True
except ImportError:  # pragma: no cover
    _pyjwt = None  # type: ignore
    _JWT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Key format constants
# ---------------------------------------------------------------------------

_KEY_PREFIX_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_KEY_FULL_PATTERN = re.compile(r"^[a-z][a-z0-9_]*_sk_[A-Za-z0-9_-]{43}$")

# Base64url encodes 32 bytes → 43 characters (no padding)
_KEY_BYTES = 32
_B64_LEN = 43  # ceil(32 * 4 / 3) without padding


# ---------------------------------------------------------------------------
# Key metadata dataclass (plain dict to avoid dataclass import weight)
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_metadata(
    key_hash: str,
    *,
    description: str = "",
    org_id: str = "",
    scopes: Optional[List[str]] = None,
    expires_hours: Optional[int] = None,
) -> Dict[str, Any]:
    """Return a metadata dict for a newly generated key."""
    now = _utcnow()
    expires_at: Optional[str] = None
    if expires_hours is not None:
        expires_at = (now + timedelta(hours=expires_hours)).isoformat()
    return {
        "key_hash": key_hash,
        "created_at": now.isoformat(),
        "expires_at": expires_at,
        "scopes": scopes or [],
        "description": description,
        "org_id": org_id,
        "key_id": str(uuid.uuid4()),
        "active": True,
    }


# ---------------------------------------------------------------------------
# APIKeyManager
# ---------------------------------------------------------------------------


class APIKeyManager:
    """Enterprise API key and JWT management for the FixOps platform.

    Parameters
    ----------
    jwt_secret:
        Secret used to sign JWT tokens.  Falls back to the
        ``FIXOPS_JWT_SECRET`` environment variable.  Required for
        ``generate_jwt_token``.
    prefix:
        Default key prefix (e.g. ``"fixops"``).  Must match
        ``[a-z][a-z0-9_]*``.
    jwt_algorithm:
        JWT signing algorithm (default ``HS256``).
    """

    def __init__(
        self,
        jwt_secret: Optional[str] = None,
        prefix: str = "fixops",
        jwt_algorithm: str = "HS256",
    ) -> None:
        if not _KEY_PREFIX_PATTERN.match(prefix):
            raise ValueError(
                f"Invalid prefix '{prefix}'. Must match [a-z][a-z0-9_]*."
            )
        self._default_prefix = prefix
        self._jwt_secret = jwt_secret or os.environ.get("FIXOPS_JWT_SECRET", "")
        self._jwt_algorithm = jwt_algorithm

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_api_key(
        self,
        prefix: Optional[str] = None,
        *,
        description: str = "",
        org_id: str = "",
        scopes: Optional[List[str]] = None,
        expires_hours: Optional[int] = None,
    ) -> str:
        """Generate a new API key.

        Returns a key in the format ``<prefix>_sk_<base64url-32-bytes>``,
        e.g. ``fixops_sk_dGhpcyBpcyBhIHRlc3QgdmFsdWU``.

        The key is generated using :func:`secrets.token_bytes` for
        cryptographic randomness.

        Parameters
        ----------
        prefix:
            Key prefix (defaults to the manager's ``prefix`` setting).
        description:
            Human-readable description for audit records.
        org_id:
            Organisation identifier for multi-tenant environments.
        scopes:
            Permission scopes granted to this key.
        expires_hours:
            Optional expiry duration in hours.  ``None`` means no expiry.

        Returns
        -------
        str
            The raw API key.  Store only its hash via :meth:`hash_api_key`.
        """
        effective_prefix = prefix or self._default_prefix
        if not _KEY_PREFIX_PATTERN.match(effective_prefix):
            raise ValueError(
                f"Invalid prefix '{effective_prefix}'. Must match [a-z][a-z0-9_]*."
            )

        raw_bytes = secrets.token_bytes(_KEY_BYTES)
        # urlsafe_b64encode produces base64url; strip the trailing '=' padding
        b64 = urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
        key = f"{effective_prefix}_sk_{b64}"

        # Attach metadata to instance store (callers can retrieve via get_metadata)
        key_hash = self.hash_api_key(key)
        self._store_metadata(
            key_hash,
            description=description,
            org_id=org_id,
            scopes=scopes,
            expires_hours=expires_hours,
        )

        return key

    def generate_jwt_token(
        self,
        subject: str,
        role: str,
        scopes: List[str],
        *,
        expires_hours: int = 24,
        org_id: str = "",
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate a signed JWT token.

        Parameters
        ----------
        subject:
            Token subject (e.g. user email or service account name).
        role:
            Role claim (e.g. ``"admin"``, ``"analyst"``, ``"readonly"``).
        scopes:
            List of permission scopes (e.g. ``["read:vulns", "write:playbooks"]``).
        expires_hours:
            Token lifetime in hours (default 24).
        org_id:
            Organisation identifier embedded in the token.
        extra_claims:
            Additional claims to merge into the payload.

        Returns
        -------
        str
            Signed JWT string.

        Raises
        ------
        RuntimeError
            If PyJWT is not installed or no JWT secret is configured.
        """
        if not _JWT_AVAILABLE:
            raise RuntimeError(
                "PyJWT is required for JWT generation. "
                "Install it with: pip install PyJWT"
            )
        if not self._jwt_secret:
            raise RuntimeError(
                "JWT secret is not configured. "
                "Pass jwt_secret= or set FIXOPS_JWT_SECRET env var."
            )

        now = _utcnow()
        payload: Dict[str, Any] = {
            "sub": subject,
            "role": role,
            "scopes": scopes,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=expires_hours)).timestamp()),
            "jti": str(uuid.uuid4()),
            "iss": "fixops-platform",
        }
        if org_id:
            payload["org_id"] = org_id
        if extra_claims:
            payload.update(extra_claims)

        return _pyjwt.encode(payload, self._jwt_secret, algorithm=self._jwt_algorithm)

    def hash_api_key(self, key: str) -> str:
        """Return the SHA-256 hex digest of the API key.

        Never store raw API keys; always store only the hash returned here.

        Parameters
        ----------
        key:
            Raw API key string.

        Returns
        -------
        str
            Lowercase hex SHA-256 digest (64 characters).
        """
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def validate_key_format(self, key: str) -> bool:
        """Return ``True`` if *key* matches the expected FixOps key format.

        The expected format is ``<prefix>_sk_<43-char-base64url>``.

        Parameters
        ----------
        key:
            API key string to validate.

        Returns
        -------
        bool
        """
        return bool(_KEY_FULL_PATTERN.match(key))

    def rotate_key(
        self,
        old_key: str,
        *,
        description: str = "",
        org_id: str = "",
        scopes: Optional[List[str]] = None,
        expires_hours: Optional[int] = None,
    ) -> Tuple[str, str]:
        """Generate a replacement key for *old_key*.

        The old key's prefix is preserved on the new key.  Both are returned
        so callers can support a transition window before revoking the old one.

        Parameters
        ----------
        old_key:
            Existing API key to rotate.
        description, org_id, scopes, expires_hours:
            Metadata for the new key (same semantics as :meth:`generate_api_key`).

        Returns
        -------
        Tuple[str, str]
            ``(old_key, new_key)`` — keep old_key active until clients migrate.

        Raises
        ------
        ValueError
            If *old_key* does not match the expected format.
        """
        if not self.validate_key_format(old_key):
            raise ValueError(
                f"old_key does not match expected format. "
                f"Got: {old_key[:20]}..."
            )
        # Extract the prefix from the old key (everything before "_sk_")
        prefix = old_key.split("_sk_")[0]

        new_key = self.generate_api_key(
            prefix=prefix,
            description=description or f"Rotated from {old_key[:20]}...",
            org_id=org_id,
            scopes=scopes,
            expires_hours=expires_hours,
        )
        return old_key, new_key

    def get_metadata(self, key_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored metadata for a key by its SHA-256 hash.

        Parameters
        ----------
        key_hash:
            SHA-256 hex digest (from :meth:`hash_api_key`).

        Returns
        -------
        dict or None
        """
        return self._key_store.get(key_hash)

    def revoke_key(self, key_hash: str) -> bool:
        """Mark a key as revoked in the in-memory store.

        Parameters
        ----------
        key_hash:
            SHA-256 hex digest of the key to revoke.

        Returns
        -------
        bool
            ``True`` if the key was found and revoked, ``False`` otherwise.
        """
        meta = self._key_store.get(key_hash)
        if meta is None:
            return False
        meta["active"] = False
        meta["revoked_at"] = _utcnow().isoformat()
        return True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @property
    def _key_store(self) -> Dict[str, Any]:
        """Lazy-initialised in-memory key metadata store."""
        if not hasattr(self, "_key_store_dict"):
            self._key_store_dict: Dict[str, Any] = {}
        return self._key_store_dict

    def _store_metadata(
        self,
        key_hash: str,
        *,
        description: str,
        org_id: str,
        scopes: Optional[List[str]],
        expires_hours: Optional[int],
    ) -> None:
        self._key_store[key_hash] = _make_metadata(
            key_hash,
            description=description,
            org_id=org_id,
            scopes=scopes or [],
            expires_hours=expires_hours,
        )
