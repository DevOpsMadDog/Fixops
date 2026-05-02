"""DSSE signing utility — real ed25519 keypair signing for ALDECI.

Implements the DSSE Pre-Authentication Encoding (PAE) spec and signs/verifies
with ed25519 via the `cryptography` package (already a core dependency).

Key lifecycle
-------------
- Keys are stored under ``data/keys/`` (path configurable via env var
  ``ALDECI_SIGNING_KEY_PATH``). The directory and key are created with mode
  0o600 (owner-read-only) on first use.
- Private key is serialised as PEM (PKCS8, no passphrase).
- Public key is serialised as PEM (SubjectPublicKeyInfo).
- ``data/keys/`` and ``*.pem`` are already in .gitignore — private key is
  NEVER committed.

DSSE PAE (per https://github.com/secure-systems-lab/dsse/blob/master/envelope.md):
    PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
    where SP is a single space, LEN(x) is the decimal UTF-8 byte-length of x.

Signature algorithm: Ed25519 (deterministic, no random needed per sign).

Public API
----------
- ``get_signer()``           — returns the module-level DSSESigner singleton
- ``DSSESigner.sign_dsse()`` — build + sign a DSSE envelope dict
- ``DSSESigner.verify_dsse()``— verify a DSSE envelope dict
- ``DSSESigner.fingerprint`` — hex SHA-256 of DER-encoded public key
- ``DSSESigner.public_key_pem`` — PEM string of public key (for distribution)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_KEY_DIR = _REPO_ROOT / "data" / "keys"
_PRIVATE_KEY_FILENAME = "slsa_signing.pem"
_PUBLIC_KEY_FILENAME = "slsa_signing_pub.pem"

# Env-var override so operators can supply their own key path.
_KEY_DIR = Path(os.environ.get("ALDECI_SIGNING_KEY_PATH", str(_DEFAULT_KEY_DIR)))

# ---------------------------------------------------------------------------
# PAE helper
# ---------------------------------------------------------------------------


def _pae(payload_type: str, payload: bytes) -> bytes:
    """Build DSSE Pre-Authentication Encoding string.

    DSSEv1 SP LEN(type) SP type SP LEN(body) SP body
    where LEN is decimal ASCII byte-count and SP is a single space.
    """
    type_bytes = payload_type.encode("utf-8")
    pae = (
        b"DSSEv1"
        + b" " + str(len(type_bytes)).encode()
        + b" " + type_bytes
        + b" " + str(len(payload)).encode()
        + b" " + payload
    )
    return pae


# ---------------------------------------------------------------------------
# DSSESigner
# ---------------------------------------------------------------------------


class DSSESigner:
    """Thread-safe ed25519 DSSE signer/verifier.

    Generates or loads a keypair from ``data/keys/``. Private key file is
    created with 0o600 permissions. Safe to call from multiple threads.
    """

    def __init__(self, key_dir: Path = _KEY_DIR) -> None:
        self._key_dir = key_dir
        self._lock = threading.Lock()
        self._private_key: Optional[Ed25519PrivateKey] = None
        self._public_key: Optional[Ed25519PublicKey] = None
        self._fingerprint: Optional[str] = None
        self._public_key_pem: Optional[str] = None
        self._load_or_generate()

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def _private_key_path(self) -> Path:
        return self._key_dir / _PRIVATE_KEY_FILENAME

    def _public_key_path(self) -> Path:
        return self._key_dir / _PUBLIC_KEY_FILENAME

    def _load_or_generate(self) -> None:
        """Load existing key or generate a new one. Called once at init."""
        priv_path = self._private_key_path()
        self._public_key_path()

        if priv_path.exists():
            try:
                raw = priv_path.read_bytes()
                priv = serialization.load_pem_private_key(raw, password=None)
                if not isinstance(priv, Ed25519PrivateKey):
                    raise ValueError("Key is not ed25519")
                self._private_key = priv
                self._public_key = priv.public_key()
                _logger.info("dsse_signer: loaded existing signing key from %s", priv_path)
            except Exception as exc:
                _logger.warning(
                    "dsse_signer: failed to load key (%s), generating fresh keypair", exc
                )
                self._generate_and_save()
        else:
            self._generate_and_save()

        self._derive_public_meta()

    def _generate_and_save(self) -> None:
        """Generate a new ed25519 keypair and persist to disk."""
        self._key_dir.mkdir(parents=True, exist_ok=True)

        priv = Ed25519PrivateKey.generate()
        self._private_key = priv
        self._public_key = priv.public_key()

        # Write private key — PKCS8 PEM, no encryption
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        priv_path = self._private_key_path()
        priv_path.write_bytes(priv_pem)
        priv_path.chmod(0o600)

        # Write public key — SubjectPublicKeyInfo PEM
        pub_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_path = self._public_key_path()
        pub_path.write_bytes(pub_pem)
        pub_path.chmod(0o644)

        _logger.info(
            "dsse_signer: generated new ed25519 keypair, private=%s public=%s",
            priv_path,
            pub_path,
        )

    def _derive_public_meta(self) -> None:
        """Compute fingerprint and PEM string from loaded public key."""
        if self._public_key is None:
            return
        der = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._fingerprint = hashlib.sha256(der).hexdigest()
        self._public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def fingerprint(self) -> str:
        """SHA-256 hex fingerprint of DER-encoded public key."""
        return self._fingerprint or ""

    @property
    def public_key_pem(self) -> str:
        """PEM-encoded public key (SubjectPublicKeyInfo)."""
        return self._public_key_pem or ""

    # ------------------------------------------------------------------
    # Sign
    # ------------------------------------------------------------------

    def sign_dsse(
        self,
        payload_type: str,
        payload_obj: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a real DSSE envelope with an ed25519 signature.

        Returns:
          {
            "payloadType": <str>,
            "payload": <base64(canonical_json)>,
            "signatures": [{"keyid": <fingerprint>, "sig": <base64(ed25519_sig)>}]
          }
        """
        payload_bytes = json.dumps(
            payload_obj, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        pae = _pae(payload_type, payload_bytes)

        with self._lock:
            if self._private_key is None:
                raise RuntimeError("DSSE signer has no private key loaded")
            raw_sig = self._private_key.sign(pae)

        sig_b64 = base64.b64encode(raw_sig).decode("ascii")
        payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

        return {
            "payloadType": payload_type,
            "payload": payload_b64,
            "signatures": [
                {"keyid": self.fingerprint, "sig": sig_b64}
            ],
        }

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def verify_dsse(self, envelope: Dict[str, Any]) -> bool:
        """Verify a DSSE envelope against the loaded public key.

        Returns True iff the signature is valid for the canonical payload.
        """
        if not isinstance(envelope, dict):
            return False
        payload_type = envelope.get("payloadType", "")
        payload_b64 = envelope.get("payload", "")
        signatures = envelope.get("signatures", [])

        if not payload_type or not payload_b64 or not signatures:
            return False

        try:
            payload_bytes = base64.b64decode(payload_b64.encode("ascii"))
        except Exception:
            return False

        pae = _pae(payload_type, payload_bytes)

        for sig_block in signatures:
            sig_b64 = sig_block.get("sig", "")
            if not sig_b64:
                continue
            try:
                raw_sig = base64.b64decode(sig_b64.encode("ascii"))
            except Exception:
                continue
            with self._lock:
                pub = self._public_key
            if pub is None:
                continue
            try:
                pub.verify(raw_sig, pae)
                return True
            except InvalidSignature:
                continue
            except Exception:
                continue

        return False

    # ------------------------------------------------------------------
    # Convenience: sign bytes directly (for air-gap bundle)
    # ------------------------------------------------------------------

    def sign_bytes(self, data: bytes) -> str:
        """Sign raw bytes with ed25519, return base64-encoded signature."""
        with self._lock:
            if self._private_key is None:
                raise RuntimeError("DSSE signer has no private key loaded")
            raw_sig = self._private_key.sign(data)
        return base64.b64encode(raw_sig).decode("ascii")

    def verify_bytes(self, data: bytes, sig_b64: str) -> bool:
        """Verify a base64-encoded ed25519 signature over raw bytes."""
        try:
            raw_sig = base64.b64decode(sig_b64.encode("ascii"))
        except Exception:
            return False
        with self._lock:
            pub = self._public_key
        if pub is None:
            return False
        try:
            pub.verify(raw_sig, data)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_singleton: Optional[DSSESigner] = None
_singleton_lock = threading.Lock()


def get_signer() -> DSSESigner:
    """Return the module-level DSSESigner singleton (thread-safe, lazy init)."""
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                try:
                    _singleton = DSSESigner()
                except Exception as exc:
                    _logger.error("dsse_signer: failed to initialise signer: %s", exc)
                    raise
    return _singleton
