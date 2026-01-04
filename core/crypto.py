"""Production-ready RSA cryptographic signing and verification.

This module provides RSA-SHA256 signing and verification for evidence bundles
using the cryptography library. It supports:
- Key generation with configurable key sizes (2048, 3072, 4096 bits)
- Key persistence in PEM format
- Key rotation with key ID tracking
- Signature generation and verification
- Key fingerprint computation for audit trails

Environment variables:
- FIXOPS_RSA_PRIVATE_KEY_PATH: Path to RSA private key PEM file
- FIXOPS_RSA_PUBLIC_KEY_PATH: Path to RSA public key PEM file
- FIXOPS_RSA_KEY_SIZE: Key size in bits (default: 4096)
- FIXOPS_RSA_KEY_ID: Optional key identifier for rotation tracking

For production deployments, keys should be stored securely (e.g., HSM, KMS)
and rotated according to your organization's security policy.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

logger = logging.getLogger(__name__)


class CryptoError(Exception):
    """Base exception for cryptographic operations."""


class KeyNotFoundError(CryptoError):
    """Raised when a required key is not found."""


class SignatureVerificationError(CryptoError):
    """Raised when signature verification fails."""


class KeyGenerationError(CryptoError):
    """Raised when key generation fails."""


@dataclass
class KeyMetadata:
    """Metadata about a cryptographic key."""

    key_id: str
    fingerprint: str
    algorithm: str
    key_size: int
    created_at: str
    public_key_pem: str

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "created_at": self.created_at,
            "public_key_pem": self.public_key_pem,
        }


class RSAKeyManager:
    """Manages RSA key pairs for signing and verification.

    This class handles key loading, generation, and persistence.
    For production use, consider integrating with a KMS or HSM.
    """

    SUPPORTED_KEY_SIZES = (2048, 3072, 4096)
    DEFAULT_KEY_SIZE = 4096

    def __init__(
        self,
        private_key_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
        key_size: int = DEFAULT_KEY_SIZE,
        key_id: Optional[str] = None,
    ):
        """Initialize the key manager.

        Args:
            private_key_path: Path to private key PEM file (or env var FIXOPS_RSA_PRIVATE_KEY_PATH)
            public_key_path: Path to public key PEM file (or env var FIXOPS_RSA_PUBLIC_KEY_PATH)
            key_size: Key size for generation (2048, 3072, or 4096 bits)
            key_id: Optional key identifier for rotation tracking
        """
        _private_path = (
            private_key_path or os.getenv("FIXOPS_RSA_PRIVATE_KEY_PATH") or ""
        )
        _public_path = public_key_path or os.getenv("FIXOPS_RSA_PUBLIC_KEY_PATH") or ""
        self.private_key_path = Path(_private_path) if _private_path else Path()
        self.public_key_path = Path(_public_path) if _public_path else Path()

        env_key_size = os.getenv("FIXOPS_RSA_KEY_SIZE")
        if env_key_size:
            try:
                key_size = int(env_key_size)
            except ValueError:
                logger.warning(
                    f"Invalid FIXOPS_RSA_KEY_SIZE: {env_key_size}, using default"
                )

        if key_size not in self.SUPPORTED_KEY_SIZES:
            raise KeyGenerationError(
                f"Unsupported key size: {key_size}. "
                f"Supported sizes: {self.SUPPORTED_KEY_SIZES}"
            )
        self.key_size = key_size
        self.key_id = (
            key_id or os.getenv("FIXOPS_RSA_KEY_ID") or self._generate_key_id()
        )

        self._private_key: Optional[RSAPrivateKey] = None
        self._public_key: Optional[RSAPublicKey] = None
        self._metadata: Optional[KeyMetadata] = None

    def _generate_key_id(self) -> str:
        """Generate a unique key ID based on timestamp."""
        return f"fixops-rsa-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    @property
    def private_key(self) -> RSAPrivateKey:
        """Get the private key, loading or generating if necessary."""
        if self._private_key is None:
            self._load_or_generate_keys()
        if self._private_key is None:
            raise KeyNotFoundError("Private key not available")
        return self._private_key

    @property
    def public_key(self) -> RSAPublicKey:
        """Get the public key, loading or generating if necessary."""
        if self._public_key is None:
            self._load_or_generate_keys()
        if self._public_key is None:
            raise KeyNotFoundError("Public key not available")
        return self._public_key

    @property
    def metadata(self) -> KeyMetadata:
        """Get key metadata."""
        if self._metadata is None:
            self._load_or_generate_keys()
        if self._metadata is None:
            raise KeyNotFoundError("Key metadata not available")
        return self._metadata

    def _load_or_generate_keys(self) -> None:
        """Load existing keys or generate new ones."""
        # Try to load existing keys
        if self.private_key_path and self.private_key_path.exists():
            self._load_private_key()
        elif self.public_key_path and self.public_key_path.exists():
            self._load_public_key()
        else:
            # Generate new key pair
            self._generate_key_pair()

    def _load_private_key(self) -> None:
        """Load private key from PEM file."""
        try:
            pem_data = self.private_key_path.read_bytes()
            loaded_key = serialization.load_pem_private_key(
                pem_data, password=None, backend=default_backend()
            )
            if not isinstance(loaded_key, RSAPrivateKey):
                raise CryptoError("Loaded key is not an RSA private key")
            self._private_key = loaded_key
            self._public_key = self._private_key.public_key()
            self._compute_metadata()
            logger.info(
                f"Loaded RSA private key from {self.private_key_path} "
                f"(fingerprint: {self._metadata.fingerprint if self._metadata else 'unknown'})"
            )
        except Exception as e:
            raise CryptoError(f"Failed to load private key: {e}") from e

    def _load_public_key(self) -> None:
        """Load public key from PEM file (for verification only)."""
        try:
            pem_data = self.public_key_path.read_bytes()
            loaded_key = serialization.load_pem_public_key(
                pem_data, backend=default_backend()
            )
            if not isinstance(loaded_key, RSAPublicKey):
                raise CryptoError("Loaded key is not an RSA public key")
            self._public_key = loaded_key
            self._compute_metadata()
            logger.info(
                f"Loaded RSA public key from {self.public_key_path} "
                f"(fingerprint: {self._metadata.fingerprint if self._metadata else 'unknown'})"
            )
        except Exception as e:
            raise CryptoError(f"Failed to load public key: {e}") from e

    def _generate_key_pair(self) -> None:
        """Generate a new RSA key pair."""
        try:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend(),
            )
            self._public_key = self._private_key.public_key()
            self._compute_metadata()

            # Save keys if paths are configured
            if self.private_key_path and str(self.private_key_path):
                self._save_private_key()
            if self.public_key_path and str(self.public_key_path):
                self._save_public_key()

            logger.info(
                f"Generated new RSA-{self.key_size} key pair "
                f"(key_id: {self.key_id}, fingerprint: {self._metadata.fingerprint if self._metadata else 'unknown'})"
            )
        except Exception as e:
            raise KeyGenerationError(f"Failed to generate key pair: {e}") from e

    def _save_private_key(self) -> None:
        """Save private key to PEM file."""
        if self._private_key is None:
            return
        try:
            self.private_key_path.parent.mkdir(parents=True, exist_ok=True)
            pem_data = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self.private_key_path.write_bytes(pem_data)
            # Set restrictive permissions
            self.private_key_path.chmod(0o600)
            logger.info(f"Saved private key to {self.private_key_path}")
        except Exception as e:
            logger.warning(f"Failed to save private key: {e}")

    def _save_public_key(self) -> None:
        """Save public key to PEM file."""
        if self._public_key is None:
            return
        try:
            self.public_key_path.parent.mkdir(parents=True, exist_ok=True)
            pem_data = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self.public_key_path.write_bytes(pem_data)
            logger.info(f"Saved public key to {self.public_key_path}")
        except Exception as e:
            logger.warning(f"Failed to save public key: {e}")

    def _compute_metadata(self) -> None:
        """Compute key metadata including fingerprint."""
        if self._public_key is None:
            return

        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Compute SHA-256 fingerprint of public key
        fingerprint = hashlib.sha256(public_pem).hexdigest()

        self._metadata = KeyMetadata(
            key_id=self.key_id,
            fingerprint=fingerprint,
            algorithm="RSA-SHA256",
            key_size=self._public_key.key_size,
            created_at=datetime.now(timezone.utc).isoformat(),
            public_key_pem=public_pem.decode("utf-8"),
        )

    def get_public_key_pem(self) -> str:
        """Get the public key in PEM format."""
        return self.metadata.public_key_pem


class RSASigner:
    """RSA-SHA256 signer for evidence bundles.

    This class provides signing functionality using RSA-SHA256 with
    PKCS#1 v1.5 padding, which is widely supported and suitable for
    signing evidence bundles.
    """

    def __init__(self, key_manager: Optional[RSAKeyManager] = None):
        """Initialize the signer.

        Args:
            key_manager: Optional key manager. If not provided, creates one
                        using environment variables.
        """
        self._key_manager = key_manager or RSAKeyManager()

    @property
    def key_manager(self) -> RSAKeyManager:
        return self._key_manager

    def sign(self, data: bytes) -> Tuple[bytes, str]:
        """Sign data using RSA-SHA256.

        Args:
            data: The data to sign

        Returns:
            Tuple of (signature_bytes, key_fingerprint)

        Raises:
            CryptoError: If signing fails
        """
        try:
            signature = self._key_manager.private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            fingerprint = self._key_manager.metadata.fingerprint
            logger.debug(f"Signed {len(data)} bytes (fingerprint: {fingerprint})")
            return signature, fingerprint
        except Exception as e:
            raise CryptoError(f"Failed to sign data: {e}") from e

    def sign_base64(self, data: bytes) -> Tuple[str, str]:
        """Sign data and return base64-encoded signature.

        Args:
            data: The data to sign

        Returns:
            Tuple of (base64_signature, key_fingerprint)
        """
        signature, fingerprint = self.sign(data)
        return base64.b64encode(signature).decode("utf-8"), fingerprint


class RSAVerifier:
    """RSA-SHA256 signature verifier.

    This class provides verification functionality for signatures
    created by RSASigner.
    """

    def __init__(self, key_manager: Optional[RSAKeyManager] = None):
        """Initialize the verifier.

        Args:
            key_manager: Optional key manager. If not provided, creates one
                        using environment variables.
        """
        self._key_manager = key_manager or RSAKeyManager()

    @property
    def key_manager(self) -> RSAKeyManager:
        return self._key_manager

    def verify(
        self,
        data: bytes,
        signature: bytes,
        expected_fingerprint: Optional[str] = None,
        raise_on_failure: bool = False,
    ) -> bool:
        """Verify an RSA-SHA256 signature.

        Args:
            data: The original data that was signed
            signature: The signature to verify
            expected_fingerprint: Optional expected key fingerprint for validation
            raise_on_failure: If True, raise exception on verification failure.
                            If False (default), return False on failure.

        Returns:
            True if signature is valid, False if invalid (when raise_on_failure=False)

        Raises:
            SignatureVerificationError: If verification fails and raise_on_failure=True,
                                       or if fingerprint mismatch occurs
        """
        # Validate fingerprint if provided
        if expected_fingerprint:
            actual_fingerprint = self._key_manager.metadata.fingerprint
            if expected_fingerprint != actual_fingerprint:
                logger.warning(
                    f"Key fingerprint mismatch. Expected: {expected_fingerprint}, "
                    f"Actual: {actual_fingerprint}"
                )
                if raise_on_failure:
                    raise SignatureVerificationError(
                        f"Key fingerprint mismatch. Expected: {expected_fingerprint}, "
                        f"Actual: {actual_fingerprint}"
                    )
                return False

        try:
            self._key_manager.public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            logger.debug(f"Verified signature for {len(data)} bytes")
            return True
        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
            if raise_on_failure:
                raise SignatureVerificationError(
                    f"Signature verification failed: {e}"
                ) from e
            return False

    def verify_base64(
        self,
        data: bytes,
        signature_b64: str,
        expected_fingerprint: Optional[str] = None,
    ) -> bool:
        """Verify a base64-encoded RSA-SHA256 signature.

        Args:
            data: The original data that was signed
            signature_b64: Base64-encoded signature
            expected_fingerprint: Optional expected key fingerprint

        Returns:
            True if signature is valid, False if invalid or malformed
        """
        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            logger.warning("Invalid base64 signature provided")
            return False
        return self.verify(data, signature, expected_fingerprint)


# Module-level convenience functions for backward compatibility
_default_key_manager: Optional[RSAKeyManager] = None
_default_signer: Optional[RSASigner] = None
_default_verifier: Optional[RSAVerifier] = None


def _get_default_key_manager() -> RSAKeyManager:
    """Get or create the default key manager."""
    global _default_key_manager
    if _default_key_manager is None:
        _default_key_manager = RSAKeyManager()
    return _default_key_manager


def _get_default_signer() -> RSASigner:
    """Get or create the default signer."""
    global _default_signer
    if _default_signer is None:
        _default_signer = RSASigner(_get_default_key_manager())
    return _default_signer


def _get_default_verifier() -> RSAVerifier:
    """Get or create the default verifier."""
    global _default_verifier
    if _default_verifier is None:
        _default_verifier = RSAVerifier(_get_default_key_manager())
    return _default_verifier


def rsa_sign(data: bytes) -> Tuple[bytes, str]:
    """Sign data using RSA-SHA256.

    This is a convenience function that uses the default key manager.
    For production use, consider creating your own RSASigner instance
    with explicit key configuration.

    Args:
        data: The data to sign

    Returns:
        Tuple of (signature_bytes, key_fingerprint)
    """
    return _get_default_signer().sign(data)


def rsa_verify(data: bytes, signature: bytes, fingerprint: str) -> bool:
    """Verify an RSA-SHA256 signature.

    This is a convenience function that uses the default key manager.
    For production use, consider creating your own RSAVerifier instance
    with explicit key configuration.

    Args:
        data: The original data that was signed
        signature: The signature to verify
        fingerprint: Expected key fingerprint

    Returns:
        True if signature is valid

    Raises:
        SignatureVerificationError: If verification fails
    """
    return _get_default_verifier().verify(data, signature, fingerprint)


def generate_key_pair(
    private_key_path: str,
    public_key_path: str,
    key_size: int = 4096,
    key_id: Optional[str] = None,
) -> KeyMetadata:
    """Generate a new RSA key pair and save to files.

    Args:
        private_key_path: Path to save private key PEM file
        public_key_path: Path to save public key PEM file
        key_size: Key size in bits (2048, 3072, or 4096)
        key_id: Optional key identifier

    Returns:
        KeyMetadata for the generated key pair
    """
    manager = RSAKeyManager(
        private_key_path=private_key_path,
        public_key_path=public_key_path,
        key_size=key_size,
        key_id=key_id,
    )
    # Force key generation by accessing the private key
    _ = manager.private_key
    return manager.metadata


__all__ = [
    "CryptoError",
    "KeyNotFoundError",
    "SignatureVerificationError",
    "KeyGenerationError",
    "KeyMetadata",
    "RSAKeyManager",
    "RSASigner",
    "RSAVerifier",
    "rsa_sign",
    "rsa_verify",
    "generate_key_pair",
]
