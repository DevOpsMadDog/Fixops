"""Enterprise cryptographic utilities and secure token generation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import string
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Protocol, Tuple

import structlog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.config.settings import get_settings

logger = structlog.get_logger()


class KeyProvider(Protocol):
    """Interface for asymmetric signing key providers."""

    def sign(self, payload: bytes) -> bytes:
        """Return an RSA-SHA256 signature for ``payload``."""

        raise NotImplementedError

    def verify(self, payload: bytes, signature: bytes, fingerprint: str) -> bool:
        """Verify ``signature`` over ``payload`` for a public key fingerprint."""

        raise NotImplementedError

    def rotate(self) -> str:
        """Rotate the signing key and return the new fingerprint."""

        raise NotImplementedError

    def fingerprint(self) -> str:
        """Return the current public key fingerprint."""

        raise NotImplementedError


@dataclass
class EnvKeyProvider:
    """Key provider that sources RSA keys from environment variables."""

    private_key_pem: Optional[str] = None
    public_key_pem: Optional[str] = None
    _public_keys: Dict[str, rsa.RSAPublicKey] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        private_key_material = self.private_key_pem or os.getenv("SIGNING_PRIVATE_KEY")

        if private_key_material:
            self._private_key = serialization.load_pem_private_key(
                private_key_material.encode(), password=None
            )
            logger.debug("Loaded RSA private key from environment")
        else:
            logger.warning(
                "SIGNING_PRIVATE_KEY not provided; generating ephemeral demo key"
            )
            self._private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )

        public_key_material = self.public_key_pem or os.getenv("SIGNING_PUBLIC_KEY")
        if public_key_material:
            self._public_key = serialization.load_pem_public_key(
                public_key_material.encode()
            )
        else:
            self._public_key = self._private_key.public_key()

        self._fingerprint = _fingerprint_public_key(self._public_key)
        self._register_public_key(self._fingerprint, self._public_key)

    def sign(self, payload: bytes) -> bytes:
        return self._private_key.sign(
            payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    def verify(self, payload: bytes, signature: bytes, fingerprint: str) -> bool:
        public_key = self._public_keys.get(fingerprint)
        if public_key is None:
            logger.warning(
                "Fingerprint mismatch during verification",
                available=list(self._public_keys.keys()),
                provided=fingerprint,
            )
            return False

        try:
            public_key.verify(
                signature,
                payload,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.error("RSA signature verification failed", error=str(exc))
            return False

    def rotate(self) -> str:
        """Generate a new ephemeral key pair and return the new fingerprint."""

        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._private_key.public_key()
        self._fingerprint = _fingerprint_public_key(self._public_key)
        self._register_public_key(self._fingerprint, self._public_key)
        logger.info("Ephemeral RSA key rotated", fingerprint=self._fingerprint)
        return self._fingerprint

    def fingerprint(self) -> str:
        return self._fingerprint

    def _register_public_key(
        self, fingerprint: str, public_key: rsa.RSAPublicKey
    ) -> None:
        self._public_keys[fingerprint] = public_key


class AWSKMSProvider:
    """Stub AWS KMS provider."""

    def __init__(self, key_id: Optional[str]):
        self.key_id = key_id or "unknown"

    def sign(self, payload: bytes) -> bytes:  # pragma: no cover - integration stub
        raise NotImplementedError("AWS KMS signing not implemented in this demo build")

    def verify(self, payload: bytes, signature: bytes, fingerprint: str) -> bool:
        raise NotImplementedError("AWS KMS verification not implemented in this demo build")

    def rotate(self) -> str:
        raise NotImplementedError("AWS KMS rotation not implemented in this demo build")

    def fingerprint(self) -> str:
        raise NotImplementedError("AWS KMS fingerprint not implemented in this demo build")


class AzureKeyVaultProvider:
    """Stub Azure Key Vault provider."""

    def __init__(self, key_id: Optional[str]):
        self.key_id = key_id or "unknown"

    def sign(self, payload: bytes) -> bytes:  # pragma: no cover - integration stub
        raise NotImplementedError(
            "Azure Key Vault signing not implemented in this demo build"
        )

    def verify(self, payload: bytes, signature: bytes, fingerprint: str) -> bool:
        raise NotImplementedError(
            "Azure Key Vault verification not implemented in this demo build"
        )

    def rotate(self) -> str:
        raise NotImplementedError(
            "Azure Key Vault rotation not implemented in this demo build"
        )

    def fingerprint(self) -> str:
        raise NotImplementedError(
            "Azure Key Vault fingerprint not implemented in this demo build"
        )


_KEY_PROVIDER: Optional[KeyProvider] = None


def get_key_provider() -> KeyProvider:
    """Return the configured signing key provider (cached)."""

    global _KEY_PROVIDER
    if _KEY_PROVIDER is not None:
        return _KEY_PROVIDER

    settings = get_settings()
    provider_name = (settings.SIGNING_PROVIDER or "env").lower()

    if provider_name == "aws_kms":
        _KEY_PROVIDER = AWSKMSProvider(settings.KEY_ID)
    elif provider_name == "azure_key_vault":
        _KEY_PROVIDER = AzureKeyVaultProvider(settings.KEY_ID)
    else:
        _KEY_PROVIDER = EnvKeyProvider()

    logger.info("Signing provider initialised", provider=provider_name)
    return _KEY_PROVIDER


def reset_key_provider_cache() -> None:
    """Reset the cached key provider (primarily for tests)."""

    global _KEY_PROVIDER
    _KEY_PROVIDER = None


def _fingerprint_public_key(public_key: rsa.RSAPublicKey) -> str:
    """Return SHA-256 fingerprint for a public key."""

    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(der).hexdigest()
    return ":".join([digest[i : i + 2] for i in range(0, len(digest), 2)])


def rsa_sign(json_bytes: bytes) -> Tuple[bytes, str]:
    """Sign ``json_bytes`` with the configured provider and return signature + fingerprint."""

    provider = get_key_provider()
    signature = provider.sign(json_bytes)
    return signature, provider.fingerprint()


def rsa_verify(json_bytes: bytes, signature: bytes, pub_fingerprint: str) -> bool:
    """Verify RSA signature for the provided payload."""

    provider = get_key_provider()
    return provider.verify(json_bytes, signature, pub_fingerprint)


def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure random token
    Suitable for session tokens, API keys, etc.
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_secure_password(length: int = 16) -> str:
    """
    Generate cryptographically secure password with mixed character types
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")
    
    # Ensure at least one character from each category
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Start with one character from each category
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Fill the rest with random characters from all categories
    all_chars = lowercase + uppercase + digits + special
    for _ in range(length - 4):
        password.append(secrets.choice(all_chars))
    
    # Shuffle the password
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)


def generate_api_key(prefix: str = "fxo", length: int = 32) -> str:
    """
    Generate API key with prefix for identification
    Format: prefix_randompart
    """
    random_part = generate_secure_token(length)
    return f"{prefix}_{random_part}"


def hash_sensitive_data(data: str, salt: Optional[str] = None) -> Dict[str, str]:
    """
    Hash sensitive data with salt for secure storage
    Returns dict with hash and salt
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    # Use PBKDF2 for key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,  # High iteration count for security
    )
    
    key = kdf.derive(data.encode())
    hash_hex = key.hex()
    
    return {
        "hash": hash_hex,
        "salt": salt
    }


def verify_sensitive_data(data: str, stored_hash: str, salt: str) -> bool:
    """
    Verify sensitive data against stored hash
    """
    try:
        # Recreate hash with same salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
        )
        
        key = kdf.derive(data.encode())
        computed_hash = key.hex()
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_hash, computed_hash)
        
    except Exception:
        return False


def generate_encryption_key() -> bytes:
    """
    Generate encryption key for Fernet symmetric encryption
    """
    return Fernet.generate_key()


def encrypt_data(data: str, key: bytes) -> str:
    """
    Encrypt data using Fernet symmetric encryption
    """
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return base64.urlsafe_b64encode(encrypted_data).decode()


def decrypt_data(encrypted_data: str, key: bytes) -> str:
    """
    Decrypt data using Fernet symmetric encryption
    """
    f = Fernet(key)
    decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
    decrypted_data = f.decrypt(decoded_data)
    return decrypted_data.decode()


def generate_checksum(data: str) -> str:
    """
    Generate SHA-256 checksum for data integrity verification
    """
    return hashlib.sha256(data.encode()).hexdigest()


def verify_checksum(data: str, expected_checksum: str) -> bool:
    """
    Verify data integrity using checksum
    """
    computed_checksum = generate_checksum(data)
    return hmac.compare_digest(expected_checksum, computed_checksum)


def generate_hmac_signature(data: str, secret_key: str) -> str:
    """
    Generate HMAC signature for message authentication
    """
    signature = hmac.new(
        secret_key.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature


def verify_hmac_signature(data: str, signature: str, secret_key: str) -> bool:
    """
    Verify HMAC signature for message authentication
    """
    expected_signature = generate_hmac_signature(data, secret_key)
    return hmac.compare_digest(expected_signature, signature)


class SecureTokenManager:
    """
    Manager for secure token operations with enterprise features
    """
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
    
    def generate_signed_token(self, payload: Dict[str, Any], expiry_minutes: int = 60) -> str:
        """
        Generate signed token with payload and expiry
        """
        import json
        import time
        
        # Add timestamp and expiry
        payload_with_meta = {
            **payload,
            "iat": int(time.time()),
            "exp": int(time.time() + (expiry_minutes * 60))
        }
        
        # Serialize payload
        payload_json = json.dumps(payload_with_meta, sort_keys=True)
        
        # Encode payload
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()
        
        # Generate signature
        signature = self.generate_hmac_signature(payload_b64, self.secret_key)
        
        # Combine payload and signature
        return f"{payload_b64}.{signature}"
    
    def verify_signed_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify signed token and return payload if valid
        """
        import json
        import time
        
        try:
            # Split token
            parts = token.split(".")
            if len(parts) != 2:
                return None
            
            payload_b64, signature = parts
            
            # Verify signature
            if not self.verify_hmac_signature(payload_b64, signature, self.secret_key):
                return None
            
            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
            payload = json.loads(payload_json)
            
            # Check expiry
            if "exp" in payload and payload["exp"] < int(time.time()):
                return None
            
            return payload
            
        except Exception:
            return None
    
    def generate_hmac_signature(self, data: str, secret_key: str) -> str:
        """Generate HMAC signature"""
        return generate_hmac_signature(data, secret_key)
    
    def verify_hmac_signature(self, data: str, signature: str, secret_key: str) -> bool:
        """Verify HMAC signature"""
        return verify_hmac_signature(data, signature, secret_key)


# Utility functions for common crypto operations
def secure_compare(a: str, b: str) -> bool:
    """
    Timing-safe string comparison to prevent timing attacks
    """
    return hmac.compare_digest(a, b)


def generate_nonce(length: int = 16) -> str:
    """
    Generate cryptographic nonce for one-time use
    """
    return secrets.token_hex(length)


def generate_salt(length: int = 16) -> str:
    """
    Generate cryptographic salt for password hashing
    """
    return secrets.token_hex(length)