"""Enterprise cryptographic utilities and secure token generation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

import structlog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:  # pragma: no cover - fallback for lightweight test environments
    from src.config.settings import get_settings
except (
    ModuleNotFoundError
):  # pragma: no cover - used when pydantic_settings is unavailable

    class _FallbackSettings:
        SIGNING_PROVIDER = "env"
        KEY_ID = None
        SIGNING_ROTATION_SLA_DAYS = 30
        AWS_REGION = None
        AZURE_VAULT_URL = None

    def get_settings() -> _FallbackSettings:
        return _FallbackSettings()


from src.services.metrics import FixOpsMetrics

logger = structlog.get_logger()


class KeyProvider(Protocol):
    """Interface for asymmetric signing key providers."""

    def sign(self, payload: bytes) -> bytes:
        """Return an RSA-SHA256 signature for ``payload``."""

        raise NotImplementedError

    def verify(self, payload: bytes, signature: bytes, fingerprint: str) -> bool:
        """Verify ``signature`` over ``payload`` for ``fingerprint``."""

        raise NotImplementedError

    def rotate(self) -> str:
        """Rotate the signing key and return the new fingerprint."""

        raise NotImplementedError

    def fingerprint(self) -> str:
        """Return the current public key fingerprint."""

        raise NotImplementedError

    @property
    def last_rotated_at(self) -> Optional[datetime]:
        """Return the timestamp when the signing material last rotated."""

        raise NotImplementedError

    def attestation(self) -> Dict[str, Any]:
        """Return metadata describing the backing key material."""

        raise NotImplementedError


@dataclass
class EnvKeyProvider:
    """Key provider that sources RSA keys from environment variables."""

    private_key_pem: Optional[str] = None
    public_key_pem: Optional[str] = None
    rotation_sla_days: int = 30
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
        self._last_rotated = datetime.now(timezone.utc)

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
            logger.error("RSA signature verification failed", exc_info=exc)
            return False

    def rotate(self) -> str:
        """Generate a new ephemeral key pair and return the new fingerprint."""

        self._private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self._public_key = self._private_key.public_key()
        self._fingerprint = _fingerprint_public_key(self._public_key)
        self._register_public_key(self._fingerprint, self._public_key)
        self._last_rotated = datetime.now(timezone.utc)
        logger.info("Ephemeral RSA key rotated", fingerprint=self._fingerprint)
        return self._fingerprint

    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def last_rotated_at(self) -> Optional[datetime]:
        return self._last_rotated

    def attestation(self) -> Dict[str, Any]:
        return {
            "provider": "env",
            "fingerprint": self._fingerprint,
            "rotation_sla_days": self.rotation_sla_days,
            "last_rotated_at": self._last_rotated.isoformat()
            if self._last_rotated
            else None,
        }

    def _register_public_key(
        self, fingerprint: str, public_key: rsa.RSAPublicKey
    ) -> None:
        self._public_keys[fingerprint] = public_key


@dataclass
class AWSKMSProvider:
    """AWS KMS-backed key provider with rotation metadata."""

    key_id: Optional[str]
    region: Optional[str] = None
    rotation_sla_days: int = 30
    kms_client: Optional[Any] = None

    def __post_init__(self) -> None:
        if not self.key_id:
            raise ValueError("AWS KMS provider requires KEY_ID to be configured")

        self.key_id = str(self.key_id)
        self.region = self.region or os.getenv("AWS_REGION") or "us-east-1"
        if self.kms_client is None:
            try:
                import boto3  # type: ignore
            except Exception as exc:  # pragma: no cover - optional dependency
                raise RuntimeError(
                    "boto3 is required to use the AWS KMS signing provider"
                ) from exc

            self.kms_client = boto3.client("kms", region_name=self.region)

        metadata = self.kms_client.describe_key(KeyId=self.key_id)["KeyMetadata"]
        self._fingerprint = metadata["KeyId"]
        self._last_rotated = metadata.get("LastRotatedDate") or metadata.get(
            "CreationDate"
        )
        if isinstance(self._last_rotated, datetime):
            self._last_rotated = self._last_rotated.replace(tzinfo=timezone.utc)

    def sign(self, payload: bytes) -> bytes:
        response = self.kms_client.sign(  # type: ignore[assignment]
            KeyId=self.key_id,
            Message=payload,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        signature = response["Signature"]
        key_id = response.get("KeyId")
        if isinstance(key_id, str):
            self._fingerprint = key_id
        return signature

    def verify(self, payload: bytes, signature: bytes, fingerprint: str) -> bool:
        response = self.kms_client.verify(
            KeyId=fingerprint,
            Message=payload,
            Signature=signature,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        return bool(response.get("SignatureValid"))

    def rotate(self) -> str:
        response = self.kms_client.rotate_key(KeyId=self.key_id)  # type: ignore[attr-defined]
        metadata = response["KeyMetadata"]
        self._fingerprint = metadata["KeyId"]
        self._last_rotated = metadata.get("LastRotatedDate")
        if isinstance(self._last_rotated, datetime):
            self._last_rotated = self._last_rotated.replace(tzinfo=timezone.utc)
        return self._fingerprint

    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def last_rotated_at(self) -> Optional[datetime]:
        return self._last_rotated

    def attestation(self) -> Dict[str, Any]:
        return {
            "provider": "aws_kms",
            "key_id": self._fingerprint,
            "rotation_sla_days": self.rotation_sla_days,
            "region": self.region,
            "last_rotated_at": self._last_rotated.isoformat()
            if isinstance(self._last_rotated, datetime)
            else None,
        }


@dataclass
class AzureKeyVaultProvider:
    """Azure Key Vault-backed signing provider."""

    key_id: Optional[str]
    vault_url: Optional[str] = None
    rotation_sla_days: int = 30
    key_client: Optional[Any] = None
    crypto_client: Optional[Any] = None

    def __post_init__(self) -> None:
        if not self.key_id:
            raise ValueError("Azure Key Vault provider requires KEY_ID to be set")

        self.vault_url = self.vault_url or os.getenv("AZURE_VAULT_URL")
        if not self.vault_url:
            raise ValueError("AZURE_VAULT_URL must be configured for Azure Key Vault")

        if self.key_client is None or self.crypto_client is None:
            try:
                from azure.identity import DefaultAzureCredential  # type: ignore
                from azure.keyvault.keys import KeyClient  # type: ignore
                from azure.keyvault.keys.crypto import (  # type: ignore
                    CryptographyClient,
                    SignatureAlgorithm,
                )
            except Exception as exc:  # pragma: no cover - optional dependency
                raise RuntimeError(
                    "azure-keyvault-keys is required for the Azure signing provider"
                ) from exc

            credential = DefaultAzureCredential()
            self.key_client = KeyClient(vault_url=self.vault_url, credential=credential)
            key = self.key_client.get_key(self.key_id)
            self.crypto_client = CryptographyClient(key, credential=credential)
            self._signature_algorithm = SignatureAlgorithm.rs256
        else:
            self._signature_algorithm = getattr(
                self.crypto_client, "default_algorithm", "RS256"
            )

        key_version = self.key_client.get_key(self.key_id)
        self._fingerprint = key_version.properties.version
        self._last_rotated = getattr(key_version.properties, "updated_on", None)
        if (
            isinstance(self._last_rotated, datetime)
            and self._last_rotated.tzinfo is None
        ):
            self._last_rotated = self._last_rotated.replace(tzinfo=timezone.utc)

    def sign(self, payload: bytes) -> bytes:
        response = self.crypto_client.sign(  # type: ignore[assignment]
            self._signature_algorithm, payload
        )
        return _extract_signature(response) or b""

    def verify(self, payload: bytes, signature: bytes, fingerprint: str) -> bool:
        key_version = self.key_client.get_key(self.key_id, version=fingerprint)
        numbers = key_version.key
        if not numbers:
            return False
        public_numbers = rsa.RSAPublicNumbers(
            e=_decode_base64url(numbers["e"]), n=_decode_base64url(numbers["n"])
        )
        public_key = public_numbers.public_key()
        try:
            public_key.verify(
                signature,
                payload,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.error("Azure RSA verification failed", exc_info=exc)
            return False

    def rotate(self) -> str:
        poller = self.key_client.begin_rotate_key(self.key_id)  # type: ignore[attr-defined]
        new_version = poller.result()
        self._fingerprint = new_version.properties.version
        self._last_rotated = getattr(new_version.properties, "updated_on", None)
        if (
            isinstance(self._last_rotated, datetime)
            and self._last_rotated.tzinfo is None
        ):
            self._last_rotated = self._last_rotated.replace(tzinfo=timezone.utc)
        return self._fingerprint

    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def last_rotated_at(self) -> Optional[datetime]:
        return self._last_rotated

    def attestation(self) -> Dict[str, Any]:
        return {
            "provider": "azure_key_vault",
            "fingerprint": self._fingerprint,
            "key_version": self._fingerprint,
            "rotation_sla_days": self.rotation_sla_days,
            "vault_url": self.vault_url,
            "last_rotated_at": self._last_rotated.isoformat()
            if isinstance(self._last_rotated, datetime)
            else None,
        }


def _fingerprint_public_key(public_key: rsa.RSAPublicKey) -> str:
    der_bytes = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der_bytes).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def get_key_provider() -> KeyProvider:
    global _KEY_PROVIDER
    if _KEY_PROVIDER is not None:
        return _KEY_PROVIDER
    settings = get_settings()
    provider_name = getattr(settings, "SIGNING_PROVIDER", None) or os.getenv(
        "SIGNING_PROVIDER"
    )
    provider = (provider_name or "env").strip().lower()

    if provider == "aws_kms":
        instance = AWSKMSProvider(
            key_id=getattr(settings, "KEY_ID", None),
            region=getattr(settings, "AWS_REGION", None)
            or os.getenv("AWS_REGION")
            or "us-east-1",
            rotation_sla_days=getattr(settings, "SIGNING_ROTATION_SLA_DAYS", 30),
        )
        _KEY_PROVIDER = instance
        return instance

    if provider == "azure_key_vault":
        instance = AzureKeyVaultProvider(
            key_id=getattr(settings, "KEY_ID", None),
            vault_url=getattr(settings, "AZURE_VAULT_URL", None)
            or os.getenv("AZURE_VAULT_URL"),
            rotation_sla_days=getattr(settings, "SIGNING_ROTATION_SLA_DAYS", 30),
        )
        _KEY_PROVIDER = instance
        return instance

    provider_instance = EnvKeyProvider(
        rotation_sla_days=getattr(settings, "SIGNING_ROTATION_SLA_DAYS", 30),
    )
    _KEY_PROVIDER = provider_instance
    return provider_instance


def reset_key_provider_cache() -> None:
    """Reset cached provider for test determinism."""

    global _KEY_PROVIDER
    _KEY_PROVIDER = None


_KEY_PROVIDER: Optional[KeyProvider] = None


def rsa_sign(json_bytes: bytes) -> Tuple[bytes, str]:
    """Sign ``json_bytes`` with the configured provider and return signature + fingerprint."""

    provider = get_key_provider()
    signature = provider.sign(json_bytes)
    return signature, provider.fingerprint()


def rsa_verify(json_bytes: bytes, signature: bytes, pub_fingerprint: str) -> bool:
    """Verify RSA signature for the provided payload."""

    provider = get_key_provider()
    return provider.verify(json_bytes, signature, pub_fingerprint)


def evaluate_rotation_health(
    provider: Optional[KeyProvider] = None,
    *,
    max_age_days: Optional[int] = None,
) -> Dict[str, Any]:
    """Evaluate signing-key rotation health and emit observability signals."""

    provider = provider or get_key_provider()
    settings = get_settings()
    max_age = max_age_days or getattr(settings, "SIGNING_ROTATION_SLA_DAYS", 30)

    last_rotated = provider.last_rotated_at
    if last_rotated and last_rotated.tzinfo is None:
        last_rotated = last_rotated.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    if last_rotated is None:
        age_days = float(max_age + 1)
        healthy = False
    else:
        delta = now - last_rotated
        age_days = delta.total_seconds() / 86400.0
        healthy = age_days <= max_age

    attestation = provider.attestation() if hasattr(provider, "attestation") else {}
    provider_name = attestation.get("provider") or provider.__class__.__name__
    FixOpsMetrics.record_key_rotation(provider_name, age_days, healthy)

    if not healthy:
        logger.warning(
            "Signing key rotation SLA breached",
            provider=provider_name,
            age_days=age_days,
            max_age_days=max_age,
        )

    attestation.setdefault("provider", provider_name)
    attestation.setdefault(
        "last_rotated_at",
        last_rotated.isoformat() if last_rotated is not None else None,
    )

    return {
        "provider": provider_name,
        "fingerprint": provider.fingerprint(),
        "last_rotated_at": last_rotated.isoformat() if last_rotated else None,
        "age_days": age_days,
        "max_age_days": max_age,
        "healthy": healthy,
        "attestation": attestation,
    }


def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure random token
    Suitable for session tokens, API keys, etc.
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


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
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>/?"

    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]

    # Fill remaining characters randomly
    alphabet = lowercase + uppercase + digits + symbols
    password.extend(secrets.choice(alphabet) for _ in range(length - 4))
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def generate_api_key(length: int = 40) -> str:
    """Generate API key with high entropy."""
    return generate_secure_token(length)


def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data with SHA-256 for storage."""
    return hashlib.sha256(data.encode()).hexdigest()


def verify_sensitive_data(data: str, hashed_value: str) -> bool:
    """Verify sensitive data against stored hash."""
    return hmac.compare_digest(hash_sensitive_data(data), hashed_value)


def generate_encryption_key() -> bytes:
    """Generate symmetric encryption key."""
    return Fernet.generate_key()


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt data with provided key."""
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_data(token: bytes, key: bytes) -> bytes:
    """Decrypt data with provided key."""
    f = Fernet(key)
    return f.decrypt(token)


def generate_checksum(data: bytes) -> str:
    """Generate SHA-256 checksum of data."""
    return hashlib.sha256(data).hexdigest()


def verify_checksum(data: bytes, checksum: str) -> bool:
    """Verify the checksum matches the provided data."""
    return generate_checksum(data) == checksum


def generate_hmac_signature(data: bytes, secret: bytes) -> str:
    """Generate HMAC signature."""
    return hmac.new(secret, data, hashlib.sha256).hexdigest()


def verify_hmac_signature(data: bytes, secret: bytes, signature: str) -> bool:
    """Verify HMAC signature."""
    return hmac.compare_digest(generate_hmac_signature(data, secret), signature)


class SecureTokenManager:
    """Manager for issuing and verifying secure tokens."""

    def __init__(self, secret: Optional[str] = None):
        self.secret = secret or base64.urlsafe_b64encode(os.urandom(32)).decode()

    def issue_token(self, payload: Mapping[str, Any]) -> str:
        data = json.dumps(payload, sort_keys=True).encode()
        signature = generate_hmac_signature(data, self.secret.encode())
        return base64.urlsafe_b64encode(data + b"." + signature.encode()).decode()

    def verify_token(self, token: str) -> Mapping[str, Any]:
        raw = base64.urlsafe_b64decode(token.encode())
        data, signature = raw.rsplit(b".", 1)
        if not verify_hmac_signature(data, self.secret.encode(), signature.decode()):
            raise ValueError("Invalid token signature")
        return json.loads(data.decode())


def secure_compare(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return hmac.compare_digest(a.encode(), b.encode())


def generate_nonce(length: int = 32) -> str:
    """Generate a cryptographically secure nonce."""
    return base64.urlsafe_b64encode(os.urandom(length)).decode()


def generate_salt(length: int = 16) -> bytes:
    """Generate a random salt for password hashing."""
    return os.urandom(length)


def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Derive a symmetric key from a password using PBKDF2."""
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))


def generate_api_signature(payload: Mapping[str, Any], secret: str) -> str:
    """Generate deterministic API signature for payload integrity."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()


def verify_api_signature(
    payload: Mapping[str, Any], secret: str, signature: str
) -> bool:
    """Verify API signature."""
    expected = generate_api_signature(payload, secret)
    return hmac.compare_digest(expected, signature)


def _decode_base64url(value: str) -> int:
    padded = value + "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded.encode()), "big")


def _require_mapping(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{location} must be a mapping")
    return value


def _extract_bundle_properties(bundle: Mapping[str, Any]) -> Dict[str, Any]:
    properties: Dict[str, Any] = {}
    properties["bundle_id"] = bundle.get("bundle_id")
    properties["generated_at"] = _coerce_datetime(bundle.get("generated_at"))
    properties["expires_at"] = _coerce_datetime(bundle.get("expires_at"))
    return properties


def _extract_signature(response: Any) -> Optional[bytes]:
    if response is None:
        return None
    if isinstance(response, Mapping):
        candidate = response.get("signature") or response.get("result")
        if isinstance(candidate, bytes):
            return candidate
    signature = getattr(response, "signature", None)
    if isinstance(signature, bytes):
        return signature
    result = getattr(response, "result", None)
    if isinstance(result, bytes):
        return result
    return None


def _coerce_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _load_public_key_from_bundle(bundle: Mapping[str, Any]) -> rsa.RSAPublicKey:
    public_key_pem = bundle.get("public_key_pem")
    if isinstance(public_key_pem, str):
        return serialization.load_pem_public_key(public_key_pem.encode())
    jwk = bundle.get("jwk")
    if isinstance(jwk, Mapping) and "n" in jwk and "e" in jwk:
        numbers = rsa.RSAPublicNumbers(
            e=_decode_base64url(jwk["e"]), n=_decode_base64url(jwk["n"])
        )
        return numbers.public_key()
    raise ValueError(
        "Bundle must contain either 'public_key_pem' or 'jwk' representation"
    )


def _fingerprint_bundle(bundle: Mapping[str, Any]) -> str:
    properties = _extract_bundle_properties(bundle)
    public_key = _load_public_key_from_bundle(bundle)
    fingerprint = _fingerprint_public_key(public_key)
    properties["fingerprint"] = fingerprint
    return fingerprint


def set_key_provider(provider: KeyProvider) -> None:
    """Inject a provider for tests."""

    global _KEY_PROVIDER
    _KEY_PROVIDER = provider
