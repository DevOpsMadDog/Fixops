"""Enterprise cryptographic utilities and secure token generation."""

from __future__ import annotations

import base64
import hashlib
import hmac
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
    from config.enterprise.settings import get_settings
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


from core.services.enterprise.metrics import FixOpsMetrics

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
            logger.error("RSA signature verification failed", error=str(exc))
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

        self._kms = self.kms_client
        self._public_keys: Dict[str, rsa.RSAPublicKey] = {}
        self._fingerprint = ""
        self._last_rotated: Optional[datetime] = None
        self._arn: Optional[str] = None
        self._refresh_key_material()

    def sign(self, payload: bytes) -> bytes:
        response = self._kms.sign(  # type: ignore[call-arg]
            KeyId=self.key_id,
            Message=payload,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        signature = response.get("Signature")
        if not signature:
            raise RuntimeError("AWS KMS did not return a signature")
        return signature

    def verify(self, payload: bytes, signature: bytes, fingerprint: str) -> bool:
        public_key = self._public_keys.get(fingerprint)
        if public_key is None:
            self._refresh_key_material()
            public_key = self._public_keys.get(fingerprint)
        if public_key is None:
            logger.warning(
                "Fingerprint not recognised for AWS KMS verification",
                fingerprint=fingerprint,
                available=list(self._public_keys.keys()),
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
            logger.error("AWS KMS signature verification failed", error=str(exc))
            return False

    def rotate(self) -> str:
        if hasattr(self._kms, "rotate_key"):
            response = self._kms.rotate_key(KeyId=self.key_id)
            bundle = response
        elif hasattr(self._kms, "create_key") and hasattr(self._kms, "update_alias"):
            bundle = self._kms.create_key(KeyUsage="SIGN_VERIFY")
            new_key_id = bundle.get("KeyMetadata", {}).get("KeyId")
            if new_key_id:
                if str(self.key_id).startswith("alias/"):
                    self._kms.update_alias(
                        AliasName=str(self.key_id), TargetKeyId=new_key_id
                    )
                else:
                    self.key_id = new_key_id
        else:  # pragma: no cover - integration fallback
            raise RuntimeError(
                "Configured AWS KMS client does not expose rotation helpers"
            )

        self._refresh_key_material(bundle)
        logger.info("AWS KMS key rotated", key_id=self.key_id, arn=self._arn)
        return self._fingerprint

    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def last_rotated_at(self) -> Optional[datetime]:
        return self._last_rotated

    def attestation(self) -> Dict[str, Any]:
        return {
            "provider": "aws_kms",
            "key_id": self.key_id,
            "arn": self._arn,
            "region": self.region,
            "fingerprint": self._fingerprint,
            "rotation_sla_days": self.rotation_sla_days,
            "last_rotated_at": self._last_rotated.isoformat()
            if self._last_rotated
            else None,
        }

    def _refresh_key_material(self, bundle: Optional[Any] = None) -> None:
        if bundle is None:
            bundle = self._kms.get_public_key(KeyId=self.key_id)
        public_bytes = bundle.get("PublicKey") if isinstance(bundle, Mapping) else None
        if public_bytes is None:
            raise RuntimeError("AWS KMS did not return public key material")
        public_key = serialization.load_der_public_key(public_bytes)
        fingerprint = _fingerprint_public_key(public_key)
        self._register_public_key(fingerprint, public_key)
        self._fingerprint = fingerprint

        metadata: Mapping[str, Any] = {}
        if isinstance(bundle, Mapping):
            metadata = bundle.get("KeyMetadata", {})
        if not metadata:
            describe = self._kms.describe_key(KeyId=self.key_id)
            metadata = describe.get("KeyMetadata", {})

        self._arn = metadata.get("Arn") or metadata.get("KeyArn")
        self._last_rotated = _coerce_datetime(
            metadata.get("LastRotatedDate")
            or metadata.get("NextKeyRotationDate")
            or metadata.get("CreationDate")
        )

    def _register_public_key(
        self, fingerprint: str, public_key: rsa.RSAPublicKey
    ) -> None:
        self._public_keys[fingerprint] = public_key


@dataclass
class AzureKeyVaultProvider:
    """Azure Key Vault-backed key provider."""

    key_id: Optional[str]
    vault_url: Optional[str]
    rotation_sla_days: int = 30
    key_client: Optional[Any] = None
    crypto_client: Optional[Any] = None

    def __post_init__(self) -> None:
        if not self.key_id:
            raise ValueError("Azure Key Vault provider requires KEY_ID")
        if not self.vault_url:
            raise ValueError("Azure Key Vault provider requires AZURE_VAULT_URL")

        self.key_id = str(self.key_id)
        self.vault_url = str(self.vault_url)

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
                    "azure-identity and azure-keyvault-keys are required for the Azure signing provider"
                ) from exc

            credential = DefaultAzureCredential()
            key_client = self.key_client or KeyClient(
                vault_url=self.vault_url, credential=credential
            )
            key_bundle = key_client.get_key(self.key_id)
            crypto_client = self.crypto_client or CryptographyClient(
                key_bundle.id, credential=credential
            )
            self.key_client = key_client
            self.crypto_client = crypto_client
            self._signature_algorithm = SignatureAlgorithm.rs256
        else:
            self._signature_algorithm = getattr(
                self.crypto_client, "default_algorithm", "RS256"
            )

        self._key_client = self.key_client
        self._crypto_client = self.crypto_client
        self._public_keys: Dict[str, rsa.RSAPublicKey] = {}
        self._fingerprint = ""
        self._last_rotated: Optional[datetime] = None
        self._current_version: Optional[str] = None
        self._refresh_key_material()

    def sign(self, payload: bytes) -> bytes:
        response = self._crypto_client.sign(payload)  # type: ignore[call-arg]
        signature = _extract_signature(response)
        if signature is None:
            raise RuntimeError("Azure Key Vault did not return a signature")
        return signature

    def verify(self, payload: bytes, signature: bytes, fingerprint: str) -> bool:
        public_key = self._public_keys.get(fingerprint)
        if public_key is None:
            self._refresh_key_material()
            public_key = self._public_keys.get(fingerprint)
        if public_key is None:
            logger.warning(
                "Fingerprint not recognised for Azure Key Vault verification",
                fingerprint=fingerprint,
                available=list(self._public_keys.keys()),
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
            logger.error(
                "Azure Key Vault signature verification failed", error=str(exc)
            )
            return False

    def rotate(self) -> str:
        if hasattr(self._key_client, "begin_rotate_key"):
            poller = self._key_client.begin_rotate_key(self.key_id)
            bundle = poller.result() if hasattr(poller, "result") else poller
        elif hasattr(self._key_client, "rotate_key"):
            bundle = self._key_client.rotate_key(self.key_id)
        else:  # pragma: no cover - integration fallback
            raise RuntimeError(
                "Configured Azure Key Vault client does not expose rotation helpers"
            )

        self._refresh_key_material(bundle)
        logger.info(
            "Azure Key Vault key rotated",
            key_id=self.key_id,
            vault_url=self.vault_url,
            version=self._current_version,
        )
        return self._fingerprint

    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def last_rotated_at(self) -> Optional[datetime]:
        return self._last_rotated

    def attestation(self) -> Dict[str, Any]:
        return {
            "provider": "azure_key_vault",
            "vault_url": self.vault_url,
            "key_id": self.key_id,
            "key_version": self._current_version,
            "fingerprint": self._fingerprint,
            "rotation_sla_days": self.rotation_sla_days,
            "last_rotated_at": self._last_rotated.isoformat()
            if self._last_rotated
            else None,
        }

    def _refresh_key_material(self, bundle: Optional[Any] = None) -> None:
        if bundle is None:
            bundle = self._key_client.get_key(self.key_id)
        public_key = _load_public_key_from_bundle(bundle)
        fingerprint = _fingerprint_public_key(public_key)
        self._register_public_key(fingerprint, public_key)
        self._fingerprint = fingerprint

        properties = _extract_bundle_properties(bundle)
        self._current_version = properties.get("version")
        rotation_hint = (
            properties.get("updated_on")
            or properties.get("created_on")
            or properties.get("not_before")
        )
        self._last_rotated = _coerce_datetime(rotation_hint)

    def _register_public_key(
        self, fingerprint: str, public_key: rsa.RSAPublicKey
    ) -> None:
        self._public_keys[fingerprint] = public_key


_KEY_PROVIDER: Optional[KeyProvider] = None


def get_key_provider() -> KeyProvider:
    """Return the configured signing key provider (cached)."""

    global _KEY_PROVIDER
    if _KEY_PROVIDER is not None:
        return _KEY_PROVIDER

    settings = get_settings()
    raw_provider = getattr(settings, "SIGNING_PROVIDER", "env")
    if not isinstance(raw_provider, str):
        raw_provider = str(raw_provider or "env")
    provider_name = raw_provider.lower()
    rotation_value = getattr(settings, "SIGNING_ROTATION_SLA_DAYS", 30)
    try:
        rotation_sla = int(rotation_value)
    except (TypeError, ValueError):
        rotation_sla = 30

    if provider_name == "aws_kms":
        _KEY_PROVIDER = AWSKMSProvider(
            settings.KEY_ID,
            region=getattr(settings, "AWS_REGION", None),
            rotation_sla_days=rotation_sla,
        )
    elif provider_name == "azure_key_vault":
        _KEY_PROVIDER = AzureKeyVaultProvider(
            settings.KEY_ID,
            vault_url=getattr(settings, "AZURE_VAULT_URL", None),
            rotation_sla_days=rotation_sla,
        )
    else:
        _KEY_PROVIDER = EnvKeyProvider(rotation_sla_days=rotation_sla)

    logger.info(f"Signing provider initialised provider={provider_name}")
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


def _decode_base64url(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _coerce_bigint_bytes(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, int):
        length = (value.bit_length() + 7) // 8 or 1
        return value.to_bytes(length, "big")
    if isinstance(value, str):
        try:
            return _decode_base64url(value)
        except Exception:
            return None
    return None


def _load_public_key_from_bundle(bundle: Any) -> rsa.RSAPublicKey:
    if isinstance(bundle, Mapping):
        pem = bundle.get("public_key_pem") or bundle.get("PublicKeyPem")
        if pem:
            material = pem if isinstance(pem, bytes) else str(pem).encode()
            return serialization.load_pem_public_key(material)
    pem_attr = getattr(bundle, "public_key_pem", None)
    if pem_attr:
        material = pem_attr if isinstance(pem_attr, bytes) else str(pem_attr).encode()
        return serialization.load_pem_public_key(material)

    jwk = None
    if isinstance(bundle, Mapping):
        jwk = bundle.get("key") or bundle
    else:
        jwk = getattr(bundle, "key", None)

    if isinstance(jwk, Mapping):
        modulus = _coerce_bigint_bytes(jwk.get("n") or jwk.get("modulus"))
        exponent = _coerce_bigint_bytes(jwk.get("e") or jwk.get("exponent"))
    else:
        modulus = _coerce_bigint_bytes(getattr(jwk, "n", None))
        exponent = _coerce_bigint_bytes(getattr(jwk, "e", None))

    if modulus and exponent:
        n_value = int.from_bytes(modulus, "big")
        e_value = int.from_bytes(exponent, "big")
        return rsa.RSAPublicNumbers(e_value, n_value).public_key()

    raise RuntimeError("Remote key bundle did not include RSA public material")


def _extract_bundle_properties(bundle: Any) -> Dict[str, Any]:
    properties: Dict[str, Any] = {}
    candidate = None
    if isinstance(bundle, Mapping):
        candidate = bundle.get("properties") or bundle
        if isinstance(candidate, Mapping):
            properties.update(candidate)
    else:
        candidate = getattr(bundle, "properties", None)
        if candidate is not None:
            if isinstance(candidate, Mapping):
                properties.update(candidate)
            else:
                for attr in (
                    "version",
                    "updated_on",
                    "created_on",
                    "not_before",
                    "vault_url",
                ):
                    if hasattr(candidate, attr):
                        properties[attr] = getattr(candidate, attr)

    identifier = properties.get("id") or getattr(bundle, "id", None)
    if isinstance(identifier, str):
        properties.setdefault("id", identifier)
        parts = identifier.rstrip("/").split("/")
        if "keys" in parts:
            try:
                key_index = parts.index("keys")
            except ValueError:
                key_index = -1
            if key_index > 1 and key_index + 2 < len(parts):
                vault = "/".join(parts[:key_index])
                properties.setdefault("vault_url", vault)
                properties.setdefault("version", parts[-1])

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
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    # Start with one character from each category
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special),
    ]

    # Fill the rest with random characters from all categories
    all_chars = lowercase + uppercase + digits + special
    for _ in range(length - 4):
        password.append(secrets.choice(all_chars))

    # Shuffle the password
    secrets.SystemRandom().shuffle(password)

    return "".join(password)


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

    return {"hash": hash_hex, "salt": salt}


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
    signature = hmac.new(secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()
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

    def generate_signed_token(
        self, payload: Dict[str, Any], expiry_minutes: int = 60
    ) -> str:
        """
        Generate signed token with payload and expiry
        """
        import json
        import time

        # Add timestamp and expiry
        payload_with_meta = {
            **payload,
            "iat": int(time.time()),
            "exp": int(time.time() + (expiry_minutes * 60)),
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
