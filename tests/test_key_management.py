"""Key management regression tests for remote signing providers."""

import base64
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from core.services.enterprise.metrics import FixOpsMetrics
from core.utils.enterprise.crypto import (
    AWSKMSProvider,
    AzureKeyVaultProvider,
    evaluate_rotation_health,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _encode_b64url(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class StubKMSClient:
    """Lightweight AWS KMS stub for exercising the provider logic."""

    def __init__(self, *, initial_age_days: int = 0) -> None:
        self._keys: dict[str, rsa.RSAPrivateKey] = {}
        self._metadata: dict[str, dict[str, datetime | str]] = {}
        self._aliases: dict[str, str] = {}
        key_id = self._create_key(age_days=initial_age_days)
        self._aliases["alias/decision"] = key_id

    def _create_key(self, *, age_days: int) -> str:
        key_id = f"key-{len(self._keys) + 1}"
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        created = datetime.now(timezone.utc) - timedelta(days=age_days)
        self._keys[key_id] = private_key
        self._metadata[key_id] = {
            "CreationDate": created,
            "Arn": f"arn:aws:kms:::key/{key_id}",
        }
        return key_id

    def _resolve(self, key_id: str) -> str:
        if key_id.startswith("alias/"):
            return self._aliases[key_id]
        return key_id

    def get_public_key(self, KeyId: str):  # noqa: N802 - AWS casing
        resolved = self._resolve(KeyId)
        public_key = self._keys[resolved].public_key()
        public_bytes = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        metadata = dict(self._metadata[resolved])
        metadata["KeyId"] = resolved
        return {"KeyMetadata": metadata, "PublicKey": public_bytes}

    def describe_key(self, KeyId: str):  # noqa: N802
        resolved = self._resolve(KeyId)
        metadata = dict(self._metadata[resolved])
        metadata["KeyId"] = resolved
        return {"KeyMetadata": metadata}

    def sign(
        self, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str
    ):  # noqa: N802
        resolved = self._resolve(KeyId)
        signature = self._keys[resolved].sign(
            Message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return {"Signature": signature, "KeyId": resolved}

    def verify(
        self,
        KeyId: str,
        Message: bytes,
        Signature: bytes,
        MessageType: str,
        SigningAlgorithm: str,
    ):  # noqa: N802
        """Verify signature using the public key for the given KeyId."""
        resolved = self._resolve(KeyId)
        public_key = self._keys[resolved].public_key()
        try:
            public_key.verify(
                Signature,
                Message,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return {"SignatureValid": True, "KeyId": resolved}
        except Exception:
            return {"SignatureValid": False, "KeyId": resolved}

    def rotate_key(self, KeyId: str):  # noqa: N802
        alias = KeyId if KeyId.startswith("alias/") else None
        new_key_id = self._create_key(age_days=0)
        if alias:
            self._aliases[alias] = new_key_id
        self._metadata[new_key_id]["LastRotatedDate"] = datetime.now(timezone.utc)
        return self.get_public_key(alias or new_key_id)

    def age_current_key(self, days: int) -> None:
        key_id = self._aliases.get("alias/decision")
        if key_id:
            self._metadata[key_id]["CreationDate"] = datetime.now(
                timezone.utc
            ) - timedelta(days=days)


class StubAzureKeyClient:
    """Minimal Azure Key Vault stub with rotate/get support."""

    def __init__(self, *, initial_age_days: int = 0) -> None:
        self.vault_url = "https://vault.example"
        self.key_name = "decision"
        self._versions: dict[str, rsa.RSAPrivateKey] = {}
        self._rotated: dict[str, datetime] = {}
        self.current_version = self._create_version(age_days=initial_age_days)

    def _create_version(self, *, age_days: int) -> str:
        version = f"v{len(self._versions) + 1}"
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rotated = datetime.now(timezone.utc) - timedelta(days=age_days)
        self._versions[version] = private
        self._rotated[version] = rotated
        return version

    def get_key(self, key_name: str, *, version: str | None = None):
        if key_name != self.key_name:
            raise ValueError("unknown key requested")
        # Use specified version or current version
        target_version = version if version else self.current_version
        if target_version not in self._versions:
            raise ValueError(f"unknown version: {target_version}")
        private = self._versions[target_version]
        numbers = private.public_key().public_numbers()
        jwk = {
            "kty": "RSA",
            "n": _encode_b64url(numbers.n),
            "e": _encode_b64url(numbers.e),
        }
        identifier = f"{self.vault_url}/keys/{self.key_name}/{target_version}"
        properties = SimpleNamespace(
            version=target_version,
            updated_on=self._rotated[target_version],
            vault_url=self.vault_url,
            id=identifier,
        )
        return SimpleNamespace(key=jwk, properties=properties, id=identifier)

    def rotate_key(self, key_name: str):
        if key_name != self.key_name:
            raise ValueError("unknown key requested")
        self.current_version = self._create_version(age_days=0)
        return self.get_key(key_name)

    def begin_rotate_key(self, key_name: str):
        client = self

        class _Poller:
            def result(self_nonlocal):  # pragma: no cover - simple delegation
                return client.rotate_key(key_name)

        return _Poller()

    def private_key(self) -> rsa.RSAPrivateKey:
        return self._versions[self.current_version]


class StubAzureCryptoClient:
    """Crypto client that signs using the stub key client."""

    default_algorithm = "RS256"

    def __init__(self, key_client: StubAzureKeyClient) -> None:
        self._key_client = key_client

    def sign(
        self, algorithm: str, payload: bytes
    ):  # pragma: no cover - exercised via provider
        """Sign payload with the given algorithm (algorithm is ignored in stub)."""
        signature = self._key_client.private_key().sign(
            payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return SimpleNamespace(signature=signature)


def test_aws_kms_provider_signs_and_rotates() -> None:
    kms = StubKMSClient(initial_age_days=5)
    provider = AWSKMSProvider(
        key_id="alias/decision",
        region="us-east-1",
        rotation_sla_days=30,
        kms_client=kms,
    )

    payload = b"kms-payload"
    signature = provider.sign(payload)
    fingerprint = provider.fingerprint()

    assert provider.verify(payload, signature, fingerprint)

    kms.age_current_key(40)
    new_fp = provider.rotate()

    assert new_fp != fingerprint
    assert provider.verify(payload, signature, fingerprint)
    rotated_signature = provider.sign(payload)
    assert provider.verify(payload, rotated_signature, new_fp)
    assert provider.last_rotated_at is not None
    assert provider.attestation()["provider"] == "aws_kms"


def test_azure_key_vault_provider_signs_and_rotates() -> None:
    key_client = StubAzureKeyClient(initial_age_days=3)
    crypto_client = StubAzureCryptoClient(key_client)
    provider = AzureKeyVaultProvider(
        key_id="decision",
        vault_url=key_client.vault_url,
        rotation_sla_days=45,
        key_client=key_client,
        crypto_client=crypto_client,
    )

    payload = b"azure-payload"
    signature = provider.sign(payload)
    fingerprint = provider.fingerprint()

    assert provider.verify(payload, signature, fingerprint)

    provider.rotate()
    new_fp = provider.fingerprint()
    assert new_fp != fingerprint
    assert provider.verify(payload, signature, fingerprint)
    new_signature = provider.sign(payload)
    assert provider.verify(payload, new_signature, new_fp)
    attestation = provider.attestation()
    assert attestation["provider"] == "azure_key_vault"
    assert attestation["key_version"] is not None


def test_rotation_health_flags_breach() -> None:
    kms = StubKMSClient(initial_age_days=50)
    provider = AWSKMSProvider(
        key_id="alias/decision",
        region="us-east-1",
        rotation_sla_days=30,
        kms_client=kms,
    )

    FixOpsMetrics.reset_runtime_stats()
    status = evaluate_rotation_health(provider=provider, max_age_days=30)

    assert status["healthy"] is False
    assert FixOpsMetrics.get_key_rotation_health(status["provider"]) is False
    assert FixOpsMetrics.get_key_rotation_age(status["provider"]) >= 30

    # Freshly rotated key should report healthy status.
    kms_fresh = StubKMSClient(initial_age_days=1)
    provider_fresh = AWSKMSProvider(
        key_id="alias/decision",
        region="us-east-1",
        rotation_sla_days=30,
        kms_client=kms_fresh,
    )
    FixOpsMetrics.reset_runtime_stats()
    healthy = evaluate_rotation_health(provider=provider_fresh, max_age_days=30)
    assert healthy["healthy"] is True
