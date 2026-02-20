from __future__ import annotations

import asyncio
import base64
import json
import sys
import types
from types import SimpleNamespace
from typing import Any, Dict, Generator

import pytest
from fastapi import HTTPException

pydantic_settings = types.ModuleType("pydantic_settings")


class _BaseSettings:
    def __init__(self, **overrides: Any) -> None:
        for key, value in self.__class__.__dict__.items():
            if key.startswith("_") or callable(value) or isinstance(value, property):
                continue
            setattr(self, key, overrides.get(key, value))

    def model_dump(self) -> Dict[str, Any]:
        return {name: getattr(self, name) for name in dir(self) if name.isupper()}


pydantic_settings.BaseSettings = _BaseSettings
pydantic_settings.SettingsConfigDict = dict
sys.modules.setdefault("pydantic_settings", pydantic_settings)

from api.v1.cicd import verify_signature
from core.utils.enterprise import crypto
from core.utils.enterprise.crypto import EnvKeyProvider
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture()
def signing_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[EnvKeyProvider, None, None]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_key = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    provider = EnvKeyProvider(private_key_pem=private_key, public_key_pem=public_key)
    crypto._KEY_PROVIDER = provider  # type: ignore[attr-defined]
    try:
        yield provider
    finally:
        crypto._KEY_PROVIDER = None  # type: ignore[attr-defined]


def test_verify_signature_success(signing_provider: EnvKeyProvider) -> None:
    payload = {"id": "EVD-123", "status": "ok"}
    signature = signing_provider.sign(json.dumps(payload, sort_keys=True).encode())
    fingerprint = signing_provider.fingerprint()
    request = SimpleNamespace(
        evidence_id="EVD-123",
        payload=payload,
        signature=base64.b64encode(signature).decode(),
        fingerprint=fingerprint,
    )

    response = asyncio.run(verify_signature(request))
    assert response["verified"] is True
    assert response["evidence_id"] == "EVD-123"


def test_verify_signature_failure(signing_provider: EnvKeyProvider) -> None:
    payload = {"id": "EVD-123", "status": "tampered"}
    signature = signing_provider.sign(json.dumps(payload, sort_keys=True).encode())
    fingerprint = signing_provider.fingerprint()
    bad_request = SimpleNamespace(
        evidence_id="EVD-123",
        payload=payload | {"status": "compromised"},
        signature=base64.b64encode(signature).decode(),
        fingerprint=fingerprint,
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(verify_signature(bad_request))

    assert exc.value.status_code == 400
    assert "signature" in str(exc.value.detail).lower()
