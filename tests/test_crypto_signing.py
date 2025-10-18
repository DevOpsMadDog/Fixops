"""Tests covering RSA signing helpers for the evidence lake."""

import json
from typing import Tuple

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from src.utils.crypto import (
    get_key_provider,
    reset_key_provider_cache,
    rsa_sign,
    rsa_verify,
)


def _generate_rsa_keypair() -> Tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture()
def signing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    private_pem, public_pem = _generate_rsa_keypair()
    monkeypatch.setenv("SIGNING_PRIVATE_KEY", private_pem)
    monkeypatch.setenv("SIGNING_PUBLIC_KEY", public_pem)
    monkeypatch.setenv("SIGNING_PROVIDER", "env")
    reset_key_provider_cache()
    yield
    reset_key_provider_cache()


def test_rsa_sign_round_trip(signing_env: None) -> None:
    payload = json.dumps({"hello": "world"}, sort_keys=True).encode()
    signature, fingerprint = rsa_sign(payload)

    assert rsa_verify(payload, signature, fingerprint)


def test_rsa_verify_rejects_tampered_payload(signing_env: None) -> None:
    payload = json.dumps({"id": 1, "status": "ok"}, sort_keys=True).encode()
    signature, fingerprint = rsa_sign(payload)

    tampered = json.dumps({"id": 1, "status": "tampered"}, sort_keys=True).encode()
    assert not rsa_verify(tampered, signature, fingerprint)


def test_rsa_verify_handles_rotated_fingerprints(signing_env: None) -> None:
    provider = get_key_provider()
    payload = b"rotation-test"

    original_signature, original_fp = rsa_sign(payload)
    new_fp = provider.rotate()
    rotated_signature, rotated_fp = rsa_sign(payload)

    assert new_fp == rotated_fp
    assert rotated_fp != original_fp
    assert rsa_verify(payload, original_signature, original_fp)
    assert rsa_verify(payload, rotated_signature, rotated_fp)
