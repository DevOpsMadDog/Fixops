from __future__ import annotations

import pytest

from src.services import signing
from src.config.settings import get_settings


def test_sign_verify_roundtrip(signing_env: None) -> None:
    payload = {"verdict": "allow", "confidence": 0.9}
    signature = signing.sign_manifest(payload)
    assert signing.verify_manifest(payload, signature)


def test_verify_failure_on_tamper(signing_env: None) -> None:
    payload = {"verdict": "allow", "confidence": 0.9}
    signature = signing.sign_manifest(payload)
    payload["confidence"] = 0.1
    assert not signing.verify_manifest(payload, signature)


def test_signing_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FIXOPS_SIGNING_KEY", raising=False)
    get_settings.cache_clear()
    signing._load_private_key.cache_clear()
    with pytest.raises(signing.SigningError):
        signing.sign_manifest({"sample": True})

