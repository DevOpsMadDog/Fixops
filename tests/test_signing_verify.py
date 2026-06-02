from __future__ import annotations

import pytest
from config.enterprise.settings import get_settings
from core.services.enterprise import signing


def test_sign_verify_roundtrip(signing_env: None) -> None:
    payload = {"verdict": "allow", "confidence": 0.9}
    signature = signing.sign_manifest(payload)
    assert signing.verify_manifest(payload, signature)


def test_verify_failure_on_tamper(signing_env: None) -> None:
    payload = {"verdict": "allow", "confidence": 0.9}
    signature = signing.sign_manifest(payload)
    payload["confidence"] = 0.1
    assert not signing.verify_manifest(payload, signature)


def test_signing_falls_back_to_labeled_dev_key_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no FIXOPS_SIGNING_KEY the module falls back to the dev key
    (documented air-gapped/dev behaviour) instead of failing — and the envelope
    is marked key_id='dev-key' so the weaker key is auditable in evidence."""
    monkeypatch.delenv("FIXOPS_SIGNING_KEY", raising=False)
    get_settings.cache_clear()
    env = signing.sign_manifest({"sample": True})
    assert env["key_id"] == "dev-key"
    assert env["algorithm"] == "HMAC-SHA256"
    # The fallback signature is still internally consistent (verifies).
    assert signing.verify_manifest({"sample": True}, env)
