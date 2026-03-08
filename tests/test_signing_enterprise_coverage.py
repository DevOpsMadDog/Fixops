"""Tests for enterprise signing — HMAC-SHA256 manifest signing and verification."""

from core.services.enterprise.signing import (
    sign_manifest,
    verify_manifest,
    is_available,
    _get_key,
    _DEFAULT_DEV_KEY,
    _SIGNING_KEY_ENV,
)


class TestGetKey:
    def test_default_dev_key(self, monkeypatch):
        monkeypatch.delenv(_SIGNING_KEY_ENV, raising=False)
        key = _get_key()
        assert key == _DEFAULT_DEV_KEY

    def test_env_key(self, monkeypatch):
        monkeypatch.setenv(_SIGNING_KEY_ENV, "my-prod-key")
        key = _get_key()
        assert key == b"my-prod-key"


class TestSignManifest:
    def test_basic_signing(self):
        doc = {"hello": "world", "count": 42}
        envelope = sign_manifest(doc)
        assert "algorithm" in envelope
        assert envelope["algorithm"] == "HMAC-SHA256"
        assert "digest" in envelope
        assert "signature" in envelope
        assert "signed_at" in envelope
        assert "key_id" in envelope

    def test_dev_key_id(self, monkeypatch):
        monkeypatch.delenv(_SIGNING_KEY_ENV, raising=False)
        envelope = sign_manifest({"test": True})
        assert envelope["key_id"] == "dev-key"

    def test_env_key_id(self, monkeypatch):
        monkeypatch.setenv(_SIGNING_KEY_ENV, "prod-key")
        envelope = sign_manifest({"test": True})
        assert envelope["key_id"] == "env-key"

    def test_deterministic_digest(self):
        doc = {"a": 1, "b": 2}
        e1 = sign_manifest(doc)
        e2 = sign_manifest(doc)
        assert e1["digest"] == e2["digest"]
        assert e1["signature"] == e2["signature"]

    def test_different_docs_different_sigs(self):
        e1 = sign_manifest({"x": 1})
        e2 = sign_manifest({"x": 2})
        assert e1["signature"] != e2["signature"]

    def test_empty_doc(self):
        envelope = sign_manifest({})
        assert len(envelope["signature"]) == 64  # SHA256 hex

    def test_nested_doc(self):
        doc = {"level1": {"level2": {"level3": "deep"}}}
        envelope = sign_manifest(doc)
        assert verify_manifest(doc, envelope)


class TestVerifyManifest:
    def test_valid_signature(self):
        doc = {"important": "data"}
        envelope = sign_manifest(doc)
        assert verify_manifest(doc, envelope) is True

    def test_tampered_document(self):
        doc = {"important": "data"}
        envelope = sign_manifest(doc)
        tampered = {"important": "TAMPERED"}
        assert verify_manifest(tampered, envelope) is False

    def test_empty_envelope(self):
        doc = {"test": True}
        assert verify_manifest(doc, {}) is False

    def test_wrong_signature(self):
        doc = {"test": True}
        envelope = sign_manifest(doc)
        envelope["signature"] = "0" * 64
        assert verify_manifest(doc, envelope) is False


class TestIsAvailable:
    def test_always_true(self):
        assert is_available() is True
