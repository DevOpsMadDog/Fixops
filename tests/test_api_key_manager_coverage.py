"""Comprehensive tests for core.api_key_manager — Enterprise API Key Management.

Tests key generation, JWT tokens, hashing, validation, rotation, and revocation.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

import pytest
from core.api_key_manager import APIKeyManager, _make_metadata, _utcnow


class TestAPIKeyGeneration:
    """Test API key generation."""

    @pytest.fixture
    def mgr(self):
        return APIKeyManager(jwt_secret="a" * 64, prefix="fixops")

    def test_generate_api_key_basic(self, mgr):
        key = mgr.generate_api_key()
        assert key.startswith("fixops_sk_")
        assert len(key) > 20

    def test_generate_api_key_custom_prefix(self, mgr):
        key = mgr.generate_api_key(prefix="myapp")
        assert key.startswith("myapp_sk_")

    def test_generate_api_key_with_description(self, mgr):
        key = mgr.generate_api_key(description="Test key for CI/CD")
        key_hash = mgr.hash_api_key(key)
        meta = mgr.get_metadata(key_hash)
        assert meta is not None
        assert meta["description"] == "Test key for CI/CD"

    def test_generate_api_key_with_scopes(self, mgr):
        key = mgr.generate_api_key(scopes=["read:vulns", "write:playbooks"])
        key_hash = mgr.hash_api_key(key)
        meta = mgr.get_metadata(key_hash)
        assert "read:vulns" in meta["scopes"]
        assert "write:playbooks" in meta["scopes"]

    def test_generate_api_key_with_expiry(self, mgr):
        key = mgr.generate_api_key(expires_hours=48)
        key_hash = mgr.hash_api_key(key)
        meta = mgr.get_metadata(key_hash)
        assert meta["expires_at"] is not None

    def test_generate_api_key_no_expiry(self, mgr):
        key = mgr.generate_api_key()
        key_hash = mgr.hash_api_key(key)
        meta = mgr.get_metadata(key_hash)
        assert meta["expires_at"] is None

    def test_generate_api_key_with_org(self, mgr):
        key = mgr.generate_api_key(org_id="org-123")
        key_hash = mgr.hash_api_key(key)
        meta = mgr.get_metadata(key_hash)
        assert meta["org_id"] == "org-123"

    def test_invalid_prefix_raises(self):
        with pytest.raises(ValueError):
            APIKeyManager(prefix="123invalid")

    def test_invalid_prefix_on_generate(self, mgr):
        with pytest.raises(ValueError):
            mgr.generate_api_key(prefix="BAD-PREFIX")

    def test_keys_are_unique(self, mgr):
        keys = [mgr.generate_api_key() for _ in range(10)]
        assert len(set(keys)) == 10


class TestKeyHashing:
    """Test key hashing."""

    @pytest.fixture
    def mgr(self):
        return APIKeyManager(jwt_secret="b" * 64)

    def test_hash_api_key_returns_sha256(self, mgr):
        key = mgr.generate_api_key()
        h = mgr.hash_api_key(key)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_deterministic(self, mgr):
        key = mgr.generate_api_key()
        h1 = mgr.hash_api_key(key)
        h2 = mgr.hash_api_key(key)
        assert h1 == h2

    def test_hash_different_for_different_keys(self, mgr):
        k1 = mgr.generate_api_key()
        k2 = mgr.generate_api_key()
        assert mgr.hash_api_key(k1) != mgr.hash_api_key(k2)


class TestKeyValidation:
    """Test key format validation."""

    @pytest.fixture
    def mgr(self):
        return APIKeyManager(jwt_secret="c" * 64)

    def test_valid_key_format(self, mgr):
        key = mgr.generate_api_key()
        assert mgr.validate_key_format(key) is True

    def test_invalid_key_too_short(self, mgr):
        assert mgr.validate_key_format("fixops_sk_tooshort") is False

    def test_invalid_key_bad_prefix(self, mgr):
        assert mgr.validate_key_format("BADPREFIX_sk_abcdefgh") is False

    def test_invalid_key_empty(self, mgr):
        assert mgr.validate_key_format("") is False

    def test_invalid_key_random_string(self, mgr):
        assert mgr.validate_key_format("not-a-valid-key-at-all") is False


class TestKeyRotation:
    """Test key rotation."""

    @pytest.fixture
    def mgr(self):
        return APIKeyManager(jwt_secret="d" * 64)

    def test_rotate_key(self, mgr):
        old_key = mgr.generate_api_key()
        old_returned, new_key = mgr.rotate_key(old_key)
        assert old_returned == old_key
        assert new_key != old_key
        assert new_key.startswith("fixops_sk_")
        assert mgr.validate_key_format(new_key) is True

    def test_rotate_preserves_prefix(self, mgr):
        old_key = mgr.generate_api_key(prefix="myprefix")
        _, new_key = mgr.rotate_key(old_key)
        assert new_key.startswith("myprefix_sk_")

    def test_rotate_invalid_key_raises(self, mgr):
        with pytest.raises(ValueError):
            mgr.rotate_key("invalid-key")

    def test_rotate_with_metadata(self, mgr):
        old_key = mgr.generate_api_key()
        _, new_key = mgr.rotate_key(
            old_key,
            description="Rotated key",
            org_id="org-456",
            scopes=["admin"],
            expires_hours=72,
        )
        key_hash = mgr.hash_api_key(new_key)
        meta = mgr.get_metadata(key_hash)
        assert meta["org_id"] == "org-456"
        assert "admin" in meta["scopes"]


class TestKeyRevocation:
    """Test key revocation."""

    @pytest.fixture
    def mgr(self):
        return APIKeyManager(jwt_secret="e" * 64)

    def test_revoke_existing_key(self, mgr):
        key = mgr.generate_api_key()
        key_hash = mgr.hash_api_key(key)
        assert mgr.revoke_key(key_hash) is True
        meta = mgr.get_metadata(key_hash)
        assert meta["active"] is False
        assert "revoked_at" in meta

    def test_revoke_nonexistent_key(self, mgr):
        assert mgr.revoke_key("nonexistent_hash") is False

    def test_get_metadata_nonexistent(self, mgr):
        result = mgr.get_metadata("fake_hash")
        assert result is None


class TestJWTTokens:
    """Test JWT token generation."""

    @pytest.fixture
    def mgr(self):
        return APIKeyManager(jwt_secret="f" * 64)

    def test_generate_jwt_basic(self, mgr):
        token = mgr.generate_jwt_token(
            "user@example.com", "admin", ["read", "write"]
        )
        assert isinstance(token, str)
        assert len(token) > 50
        # JWT has 3 parts separated by dots
        parts = token.split(".")
        assert len(parts) == 3

    def test_generate_jwt_with_org(self, mgr):
        token = mgr.generate_jwt_token(
            "svc-account", "service", ["full"], org_id="org-789"
        )
        assert isinstance(token, str)

    def test_generate_jwt_with_extra_claims(self, mgr):
        token = mgr.generate_jwt_token(
            "user@test.com",
            "analyst",
            ["read:vulns"],
            extra_claims={"team": "security", "env": "prod"},
        )
        assert isinstance(token, str)

    def test_generate_jwt_custom_expiry(self, mgr):
        token = mgr.generate_jwt_token(
            "user@test.com", "admin", ["all"], expires_hours=1
        )
        assert isinstance(token, str)

    def test_generate_jwt_no_secret_raises(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_JWT_SECRET", raising=False)
        mgr = APIKeyManager(jwt_secret="")
        with pytest.raises(RuntimeError, match="JWT secret"):
            mgr.generate_jwt_token("user", "admin", ["read"])


class TestMakeMetadata:
    """Test metadata helper function."""

    def test_make_metadata_basic(self):
        meta = _make_metadata("hash123")
        assert meta["key_hash"] == "hash123"
        assert meta["active"] is True
        assert meta["scopes"] == []
        assert meta["expires_at"] is None

    def test_make_metadata_with_scopes(self):
        meta = _make_metadata("hash456", scopes=["read", "write"])
        assert meta["scopes"] == ["read", "write"]

    def test_make_metadata_with_expiry(self):
        meta = _make_metadata("hash789", expires_hours=24)
        assert meta["expires_at"] is not None


class TestUtcNow:
    """Test UTC timestamp helper."""

    def test_utcnow_returns_datetime(self):
        result = _utcnow()
        from datetime import datetime
        assert isinstance(result, datetime)
