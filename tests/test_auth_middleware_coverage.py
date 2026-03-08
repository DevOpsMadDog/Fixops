"""Comprehensive tests for core.auth_middleware — JWT, API keys, auth flow."""
import uuid
import warnings
from datetime import datetime, timedelta, timezone

import jwt
import pytest

# Ensure JWT secret is >= 32 bytes for PyJWT 3.x
import core.auth_middleware as _auth_mod

_SAFE_SECRET = "fixops-test-secret-key-that-is-long-enough-for-hs256"
_auth_mod._JWT_SECRET = _SAFE_SECRET

from core.auth_middleware import (
    _JWT_ALGORITHM,
    create_jwt,
    decode_jwt,
    generate_api_key,
    verify_api_key_hash,
)
from core.auth_models import ROLE_SCOPES, User, UserRole

_JWT_SECRET = _SAFE_SECRET


def _make_user(**overrides) -> User:
    defaults = dict(
        id=str(uuid.uuid4()),
        email="test@example.com",
        name="Test User",
        role=UserRole.ANALYST,
        org_id="org-1",
    )
    defaults.update(overrides)
    return User(**defaults)


# ─── JWT ────────────────────────────────────────────────────────────────


class TestJWT:
    def test_create_jwt_returns_string(self):
        user = _make_user()
        token = create_jwt(user)
        assert isinstance(token, str)
        assert len(token) > 20

    def test_create_and_decode_jwt(self):
        user = _make_user(email="alice@example.com", role=UserRole.ADMIN)
        token = create_jwt(user)
        payload = decode_jwt(token)
        assert payload["sub"] == user.id
        assert payload["email"] == "alice@example.com"
        assert payload["role"] == "admin"
        assert payload["org_id"] == "org-1"

    def test_jwt_contains_scopes(self):
        user = _make_user(role=UserRole.ANALYST)
        token = create_jwt(user)
        payload = decode_jwt(token)
        assert "scopes" in payload
        expected_scopes = ROLE_SCOPES[UserRole.ANALYST]
        assert payload["scopes"] == expected_scopes

    def test_jwt_contains_timestamps(self):
        user = _make_user()
        token = create_jwt(user)
        payload = decode_jwt(token)
        assert "iat" in payload
        assert "exp" in payload
        assert payload["exp"] > payload["iat"]

    def test_jwt_extra_claims(self):
        user = _make_user()
        token = create_jwt(user, extra_claims={"tenant_id": "t-123"})
        payload = decode_jwt(token)
        assert payload["tenant_id"] == "t-123"

    def test_decode_expired_jwt(self):
        user = _make_user()
        # Create token that expired 1 hour ago
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user.id,
            "email": user.email,
            "role": user.role.value,
            "org_id": user.org_id,
            "scopes": [],
            "iat": now - timedelta(hours=25),
            "exp": now - timedelta(hours=1),
        }
        token = jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)
        with pytest.raises(jwt.ExpiredSignatureError):
            decode_jwt(token)

    def test_decode_invalid_jwt(self):
        with pytest.raises(Exception):
            decode_jwt("invalid.token.here")

    def test_decode_wrong_secret(self):
        user = _make_user()
        payload = {
            "sub": user.id,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        wrong_secret = "a-totally-different-secret-key-that-is-long-enough"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            token = jwt.encode(payload, wrong_secret, algorithm="HS256")
        with pytest.raises(Exception):
            decode_jwt(token)

    def test_jwt_all_roles(self):
        for role in UserRole:
            user = _make_user(role=role)
            token = create_jwt(user)
            payload = decode_jwt(token)
            assert payload["role"] == role.value


# ─── API Key Generation ────────────────────────────────────────────────


class TestAPIKeyGeneration:
    def test_generate_api_key_returns_tuple(self):
        full_key, prefix, key_hash = generate_api_key()
        assert isinstance(full_key, str)
        assert isinstance(prefix, str)
        assert isinstance(key_hash, str)

    def test_api_key_starts_with_fixops(self):
        full_key, prefix, key_hash = generate_api_key()
        assert full_key.startswith("fixops_")

    def test_api_key_prefix_length(self):
        full_key, prefix, key_hash = generate_api_key()
        assert len(prefix) == 8

    def test_api_key_hash_is_bcrypt(self):
        full_key, prefix, key_hash = generate_api_key()
        assert key_hash.startswith("$2b$")

    def test_api_key_verification(self):
        full_key, prefix, key_hash = generate_api_key()
        assert verify_api_key_hash(full_key, key_hash) is True

    def test_api_key_wrong_key_fails(self):
        full_key, prefix, key_hash = generate_api_key()
        assert verify_api_key_hash("wrong_key", key_hash) is False

    def test_unique_api_keys(self):
        keys = set()
        for _ in range(10):
            full_key, _, _ = generate_api_key()
            keys.add(full_key)
        assert len(keys) == 10  # All unique
