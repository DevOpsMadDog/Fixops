"""Tests for core.auth_models and core.auth_middleware — auth data models and JWT/API key helpers."""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.auth_middleware import (  # noqa: E402
    AuthContext,
    create_jwt,
    decode_jwt,
    generate_api_key,
    hash_password,
    verify_api_key_hash,
    verify_password,
)
from core.auth_models import (  # noqa: E402
    APIKey,
    APIKeyScope,
    AuthProvider,
    ROLE_SCOPES,
    SAMLAssertion,
    SSOConfig,
    SSOStatus,
    User,
    UserRole,
)


# ---------------------------------------------------------------------------
# Auth Models — Enums
# ---------------------------------------------------------------------------


class TestAuthProvider:
    def test_all_values(self):
        assert AuthProvider.LOCAL.value == "local"
        assert AuthProvider.SAML.value == "saml"
        assert AuthProvider.OAUTH2.value == "oauth2"
        assert AuthProvider.LDAP.value == "ldap"
        assert len(AuthProvider) == 4


class TestSSOStatus:
    def test_all_values(self):
        assert SSOStatus.ACTIVE.value == "active"
        assert SSOStatus.INACTIVE.value == "inactive"
        assert SSOStatus.PENDING.value == "pending"


class TestUserRole:
    def test_all_values(self):
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.ANALYST.value == "analyst"
        assert UserRole.VIEWER.value == "viewer"
        assert UserRole.SERVICE.value == "service"


class TestAPIKeyScope:
    def test_has_admin_all(self):
        assert APIKeyScope.ADMIN_ALL.value == "admin:all"

    def test_scope_count(self):
        assert len(APIKeyScope) == 13

    def test_read_write_scopes(self):
        read_scopes = [s for s in APIKeyScope if s.value.startswith("read:")]
        write_scopes = [s for s in APIKeyScope if s.value.startswith("write:")]
        assert len(read_scopes) > 0
        assert len(write_scopes) > 0


class TestRoleScopes:
    def test_admin_has_all_scopes(self):
        admin_scopes = ROLE_SCOPES[UserRole.ADMIN]
        assert "admin:all" in admin_scopes
        assert len(admin_scopes) == len(APIKeyScope)

    def test_viewer_has_read_only(self):
        viewer_scopes = ROLE_SCOPES[UserRole.VIEWER]
        assert all(s.startswith("read:") for s in viewer_scopes)

    def test_analyst_has_write(self):
        analyst_scopes = ROLE_SCOPES[UserRole.ANALYST]
        assert "write:sbom" in analyst_scopes
        assert "admin:all" not in analyst_scopes


# ---------------------------------------------------------------------------
# Auth Models — Data Classes
# ---------------------------------------------------------------------------


class TestUser:
    def test_create(self):
        user = User(
            id="user-1", email="test@test.com", name="Test User", role=UserRole.ADMIN,
        )
        assert user.id == "user-1"
        assert user.is_active is True
        assert user.org_id == "default"

    def test_to_dict(self):
        user = User(
            id="user-2", email="a@b.com", name="A B", role=UserRole.ANALYST,
        )
        d = user.to_dict()
        assert d["id"] == "user-2"
        assert d["role"] == "analyst"
        assert d["is_active"] is True
        assert "password_hash" not in d  # Not exposed


class TestSSOConfig:
    def test_create(self):
        config = SSOConfig(
            id="sso-1", name="Corporate SAML",
            provider=AuthProvider.SAML, status=SSOStatus.ACTIVE,
            entity_id="https://idp.corp.com", sso_url="https://idp.corp.com/sso",
        )
        assert config.provider == AuthProvider.SAML
        assert config.status == SSOStatus.ACTIVE

    def test_to_dict(self):
        config = SSOConfig(
            id="sso-2", name="Test", provider=AuthProvider.OAUTH2, status=SSOStatus.PENDING,
        )
        d = config.to_dict()
        assert d["provider"] == "oauth2"
        assert d["status"] == "pending"


class TestSAMLAssertion:
    def test_create(self):
        assertion = SAMLAssertion(
            id="sa-1", user_id="user-1", assertion_data={"email": "test@test.com"},
        )
        assert assertion.expires_at is None

    def test_to_dict(self):
        assertion = SAMLAssertion(
            id="sa-2", user_id="user-2", assertion_data={"name": "Test"},
        )
        d = assertion.to_dict()
        assert d["id"] == "sa-2"
        assert d["expires_at"] is None


class TestAPIKey:
    def test_create(self):
        key = APIKey(
            id="key-1", key_prefix="abc12345", key_hash="$2b$...",
            user_id="user-1", name="CI Key", scopes=["read:sbom", "write:sbom"],
        )
        assert key.is_active is True
        assert key.expires_at is None

    def test_to_dict(self):
        key = APIKey(
            id="key-2", key_prefix="def67890", key_hash="$2b$...",
            user_id="user-2", name="Deploy Key", scopes=["admin:all"],
        )
        d = key.to_dict()
        assert d["key_prefix"] == "def67890"
        assert "key_hash" not in d  # Not exposed
        assert d["scopes"] == ["admin:all"]


# ---------------------------------------------------------------------------
# Auth Middleware — JWT
# ---------------------------------------------------------------------------


class TestJWT:
    @pytest.fixture(autouse=True)
    def _set_jwt_secret(self, monkeypatch):
        monkeypatch.setattr(
            "core.auth_middleware._JWT_SECRET",
            "fixops-test-secret-that-is-long-enough-for-hmac-sha256",
        )

    def test_create_and_decode(self):
        user = User(
            id="user-jwt", email="jwt@test.com", name="JWT User", role=UserRole.ADMIN,
        )
        token = create_jwt(user)
        assert isinstance(token, str)

        claims = decode_jwt(token)
        assert claims["sub"] == "user-jwt"
        assert claims["email"] == "jwt@test.com"
        assert claims["role"] == "admin"

    def test_extra_claims(self):
        user = User(
            id="user-extra", email="extra@test.com", name="Extra", role=UserRole.ANALYST,
        )
        token = create_jwt(user, extra_claims={"team": "security"})
        claims = decode_jwt(token)
        assert claims["team"] == "security"

    def test_decode_invalid_token(self):
        with pytest.raises(Exception):
            decode_jwt("invalid.token.here")

    def test_scopes_in_token(self):
        user = User(
            id="user-scopes", email="sc@test.com", name="SC", role=UserRole.VIEWER,
        )
        token = create_jwt(user)
        claims = decode_jwt(token)
        assert isinstance(claims["scopes"], list)
        assert all(s.startswith("read:") for s in claims["scopes"])


# ---------------------------------------------------------------------------
# Auth Middleware — API Key
# ---------------------------------------------------------------------------


class TestAPIKeyGeneration:
    def test_generate_api_key(self):
        full_key, prefix, key_hash = generate_api_key()
        assert full_key.startswith("fixops_")
        assert len(prefix) == 8
        assert key_hash.startswith("$2")

    def test_verify_api_key_hash(self):
        full_key, prefix, key_hash = generate_api_key()
        assert verify_api_key_hash(full_key, key_hash) is True
        assert verify_api_key_hash("wrong_key", key_hash) is False

    def test_different_keys_different_hashes(self):
        _, _, hash1 = generate_api_key()
        _, _, hash2 = generate_api_key()
        assert hash1 != hash2


# ---------------------------------------------------------------------------
# Auth Middleware — Password
# ---------------------------------------------------------------------------


class TestPassword:
    def test_hash_and_verify(self):
        hashed = hash_password("secret123")
        assert verify_password("secret123", hashed) is True
        assert verify_password("wrong", hashed) is False

    def test_different_passwords_different_hashes(self):
        h1 = hash_password("pass1")
        h2 = hash_password("pass2")
        assert h1 != h2


# ---------------------------------------------------------------------------
# AuthContext
# ---------------------------------------------------------------------------


class TestAuthContext:
    def test_create(self):
        ctx = AuthContext(
            user_id="u1", email="e@t.com", role="admin",
            org_id="org1", scopes=["admin:all"], auth_method="jwt",
        )
        assert ctx.user_id == "u1"
        assert ctx.auth_method == "jwt"

    def test_has_scope(self):
        ctx = AuthContext(
            user_id="u2", email="e@t.com", role="analyst",
            org_id="org1", scopes=["read:sbom", "write:sbom"], auth_method="api_key",
        )
        assert ctx.has_scope("read:sbom") is True
        assert ctx.has_scope("admin:all") is False

    def test_admin_has_all_scopes(self):
        ctx = AuthContext(
            user_id="u3", email="e@t.com", role="admin",
            org_id="org1", scopes=["admin:all"], auth_method="jwt",
        )
        assert ctx.has_scope("admin:all") is True
        assert ctx.has_scope("read:sbom") is True  # admin:all grants all
        assert ctx.has_scope("anything") is True
