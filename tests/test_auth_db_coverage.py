"""Comprehensive tests for core.auth_db — SSO, users, API keys."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from core.auth_db import AuthDB
from core.auth_models import (
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


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_auth.db")
    return AuthDB(db_path=db_path)


def _make_sso(**overrides) -> SSOConfig:
    defaults = dict(
        id=str(uuid.uuid4()),
        name=f"sso-{uuid.uuid4().hex[:6]}",
        provider=AuthProvider.SAML,
        status=SSOStatus.ACTIVE,
        metadata={"domain": "example.com"},
        entity_id="https://idp.example.com/metadata",
        sso_url="https://idp.example.com/sso",
        certificate="MIIBxTCCAW...",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return SSOConfig(**defaults)


def _make_user(**overrides) -> User:
    defaults = dict(
        id=str(uuid.uuid4()),
        email=f"user-{uuid.uuid4().hex[:6]}@example.com",
        name="Test User",
        role=UserRole.ANALYST,
        password_hash="hashed_pw",
        is_active=True,
        org_id="org-1",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return User(**defaults)


def _make_api_key(user_id: str, **overrides) -> APIKey:
    defaults = dict(
        id=str(uuid.uuid4()),
        key_prefix="abcd1234",
        key_hash="$2b$12$fake_bcrypt_hash",
        user_id=user_id,
        name="Test Key",
        scopes=["read:findings", "read:sbom"],
        is_active=True,
        expires_at=None,
        last_used_at=None,
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return APIKey(**defaults)


# ─── SSO Config CRUD ────────────────────────────────────────────────────


class TestSSOConfigCRUD:
    def test_create_sso_config(self, db):
        cfg = _make_sso()
        result = db.create_sso_config(cfg)
        assert result.id == cfg.id

    def test_create_sso_config_auto_id(self, db):
        cfg = _make_sso(id="")
        result = db.create_sso_config(cfg)
        assert result.id  # auto-generated

    def test_get_sso_config(self, db):
        cfg = _make_sso()
        db.create_sso_config(cfg)
        result = db.get_sso_config(cfg.id)
        assert result is not None
        assert result.name == cfg.name
        assert result.provider == AuthProvider.SAML

    def test_get_sso_config_not_found(self, db):
        assert db.get_sso_config("nonexistent") is None

    def test_list_sso_configs(self, db):
        for _ in range(3):
            db.create_sso_config(_make_sso())
        results = db.list_sso_configs()
        assert len(results) == 3

    def test_list_sso_configs_pagination(self, db):
        for _ in range(5):
            db.create_sso_config(_make_sso())
        page = db.list_sso_configs(limit=2, offset=0)
        assert len(page) == 2

    def test_update_sso_config(self, db):
        cfg = _make_sso()
        db.create_sso_config(cfg)
        cfg.status = SSOStatus.INACTIVE
        cfg.certificate = "UPDATED_CERT"
        db.update_sso_config(cfg)
        reloaded = db.get_sso_config(cfg.id)
        assert reloaded.status == SSOStatus.INACTIVE
        assert reloaded.certificate == "UPDATED_CERT"

    def test_delete_sso_config(self, db):
        cfg = _make_sso()
        db.create_sso_config(cfg)
        assert db.delete_sso_config(cfg.id) is True
        assert db.get_sso_config(cfg.id) is None

    def test_sso_providers(self):
        for p in AuthProvider:
            assert p.value in ("local", "saml", "oauth2", "ldap")

    def test_sso_statuses(self):
        for s in SSOStatus:
            assert s.value in ("active", "inactive", "pending")

    def test_sso_metadata_roundtrip(self, db):
        meta = {"allowed_domains": ["a.com", "b.com"], "mfa": True}
        cfg = _make_sso(metadata=meta)
        db.create_sso_config(cfg)
        result = db.get_sso_config(cfg.id)
        assert result.metadata == meta


# ─── User CRUD ──────────────────────────────────────────────────────────


class TestUserCRUD:
    def test_create_user(self, db):
        u = _make_user()
        result = db.create_user(u)
        assert result.id == u.id

    def test_create_user_auto_id(self, db):
        u = _make_user(id="")
        result = db.create_user(u)
        assert result.id

    def test_get_user(self, db):
        u = _make_user()
        db.create_user(u)
        result = db.get_user(u.id)
        assert result is not None
        assert result.email == u.email
        assert result.role == UserRole.ANALYST

    def test_get_user_not_found(self, db):
        assert db.get_user("nonexistent") is None

    def test_get_user_by_email(self, db):
        u = _make_user(email="unique@example.com")
        db.create_user(u)
        result = db.get_user_by_email("unique@example.com")
        assert result is not None
        assert result.id == u.id

    def test_get_user_by_email_not_found(self, db):
        assert db.get_user_by_email("nobody@example.com") is None

    def test_list_users(self, db):
        for _ in range(4):
            db.create_user(_make_user())
        results = db.list_users()
        assert len(results) == 4

    def test_list_users_by_org(self, db):
        db.create_user(_make_user(org_id="org-alpha"))
        db.create_user(_make_user(org_id="org-alpha"))
        db.create_user(_make_user(org_id="org-beta"))
        results = db.list_users(org_id="org-alpha")
        assert len(results) == 2

    def test_list_users_pagination(self, db):
        for _ in range(6):
            db.create_user(_make_user())
        page = db.list_users(limit=2, offset=2)
        assert len(page) == 2

    def test_user_roles(self):
        for r in UserRole:
            assert r.value in ("admin", "analyst", "viewer", "service")

    def test_user_to_dict(self):
        u = _make_user()
        d = u.to_dict()
        assert d["email"] == u.email
        assert d["role"] == "analyst"
        assert "password_hash" not in d  # Should not leak password hash


# ─── API Key CRUD ───────────────────────────────────────────────────────


class TestAPIKeyCRUD:
    def test_create_api_key(self, db):
        u = _make_user()
        db.create_user(u)
        key = _make_api_key(u.id)
        result = db.create_api_key(key)
        assert result.id == key.id

    def test_create_api_key_auto_id(self, db):
        u = _make_user()
        db.create_user(u)
        key = _make_api_key(u.id, id="")
        result = db.create_api_key(key)
        assert result.id

    def test_get_api_key_by_prefix(self, db):
        u = _make_user()
        db.create_user(u)
        key = _make_api_key(u.id, key_prefix="testpfx1")
        db.create_api_key(key)
        result = db.get_api_key_by_prefix("testpfx1")
        assert result is not None
        assert result.id == key.id

    def test_get_api_key_by_prefix_not_found(self, db):
        assert db.get_api_key_by_prefix("nonexist") is None

    def test_list_api_keys(self, db):
        u = _make_user()
        db.create_user(u)
        for i in range(3):
            db.create_api_key(_make_api_key(u.id, key_prefix=f"pfx{i:04d}"))
        results = db.list_api_keys(u.id)
        assert len(results) == 3

    def test_revoke_api_key(self, db):
        u = _make_user()
        db.create_user(u)
        key = _make_api_key(u.id, key_prefix="revoke01")
        db.create_api_key(key)
        assert db.revoke_api_key(key.id) is True
        # Revoked key should not be found by prefix (is_active=0)
        assert db.get_api_key_by_prefix("revoke01") is None

    def test_touch_api_key(self, db):
        u = _make_user()
        db.create_user(u)
        key = _make_api_key(u.id, key_prefix="touch001")
        db.create_api_key(key)
        db.touch_api_key(key.id)
        # Should not raise

    def test_api_key_scopes(self):
        all_scopes = [s.value for s in APIKeyScope]
        assert "read:findings" in all_scopes
        assert "admin:all" in all_scopes
        assert len(all_scopes) >= 12

    def test_role_scopes_mapping(self):
        assert len(ROLE_SCOPES[UserRole.ADMIN]) == len(APIKeyScope)
        assert len(ROLE_SCOPES[UserRole.VIEWER]) < len(ROLE_SCOPES[UserRole.ADMIN])
        assert "admin:all" not in ROLE_SCOPES[UserRole.VIEWER]

    def test_api_key_to_dict(self):
        key = _make_api_key("user-1")
        d = key.to_dict()
        assert d["key_prefix"] == "abcd1234"
        assert "key_hash" not in d  # Should not leak hash

    def test_api_key_with_expiry(self, db):
        u = _make_user()
        db.create_user(u)
        exp = datetime.now(timezone.utc) + timedelta(days=30)
        key = _make_api_key(u.id, key_prefix="expiry01", expires_at=exp)
        db.create_api_key(key)
        result = db.get_api_key_by_prefix("expiry01")
        assert result.expires_at is not None


# ─── Model dataclass tests ─────────────────────────────────────────────


class TestModels:
    def test_sso_config_to_dict(self):
        cfg = _make_sso()
        d = cfg.to_dict()
        assert d["provider"] == "saml"
        assert d["status"] == "active"

    def test_saml_assertion_to_dict(self):
        a = SAMLAssertion(
            id="saml-1",
            user_id="user-1",
            assertion_data={"email": "test@example.com"},
        )
        d = a.to_dict()
        assert d["user_id"] == "user-1"
        assert d["assertion_data"]["email"] == "test@example.com"
        assert d["expires_at"] is None

    def test_saml_assertion_with_expiry(self):
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        a = SAMLAssertion(
            id="saml-2",
            user_id="user-2",
            assertion_data={},
            expires_at=exp,
        )
        d = a.to_dict()
        assert d["expires_at"] is not None
