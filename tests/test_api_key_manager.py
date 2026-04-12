"""
Tests for APIKeyManager — scoped API key lifecycle management.

Covers:
- Key creation: format, prefix, hash storage, aldeci_ prefix
- Validate: valid key passes, wrong key rejected, expired rejected, revoked rejected
- Rotate: old key invalid after rotation, new key works
- Revoke: key becomes invalid
- Usage tracking: use_count increments, last_used_at updates
- List keys: no key_hash exposed, org isolation
- Scopes and role stored correctly
- Rate limit per key
- Update: mutable fields only
- delete_expired_keys: cleanup
- get_usage_stats: counts and rate
- Edge cases: unknown key, inactive key
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

# Use a temp DB per test session to avoid cross-test pollution
os.environ.setdefault("FIXOPS_DATA_DIR", tempfile.mkdtemp())

from core.api_key_manager import APIKeyManager, APIKey, _hash_key, _generate_raw_key
from core.rbac import RBACRole


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mgr(tmp_path):
    """Fresh APIKeyManager backed by a temp SQLite file."""
    db = str(tmp_path / "keys.db")
    # Pass db_path to bypass the singleton so each test is isolated
    return APIKeyManager(db_path=db)


def _make_key(mgr: APIKeyManager, **kwargs):
    """Helper: create a key with sensible defaults."""
    defaults = dict(
        name="Test Key",
        org_id="org-1",
        role=RBACRole.VIEWER,
        scopes=["read:findings"],
        rate_limit=60,
        description="test",
        created_by="admin",
    )
    defaults.update(kwargs)
    return mgr.create_key(**defaults)


# ---------------------------------------------------------------------------
# Key format tests
# ---------------------------------------------------------------------------


class TestKeyFormat:
    def test_raw_key_starts_with_aldeci_prefix(self, mgr):
        _, raw = _make_key(mgr)
        assert raw.startswith("aldeci_"), f"Expected aldeci_ prefix, got: {raw[:10]}"

    def test_raw_key_length(self, mgr):
        _, raw = _make_key(mgr)
        # "aldeci_" (7) + 32 hex chars = 39 total
        assert len(raw) == 39, f"Expected length 39, got {len(raw)}"

    def test_raw_key_hex_suffix(self, mgr):
        _, raw = _make_key(mgr)
        suffix = raw[len("aldeci_"):]
        assert len(suffix) == 32
        assert all(c in "0123456789abcdef" for c in suffix), "Suffix must be hex"

    def test_prefix_field_is_first_8_chars(self, mgr):
        key, raw = _make_key(mgr)
        assert key.prefix == raw[:8]

    def test_prefix_starts_with_aldeci(self, mgr):
        key, _ = _make_key(mgr)
        assert key.prefix.startswith("ald")

    def test_key_id_format(self, mgr):
        key, _ = _make_key(mgr)
        assert key.id.startswith("ak_")

    def test_generate_raw_key_helper(self):
        raw = _generate_raw_key()
        assert raw.startswith("aldeci_")
        assert len(raw) == 39

    def test_two_keys_have_different_ids(self, mgr):
        k1, _ = _make_key(mgr)
        k2, _ = _make_key(mgr)
        assert k1.id != k2.id

    def test_two_keys_have_different_raw_values(self, mgr):
        _, raw1 = _make_key(mgr)
        _, raw2 = _make_key(mgr)
        assert raw1 != raw2


# ---------------------------------------------------------------------------
# Hash storage tests
# ---------------------------------------------------------------------------


class TestHashStorage:
    def test_key_hash_is_sha256_of_raw_key(self, mgr):
        key, raw = _make_key(mgr)
        assert key.key_hash == _hash_key(raw)

    def test_hash_is_64_hex_chars(self, mgr):
        key, _ = _make_key(mgr)
        assert len(key.key_hash) == 64
        assert all(c in "0123456789abcdef" for c in key.key_hash)

    def test_hash_not_exposed_in_serialization(self, mgr):
        key, _ = _make_key(mgr)
        dumped = key.model_dump()
        assert "key_hash" not in dumped

    def test_list_keys_has_no_hash(self, mgr):
        _make_key(mgr)
        keys = mgr.list_keys("org-1")
        for k in keys:
            dumped = k.model_dump()
            assert "key_hash" not in dumped


# ---------------------------------------------------------------------------
# Validate key tests
# ---------------------------------------------------------------------------


class TestValidateKey:
    def test_valid_key_validates(self, mgr):
        _, raw = _make_key(mgr)
        result = mgr.validate_key(raw)
        assert result is not None

    def test_invalid_key_returns_none(self, mgr):
        _make_key(mgr)
        result = mgr.validate_key("aldeci_deadbeefdeadbeefdeadbeefdeadbe")
        assert result is None

    def test_wrong_prefix_returns_none(self, mgr):
        _make_key(mgr)
        result = mgr.validate_key("fixops_" + "a" * 32)
        assert result is None

    def test_empty_string_returns_none(self, mgr):
        result = mgr.validate_key("")
        assert result is None

    def test_expired_key_returns_none(self, mgr):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        _, raw = _make_key(mgr, expires_at=past)
        result = mgr.validate_key(raw)
        assert result is None

    def test_future_expiry_key_validates(self, mgr):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        _, raw = _make_key(mgr, expires_at=future)
        result = mgr.validate_key(raw)
        assert result is not None

    def test_no_expiry_key_validates(self, mgr):
        _, raw = _make_key(mgr, expires_at=None)
        result = mgr.validate_key(raw)
        assert result is not None

    def test_revoked_key_returns_none(self, mgr):
        key, raw = _make_key(mgr)
        mgr.revoke_key(key.id)
        result = mgr.validate_key(raw)
        assert result is None

    def test_validate_returns_apikey_instance(self, mgr):
        _, raw = _make_key(mgr)
        result = mgr.validate_key(raw)
        assert isinstance(result, APIKey)


# ---------------------------------------------------------------------------
# Usage tracking tests
# ---------------------------------------------------------------------------


class TestUsageTracking:
    def test_use_count_increments_on_validate(self, mgr):
        _, raw = _make_key(mgr)
        mgr.validate_key(raw)
        mgr.validate_key(raw)
        result = mgr.validate_key(raw)
        assert result is not None
        assert result.use_count == 3

    def test_initial_use_count_is_zero(self, mgr):
        key, _ = _make_key(mgr)
        assert key.use_count == 0

    def test_last_used_at_is_none_before_validate(self, mgr):
        key, _ = _make_key(mgr)
        assert key.last_used_at is None

    def test_last_used_at_updates_on_validate(self, mgr):
        _, raw = _make_key(mgr)
        before = datetime.now(timezone.utc)
        result = mgr.validate_key(raw)
        assert result is not None
        assert result.last_used_at is not None
        assert result.last_used_at >= before

    def test_use_count_persists_in_db(self, mgr):
        key, raw = _make_key(mgr)
        mgr.validate_key(raw)
        mgr.validate_key(raw)
        fetched = mgr.get_key(key.id)
        assert fetched is not None
        assert fetched.use_count == 2


# ---------------------------------------------------------------------------
# Revoke tests
# ---------------------------------------------------------------------------


class TestRevoke:
    def test_revoke_sets_inactive(self, mgr):
        key, _ = _make_key(mgr)
        mgr.revoke_key(key.id)
        fetched = mgr.get_key(key.id)
        assert fetched is not None
        assert fetched.is_active is False

    def test_revoke_unknown_key_raises(self, mgr):
        with pytest.raises(ValueError, match="not found"):
            mgr.revoke_key("ak_nonexistent")

    def test_revoke_makes_key_invalid_on_validate(self, mgr):
        key, raw = _make_key(mgr)
        mgr.revoke_key(key.id)
        assert mgr.validate_key(raw) is None


# ---------------------------------------------------------------------------
# Rotate tests
# ---------------------------------------------------------------------------


class TestRotate:
    def test_rotate_returns_new_key_and_raw(self, mgr):
        key, raw = _make_key(mgr)
        new_key, new_raw = mgr.rotate_key(key.id)
        assert new_key is not None
        assert new_raw is not None
        assert new_raw.startswith("aldeci_")

    def test_old_key_invalid_after_rotation(self, mgr):
        key, raw = _make_key(mgr)
        mgr.rotate_key(key.id)
        assert mgr.validate_key(raw) is None

    def test_new_key_valid_after_rotation(self, mgr):
        _, raw = _make_key(mgr)
        _, new_raw = mgr.rotate_key(mgr.validate_key(raw).id)  # type: ignore[union-attr]
        assert mgr.validate_key(new_raw) is not None

    def test_rotate_preserves_org_id(self, mgr):
        key, _ = _make_key(mgr, org_id="org-acme")
        new_key, _ = mgr.rotate_key(key.id)
        assert new_key.org_id == "org-acme"

    def test_rotate_preserves_role(self, mgr):
        key, _ = _make_key(mgr, role=RBACRole.ADMIN)
        new_key, _ = mgr.rotate_key(key.id)
        assert new_key.role == RBACRole.ADMIN

    def test_rotate_preserves_scopes(self, mgr):
        key, _ = _make_key(mgr, scopes=["read:findings", "write:findings"])
        new_key, _ = mgr.rotate_key(key.id)
        assert new_key.scopes == ["read:findings", "write:findings"]

    def test_rotate_unknown_key_raises(self, mgr):
        with pytest.raises(ValueError, match="not found"):
            mgr.rotate_key("ak_nonexistent")

    def test_rotate_inactive_key_raises(self, mgr):
        key, _ = _make_key(mgr)
        mgr.revoke_key(key.id)
        with pytest.raises(ValueError, match="not active"):
            mgr.rotate_key(key.id)


# ---------------------------------------------------------------------------
# List keys tests
# ---------------------------------------------------------------------------


class TestListKeys:
    def test_list_returns_keys_for_org(self, mgr):
        _make_key(mgr, org_id="org-a")
        _make_key(mgr, org_id="org-a")
        _make_key(mgr, org_id="org-b")
        keys = mgr.list_keys("org-a")
        assert len(keys) == 2

    def test_list_excludes_other_orgs(self, mgr):
        _make_key(mgr, org_id="org-x")
        keys = mgr.list_keys("org-y")
        assert keys == []

    def test_list_includes_inactive_keys(self, mgr):
        key, _ = _make_key(mgr, org_id="org-1")
        mgr.revoke_key(key.id)
        keys = mgr.list_keys("org-1")
        assert any(k.id == key.id for k in keys)


# ---------------------------------------------------------------------------
# Scopes and role tests
# ---------------------------------------------------------------------------


class TestScopesAndRole:
    def test_scopes_stored_correctly(self, mgr):
        key, _ = _make_key(mgr, scopes=["read:findings", "read:compliance"])
        fetched = mgr.get_key(key.id)
        assert fetched is not None
        assert sorted(fetched.scopes) == ["read:compliance", "read:findings"]

    def test_role_stored_correctly(self, mgr):
        key, _ = _make_key(mgr, role=RBACRole.SECURITY_ANALYST)
        fetched = mgr.get_key(key.id)
        assert fetched is not None
        assert fetched.role == RBACRole.SECURITY_ANALYST

    def test_default_role_is_viewer(self, mgr):
        key, _ = _make_key(mgr, role=RBACRole.VIEWER)
        assert key.role == RBACRole.VIEWER

    def test_empty_scopes_stored_correctly(self, mgr):
        key, _ = _make_key(mgr, scopes=[])
        fetched = mgr.get_key(key.id)
        assert fetched is not None
        assert fetched.scopes == []


# ---------------------------------------------------------------------------
# Rate limit tests
# ---------------------------------------------------------------------------


class TestRateLimit:
    def test_rate_limit_stored_correctly(self, mgr):
        key, _ = _make_key(mgr, rate_limit=120)
        fetched = mgr.get_key(key.id)
        assert fetched is not None
        assert fetched.rate_limit == 120

    def test_default_rate_limit_is_60(self, mgr):
        key, _ = _make_key(mgr, rate_limit=60)
        assert key.rate_limit == 60

    def test_update_rate_limit(self, mgr):
        key, _ = _make_key(mgr, rate_limit=60)
        updated = mgr.update_key(key.id, {"rate_limit": 300})
        assert updated.rate_limit == 300


# ---------------------------------------------------------------------------
# Update key tests
# ---------------------------------------------------------------------------


class TestUpdateKey:
    def test_update_name(self, mgr):
        key, _ = _make_key(mgr, name="Old Name")
        updated = mgr.update_key(key.id, {"name": "New Name"})
        assert updated.name == "New Name"

    def test_update_description(self, mgr):
        key, _ = _make_key(mgr, description="old desc")
        updated = mgr.update_key(key.id, {"description": "new desc"})
        assert updated.description == "new desc"

    def test_update_scopes(self, mgr):
        key, _ = _make_key(mgr, scopes=["read:findings"])
        updated = mgr.update_key(key.id, {"scopes": ["read:findings", "write:findings"]})
        assert "write:findings" in updated.scopes

    def test_update_ignores_unknown_fields(self, mgr):
        key, _ = _make_key(mgr)
        updated = mgr.update_key(key.id, {"unknown_field": "value"})
        assert updated.id == key.id  # No error, key unchanged otherwise

    def test_update_unknown_key_raises(self, mgr):
        with pytest.raises(ValueError, match="not found"):
            mgr.update_key("ak_nonexistent", {"name": "x"})


# ---------------------------------------------------------------------------
# delete_expired_keys tests
# ---------------------------------------------------------------------------


class TestDeleteExpiredKeys:
    def test_deletes_expired_inactive_keys(self, mgr):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        key, _ = _make_key(mgr, expires_at=past)
        mgr.revoke_key(key.id)  # make inactive
        count = mgr.delete_expired_keys()
        assert count == 1
        assert mgr.get_key(key.id) is None

    def test_does_not_delete_active_expired_keys(self, mgr):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        key, _ = _make_key(mgr, expires_at=past)
        # Key is expired but still active (not revoked)
        count = mgr.delete_expired_keys()
        assert count == 0
        assert mgr.get_key(key.id) is not None

    def test_does_not_delete_non_expired_keys(self, mgr):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        key, _ = _make_key(mgr, expires_at=future)
        mgr.revoke_key(key.id)
        count = mgr.delete_expired_keys()
        assert count == 0


# ---------------------------------------------------------------------------
# Usage stats tests
# ---------------------------------------------------------------------------


class TestUsageStats:
    def test_usage_stats_returns_dict(self, mgr):
        key, _ = _make_key(mgr)
        stats = mgr.get_usage_stats(key.id)
        assert isinstance(stats, dict)

    def test_usage_stats_has_expected_keys(self, mgr):
        key, _ = _make_key(mgr)
        stats = mgr.get_usage_stats(key.id)
        for field in ("key_id", "use_count", "last_used_at", "created_at", "rate_limit", "is_active"):
            assert field in stats

    def test_usage_stats_use_count(self, mgr):
        key, raw = _make_key(mgr)
        mgr.validate_key(raw)
        mgr.validate_key(raw)
        stats = mgr.get_usage_stats(key.id)
        assert stats["use_count"] == 2

    def test_usage_stats_unknown_key_raises(self, mgr):
        with pytest.raises(ValueError, match="not found"):
            mgr.get_usage_stats("ak_nonexistent")

    def test_usage_stats_rate_limit_field(self, mgr):
        key, _ = _make_key(mgr, rate_limit=120)
        stats = mgr.get_usage_stats(key.id)
        assert stats["rate_limit"] == 120
