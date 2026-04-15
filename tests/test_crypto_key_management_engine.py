"""Tests for CryptoKeyManagementEngine.

Covers key creation, listing, retrieval, rotation, revocation,
expiry tracking, usage audit trail, and statistics.
Total: 34 tests.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from core.crypto_key_management_engine import CryptoKeyManagementEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "crypto_keys_test.db")
    return CryptoKeyManagementEngine(db_path=db)


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "ck_init.db")
    CryptoKeyManagementEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "ck_idem.db")
    CryptoKeyManagementEngine(db_path=db)
    CryptoKeyManagementEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. create_key
# ---------------------------------------------------------------------------

def test_create_key_returns_dict(engine):
    key = engine.create_key("org1", {
        "name": "data-encryption-key",
        "key_type": "aes256",
        "purpose": "encryption",
        "expiry_days": 365,
        "tags": ["prod", "pii"],
    })
    assert key["key_id"]
    assert key["name"] == "data-encryption-key"
    assert key["key_type"] == "aes256"
    assert key["purpose"] == "encryption"
    assert key["status"] == "active"
    assert key["version"] == 1
    assert key["tags"] == ["prod", "pii"]
    assert key["expiry_date"]


def test_create_key_defaults(engine):
    key = engine.create_key("org1", {})
    assert key["key_type"] == "aes256"
    assert key["purpose"] == "encryption"
    assert key["status"] == "active"
    assert key["version"] == 1
    assert key["tags"] == []


def test_create_key_invalid_key_type_defaults(engine):
    key = engine.create_key("org1", {"key_type": "bogus"})
    assert key["key_type"] == "aes256"


def test_create_key_invalid_purpose_defaults(engine):
    key = engine.create_key("org1", {"purpose": "unknown"})
    assert key["purpose"] == "encryption"


def test_create_key_all_types(engine):
    for kt in ("aes256", "rsa2048", "rsa4096", "ecdsa256", "ed25519"):
        key = engine.create_key("org1", {"key_type": kt})
        assert key["key_type"] == kt


def test_create_key_all_purposes(engine):
    for p in ("encryption", "signing", "authentication"):
        key = engine.create_key("org1", {"purpose": p})
        assert key["purpose"] == p


def test_create_key_org_isolation(engine):
    engine.create_key("org-a", {"name": "key-a"})
    engine.create_key("org-b", {"name": "key-b"})
    assert len(engine.list_keys("org-a")) == 1
    assert len(engine.list_keys("org-b")) == 1


# ---------------------------------------------------------------------------
# 3. list_keys
# ---------------------------------------------------------------------------

def test_list_keys_empty(engine):
    assert engine.list_keys("org-none") == []


def test_list_keys_returns_all(engine):
    engine.create_key("org1", {"key_type": "aes256"})
    engine.create_key("org1", {"key_type": "rsa2048"})
    keys = engine.list_keys("org1")
    assert len(keys) == 2


def test_list_keys_filter_by_type(engine):
    engine.create_key("org1", {"key_type": "aes256"})
    engine.create_key("org1", {"key_type": "rsa2048"})
    keys = engine.list_keys("org1", key_type="aes256")
    assert all(k["key_type"] == "aes256" for k in keys)
    assert len(keys) == 1


def test_list_keys_filter_by_purpose(engine):
    engine.create_key("org1", {"purpose": "encryption"})
    engine.create_key("org1", {"purpose": "signing"})
    keys = engine.list_keys("org1", purpose="signing")
    assert all(k["purpose"] == "signing" for k in keys)
    assert len(keys) == 1


# ---------------------------------------------------------------------------
# 4. get_key
# ---------------------------------------------------------------------------

def test_get_key_returns_key(engine):
    created = engine.create_key("org1", {"name": "my-key"})
    fetched = engine.get_key("org1", created["key_id"])
    assert fetched is not None
    assert fetched["key_id"] == created["key_id"]
    assert fetched["name"] == "my-key"


def test_get_key_not_found(engine):
    assert engine.get_key("org1", "nonexistent-id") is None


def test_get_key_org_isolation(engine):
    created = engine.create_key("org-a", {"name": "key-a"})
    assert engine.get_key("org-b", created["key_id"]) is None


# ---------------------------------------------------------------------------
# 5. rotate_key
# ---------------------------------------------------------------------------

def test_rotate_key_returns_rotation_record(engine):
    key = engine.create_key("org1", {"name": "signing-key", "key_type": "ed25519"})
    result = engine.rotate_key("org1", key["key_id"])
    assert result["rotated_key_id"] == key["key_id"]
    assert result["new_key_id"]
    assert result["new_key_id"] != key["key_id"]
    assert result["new_version"] == 2
    assert result["status"] == "rotating"


def test_rotate_key_marks_old_as_rotating(engine):
    key = engine.create_key("org1", {"name": "k"})
    engine.rotate_key("org1", key["key_id"])
    old = engine.get_key("org1", key["key_id"])
    assert old["status"] == "rotating"


def test_rotate_key_new_key_is_active(engine):
    key = engine.create_key("org1", {"name": "k", "key_type": "rsa4096"})
    result = engine.rotate_key("org1", key["key_id"])
    new_key = engine.get_key("org1", result["new_key_id"])
    assert new_key["status"] == "active"
    assert new_key["key_type"] == "rsa4096"


def test_rotate_key_not_found_raises(engine):
    with pytest.raises(ValueError):
        engine.rotate_key("org1", "bad-id")


# ---------------------------------------------------------------------------
# 6. revoke_key
# ---------------------------------------------------------------------------

def test_revoke_key_returns_record(engine):
    key = engine.create_key("org1", {})
    result = engine.revoke_key("org1", key["key_id"], "compromised")
    assert result["status"] == "revoked"
    assert result["reason"] == "compromised"
    assert result["key_id"] == key["key_id"]


def test_revoke_key_persists_status(engine):
    key = engine.create_key("org1", {})
    engine.revoke_key("org1", key["key_id"], "policy")
    fetched = engine.get_key("org1", key["key_id"])
    assert fetched["status"] == "revoked"


def test_revoke_key_not_found_raises(engine):
    with pytest.raises(ValueError):
        engine.revoke_key("org1", "bad-id", "reason")


# ---------------------------------------------------------------------------
# 7. get_expiring_keys
# ---------------------------------------------------------------------------

def test_get_expiring_keys_empty_when_none(engine):
    assert engine.get_expiring_keys("org1") == []


def test_get_expiring_keys_finds_soon_expiring(engine):
    # Create key expiring in 5 days
    key = engine.create_key("org1", {"expiry_days": 5})
    expiring = engine.get_expiring_keys("org1", days_ahead=10)
    assert any(k["key_id"] == key["key_id"] for k in expiring)


def test_get_expiring_keys_excludes_far_future(engine):
    engine.create_key("org1", {"expiry_days": 365})
    expiring = engine.get_expiring_keys("org1", days_ahead=10)
    assert expiring == []


# ---------------------------------------------------------------------------
# 8. record_key_usage
# ---------------------------------------------------------------------------

def test_record_key_usage_returns_log(engine):
    key = engine.create_key("org1", {})
    log = engine.record_key_usage("org1", key["key_id"], "encrypt")
    assert log["log_id"]
    assert log["key_id"] == key["key_id"]
    assert log["usage_type"] == "encrypt"
    assert log["recorded_at"]


def test_record_key_usage_multiple_events(engine):
    key = engine.create_key("org1", {})
    for ut in ("encrypt", "decrypt", "sign"):
        engine.record_key_usage("org1", key["key_id"], ut)
    stats = engine.get_key_stats("org1")
    assert stats["total_usage_events"] == 3


# ---------------------------------------------------------------------------
# 9. get_key_stats
# ---------------------------------------------------------------------------

def test_get_key_stats_empty(engine):
    stats = engine.get_key_stats("org-empty")
    assert stats["total_keys"] == 0
    assert stats["by_type"] == {}
    assert stats["by_purpose"] == {}
    assert stats["expiring_soon_30d"] == 0
    assert stats["revoked"] == 0
    assert stats["total_usage_events"] == 0


def test_get_key_stats_counts_correctly(engine):
    engine.create_key("org1", {"key_type": "aes256", "purpose": "encryption"})
    engine.create_key("org1", {"key_type": "rsa2048", "purpose": "signing"})
    k = engine.create_key("org1", {"key_type": "aes256", "purpose": "encryption"})
    engine.revoke_key("org1", k["key_id"], "test")
    stats = engine.get_key_stats("org1")
    assert stats["total_keys"] == 3
    assert stats["by_type"]["aes256"] == 2
    assert stats["by_type"]["rsa2048"] == 1
    assert stats["revoked"] == 1


def test_get_key_stats_expiring_soon(engine):
    engine.create_key("org1", {"expiry_days": 5})
    engine.create_key("org1", {"expiry_days": 200})
    stats = engine.get_key_stats("org1")
    assert stats["expiring_soon_30d"] == 1
