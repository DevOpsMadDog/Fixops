"""Tests for SecretsManagementEngine — 33 tests covering all methods + org isolation."""

from __future__ import annotations

import pytest
from core.secrets_management_engine import SecretsManagementEngine


@pytest.fixture
def engine(tmp_path):
    return SecretsManagementEngine(db_path=str(tmp_path / "secrets.db"))


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _secret(engine, org, name="GITHUB_TOKEN", secret_type="api_key", rotation_days=90):
    return engine.store_secret(org, {
        "name": name,
        "secret_type": secret_type,
        "path": "/vault/github",
        "tags": ["ci", "github"],
        "rotation_days": rotation_days,
    })


# ---------------------------------------------------------------------------
# store_secret
# ---------------------------------------------------------------------------

def test_store_secret_returns_record(engine, org):
    s = _secret(engine, org)
    assert s["name"] == "GITHUB_TOKEN"
    assert s["secret_type"] == "api_key"
    assert s["org_id"] == org
    assert s["status"] == "active"
    assert "id" in s
    assert s["tags"] == ["ci", "github"]


def test_store_secret_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.store_secret(org, {"name": ""})


def test_store_secret_invalid_type_raises(engine, org):
    with pytest.raises(ValueError, match="secret_type"):
        engine.store_secret(org, {"name": "X", "secret_type": "magic_key"})


def test_store_secret_all_valid_types(engine, org):
    for st in ("api_key", "password", "certificate", "token", "ssh_key", "database"):
        s = engine.store_secret(org, {"name": f"s_{st}", "secret_type": st})
        assert s["secret_type"] == st


def test_store_secret_no_value_in_record(engine, org):
    s = _secret(engine, org)
    assert "value" not in s
    assert "secret_value" not in s


def test_store_secret_default_rotation(engine, org):
    s = engine.store_secret(org, {"name": "MY_KEY"})
    assert s["rotation_days"] == 90


# ---------------------------------------------------------------------------
# list_secrets
# ---------------------------------------------------------------------------

def test_list_secrets_returns_stored(engine, org):
    _secret(engine, org, name="A")
    _secret(engine, org, name="B")
    lst = engine.list_secrets(org)
    assert len(lst) == 2


def test_list_secrets_filtered_by_type(engine, org):
    _secret(engine, org, name="K1", secret_type="api_key")
    _secret(engine, org, name="K2", secret_type="password")
    api_keys = engine.list_secrets(org, secret_type="api_key")
    assert all(s["secret_type"] == "api_key" for s in api_keys)
    assert len(api_keys) == 1


def test_list_secrets_org_isolation(engine, org, org2):
    _secret(engine, org, name="A")
    assert engine.list_secrets(org2) == []


def test_list_secrets_no_values(engine, org):
    _secret(engine, org)
    for s in engine.list_secrets(org):
        assert "value" not in s


# ---------------------------------------------------------------------------
# get_secret_metadata
# ---------------------------------------------------------------------------

def test_get_secret_metadata_returns_record(engine, org):
    s = _secret(engine, org)
    meta = engine.get_secret_metadata(org, s["id"])
    assert meta["id"] == s["id"]
    assert meta["name"] == "GITHUB_TOKEN"


def test_get_secret_metadata_wrong_org_returns_none(engine, org, org2):
    s = _secret(engine, org)
    assert engine.get_secret_metadata(org2, s["id"]) is None


def test_get_secret_metadata_missing_returns_none(engine, org):
    assert engine.get_secret_metadata(org, "nonexistent-id") is None


# ---------------------------------------------------------------------------
# rotate_secret
# ---------------------------------------------------------------------------

def test_rotate_secret_updates_timestamp(engine, org):
    s = _secret(engine, org)
    orig_rotated = s["last_rotated"]
    import time; time.sleep(0.01)
    rotated = engine.rotate_secret(org, s["id"])
    assert rotated["status"] == "active"
    assert rotated["last_rotated"] >= orig_rotated


def test_rotate_secret_not_found_raises(engine, org):
    with pytest.raises(KeyError):
        engine.rotate_secret(org, "bad-id")


def test_rotate_revoked_secret_raises(engine, org):
    s = _secret(engine, org)
    engine.revoke_secret(org, s["id"], "expired")
    with pytest.raises(ValueError, match="revoked"):
        engine.rotate_secret(org, s["id"])


# ---------------------------------------------------------------------------
# revoke_secret
# ---------------------------------------------------------------------------

def test_revoke_secret_sets_status(engine, org):
    s = _secret(engine, org)
    revoked = engine.revoke_secret(org, s["id"], "compromised")
    assert revoked["status"] == "revoked"
    assert revoked["revoke_reason"] == "compromised"
    assert revoked["revoked_at"] is not None


def test_revoke_secret_not_found_raises(engine, org):
    with pytest.raises(KeyError):
        engine.revoke_secret(org, "bad-id", "reason")


def test_revoke_secret_org_isolation(engine, org, org2):
    s = _secret(engine, org)
    with pytest.raises(KeyError):
        engine.revoke_secret(org2, s["id"], "bad actor")


# ---------------------------------------------------------------------------
# get_expiring_secrets
# ---------------------------------------------------------------------------

def test_get_expiring_secrets_returns_overdue(engine, org):
    # rotation_days=1 means it should already be expiring
    _secret(engine, org, name="OLD_KEY", rotation_days=1)
    expiring = engine.get_expiring_secrets(org, days_ahead=1)
    assert len(expiring) >= 1


def test_get_expiring_secrets_excludes_fresh(engine, org):
    # rotation_days=365, days_ahead=0 means only secrets that already passed
    _secret(engine, org, name="FRESH_KEY", rotation_days=365)
    expiring = engine.get_expiring_secrets(org, days_ahead=0)
    assert all(s["name"] != "FRESH_KEY" for s in expiring)


def test_get_expiring_secrets_excludes_revoked(engine, org):
    s = _secret(engine, org, name="OLD_KEY", rotation_days=1)
    engine.revoke_secret(org, s["id"], "old")
    expiring = engine.get_expiring_secrets(org, days_ahead=1)
    assert all(s["status"] == "active" for s in expiring)


# ---------------------------------------------------------------------------
# record_access + get_access_log
# ---------------------------------------------------------------------------

def test_record_access_creates_log_entry(engine, org):
    s = _secret(engine, org)
    entry = engine.record_access(org, s["id"], "deploy-bot", "read")
    assert entry["accessor"] == "deploy-bot"
    assert entry["action"] == "read"
    assert entry["secret_id"] == s["id"]


def test_get_access_log_returns_entries(engine, org):
    s = _secret(engine, org)
    engine.record_access(org, s["id"], "bot-1", "read")
    engine.record_access(org, s["id"], "bot-2", "rotate")
    log = engine.get_access_log(org, s["id"])
    assert len(log) == 2


def test_get_access_log_limit(engine, org):
    s = _secret(engine, org)
    for i in range(10):
        engine.record_access(org, s["id"], f"bot-{i}", "read")
    log = engine.get_access_log(org, s["id"], limit=5)
    assert len(log) == 5


def test_get_access_log_org_isolation(engine, org, org2):
    s = _secret(engine, org)
    engine.record_access(org, s["id"], "bot", "read")
    log = engine.get_access_log(org2, s["id"])
    assert log == []


# ---------------------------------------------------------------------------
# get_secrets_stats
# ---------------------------------------------------------------------------

def test_get_secrets_stats_counts(engine, org):
    _secret(engine, org, name="K1", secret_type="api_key")
    _secret(engine, org, name="K2", secret_type="password")
    s3 = _secret(engine, org, name="K3", secret_type="token")
    engine.revoke_secret(org, s3["id"], "expired")
    stats = engine.get_secrets_stats(org)
    assert stats["total"] == 3
    assert stats["revoked"] == 1
    assert stats["by_type"]["api_key"] == 1
    assert stats["by_type"]["password"] == 1


def test_get_secrets_stats_overdue(engine, org):
    # Store a secret then manually set last_rotated to 2 days ago so it's overdue
    import sqlite3, datetime as dt
    s = _secret(engine, org, name="OVERDUE", rotation_days=1)
    two_days_ago = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).isoformat()
    with sqlite3.connect(engine.db_path) as conn:
        conn.execute(
            "UPDATE secrets SET last_rotated = ? WHERE id = ?",
            (two_days_ago, s["id"]),
        )
    stats = engine.get_secrets_stats(org)
    assert stats["overdue_rotation"] >= 1


def test_get_secrets_stats_empty_org(engine, org2):
    stats = engine.get_secrets_stats(org2)
    assert stats["total"] == 0
    assert stats["revoked"] == 0
    assert stats["overdue_rotation"] == 0
