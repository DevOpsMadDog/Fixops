"""Tests for suite-core/core/secrets_manager_engine.py — 25 tests."""

import time
import pytest

from core.secrets_manager_engine import SecretsManagerEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "secrets_test.db")
    return SecretsManagerEngine(db_path=db)


def _make_vault(engine, org_id="org1", name="TestVault", vault_type="local"):
    return engine.create_vault(org_id, {"name": name, "vault_type": vault_type})


def _make_secret(engine, org_id, vault_id, **kwargs):
    data = {
        "name": "my-api-key",
        "secret_type": "api_key",
        "owner": "platform-team",
        "environment": "prod",
        "rotation_days": 90,
    }
    data.update(kwargs)
    return engine.add_secret(org_id, vault_id, data)


# ------------------------------------------------------------------
# 1. Initialization
# ------------------------------------------------------------------

def test_init_creates_db(engine, tmp_path):
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "secrets_test.db"))
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    for t in ("secret_vaults", "secrets", "rotation_schedules", "rotation_history"):
        assert t in tables


# ------------------------------------------------------------------
# 2. Vault CRUD
# ------------------------------------------------------------------

def test_create_vault_returns_fields(engine):
    v = _make_vault(engine)
    assert "vault_id" in v
    assert v["vault_type"] == "local"
    assert v["status"] == "active"
    assert v["secret_count"] == 0


def test_create_vault_invalid_type(engine):
    with pytest.raises(ValueError, match="vault_type"):
        engine.create_vault("org1", {"name": "bad", "vault_type": "unknown"})


def test_list_vaults_empty(engine):
    assert engine.list_vaults("org1") == []


def test_list_vaults_returns_created(engine):
    _make_vault(engine, name="V1")
    _make_vault(engine, name="V2")
    vaults = engine.list_vaults("org1")
    assert len(vaults) == 2


def test_get_vault(engine):
    v = _make_vault(engine)
    fetched = engine.get_vault("org1", v["vault_id"])
    assert fetched is not None
    assert fetched["vault_id"] == v["vault_id"]


def test_get_vault_wrong_org_returns_none(engine):
    v = _make_vault(engine, org_id="org1")
    assert engine.get_vault("org2", v["vault_id"]) is None


# ------------------------------------------------------------------
# 3. Secret CRUD
# ------------------------------------------------------------------

def test_add_secret_returns_fields(engine):
    v = _make_vault(engine)
    s = _make_secret(engine, "org1", v["vault_id"])
    assert "secret_id" in s
    assert s["secret_type"] == "api_key"
    assert s["status"] in ("active", "expiring_soon", "expired")


def test_add_secret_invalid_type(engine):
    v = _make_vault(engine)
    with pytest.raises(ValueError, match="secret_type"):
        engine.add_secret("org1", v["vault_id"], {"name": "x", "secret_type": "invalid"})


def test_add_secret_invalid_vault(engine):
    with pytest.raises(ValueError, match="Vault"):
        engine.add_secret("org1", "nonexistent-vault-id", {"name": "x", "secret_type": "api_key"})


def test_add_secret_increments_vault_count(engine):
    v = _make_vault(engine)
    _make_secret(engine, "org1", v["vault_id"])
    _make_secret(engine, "org1", v["vault_id"])
    vault = engine.get_vault("org1", v["vault_id"])
    assert vault["secret_count"] == 2


def test_list_secrets(engine):
    v = _make_vault(engine)
    _make_secret(engine, "org1", v["vault_id"])
    _make_secret(engine, "org1", v["vault_id"], name="db-pass", secret_type="db_password")
    secrets = engine.list_secrets("org1")
    assert len(secrets) == 2


def test_list_secrets_filter_vault(engine):
    v1 = _make_vault(engine, name="Vault1")
    v2 = _make_vault(engine, name="Vault2")
    _make_secret(engine, "org1", v1["vault_id"])
    _make_secret(engine, "org1", v2["vault_id"], name="other")
    filtered = engine.list_secrets("org1", vault_id=v1["vault_id"])
    assert len(filtered) == 1


def test_list_secrets_filter_status(engine):
    v = _make_vault(engine)
    now = time.time()
    # Create an expired secret
    _make_secret(engine, "org1", v["vault_id"], name="expired",
                 expires_at=now - 3600, rotation_days=1)
    _make_secret(engine, "org1", v["vault_id"], name="active")
    expired = engine.list_secrets("org1", status="expired")
    assert any(s["name"] == "expired" for s in expired)


# ------------------------------------------------------------------
# 4. Rotation
# ------------------------------------------------------------------

def test_schedule_rotation(engine):
    v = _make_vault(engine)
    s = _make_secret(engine, "org1", v["vault_id"])
    sched = engine.schedule_rotation("org1", s["secret_id"], 30)
    assert sched["rotation_days"] == 30
    assert sched["next_rotation"] > time.time()


def test_schedule_rotation_unknown_secret(engine):
    with pytest.raises(ValueError, match="Secret"):
        engine.schedule_rotation("org1", "nonexistent-id", 30)


def test_schedule_rotation_updates_existing(engine):
    v = _make_vault(engine)
    s = _make_secret(engine, "org1", v["vault_id"])
    s1 = engine.schedule_rotation("org1", s["secret_id"], 30)
    s2 = engine.schedule_rotation("org1", s["secret_id"], 60)
    assert s1["schedule_id"] == s2["schedule_id"]
    assert s2["rotation_days"] == 60


def test_record_rotation(engine):
    v = _make_vault(engine)
    s = _make_secret(engine, "org1", v["vault_id"])
    result = engine.record_rotation("org1", s["secret_id"], "manual", "alice")
    assert "history_id" in result
    assert result["rotation_type"] == "manual"
    assert result["performed_by"] == "alice"


def test_get_rotation_history(engine):
    v = _make_vault(engine)
    s = _make_secret(engine, "org1", v["vault_id"])
    engine.record_rotation("org1", s["secret_id"], "manual", "alice")
    engine.record_rotation("org1", s["secret_id"], "automated", "system")
    history = engine.get_rotation_history("org1", s["secret_id"])
    assert len(history) == 2


def test_get_rotation_history_wrong_org(engine):
    v = _make_vault(engine, org_id="org1")
    s = _make_secret(engine, "org1", v["vault_id"])
    with pytest.raises(ValueError, match="Secret"):
        engine.get_rotation_history("org2", s["secret_id"])


# ------------------------------------------------------------------
# 5. Expiring secrets
# ------------------------------------------------------------------

def test_get_expiring_secrets(engine):
    v = _make_vault(engine)
    now = time.time()
    # expires in 5 days
    _make_secret(engine, "org1", v["vault_id"], name="soon",
                 expires_at=now + 5 * 86400, rotation_days=90)
    # expires in 60 days (outside 30-day window)
    _make_secret(engine, "org1", v["vault_id"], name="later",
                 expires_at=now + 60 * 86400, rotation_days=90)
    expiring = engine.get_expiring_secrets("org1", days_ahead=30)
    assert len(expiring) == 1
    assert expiring[0]["name"] == "soon"


# ------------------------------------------------------------------
# 6. Stats
# ------------------------------------------------------------------

def test_get_secrets_stats_empty(engine):
    stats = engine.get_secrets_stats("org1")
    assert stats["total_secrets"] == 0
    assert stats["vaults_count"] == 0


def test_get_secrets_stats_populated(engine):
    v = _make_vault(engine)
    _make_secret(engine, "org1", v["vault_id"], name="k1", secret_type="api_key", environment="prod")
    _make_secret(engine, "org1", v["vault_id"], name="k2", secret_type="db_password", environment="staging")
    stats = engine.get_secrets_stats("org1")
    assert stats["total_secrets"] == 2
    assert stats["vaults_count"] == 1
    assert stats["by_type"].get("api_key") == 1
    assert stats["by_environment"].get("prod") == 1


# ------------------------------------------------------------------
# 7. Org isolation
# ------------------------------------------------------------------

def test_org_isolation_vaults(engine):
    _make_vault(engine, org_id="orgA", name="A-Vault")
    _make_vault(engine, org_id="orgB", name="B-Vault")
    assert len(engine.list_vaults("orgA")) == 1
    assert len(engine.list_vaults("orgB")) == 1


def test_org_isolation_secrets(engine):
    vA = _make_vault(engine, org_id="orgA")
    vB = _make_vault(engine, org_id="orgB")
    _make_secret(engine, "orgA", vA["vault_id"], name="secret-a")
    _make_secret(engine, "orgB", vB["vault_id"], name="secret-b")
    assert len(engine.list_secrets("orgA")) == 1
    assert len(engine.list_secrets("orgB")) == 1
