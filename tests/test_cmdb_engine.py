"""Tests for CMDBEngine — Configuration Management Database.

20 tests covering init, CI CRUD, relationships, change records,
stats, and multi-tenant org isolation.
"""

from __future__ import annotations

import os

import pytest

from core.cmdb_engine import CMDBEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "test_cmdb.db")


@pytest.fixture()
def engine(db_path):
    return CMDBEngine(db_path=db_path)


@pytest.fixture()
def org(engine):
    """Return an org_id with one registered CI."""
    oid = "org-cmdb-001"
    ci = engine.add_ci(oid, {
        "name": "web-server-01",
        "ci_type": "server",
        "environment": "prod",
        "criticality": "high",
        "owner": "ops-team",
    })
    return oid, ci["ci_id"]


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_engine_init_creates_db(db_path):
    eng = CMDBEngine(db_path=db_path)
    assert os.path.exists(db_path)


def test_engine_init_idempotent(db_path):
    """Creating the engine twice should not raise."""
    CMDBEngine(db_path=db_path)
    CMDBEngine(db_path=db_path)


# ---------------------------------------------------------------------------
# 2. CI CRUD
# ---------------------------------------------------------------------------

def test_add_ci_returns_dict(engine):
    ci = engine.add_ci("org1", {
        "name": "db-01",
        "ci_type": "database",
        "environment": "prod",
    })
    assert ci["name"] == "db-01"
    assert ci["ci_type"] == "database"
    assert "ci_id" in ci
    assert ci["tags"] == []


def test_add_ci_requires_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.add_ci("org1", {"ci_type": "server"})


def test_add_ci_invalid_type(engine):
    with pytest.raises(ValueError, match="ci_type"):
        engine.add_ci("org1", {"name": "x", "ci_type": "INVALID"})


def test_add_ci_invalid_environment(engine):
    with pytest.raises(ValueError, match="environment"):
        engine.add_ci("org1", {"name": "x", "ci_type": "server", "environment": "INVALID"})


def test_add_ci_invalid_criticality(engine):
    with pytest.raises(ValueError, match="criticality"):
        engine.add_ci("org1", {"name": "x", "ci_type": "server", "criticality": "INVALID"})


def test_list_cis_empty(engine):
    assert engine.list_cis("org-empty") == []


def test_list_cis_returns_added(engine, org):
    oid, cid = org
    cis = engine.list_cis(oid)
    assert any(c["ci_id"] == cid for c in cis)


def test_list_cis_filter_by_type(engine):
    oid = "org-type"
    engine.add_ci(oid, {"name": "srv1", "ci_type": "server"})
    engine.add_ci(oid, {"name": "db1", "ci_type": "database"})
    servers = engine.list_cis(oid, ci_type="server")
    assert all(c["ci_type"] == "server" for c in servers)
    assert len(servers) == 1


def test_list_cis_filter_by_environment(engine):
    oid = "org-env"
    engine.add_ci(oid, {"name": "prod-srv", "ci_type": "server", "environment": "prod"})
    engine.add_ci(oid, {"name": "dev-srv", "ci_type": "server", "environment": "dev"})
    prod = engine.list_cis(oid, environment="prod")
    assert all(c["environment"] == "prod" for c in prod)


def test_get_ci(engine, org):
    oid, cid = org
    ci = engine.get_ci(oid, cid)
    assert ci is not None
    assert ci["ci_id"] == cid


def test_get_ci_not_found(engine, org):
    oid, _ = org
    assert engine.get_ci(oid, "nonexistent") is None


def test_update_ci(engine, org):
    oid, cid = org
    result = engine.update_ci(oid, cid, {"version": "2.0", "os": "Ubuntu 24.04"})
    assert result is True
    ci = engine.get_ci(oid, cid)
    assert ci["version"] == "2.0"
    assert ci["os"] == "Ubuntu 24.04"


def test_update_ci_no_valid_fields(engine, org):
    oid, cid = org
    result = engine.update_ci(oid, cid, {"ci_id": "hack"})
    assert result is False


# ---------------------------------------------------------------------------
# 3. Relationships
# ---------------------------------------------------------------------------

def test_add_relationship(engine):
    oid = "org-rel"
    c1 = engine.add_ci(oid, {"name": "app", "ci_type": "application"})
    c2 = engine.add_ci(oid, {"name": "db", "ci_type": "database"})
    rel = engine.add_relationship(oid, c1["ci_id"], c2["ci_id"], "depends_on")
    assert rel["rel_type"] == "depends_on"
    assert "rel_id" in rel


def test_add_relationship_invalid_type(engine):
    oid = "org-rel2"
    c1 = engine.add_ci(oid, {"name": "a", "ci_type": "server"})
    c2 = engine.add_ci(oid, {"name": "b", "ci_type": "server"})
    with pytest.raises(ValueError, match="rel_type"):
        engine.add_relationship(oid, c1["ci_id"], c2["ci_id"], "INVALID")


def test_list_relationships_by_ci(engine):
    oid = "org-rel3"
    c1 = engine.add_ci(oid, {"name": "a", "ci_type": "server"})
    c2 = engine.add_ci(oid, {"name": "b", "ci_type": "database"})
    engine.add_relationship(oid, c1["ci_id"], c2["ci_id"], "hosts")
    rels = engine.list_relationships(oid, ci_id=c1["ci_id"])
    assert len(rels) == 1
    assert rels[0]["src_ci_id"] == c1["ci_id"]


# ---------------------------------------------------------------------------
# 4. Change records
# ---------------------------------------------------------------------------

def test_record_change(engine, org):
    oid, cid = org
    change = engine.record_change(oid, cid, "patched", "Applied security patch", "ops-bot")
    assert change["change_type"] == "patched"
    assert "change_id" in change


def test_list_changes_by_ci(engine, org):
    oid, cid = org
    engine.record_change(oid, cid, "updated", "Updated config", "admin")
    changes = engine.list_changes(oid, ci_id=cid)
    assert len(changes) >= 1
    assert all(c["ci_id"] == cid for c in changes)


def test_list_changes_all_org(engine, org):
    oid, cid = org
    engine.record_change(oid, cid, "config_change", "Changed settings", "admin")
    all_changes = engine.list_changes(oid)
    assert len(all_changes) >= 1


# ---------------------------------------------------------------------------
# 5. Stats
# ---------------------------------------------------------------------------

def test_get_cmdb_stats_structure(engine, org):
    oid, _ = org
    stats = engine.get_cmdb_stats(oid)
    assert "total_cis" in stats
    assert "by_type" in stats
    assert "by_environment" in stats
    assert "by_criticality" in stats
    assert "changes_this_week" in stats


def test_get_cmdb_stats_counts(engine, org):
    oid, cid = org
    engine.record_change(oid, cid, "updated", "change", "admin")
    stats = engine.get_cmdb_stats(oid)
    assert stats["total_cis"] >= 1
    assert stats["changes_this_week"] >= 1
    assert "server" in stats["by_type"]


def test_get_cmdb_stats_empty_org(engine):
    stats = engine.get_cmdb_stats("org-empty-stats")
    assert stats["total_cis"] == 0
    assert stats["by_type"] == {}
    assert stats["changes_this_week"] == 0


# ---------------------------------------------------------------------------
# 6. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_cis(engine):
    engine.add_ci("org-a", {"name": "srv-a", "ci_type": "server"})
    engine.add_ci("org-b", {"name": "srv-b", "ci_type": "server"})
    a_cis = engine.list_cis("org-a")
    b_cis = engine.list_cis("org-b")
    assert all(c["org_id"] == "org-a" for c in a_cis)
    assert all(c["org_id"] == "org-b" for c in b_cis)


def test_org_isolation_changes(engine):
    c = engine.add_ci("org-a", {"name": "srv", "ci_type": "server"})
    engine.record_change("org-a", c["ci_id"], "updated", "desc", "admin")
    assert engine.list_changes("org-b") == []
