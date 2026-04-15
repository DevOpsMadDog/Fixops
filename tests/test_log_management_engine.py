"""Tests for LogManagementEngine.

Covers: init, create_log_source (valid/invalid), list_log_sources (filter),
store_log_entry, query_logs (level/search filters), retention policy CRUD,
apply_retention_policy (verify deletion), get_log_stats (by_level breakdown),
org isolation.

Total: 35 tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.log_management_engine import LogManagementEngine


@pytest.fixture()
def engine(tmp_path):
    return LogManagementEngine(db_path=str(tmp_path / "test_log_mgmt.db"))


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "log_init.db")
    eng = LogManagementEngine(db_path=db)
    assert eng._db_path == db


def test_init_empty_stats(engine):
    stats = engine.get_log_stats("org1")
    assert stats["total_sources"] == 0
    assert stats["total_entries"] == 0
    assert stats["retention_policies_count"] == 0
    assert stats["by_log_type"] == {}
    assert stats["entries_by_level"] == {}


# ---------------------------------------------------------------------------
# 2. Log Source creation
# ---------------------------------------------------------------------------


def test_create_log_source_returns_record(engine):
    result = engine.create_log_source("org1", {
        "name": "App Logs",
        "log_type": "application",
    })
    assert "id" in result
    assert result["name"] == "App Logs"
    assert result["log_type"] == "application"
    assert result["format"] == "json"
    assert result["retention_days"] == 90
    assert result["status"] == "active"


def test_create_log_source_all_valid_types(engine):
    valid = ["application", "system", "security", "network", "database", "audit"]
    for lt in valid:
        r = engine.create_log_source("org1", {"name": lt, "log_type": lt})
        assert r["log_type"] == lt


def test_create_log_source_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="log_type"):
        engine.create_log_source("org1", {"name": "Bad", "log_type": "metrics"})


def test_create_log_source_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_log_source("org1", {"name": "", "log_type": "application"})


def test_create_log_source_custom_format(engine):
    result = engine.create_log_source("org1", {
        "name": "Syslog Src",
        "log_type": "system",
        "format": "syslog",
        "retention_days": 30,
    })
    assert result["format"] == "syslog"
    assert result["retention_days"] == 30


def test_create_log_source_invalid_format_defaults_json(engine):
    result = engine.create_log_source("org1", {
        "name": "Src",
        "log_type": "audit",
        "format": "xml",
    })
    assert result["format"] == "json"


# ---------------------------------------------------------------------------
# 3. List Log Sources
# ---------------------------------------------------------------------------


def test_list_log_sources_empty(engine):
    assert engine.list_log_sources("org1") == []


def test_list_log_sources_returns_all(engine):
    engine.create_log_source("org1", {"name": "A", "log_type": "application"})
    engine.create_log_source("org1", {"name": "B", "log_type": "security"})
    sources = engine.list_log_sources("org1")
    assert len(sources) == 2


def test_list_log_sources_filter_by_log_type(engine):
    engine.create_log_source("org1", {"name": "A", "log_type": "application"})
    engine.create_log_source("org1", {"name": "B", "log_type": "security"})
    app = engine.list_log_sources("org1", log_type="application")
    assert len(app) == 1
    assert app[0]["log_type"] == "application"


# ---------------------------------------------------------------------------
# 4. Log Entry storage
# ---------------------------------------------------------------------------


def test_store_log_entry_returns_record(engine):
    src = engine.create_log_source("org1", {"name": "Src", "log_type": "application"})
    result = engine.store_log_entry("org1", {
        "source_id": src["id"],
        "level": "info",
        "message": "Application started",
    })
    assert "id" in result
    assert result["level"] == "info"
    assert result["message"] == "Application started"
    assert result["metadata"] is None


def test_store_log_entry_with_metadata(engine):
    src = engine.create_log_source("org1", {"name": "S", "log_type": "security"})
    result = engine.store_log_entry("org1", {
        "source_id": src["id"],
        "level": "warn",
        "message": "Login failed",
        "metadata": {"ip": "10.0.0.1", "user": "admin"},
    })
    assert result["metadata"]["ip"] == "10.0.0.1"


def test_store_log_entry_all_valid_levels(engine):
    src = engine.create_log_source("org1", {"name": "S", "log_type": "system"})
    for level in ["debug", "info", "warn", "error", "fatal"]:
        result = engine.store_log_entry("org1", {
            "source_id": src["id"], "level": level, "message": f"msg-{level}",
        })
        assert result["level"] == level


def test_store_log_entry_invalid_level_raises(engine):
    with pytest.raises(ValueError, match="level"):
        engine.store_log_entry("org1", {
            "source_id": "any", "level": "verbose", "message": "test",
        })


# ---------------------------------------------------------------------------
# 5. Query Logs
# ---------------------------------------------------------------------------


def test_query_logs_empty(engine):
    assert engine.query_logs("org1") == []


def test_query_logs_returns_all(engine):
    src = engine.create_log_source("org1", {"name": "S", "log_type": "application"})
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "info", "message": "A"})
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "error", "message": "B"})
    entries = engine.query_logs("org1")
    assert len(entries) == 2


def test_query_logs_filter_by_level(engine):
    src = engine.create_log_source("org1", {"name": "S", "log_type": "application"})
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "error", "message": "ERR"})
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "info", "message": "OK"})
    errors = engine.query_logs("org1", level="error")
    assert len(errors) == 1
    assert errors[0]["level"] == "error"


def test_query_logs_filter_by_source_id(engine):
    src1 = engine.create_log_source("org1", {"name": "S1", "log_type": "application"})
    src2 = engine.create_log_source("org1", {"name": "S2", "log_type": "security"})
    engine.store_log_entry("org1", {"source_id": src1["id"], "level": "info", "message": "M1"})
    engine.store_log_entry("org1", {"source_id": src2["id"], "level": "info", "message": "M2"})
    entries = engine.query_logs("org1", source_id=src1["id"])
    assert len(entries) == 1
    assert entries[0]["source_id"] == src1["id"]


def test_query_logs_search_on_message(engine):
    src = engine.create_log_source("org1", {"name": "S", "log_type": "application"})
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "error", "message": "Connection timeout"})
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "info", "message": "User login"})
    results = engine.query_logs("org1", search="timeout")
    assert len(results) == 1
    assert "timeout" in results[0]["message"]


def test_query_logs_search_case_insensitive_via_like(engine):
    src = engine.create_log_source("org1", {"name": "S", "log_type": "application"})
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "info", "message": "Database error occurred"})
    results = engine.query_logs("org1", search="Database")
    assert len(results) == 1


def test_query_logs_limit(engine):
    src = engine.create_log_source("org1", {"name": "S", "log_type": "application"})
    for i in range(10):
        engine.store_log_entry("org1", {"source_id": src["id"], "level": "info", "message": f"msg{i}"})
    results = engine.query_logs("org1", limit=3)
    assert len(results) == 3


def test_query_logs_ordered_desc(engine):
    src = engine.create_log_source("org1", {"name": "S", "log_type": "application"})
    for i in range(3):
        engine.store_log_entry("org1", {"source_id": src["id"], "level": "info", "message": f"m{i}"})
    entries = engine.query_logs("org1")
    timestamps = [e["timestamp"] for e in entries]
    assert timestamps == sorted(timestamps, reverse=True)


# ---------------------------------------------------------------------------
# 6. Retention Policies
# ---------------------------------------------------------------------------


def test_create_retention_policy_returns_record(engine):
    result = engine.create_retention_policy("org1", {
        "name": "90-day security logs",
        "log_type": "security",
        "retention_days": 90,
        "action": "delete",
    })
    assert "id" in result
    assert result["name"] == "90-day security logs"
    assert result["retention_days"] == 90
    assert result["action"] == "delete"
    assert result["status"] == "active"


def test_create_retention_policy_clamps_days(engine):
    result = engine.create_retention_policy("org1", {
        "name": "Too long",
        "log_type": "audit",
        "retention_days": 9999,
    })
    assert result["retention_days"] == 3650

    result2 = engine.create_retention_policy("org1", {
        "name": "Too short",
        "log_type": "audit",
        "retention_days": 0,
    })
    assert result2["retention_days"] == 1


def test_create_retention_policy_invalid_log_type_raises(engine):
    with pytest.raises(ValueError, match="log_type"):
        engine.create_retention_policy("org1", {
            "name": "P", "log_type": "metrics", "retention_days": 30,
        })


def test_create_retention_policy_invalid_action_defaults_archive(engine):
    result = engine.create_retention_policy("org1", {
        "name": "P", "log_type": "system", "retention_days": 30, "action": "purge",
    })
    assert result["action"] == "archive"


def test_list_retention_policies_empty(engine):
    assert engine.list_retention_policies("org1") == []


def test_list_retention_policies_returns_all(engine):
    engine.create_retention_policy("org1", {"name": "P1", "log_type": "application", "retention_days": 30})
    engine.create_retention_policy("org1", {"name": "P2", "log_type": "security", "retention_days": 90})
    policies = engine.list_retention_policies("org1")
    assert len(policies) == 2


# ---------------------------------------------------------------------------
# 7. Apply Retention Policy (verify deletion)
# ---------------------------------------------------------------------------


def test_apply_retention_policy_deletes_expired(engine, tmp_path):
    """Entries older than retention_days for matching log_type should be deleted."""
    src = engine.create_log_source("org1", {"name": "AppSrc", "log_type": "application"})
    policy = engine.create_retention_policy("org1", {
        "name": "1-day app logs",
        "log_type": "application",
        "retention_days": 1,
        "action": "delete",
    })

    # Insert an old entry manually via SQLite
    import sqlite3
    old_ts = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    with sqlite3.connect(engine._db_path) as conn:
        conn.execute(
            "INSERT INTO log_entries (id, org_id, source_id, level, message, metadata, timestamp) "
            "VALUES (?,?,?,?,?,?,?)",
            ("old-entry-id", "org1", src["id"], "info", "old message", None, old_ts),
        )

    # Also store a recent entry
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "info", "message": "recent"})

    result = engine.apply_retention_policy("org1", policy["id"])
    assert result["deleted"] == 1
    assert result["policy_id"] == policy["id"]

    # Recent entry should remain
    remaining = engine.query_logs("org1")
    assert len(remaining) == 1
    assert remaining[0]["message"] == "recent"


def test_apply_retention_policy_no_sources_returns_zero(engine):
    """Policy applied when no sources of that log_type exist — returns 0 deleted."""
    policy = engine.create_retention_policy("org1", {
        "name": "Net policy",
        "log_type": "network",
        "retention_days": 7,
    })
    result = engine.apply_retention_policy("org1", policy["id"])
    assert result["deleted"] == 0


def test_apply_retention_policy_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.apply_retention_policy("org1", "bad-policy-id")


def test_apply_retention_policy_does_not_delete_other_log_types(engine, tmp_path):
    """Retention policy for 'security' should not delete 'application' logs."""
    app_src = engine.create_log_source("org1", {"name": "AppSrc", "log_type": "application"})
    policy = engine.create_retention_policy("org1", {
        "name": "1-day security",
        "log_type": "security",
        "retention_days": 1,
    })

    import sqlite3
    old_ts = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    with sqlite3.connect(engine._db_path) as conn:
        conn.execute(
            "INSERT INTO log_entries (id, org_id, source_id, level, message, metadata, timestamp) "
            "VALUES (?,?,?,?,?,?,?)",
            ("app-entry", "org1", app_src["id"], "info", "app log", None, old_ts),
        )

    result = engine.apply_retention_policy("org1", policy["id"])
    assert result["deleted"] == 0
    # Application entry still there
    remaining = engine.query_logs("org1")
    assert len(remaining) == 1


# ---------------------------------------------------------------------------
# 8. Stats
# ---------------------------------------------------------------------------


def test_stats_by_log_type(engine):
    engine.create_log_source("org1", {"name": "A", "log_type": "application"})
    engine.create_log_source("org1", {"name": "B", "log_type": "application"})
    engine.create_log_source("org1", {"name": "C", "log_type": "security"})
    stats = engine.get_log_stats("org1")
    assert stats["total_sources"] == 3
    assert stats["by_log_type"]["application"] == 2
    assert stats["by_log_type"]["security"] == 1


def test_stats_entries_by_level(engine):
    src = engine.create_log_source("org1", {"name": "S", "log_type": "application"})
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "error", "message": "E1"})
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "error", "message": "E2"})
    engine.store_log_entry("org1", {"source_id": src["id"], "level": "info", "message": "I1"})
    stats = engine.get_log_stats("org1")
    assert stats["total_entries"] == 3
    assert stats["entries_by_level"]["error"] == 2
    assert stats["entries_by_level"]["info"] == 1


def test_stats_retention_policies_count(engine):
    engine.create_retention_policy("org1", {"name": "P1", "log_type": "application", "retention_days": 30})
    engine.create_retention_policy("org1", {"name": "P2", "log_type": "security", "retention_days": 90})
    stats = engine.get_log_stats("org1")
    assert stats["retention_policies_count"] == 2


# ---------------------------------------------------------------------------
# 9. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_sources(engine):
    engine.create_log_source("org1", {"name": "S1", "log_type": "application"})
    engine.create_log_source("org2", {"name": "S2", "log_type": "security"})
    assert len(engine.list_log_sources("org1")) == 1
    assert len(engine.list_log_sources("org2")) == 1


def test_org_isolation_entries(engine):
    engine.store_log_entry("org1", {"source_id": "s1", "level": "info", "message": "org1 msg"})
    engine.store_log_entry("org2", {"source_id": "s2", "level": "info", "message": "org2 msg"})
    org1 = engine.query_logs("org1")
    org2 = engine.query_logs("org2")
    assert len(org1) == 1
    assert len(org2) == 1
    assert org1[0]["message"] == "org1 msg"


def test_org_isolation_policies(engine):
    engine.create_retention_policy("org1", {"name": "P1", "log_type": "application", "retention_days": 30})
    assert len(engine.list_retention_policies("org2")) == 0


def test_org_isolation_stats(engine):
    engine.create_log_source("org1", {"name": "S", "log_type": "security"})
    stats_org2 = engine.get_log_stats("org2")
    assert stats_org2["total_sources"] == 0
    assert stats_org2["total_entries"] == 0
