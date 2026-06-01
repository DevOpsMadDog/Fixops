"""
REQ-010-04 / AC-010-04 — Schema Registry tests
================================================
Verifies that schema_registry.py:
  - registers DDL and applies it (creates table)
  - adds a missing column to an existing populated table without data loss
  - is idempotent (apply_pending twice does nothing harmful)
  - handles multiple registered schemas
  - add_missing_columns is a no-op when all columns already exist
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

# Ensure suite-core/core is importable
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "suite-core"))

from core.schema_registry import (  # noqa: E402
    add_missing_columns,
    apply_pending,
    clear_registry,
    get_registered,
    register_schema,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_registry():
    """Clear the global registry before and after each test."""
    clear_registry()
    yield
    clear_registry()


@pytest.fixture()
def mem_conn():
    """Fresh in-memory SQLite connection per test."""
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRegisterAndApply:
    def test_register_stores_schema(self):
        register_schema("findings", "CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY)")
        reg = get_registered()
        assert "findings" in reg

    def test_apply_creates_table(self, mem_conn):
        register_schema(
            "findings",
            "CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, title TEXT)",
        )
        apply_pending(mem_conn)
        # Table must exist
        row = mem_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
        ).fetchone()
        assert row is not None, "Table 'findings' was not created"

    def test_apply_idempotent(self, mem_conn):
        register_schema(
            "findings",
            "CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY)",
        )
        apply_pending(mem_conn)
        apply_pending(mem_conn)  # second call must not raise
        row = mem_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
        ).fetchone()
        assert row is not None


class TestAddMissingColumns:
    """AC-010-04 core: column added to existing populated table without data loss."""

    def test_adds_missing_column_no_data_loss(self, mem_conn):
        # 1. Create table with original schema + insert rows
        mem_conn.execute(
            "CREATE TABLE widgets (id TEXT PRIMARY KEY, name TEXT NOT NULL)"
        )
        mem_conn.execute("INSERT INTO widgets VALUES ('w1', 'Alpha')")
        mem_conn.execute("INSERT INTO widgets VALUES ('w2', 'Beta')")
        mem_conn.commit()

        # 2. Add a new column that the old schema didn't have
        added = add_missing_columns(
            mem_conn,
            "widgets",
            {"tenant_id": "TEXT DEFAULT ''", "severity": "TEXT DEFAULT 'low'"},
        )

        assert "tenant_id" in added, "tenant_id column was not added"
        assert "severity" in added, "severity column was not added"

        # 3. Verify existing rows are intact
        rows = mem_conn.execute(
            "SELECT id, name, tenant_id, severity FROM widgets ORDER BY id"
        ).fetchall()
        assert len(rows) == 2, f"Row count changed after ALTER: {rows}"
        assert rows[0] == ("w1", "Alpha", "", "low")
        assert rows[1] == ("w2", "Beta", "", "low")

    def test_skips_existing_columns(self, mem_conn):
        mem_conn.execute(
            "CREATE TABLE widgets (id TEXT PRIMARY KEY, name TEXT, tenant_id TEXT)"
        )
        mem_conn.commit()

        added = add_missing_columns(mem_conn, "widgets", {"tenant_id": "TEXT"})
        assert added == [], f"Should not have added existing column, got: {added}"

    def test_handles_nonexistent_table_gracefully(self, mem_conn):
        # Should log a warning but not raise
        added = add_missing_columns(mem_conn, "nonexistent_table", {"col": "TEXT"})
        assert added == []


class TestRegisterWithExpectedColumns:
    """apply_pending with expected_columns triggers add_missing_columns."""

    def test_apply_adds_columns_declared_in_registry(self, mem_conn):
        # Pre-create the table with fewer columns
        mem_conn.execute(
            "CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, event_type TEXT)"
        )
        mem_conn.execute("INSERT INTO events VALUES ('e1', 'scan')")
        mem_conn.commit()

        # Register schema with an extra expected column
        register_schema(
            "events",
            "CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, event_type TEXT)",
            expected_columns={"tenant_id": "TEXT DEFAULT ''"},
        )

        apply_pending(mem_conn)

        # Verify column was added
        pragma = mem_conn.execute("PRAGMA table_info(events)").fetchall()
        col_names = [r[1] for r in pragma]
        assert "tenant_id" in col_names, f"tenant_id not in {col_names}"

        # Verify existing data is intact
        row = mem_conn.execute("SELECT id, event_type FROM events WHERE id='e1'").fetchone()
        assert row == ("e1", "scan")


class TestMultipleSchemas:
    def test_multiple_schemas_applied(self, mem_conn):
        register_schema(
            "alpha", "CREATE TABLE IF NOT EXISTS alpha (id TEXT PRIMARY KEY)"
        )
        register_schema(
            "beta", "CREATE TABLE IF NOT EXISTS beta (id INTEGER PRIMARY KEY AUTOINCREMENT)"
        )
        apply_pending(mem_conn)

        tables = {
            r[0]
            for r in mem_conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "alpha" in tables
        assert "beta" in tables
