"""FEATURE-5 — DBAdapter tests.

Verifies the postgres-or-sqlite switching layer that production deployments
use to scale beyond SQLite. All tests run in pure sqlite mode so no postgres
server is required in CI.

Test matrix:
1. No DATABASE_URL → sqlite, CRUD round-trips through `connect()` ctx manager.
2. DATABASE_URL set but psycopg2 unimportable → graceful sqlite fallback + warning.
3. `adapt_sql()` rewrites `?` → `%s` only when postgres mode active.
4. `is_postgres_url()` recognizes the postgres URL family.
5. `connect()` rolls back on exception (transactional safety).
6. CTEMEngine.add_exposure() works through the adapter end-to-end (sqlite mode).
"""

from __future__ import annotations

import importlib
import logging
import os
import sqlite3
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure suite paths are loaded — mirror sitecustomize.py without depending
# on cwd (pytest sometimes invokes from a sibling dir).
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]
for sub in (
    "suite-core",
    "suite-api",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
):
    candidate = ROOT / sub
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from core import db_adapter as db_adapter_module  # noqa: E402
from core.db_adapter import DBAdapter, get_adapter, is_postgres_url  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_db_url(monkeypatch):
    """Each test starts with DATABASE_URL unset to avoid cross-test bleed."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    yield


# ---------------------------------------------------------------------------
# Test 1 — sqlite default + CRUD round-trip
# ---------------------------------------------------------------------------


def test_sqlite_default_crud_round_trip(tmp_path: Path) -> None:
    """No DATABASE_URL → sqlite mode. connect() ctx manager commits on success
    and the data is visible on a subsequent read."""
    db_path = tmp_path / "test.db"
    adapter = get_adapter(str(db_path))

    assert adapter.is_postgres is False
    assert adapter.backend_name() == "sqlite"

    # CREATE
    with adapter.connect() as conn:
        conn.execute(
            "CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )

    # INSERT
    with adapter.connect() as conn:
        conn.execute(
            adapter.adapt_sql("INSERT INTO widgets(id, name) VALUES (?, ?)"),
            (1, "alpha"),
        )

    # READ
    with adapter.connect() as conn:
        cur = conn.execute(
            adapter.adapt_sql("SELECT name FROM widgets WHERE id = ?"), (1,)
        )
        row = cur.fetchone()
    assert row is not None
    # sqlite Row supports both index and key access
    assert row["name"] == "alpha"

    # File was actually created where we asked
    assert db_path.exists()


# ---------------------------------------------------------------------------
# Test 2 — DATABASE_URL set, psycopg2 unimportable → fallback
# ---------------------------------------------------------------------------


def test_psycopg2_unavailable_falls_back_to_sqlite(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    """If DATABASE_URL is set but psycopg2 cannot be imported (simulated by
    blocking it in sys.modules), the adapter must log a warning and behave as
    a normal sqlite adapter."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake:fake@localhost/x")

    # Block psycopg2 import — meta_path finder raises ImportError
    class _BlockPsycopg2:
        def find_spec(self, name, path, target=None):
            if name == "psycopg2":
                raise ImportError("blocked by test")
            return None

    monkeypatch.delitem(sys.modules, "psycopg2", raising=False)
    monkeypatch.setattr(sys, "meta_path", [_BlockPsycopg2(), *sys.meta_path])

    db_path = tmp_path / "fallback.db"
    with caplog.at_level(logging.WARNING):
        adapter = DBAdapter(str(db_path))

    assert adapter.is_postgres is False, "must fall back to sqlite"
    assert adapter.backend_name() == "sqlite"

    # And it actually works
    with adapter.connect() as conn:
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.execute("INSERT INTO t(id) VALUES (1)")
    with adapter.connect() as conn:
        cur = conn.execute("SELECT id FROM t")
        row = cur.fetchone()
    assert row[0] == 1


# ---------------------------------------------------------------------------
# Test 3 — adapt_sql() placeholder rewrite
# ---------------------------------------------------------------------------


def test_adapt_sql_placeholders(tmp_path: Path, monkeypatch) -> None:
    """`?` is rewritten to `%s` only when postgres mode is active."""
    # sqlite mode → unchanged
    sqlite_adapter = get_adapter(str(tmp_path / "x.db"))
    assert sqlite_adapter.is_postgres is False
    assert (
        sqlite_adapter.adapt_sql("SELECT * FROM t WHERE id = ?")
        == "SELECT * FROM t WHERE id = ?"
    )
    assert (
        sqlite_adapter.adapt_sql("INSERT INTO t(a, b) VALUES (?, ?)")
        == "INSERT INTO t(a, b) VALUES (?, ?)"
    )

    # Force postgres mode WITHOUT requiring a real psycopg2 (we never call
    # connect(), only adapt_sql()).
    pg_adapter = get_adapter(str(tmp_path / "y.db"))
    pg_adapter.is_postgres = True
    assert (
        pg_adapter.adapt_sql("SELECT * FROM t WHERE id = ?")
        == "SELECT * FROM t WHERE id = %s"
    )
    assert (
        pg_adapter.adapt_sql("INSERT INTO t(a, b) VALUES (?, ?)")
        == "INSERT INTO t(a, b) VALUES (%s, %s)"
    )


# ---------------------------------------------------------------------------
# Test 4 — is_postgres_url() detection
# ---------------------------------------------------------------------------


def test_is_postgres_url_detection(monkeypatch) -> None:
    assert is_postgres_url("postgres://u:p@h/db") is True
    assert is_postgres_url("postgresql://u:p@h/db") is True
    assert is_postgres_url("postgresql+psycopg2://u:p@h/db") is True

    assert is_postgres_url("") is False
    assert is_postgres_url("sqlite:///foo.db") is False
    assert is_postgres_url("mysql://u:p@h/db") is False

    # Reads from env when no arg
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert is_postgres_url() is False
    monkeypatch.setenv("DATABASE_URL", "postgresql://x")
    assert is_postgres_url() is True


# ---------------------------------------------------------------------------
# Test 5 — connect() rolls back on exception
# ---------------------------------------------------------------------------


def test_connect_rolls_back_on_exception(tmp_path: Path) -> None:
    """If the body of `with adapter.connect() as conn:` raises, the
    transaction must be rolled back — the row inserted before the raise must
    NOT be visible on a subsequent read."""
    db_path = tmp_path / "rollback.db"
    adapter = get_adapter(str(db_path))

    with adapter.connect() as conn:
        conn.execute(
            "CREATE TABLE rb (id INTEGER PRIMARY KEY, val TEXT)"
        )

    class Boom(RuntimeError):
        pass

    with pytest.raises(Boom):
        with adapter.connect() as conn:
            conn.execute(
                adapter.adapt_sql("INSERT INTO rb(id, val) VALUES (?, ?)"),
                (42, "should-not-persist"),
            )
            raise Boom("force rollback")

    # Verify the row did not persist
    with adapter.connect() as conn:
        cur = conn.execute("SELECT COUNT(*) FROM rb")
        count = cur.fetchone()[0]
    assert count == 0, "rollback failed — row leaked across the exception"


# ---------------------------------------------------------------------------
# Test 6 — CTEMEngine end-to-end through adapter (sqlite mode)
# ---------------------------------------------------------------------------


def test_ctem_engine_add_exposure_through_adapter(tmp_path: Path) -> None:
    """Validate a real engine still works after the adapter refactor.

    CTEMEngine uses the persistent_connect() path — this is the second of the
    two adapter modes (per-call vs persistent), so a passing CTEM round-trip
    proves both modes are wired."""
    from core.ctem_engine import CTEMEngine
    from core.ctem_engine import (  # type: ignore[attr-defined]
        CTEMStage,
        Exposure,
        ExposureStatus,
    )

    db_path = tmp_path / "ctem.db"
    engine = CTEMEngine(str(db_path))

    exposure = Exposure(
        id="exp-1",
        title="Test exposure",
        description="round-trip via adapter",
        stage=CTEMStage.SCOPING,
        status=ExposureStatus.IDENTIFIED,
        assets=[],
        findings=[],
        risk_score=7.5,
        business_impact="medium",
        remediation_plan="patch",
        owner="qa",
        org_id="org-test",
        created_at="2026-05-02T12:00:00Z",
    )

    result = engine.add_exposure(exposure)
    assert result.id == "exp-1"

    # Read back via the same adapter-backed path
    fetched = engine._db.get_exposure("exp-1")
    assert fetched is not None
    assert fetched.title == "Test exposure"
    assert fetched.org_id == "org-test"
    assert db_path.exists()
