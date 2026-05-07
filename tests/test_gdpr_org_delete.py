"""Smoke tests — GDPR right-to-be-forgotten: soft-delete + hard-purge.

Tests:
  1. Soft delete leaves org data in place (rows still exist in engine DB).
  2. Hard purge after 30d removes all org rows from engine tables.

Run:
    python -m pytest tests/test_gdpr_org_delete.py -v --timeout=15
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.org_engine import OrgEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(tmp_path: Path, engine_dbs: list[str] | None = None) -> OrgEngine:
    db_path = str(tmp_path / "orgs.db")
    globs = engine_dbs or []
    return OrgEngine(db_path=db_path, engine_db_globs=globs)


def _create_engine_db(tmp_path: Path, db_name: str, org_id: str, n_rows: int = 3) -> str:
    """Create a fake engine SQLite DB with findings + incidents for org_id."""
    db_path = str(tmp_path / db_name)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY, org_id TEXT, title TEXT)"
    )
    conn.execute(
        "CREATE TABLE incidents (id INTEGER PRIMARY KEY, org_id TEXT, description TEXT)"
    )
    for i in range(n_rows):
        conn.execute("INSERT INTO findings (org_id, title) VALUES (?, ?)", (org_id, f"finding-{i}"))
        conn.execute("INSERT INTO incidents (org_id, description) VALUES (?, ?)", (org_id, f"incident-{i}"))
    conn.commit()
    conn.close()
    return db_path


def _count_rows(db_path: str, table: str, org_id: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        n = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE org_id = ?", (org_id,)
        ).fetchone()[0]
    finally:
        conn.close()
    return n


# ---------------------------------------------------------------------------
# Test 1 — Soft delete leaves engine data intact
# ---------------------------------------------------------------------------

def test_soft_delete_leaves_data_in_place(tmp_path):
    """Soft-deleting an org marks it DELETED but does NOT remove engine rows."""
    org_id = "acme-gdpr-test"
    engine_db = _create_engine_db(tmp_path, "findings.db", org_id, n_rows=5)
    engine = _make_engine(tmp_path, engine_dbs=[str(tmp_path / "*.db")])

    engine.create_org(org_id=org_id, name="Acme GDPR Test")

    # Verify rows exist before soft delete
    assert _count_rows(engine_db, "findings", org_id) == 5
    assert _count_rows(engine_db, "incidents", org_id) == 5

    result = engine.soft_delete_org(org_id)

    # API contract
    assert result["status"] == "DELETED"
    assert result["deleted_at"] is not None
    assert result["purge_after_days"] == 30

    # Engine data must still be present
    assert _count_rows(engine_db, "findings", org_id) == 5
    assert _count_rows(engine_db, "incidents", org_id) == 5

    # Registry row is still there (soft delete, not removed)
    conn = sqlite3.connect(str(tmp_path / "orgs.db"))
    row = conn.execute("SELECT status, deleted_at FROM orgs WHERE org_id = ?", (org_id,)).fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "DELETED"
    assert row[1] is not None


# ---------------------------------------------------------------------------
# Test 2 — Hard purge after 30d removes engine table rows
# ---------------------------------------------------------------------------

def test_hard_purge_after_30d_removes_all_rows(tmp_path):
    """Hard purge (forced) removes all org rows from engine tables."""
    org_id = "beta-gdpr-test"
    engine_db = _create_engine_db(tmp_path, "engine.db", org_id, n_rows=4)
    engine = _make_engine(tmp_path, engine_dbs=[str(tmp_path / "*.db")])

    engine.create_org(org_id=org_id, name="Beta GDPR Test")
    engine.soft_delete_org(org_id)

    # Backdate deleted_at to simulate 31 days ago
    deleted_at_old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
    conn = sqlite3.connect(str(tmp_path / "orgs.db"))
    conn.execute("UPDATE orgs SET deleted_at = ? WHERE org_id = ?", (deleted_at_old, org_id))
    conn.commit()
    conn.close()

    # Verify rows exist before purge
    assert _count_rows(engine_db, "findings", org_id) == 4
    assert _count_rows(engine_db, "incidents", org_id) == 4

    result = engine.hard_purge_org(org_id)

    # API contract
    assert result["status"] == "PURGED"
    assert result["rows_deleted"] >= 8  # 4 findings + 4 incidents

    # Engine rows must be gone
    assert _count_rows(engine_db, "findings", org_id) == 0
    assert _count_rows(engine_db, "incidents", org_id) == 0

    # Registry row must be gone
    conn = sqlite3.connect(str(tmp_path / "orgs.db"))
    row = conn.execute("SELECT org_id FROM orgs WHERE org_id = ?", (org_id,)).fetchone()
    conn.close()
    assert row is None


# ---------------------------------------------------------------------------
# Guard: cannot delete 'default' org
# ---------------------------------------------------------------------------

def test_cannot_soft_delete_default_org(tmp_path):
    engine = _make_engine(tmp_path)
    with pytest.raises(ValueError, match="default"):
        engine.soft_delete_org("default")


# ---------------------------------------------------------------------------
# Guard: hard purge blocked before 30d
# ---------------------------------------------------------------------------

def test_hard_purge_blocked_before_30d(tmp_path):
    org_id = "early-purge-test"
    engine = _make_engine(tmp_path)
    engine.create_org(org_id=org_id, name="Early Purge Test")
    engine.soft_delete_org(org_id)

    with pytest.raises(ValueError, match="30-day window"):
        engine.hard_purge_org(org_id)
