"""Tests for OrgEngine — multi-tenancy org management.

Covers:
- DB initialisation and idempotency
- Default org always present
- create_org happy path and duplicate rejection
- list_orgs with and without discovery
- get_org present / missing
- get_org_summary counts rows from engine DBs
- Discovery scans engine DBs for distinct org_ids
- Empty org_id rejected

Total: 15 tests.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.org_engine import OrgEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine_db(tmp_path: Path, db_name: str, org_ids: list[str]) -> str:
    """Create a minimal engine-style SQLite DB with an org_id column."""
    db_path = str(tmp_path / db_name)
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE alerts (id TEXT, org_id TEXT, title TEXT)")
    for oid in org_ids:
        conn.execute("INSERT INTO alerts VALUES (?, ?, ?)", (oid + "_row", oid, "test"))
    conn.commit()
    conn.close()
    return db_path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    db_path = str(tmp_path / "orgs_test.db")
    return OrgEngine(db_path=db_path, engine_db_globs=[])


@pytest.fixture()
def engine_with_discovery(tmp_path):
    """OrgEngine wired to scan two fake engine DBs."""
    fake_db1 = _make_engine_db(tmp_path, "engine1.db", ["acme", "beta"])
    fake_db2 = _make_engine_db(tmp_path, "engine2.db", ["acme", "gamma"])
    db_path = str(tmp_path / "orgs_disc.db")
    return OrgEngine(
        db_path=db_path,
        engine_db_globs=[str(tmp_path / "engine*.db")],
    )


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "init_test.db")
    OrgEngine(db_path=db, engine_db_globs=[])
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "idem.db")
    OrgEngine(db_path=db, engine_db_globs=[])
    OrgEngine(db_path=db, engine_db_globs=[])  # second init should not raise


def test_default_org_always_present(engine):
    orgs = engine.list_orgs(include_discovered=False)
    org_ids = [o["org_id"] for o in orgs]
    assert "default" in org_ids


# ---------------------------------------------------------------------------
# 2. create_org
# ---------------------------------------------------------------------------

def test_create_org_returns_org_dict(engine):
    org = engine.create_org("acme-corp", "Acme Corp", "A test org")
    assert org["org_id"] == "acme-corp"
    assert org["name"] == "Acme Corp"
    assert org["description"] == "A test org"
    assert org["is_active"] is True
    assert org["source"] == "registry"
    assert org["created_at"] is not None


def test_create_org_duplicate_raises(engine):
    engine.create_org("dup-org", "Dup Org")
    with pytest.raises(ValueError, match="already exists"):
        engine.create_org("dup-org", "Dup Again")


def test_create_org_empty_id_raises(engine):
    with pytest.raises(ValueError, match="must not be empty"):
        engine.create_org("", "Empty ID Org")


def test_create_org_appears_in_list(engine):
    engine.create_org("listed-org", "Listed Org")
    orgs = engine.list_orgs(include_discovered=False)
    ids = [o["org_id"] for o in orgs]
    assert "listed-org" in ids


# ---------------------------------------------------------------------------
# 3. get_org
# ---------------------------------------------------------------------------

def test_get_org_existing(engine):
    engine.create_org("get-test", "Get Test")
    org = engine.get_org("get-test")
    assert org is not None
    assert org["org_id"] == "get-test"


def test_get_org_missing_returns_none(engine):
    result = engine.get_org("nonexistent-org-xyz")
    assert result is None


# ---------------------------------------------------------------------------
# 4. list_orgs with discovery
# ---------------------------------------------------------------------------

def test_list_orgs_includes_discovered(engine_with_discovery):
    orgs = engine_with_discovery.list_orgs(include_discovered=True)
    ids = [o["org_id"] for o in orgs]
    assert "acme" in ids
    assert "beta" in ids
    assert "gamma" in ids


def test_list_orgs_discovery_source_label(engine_with_discovery):
    orgs = engine_with_discovery.list_orgs(include_discovered=True)
    discovered = [o for o in orgs if o["org_id"] == "acme"]
    assert len(discovered) == 1
    assert discovered[0]["source"] == "discovered"


def test_list_orgs_no_discovery_excludes_engine_orgs(engine_with_discovery):
    orgs = engine_with_discovery.list_orgs(include_discovered=False)
    ids = [o["org_id"] for o in orgs]
    assert "acme" not in ids
    assert "beta" not in ids


# ---------------------------------------------------------------------------
# 5. get_org_summary
# ---------------------------------------------------------------------------

def test_get_org_summary_counts_rows(tmp_path):
    fake_db = _make_engine_db(tmp_path, "summary_engine.db", ["summary-org", "summary-org", "other-org"])
    # Actually insert two rows for summary-org — recreate properly
    db_path = str(tmp_path / "summary_engine2.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE findings (id TEXT, org_id TEXT, title TEXT)")
    conn.execute("INSERT INTO findings VALUES ('r1', 'summary-org', 'Finding 1')")
    conn.execute("INSERT INTO findings VALUES ('r2', 'summary-org', 'Finding 2')")
    conn.execute("INSERT INTO findings VALUES ('r3', 'other-org', 'Other')")
    conn.commit()
    conn.close()

    org_db = str(tmp_path / "orgs_summary.db")
    eng = OrgEngine(db_path=org_db, engine_db_globs=[str(tmp_path / "summary_engine2.db")])
    summary = eng.get_org_summary("summary-org")

    assert summary["org_id"] == "summary-org"
    assert summary["summary"]["total_rows"] == 2
    assert summary["summary"]["engines_with_data"] == 1


def test_get_org_summary_missing_org_still_returns(engine):
    summary = engine.get_org_summary("totally-unknown-org")
    assert summary["org_id"] == "totally-unknown-org"
    assert "summary" in summary
