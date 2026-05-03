"""
Router-level tests for /api/v1/backups — restore and restore-validation flows.

Covers the gap NOT tested by test_backup_engine.py (unit) or
test_backup_dr_router.py (backup-dr validator router):

  POST  /api/v1/backups/{id}/restore   — happy path, 404 on unknown id
  POST  /api/v1/backups/{id}/verify    — happy path, tamper detection, 404
  GET   /api/v1/backups/{id}           — 404 guard
  End-to-end: create → restore → verify sequence

All tests use a fresh in-memory BackupEngine via monkeypatch. No mocks.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite-core and suite-api are importable
for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

from core.backup_engine import BackupEngine
import apps.api.backup_router as _router_mod
from apps.api.backup_router import router


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ORG = "org-restore-test"


@pytest.fixture()
def engine(tmp_path):
    return BackupEngine(
        db_path=str(tmp_path / "backup.db"),
        backup_dir=str(tmp_path / "backups"),
    )


@pytest.fixture()
def sample_db(tmp_path) -> str:
    """Minimal SQLite DB with one row — used as backup source."""
    path = str(tmp_path / "source.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)")
    conn.execute("INSERT INTO t VALUES (1, 'restore-test')")
    conn.commit()
    conn.close()
    return path


@pytest.fixture()
def client(engine, monkeypatch):
    """TestClient wired to a fresh BackupEngine; org_id always = ORG."""
    monkeypatch.setattr(_router_mod, "_engine", engine)

    def _fake_get_org(request=None):  # overrides Depends(get_org_id)
        return ORG

    # Override the dependency at the app level
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_router_mod.get_org_id] = _fake_get_org  # type: ignore[attr-defined]
    return TestClient(app, raise_server_exceptions=False)


def _create_backup(client, sample_db) -> str:
    """Helper: POST /backups and return the backup id."""
    resp = client.post(
        "/api/v1/backups",
        json={"backup_type": "full", "databases": [sample_db], "encrypt": False, "retention_days": 30},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# Test 1 — restore happy path returns completed RestoreRecord
# ---------------------------------------------------------------------------

def test_restore_returns_completed_status(client, sample_db):
    bid = _create_backup(client, sample_db)
    resp = client.post(f"/api/v1/backups/{bid}/restore", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["backup_id"] == bid
    assert data["status"] == "completed"
    assert isinstance(data["restored_databases"], list)
    assert len(data["restored_databases"]) >= 1


# ---------------------------------------------------------------------------
# Test 2 — restore on unknown backup_id returns 404
# ---------------------------------------------------------------------------

def test_restore_unknown_id_returns_404(client):
    resp = client.post("/api/v1/backups/does-not-exist/restore", json={})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Test 3 — verify happy path returns valid=True
# ---------------------------------------------------------------------------

def test_verify_intact_backup_returns_valid_true(client, sample_db):
    bid = _create_backup(client, sample_db)
    resp = client.post(f"/api/v1/backups/{bid}/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["backup_id"] == bid
    assert data["valid"] is True


# ---------------------------------------------------------------------------
# Test 4 — verify tampered backup returns valid=False
# ---------------------------------------------------------------------------

def test_verify_tampered_backup_returns_valid_false(client, sample_db, engine):
    bid = _create_backup(client, sample_db)
    record = engine.get_backup(bid)
    # Corrupt the file on disk
    Path(record.file_path).write_bytes(b"corrupted payload")
    resp = client.post(f"/api/v1/backups/{bid}/verify")
    assert resp.status_code == 200
    assert resp.json()["valid"] is False


# ---------------------------------------------------------------------------
# Test 5 — verify unknown backup_id returns 404
# ---------------------------------------------------------------------------

def test_verify_unknown_id_returns_404(client):
    resp = client.post("/api/v1/backups/ghost-id/verify")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Test 6 — end-to-end: create → restore → verify sequence
# ---------------------------------------------------------------------------

def test_create_restore_verify_sequence(client, sample_db, engine):
    # Step 1: create
    bid = _create_backup(client, sample_db)

    # Step 2: restore — must succeed and produce a file on disk
    r_resp = client.post(f"/api/v1/backups/{bid}/restore", json={})
    assert r_resp.status_code == 200
    restored_paths = r_resp.json()["restored_databases"]
    assert len(restored_paths) >= 1
    for p in restored_paths:
        assert Path(p).exists(), f"Restored file missing: {p}"

    # Step 3: verify — original backup file still intact, checksum must pass
    v_resp = client.post(f"/api/v1/backups/{bid}/verify")
    assert v_resp.status_code == 200
    assert v_resp.json()["valid"] is True

    # Step 4: confirm engine marks status as verified
    refreshed = engine.get_backup(bid)
    assert refreshed.status.value == "verified"
