"""
Tests for BackupEngine — backup creation, restore, verification,
scheduling, retention cleanup, encryption, and stats.

Usage:
    pytest tests/test_backup_engine.py -x --tb=short --timeout=10 -q
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

import pytest

# Ensure suite-core is importable
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.backup_engine import (
    BackupEngine,
    BackupRecord,
    BackupStatus,
    BackupType,
    RestoreRecord,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """BackupEngine with isolated temp directories."""
    db_path = str(tmp_path / "backup.db")
    backup_dir = str(tmp_path / "backups")
    return BackupEngine(db_path=db_path, backup_dir=backup_dir)


@pytest.fixture
def sample_sqlite_db(tmp_path) -> str:
    """Create a minimal SQLite database for backup tests."""
    db_path = str(tmp_path / "sample.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO items VALUES (1, 'alpha')")
    conn.execute("INSERT INTO items VALUES (2, 'beta')")
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def second_sqlite_db(tmp_path) -> str:
    """Create a second SQLite database."""
    db_path = str(tmp_path / "second.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT)")
    conn.execute("INSERT INTO logs VALUES (1, 'hello')")
    conn.commit()
    conn.close()
    return db_path


ORG = "org-test-001"


# ---------------------------------------------------------------------------
# BackupStatus / BackupType enums
# ---------------------------------------------------------------------------


def test_backup_status_values():
    assert BackupStatus.PENDING == "pending"
    assert BackupStatus.IN_PROGRESS == "in_progress"
    assert BackupStatus.COMPLETED == "completed"
    assert BackupStatus.FAILED == "failed"
    assert BackupStatus.VERIFIED == "verified"


def test_backup_type_values():
    assert BackupType.FULL == "full"
    assert BackupType.INCREMENTAL == "incremental"
    assert BackupType.CONFIG_ONLY == "config_only"


# ---------------------------------------------------------------------------
# BackupRecord / RestoreRecord models
# ---------------------------------------------------------------------------


def test_backup_record_fields():
    now = datetime.now(timezone.utc)
    r = BackupRecord(
        id="bid-1",
        type=BackupType.FULL,
        status=BackupStatus.COMPLETED,
        databases=["a.db", "b.db"],
        file_path="/tmp/backup.zip",
        file_size_bytes=1024,
        checksum="abc123",
        encrypted=False,
        created_at=now,
        completed_at=now,
        retention_days=30,
        org_id=ORG,
    )
    assert r.id == "bid-1"
    assert r.databases == ["a.db", "b.db"]
    assert r.retention_days == 30


def test_restore_record_fields():
    now = datetime.now(timezone.utc)
    r = RestoreRecord(
        id="rid-1",
        backup_id="bid-1",
        status=BackupStatus.COMPLETED,
        restored_databases=["a.db"],
        started_at=now,
        completed_at=now,
        error=None,
    )
    assert r.backup_id == "bid-1"
    assert r.error is None


# ---------------------------------------------------------------------------
# create_backup
# ---------------------------------------------------------------------------


def test_create_backup_no_databases(engine):
    record = engine.create_backup(org_id=ORG)
    assert record.status == BackupStatus.COMPLETED
    assert record.org_id == ORG
    assert record.type == BackupType.FULL
    assert record.file_size_bytes > 0
    assert len(record.checksum) == 64  # sha256 hex
    assert Path(record.file_path).exists()


def test_create_backup_with_database(engine, sample_sqlite_db):
    record = engine.create_backup(org_id=ORG, databases=[sample_sqlite_db])
    assert record.status == BackupStatus.COMPLETED
    assert sample_sqlite_db in record.databases
    assert Path(record.file_path).exists()


def test_create_backup_multiple_databases(engine, sample_sqlite_db, second_sqlite_db):
    record = engine.create_backup(org_id=ORG, databases=[sample_sqlite_db, second_sqlite_db])
    assert record.status == BackupStatus.COMPLETED
    assert len(record.databases) == 2


def test_create_backup_incremental_type(engine):
    record = engine.create_backup(org_id=ORG, backup_type=BackupType.INCREMENTAL)
    assert record.type == BackupType.INCREMENTAL
    assert record.status == BackupStatus.COMPLETED


def test_create_backup_config_only_type(engine):
    record = engine.create_backup(org_id=ORG, backup_type=BackupType.CONFIG_ONLY)
    assert record.type == BackupType.CONFIG_ONLY


def test_create_backup_with_retention(engine):
    record = engine.create_backup(org_id=ORG, retention_days=7)
    assert record.retention_days == 7


def test_create_backup_returns_backup_record_type(engine):
    record = engine.create_backup(org_id=ORG)
    assert isinstance(record, BackupRecord)


def test_create_backup_completed_at_set(engine):
    record = engine.create_backup(org_id=ORG)
    assert record.completed_at is not None


def test_create_backup_nonexistent_db_does_not_raise(engine):
    # Should succeed but include an empty snapshot for missing dbs
    record = engine.create_backup(org_id=ORG, databases=["/nonexistent/path.db"])
    assert record.status == BackupStatus.COMPLETED


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


def test_create_backup_encrypted(engine, sample_sqlite_db):
    record = engine.create_backup(org_id=ORG, databases=[sample_sqlite_db], encrypt=True)
    assert record.encrypted is True
    assert record.status == BackupStatus.COMPLETED
    # File should start with encryption header
    raw = Path(record.file_path).read_bytes()
    assert raw.startswith(b"ALDECI_ENC_V1:")


def test_encrypt_decrypt_roundtrip(engine):
    data = b"Hello ALDECI backup data 12345"
    key = b"test-key"
    encrypted = engine._encrypt_data(data, key)
    assert encrypted != data
    decrypted = engine._decrypt_data(encrypted, key)
    assert decrypted == data


def test_encrypt_adds_header(engine):
    data = b"some bytes"
    encrypted = engine._encrypt_data(data, b"key")
    assert encrypted.startswith(b"ALDECI_ENC_V1:")


def test_decrypt_without_header(engine):
    # _decrypt_data should handle data that has no header (pass-through XOR)
    data = b"raw"
    key = b"k"
    result = engine._decrypt_data(data, key)
    assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# verify_backup
# ---------------------------------------------------------------------------


def test_verify_backup_valid(engine, sample_sqlite_db):
    record = engine.create_backup(org_id=ORG, databases=[sample_sqlite_db])
    assert engine.verify_backup(record.id) is True


def test_verify_backup_marks_verified(engine):
    record = engine.create_backup(org_id=ORG)
    engine.verify_backup(record.id)
    refreshed = engine.get_backup(record.id)
    assert refreshed.status == BackupStatus.VERIFIED


def test_verify_backup_tampered_file(engine):
    record = engine.create_backup(org_id=ORG)
    # Tamper the file
    Path(record.file_path).write_bytes(b"corrupted data")
    assert engine.verify_backup(record.id) is False


def test_verify_backup_missing_file(engine):
    record = engine.create_backup(org_id=ORG)
    Path(record.file_path).unlink()
    assert engine.verify_backup(record.id) is False


def test_verify_backup_nonexistent_id(engine):
    assert engine.verify_backup("does-not-exist") is False


# ---------------------------------------------------------------------------
# get_backup / list_backups
# ---------------------------------------------------------------------------


def test_get_backup_returns_record(engine):
    record = engine.create_backup(org_id=ORG)
    fetched = engine.get_backup(record.id)
    assert fetched is not None
    assert fetched.id == record.id


def test_get_backup_nonexistent_returns_none(engine):
    assert engine.get_backup("bad-id") is None


def test_list_backups_returns_all(engine):
    engine.create_backup(org_id=ORG)
    engine.create_backup(org_id=ORG)
    backups = engine.list_backups(org_id=ORG)
    assert len(backups) >= 2


def test_list_backups_type_filter(engine):
    engine.create_backup(org_id=ORG, backup_type=BackupType.FULL)
    engine.create_backup(org_id=ORG, backup_type=BackupType.INCREMENTAL)
    full_only = engine.list_backups(org_id=ORG, type_filter=BackupType.FULL)
    assert all(b.type == BackupType.FULL for b in full_only)


def test_list_backups_org_isolation(engine):
    engine.create_backup(org_id="org-A")
    engine.create_backup(org_id="org-B")
    a_backups = engine.list_backups(org_id="org-A")
    assert all(b.org_id == "org-A" for b in a_backups)


# ---------------------------------------------------------------------------
# delete_backup
# ---------------------------------------------------------------------------


def test_delete_backup_removes_record(engine):
    record = engine.create_backup(org_id=ORG)
    engine.delete_backup(record.id)
    assert engine.get_backup(record.id) is None


def test_delete_backup_removes_file(engine):
    record = engine.create_backup(org_id=ORG)
    fp = record.file_path
    engine.delete_backup(record.id)
    assert not Path(fp).exists()


def test_delete_backup_nonexistent_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.delete_backup("nonexistent-id")


# ---------------------------------------------------------------------------
# restore_backup
# ---------------------------------------------------------------------------


def test_restore_backup_succeeds(engine, sample_sqlite_db, tmp_path):
    record = engine.create_backup(org_id=ORG, databases=[sample_sqlite_db])
    restore = engine.restore_backup(backup_id=record.id)
    assert restore.status == BackupStatus.COMPLETED
    assert isinstance(restore, RestoreRecord)


def test_restore_backup_creates_files(engine, sample_sqlite_db, tmp_path):
    record = engine.create_backup(org_id=ORG, databases=[sample_sqlite_db])
    restore = engine.restore_backup(backup_id=record.id)
    assert len(restore.restored_databases) > 0
    for path in restore.restored_databases:
        assert Path(path).exists()


def test_restore_encrypted_backup(engine, sample_sqlite_db):
    record = engine.create_backup(org_id=ORG, databases=[sample_sqlite_db], encrypt=True)
    restore = engine.restore_backup(backup_id=record.id)
    assert restore.status == BackupStatus.COMPLETED


def test_restore_nonexistent_backup_raises(engine):
    with pytest.raises((ValueError, RuntimeError)):
        engine.restore_backup(backup_id="nonexistent")


# ---------------------------------------------------------------------------
# schedule_backup / get_schedules
# ---------------------------------------------------------------------------


def test_schedule_backup_returns_dict(engine):
    sched = engine.schedule_backup(
        org_id=ORG, backup_type=BackupType.FULL, frequency="daily"
    )
    assert sched["org_id"] == ORG
    assert sched["backup_type"] == "full"
    assert sched["frequency"] == "daily"
    assert "next_run" in sched


def test_schedule_backup_weekly(engine):
    sched = engine.schedule_backup(
        org_id=ORG, backup_type=BackupType.INCREMENTAL, frequency="weekly"
    )
    assert sched["frequency"] == "weekly"


def test_get_schedules_returns_list(engine):
    engine.schedule_backup(org_id=ORG, backup_type=BackupType.FULL, frequency="daily")
    engine.schedule_backup(org_id=ORG, backup_type=BackupType.INCREMENTAL, frequency="weekly")
    schedules = engine.get_schedules(org_id=ORG)
    assert len(schedules) >= 2


def test_get_schedules_org_isolation(engine):
    engine.schedule_backup(org_id="org-X", backup_type=BackupType.FULL, frequency="daily")
    engine.schedule_backup(org_id="org-Y", backup_type=BackupType.FULL, frequency="daily")
    x_scheds = engine.get_schedules(org_id="org-X")
    assert all(s["org_id"] == "org-X" for s in x_scheds)


# ---------------------------------------------------------------------------
# cleanup_expired
# ---------------------------------------------------------------------------


def test_cleanup_expired_removes_old_backups(engine, tmp_path):
    # Create a backup then manually fudge the created_at to be expired
    record = engine.create_backup(org_id=ORG, retention_days=1)

    # Force created_at to be 2 days ago directly in the DB
    conn = sqlite3.connect(str(engine.db_path))
    old_ts = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    conn.execute(
        "UPDATE backup_records SET created_at=? WHERE id=?", (old_ts, record.id)
    )
    conn.commit()
    conn.close()

    removed = engine.cleanup_expired(org_id=ORG)
    assert removed >= 1
    assert engine.get_backup(record.id) is None


def test_cleanup_expired_keeps_fresh_backups(engine):
    record = engine.create_backup(org_id=ORG, retention_days=30)
    removed = engine.cleanup_expired(org_id=ORG)
    assert removed == 0
    assert engine.get_backup(record.id) is not None


def test_cleanup_expired_returns_count(engine):
    result = engine.cleanup_expired(org_id=ORG)
    assert isinstance(result, int)


# ---------------------------------------------------------------------------
# get_backup_stats
# ---------------------------------------------------------------------------


def test_get_backup_stats_empty(engine):
    stats = engine.get_backup_stats(org_id="empty-org")
    assert stats["total_backups"] == 0
    assert stats["total_size_bytes"] == 0
    assert stats["last_backup"] is None


def test_get_backup_stats_with_backups(engine):
    engine.create_backup(org_id=ORG, backup_type=BackupType.FULL)
    engine.create_backup(org_id=ORG, backup_type=BackupType.INCREMENTAL)
    stats = engine.get_backup_stats(org_id=ORG)
    assert stats["total_backups"] >= 2
    assert stats["total_size_bytes"] > 0
    assert stats["last_backup"] is not None
    assert "full" in stats["by_type"]


def test_get_backup_stats_by_type(engine):
    engine.create_backup(org_id=ORG, backup_type=BackupType.FULL)
    engine.create_backup(org_id=ORG, backup_type=BackupType.FULL)
    engine.create_backup(org_id=ORG, backup_type=BackupType.CONFIG_ONLY)
    stats = engine.get_backup_stats(org_id=ORG)
    assert stats["by_type"].get("full", 0) >= 2
    assert stats["by_type"].get("config_only", 0) >= 1


# ---------------------------------------------------------------------------
# _calculate_checksum
# ---------------------------------------------------------------------------


def test_calculate_checksum_is_sha256(engine, tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello world")
    checksum = engine._calculate_checksum(str(f))
    import hashlib
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert checksum == expected


def test_calculate_checksum_length(engine, tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"test")
    assert len(engine._calculate_checksum(str(f))) == 64


# ---------------------------------------------------------------------------
# _snapshot_database
# ---------------------------------------------------------------------------


def test_snapshot_database_returns_bytes(engine, sample_sqlite_db):
    data = engine._snapshot_database(sample_sqlite_db)
    assert isinstance(data, bytes)
    assert len(data) > 0


def test_snapshot_nonexistent_db_returns_empty(engine):
    data = engine._snapshot_database("/nonexistent/path.db")
    assert data == b""
