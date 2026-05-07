"""Smoke tests for audit log retention and purging."""

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.audit_log import AuditAction, AuditLogger


@pytest.fixture
def temp_db():
    """Create a temporary audit database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


def test_audit_logger_purge_old_removes_old_entries(temp_db):
    """Test that purge_old() removes entries older than retention_days."""
    AuditLogger.reset_instance()
    logger = AuditLogger(db_path=temp_db)

    # Add an entry from 100 days ago
    old_timestamp = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    conn = logger._connect()
    conn.execute(
        """
        INSERT INTO audit_log
        (id, timestamp, user_email, user_role, action, resource_type, resource_id, details, correlation_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "old-entry-1",
            old_timestamp,
            "alice@example.com",
            "analyst",
            "create",
            "finding",
            "f-123",
            "{}",
            "corr-1",
        ),
    )
    conn.commit()

    # Add a recent entry
    logger.log(
        action=AuditAction.CREATE,
        resource_type="finding",
        resource_id="f-456",
        user_email="bob@example.com",
        user_role="analyst",
    )

    # Purge entries older than 90 days
    deleted = logger.purge_old(retention_days=90)

    assert deleted == 1, "Should have deleted exactly 1 old entry"

    # Verify the old entry is gone
    all_entries = logger.query(limit=1000)
    assert len(all_entries) == 1, "Should have 1 entry remaining"
    assert all_entries[0].user_email == "bob@example.com"


def test_audit_logger_purge_old_keeps_recent_entries(temp_db):
    """Test that purge_old() keeps entries within the retention period."""
    AuditLogger.reset_instance()
    logger = AuditLogger(db_path=temp_db)

    # Add entries
    for i in range(5):
        logger.log(
            action=AuditAction.CREATE,
            resource_type="finding",
            resource_id=f"f-{i}",
            user_email=f"user{i}@example.com",
            user_role="analyst",
        )

    # Purge with 90-day retention
    deleted = logger.purge_old(retention_days=90)

    assert deleted == 0, "Should not delete recent entries"

    # All entries should still be there
    all_entries = logger.query(limit=1000)
    assert len(all_entries) == 5


def test_audit_logger_purge_old_respects_env_override(temp_db, monkeypatch):
    """Test that FIXOPS_AUDIT_RETENTION_DAYS env var is read correctly."""
    monkeypatch.setenv("FIXOPS_AUDIT_RETENTION_DAYS", "30")

    AuditLogger.reset_instance()
    logger = AuditLogger(db_path=temp_db)

    # Add an entry from 50 days ago (beyond the 30-day retention)
    old_timestamp = (datetime.now(timezone.utc) - timedelta(days=50)).isoformat()
    conn = logger._connect()
    conn.execute(
        """
        INSERT INTO audit_log
        (id, timestamp, user_email, user_role, action, resource_type, resource_id, details, correlation_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "old-entry-2",
            old_timestamp,
            "alice@example.com",
            "analyst",
            "create",
            "finding",
            "f-123",
            "{}",
            "corr-2",
        ),
    )
    conn.commit()

    # Purge with 30-day retention
    deleted = logger.purge_old(retention_days=30)

    assert deleted == 1, "Should have deleted entry older than 30 days"
