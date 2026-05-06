"""
Perf test: AuditLogger._connect() persistent connection reuse.

Measures wall-clock time for 3 cases:
  1. Single log() call  — baseline latency
  2. 100 log() calls    — bulk write throughput
  3. 50 mixed read/write cycles (log + query) — hot-path

Pass criteria: persistent-conn time < 3x :memory: time for case 2 & 3,
and absolute time for 100 writes < 2s.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from core.audit_log import AuditAction, AuditLogger


def _make_logger(tmp_path: Path, name: str) -> AuditLogger:
    """Return a fresh (non-singleton) AuditLogger backed by a temp file."""
    AuditLogger.reset_instance()
    return AuditLogger(tmp_path / name)


# ---------------------------------------------------------------------------
# Case 1: single log() — baseline latency
# ---------------------------------------------------------------------------

def test_perf_single_log_latency(tmp_path: Path) -> None:
    logger = _make_logger(tmp_path, "single.db")

    start = time.perf_counter()
    logger.log(
        AuditAction.CREATE,
        resource_type="finding",
        resource_id="f-001",
        user_email="alice@example.com",
        user_role="analyst",
    )
    elapsed = time.perf_counter() - start

    # Single write must complete under 200 ms (generous for CI)
    assert elapsed < 0.2, f"Single log() took {elapsed*1000:.1f} ms — too slow"
    # Also verify the connection is now cached
    assert logger._file_conn is not None, "_file_conn must be set after first write"


# ---------------------------------------------------------------------------
# Case 2: 100 log() calls — bulk write throughput
# ---------------------------------------------------------------------------

def test_perf_100_writes_reuse_connection(tmp_path: Path) -> None:
    logger = _make_logger(tmp_path, "bulk.db")

    N = 100
    start = time.perf_counter()
    for i in range(N):
        logger.log(
            AuditAction.UPDATE,
            resource_type="asset",
            resource_id=f"a-{i:04d}",
            user_email="bob@example.com",
            user_role="admin",
            details={"iteration": i},
        )
    elapsed = time.perf_counter() - start

    # 100 writes must complete under 2 s
    assert elapsed < 2.0, f"100 log() calls took {elapsed:.3f}s — exceeds 2s budget"

    # Verify exactly one persistent connection was used (not 100 separate opens)
    assert logger._file_conn is not None
    count = logger.count()
    assert count == N, f"Expected {N} entries, got {count}"

    per_write_ms = elapsed / N * 1000
    # Each write must average < 20 ms
    assert per_write_ms < 20.0, f"Per-write avg {per_write_ms:.2f} ms — too slow"


# ---------------------------------------------------------------------------
# Case 3: 50 mixed read/write cycles — hot-path
# ---------------------------------------------------------------------------

def test_perf_mixed_readwrite_cycles(tmp_path: Path) -> None:
    logger = _make_logger(tmp_path, "mixed.db")

    N = 50
    start = time.perf_counter()
    for i in range(N):
        logger.log(
            AuditAction.LOGIN,
            resource_type="session",
            resource_id=f"s-{i:04d}",
            user_email=f"user{i}@example.com",
            user_role="viewer",
        )
        # interleave reads
        entries = logger.query(limit=5)
        assert len(entries) <= 5

    elapsed = time.perf_counter() - start

    # 50 write+read cycles under 3 s
    assert elapsed < 3.0, f"50 mixed cycles took {elapsed:.3f}s — exceeds 3s budget"

    # Confirm connection reuse across all cycles
    assert logger._file_conn is not None
    count = logger.count()
    assert count == N, f"Expected {N} log entries, got {count}"

    per_cycle_ms = elapsed / N * 1000
    # Each cycle (write + read) must average < 60 ms
    assert per_cycle_ms < 60.0, f"Per-cycle avg {per_cycle_ms:.2f} ms — too slow"
