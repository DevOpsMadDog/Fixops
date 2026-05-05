"""
Perf test: notification_engine persistent SQLite connection.

Measures _record_history throughput before/after the persistent-connection fix.
The fix eliminates per-call sqlite3.connect()/close() overhead.

Expected: >=3x speedup for 100 sequential writes (typically 8x+ on local SSD).
"""
from __future__ import annotations

import asyncio
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(tmp_path):
    from core.notification_engine import NotificationEngine
    return NotificationEngine(db_path=tmp_path / "notif_perf.db")


def _make_action(engine):
    from core.notification_engine import NotificationAction, NotificationChannel
    from core.event_streaming import StreamEvent

    event = StreamEvent(
        event_id=str(uuid.uuid4()),
        event_type="system:alert",
        source="perf_test",
        org_id="org-perf",
        severity="critical",
        payload={"detail": "perf"},
    )
    return NotificationAction(
        rule_id="rule-perf",
        channel=NotificationChannel.WEBSOCKET,
        event=event,
    )


def _old_record_history_loop(engine, action, n: int) -> float:
    """Replicate the old per-call connect/close pattern for baseline timing."""
    start = time.perf_counter()
    for _ in range(n):
        try:
            conn = sqlite3.connect(str(engine._db_path))
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO notification_history
                   (history_id, rule_id, channel, event_id, org_id,
                    status, message, error, created_at, sent_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    action.rule_id,
                    str(action.channel),
                    action.event.event_id,
                    action.event.org_id,
                    "sent",
                    "baseline",
                    None,
                    datetime.now(timezone.utc).isoformat(),
                    None,
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
    return time.perf_counter() - start


# ---------------------------------------------------------------------------
# Tests (sync wrappers around async _record_history)
# ---------------------------------------------------------------------------

@pytest.mark.perf
def test_persistent_conn_speedup(tmp_path):
    """Persistent connection must be >=3x faster than per-call connect for 100 writes."""
    engine = _make_engine(tmp_path)
    action = _make_action(engine)
    n = 100

    # Baseline: old per-call connect pattern
    baseline_s = _old_record_history_loop(engine, action, n)

    # New: persistent connection via _record_history
    async def _run_new():
        start = time.perf_counter()
        for _ in range(n):
            await engine._record_history(action, "sent", "perf-test")
        return time.perf_counter() - start

    new_s = asyncio.run(_run_new())

    speedup = baseline_s / new_s if new_s > 0 else float("inf")
    print(
        f"\n[perf] baseline={baseline_s*1000:.1f}ms  "
        f"new={new_s*1000:.1f}ms  speedup={speedup:.1f}x  n={n}"
    )

    assert speedup >= 3.0, (
        f"Expected >=3x speedup, got {speedup:.1f}x "
        f"(baseline={baseline_s*1000:.1f}ms, new={new_s*1000:.1f}ms)"
    )


@pytest.mark.perf
def test_history_roundtrip(tmp_path):
    """Records written via _record_history must be retrievable via get_history."""
    engine = _make_engine(tmp_path)
    action = _make_action(engine)

    asyncio.run(engine._record_history(action, "sent", "roundtrip-test"))
    rows = engine.get_history(org_id="org-perf", limit=10)
    assert len(rows) >= 1
    assert rows[0]["status"] == "sent"
    assert rows[0]["org_id"] == "org-perf"


@pytest.mark.perf
def test_single_connection_reused(tmp_path):
    """Engine must expose exactly one persistent _conn object (not open new ones)."""
    engine = _make_engine(tmp_path)
    conn_id_before = id(engine._conn)
    action = _make_action(engine)

    async def _run():
        for _ in range(10):
            await engine._record_history(action, "sent", "conn-reuse")

    asyncio.run(_run())
    assert id(engine._conn) == conn_id_before, "Connection object was replaced — not a persistent conn"


@pytest.mark.perf
def test_wal_mode_enabled(tmp_path):
    """WAL journal mode must be active for concurrent reader support."""
    engine = _make_engine(tmp_path)
    row = engine._conn.execute("PRAGMA journal_mode").fetchone()
    assert row[0] == "wal", f"Expected WAL, got {row[0]}"
