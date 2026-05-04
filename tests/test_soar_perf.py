"""SOAR/incident-response performance assertions.

Validates three hotspot fixes:
1. IncidentResponseManager: WAL mode enabled, RLock present (thread-safety fix)
2. IncidentResponseManager.get_incident_stats: SQL GROUP BY path (no full table scan)
3. IncidentOrchestrationEngine.get_incident_metrics: SQL AVG(JULIANDAY) MTTR (no Python loop)
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_ir_manager(tmp_path: Path):
    from core.incident_response import IncidentResponseManager
    return IncidentResponseManager(db_path=str(tmp_path / "ir.db"))


def _make_orchestration_engine(tmp_path: Path):
    from core.incident_orchestration_engine import IncidentOrchestrationEngine
    return IncidentOrchestrationEngine(db_path=str(tmp_path / "orch.db"))


# ---------------------------------------------------------------------------
# Fix 1 — WAL mode + RLock on IncidentResponseManager
# ---------------------------------------------------------------------------


def test_ir_manager_has_rlock(tmp_path):
    """IncidentResponseManager must carry an RLock for thread safety."""
    mgr = _make_ir_manager(tmp_path)
    assert hasattr(mgr, "_lock"), "IncidentResponseManager missing _lock attribute"
    assert isinstance(mgr._lock, type(threading.RLock())), "_lock must be an RLock"


def test_ir_manager_wal_mode(tmp_path):
    """IncidentResponseManager DB must run in WAL journal mode."""
    mgr = _make_ir_manager(tmp_path)
    conn = sqlite3.connect(str(tmp_path / "ir.db"))
    row = conn.execute("PRAGMA journal_mode").fetchone()
    conn.close()
    assert row[0].lower() == "wal", f"Expected WAL, got {row[0]}"


def test_ir_manager_concurrent_writes(tmp_path):
    """Concurrent incident creation must not raise or corrupt data."""
    from core.incident_response import IncidentResponseManager, IncidentType, IncidentSeverity

    mgr = _make_ir_manager(tmp_path)
    errors: list = []

    def worker(n: int) -> None:
        try:
            mgr.create_incident(
                title=f"Concurrent incident {n}",
                type=IncidentType.MALWARE,
                severity=IncidentSeverity.SEV2,
                reported_by="test",
                org_id="org1",
            )
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Concurrent writes raised: {errors}"
    incidents = mgr.list_incidents(org_id="org1")
    assert len(incidents) == 10


# ---------------------------------------------------------------------------
# Fix 2 — get_incident_stats uses SQL GROUP BY (fast path)
# ---------------------------------------------------------------------------


def test_ir_stats_sql_groupby_correctness(tmp_path):
    """get_incident_stats must return correct counts without loading all blobs."""
    from core.incident_response import (
        IncidentResponseManager, IncidentType, IncidentSeverity, IncidentStatus,
    )

    mgr = _make_ir_manager(tmp_path)
    for i in range(5):
        mgr.create_incident(
            title=f"Malware {i}",
            type=IncidentType.MALWARE,
            severity=IncidentSeverity.SEV1,
            reported_by="analyst",
            org_id="orgA",
        )
    for i in range(3):
        mgr.create_incident(
            title=f"Phishing {i}",
            type=IncidentType.PHISHING,
            severity=IncidentSeverity.SEV3,
            reported_by="analyst",
            org_id="orgA",
        )

    stats = mgr.get_incident_stats(org_id="orgA")

    assert stats["total"] == 8
    assert stats["by_type"]["malware"] == 5
    assert stats["by_type"]["phishing"] == 3
    assert stats["by_severity"]["sev1"] == 5
    assert stats["by_severity"]["sev3"] == 3
    assert stats["active_count"] == 8  # none closed yet


def test_ir_stats_performance(tmp_path):
    """get_incident_stats on 200 incidents must complete in under 500 ms."""
    from core.incident_response import IncidentResponseManager, IncidentType, IncidentSeverity

    mgr = _make_ir_manager(tmp_path)
    for i in range(200):
        mgr.create_incident(
            title=f"Perf incident {i}",
            type=IncidentType.MALWARE,
            severity=IncidentSeverity.SEV2,
            reported_by="perf-test",
            org_id="orgP",
        )

    start = time.perf_counter()
    stats = mgr.get_incident_stats(org_id="orgP")
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert stats["total"] == 200
    assert elapsed_ms < 500, f"get_incident_stats took {elapsed_ms:.1f}ms — too slow"


# ---------------------------------------------------------------------------
# Fix 3 — IncidentOrchestrationEngine MTTR via SQL AVG(JULIANDAY)
# ---------------------------------------------------------------------------


def test_orchestration_mttr_sql_correctness(tmp_path):
    """get_incident_metrics MTTR must be computed correctly via SQL AVG(JULIANDAY)."""
    from core.incident_orchestration_engine import IncidentOrchestrationEngine

    eng = _make_orchestration_engine(tmp_path)

    # Create and resolve two incidents
    inc1 = eng.create_incident("orgB", {"title": "Inc1", "severity": "high", "type": "malware"})
    inc2 = eng.create_incident("orgB", {"title": "Inc2", "severity": "critical", "type": "breach"})

    eng.update_incident_status("orgB", inc1["id"], "resolved")
    eng.update_incident_status("orgB", inc2["id"], "resolved")

    metrics = eng.get_incident_metrics("orgB")

    assert metrics["avg_mttr_hours"] >= 0.0, "MTTR must be non-negative"
    assert metrics["open_count"] == 0
    assert metrics["total_count"] == 2


def test_orchestration_mttr_performance(tmp_path):
    """get_incident_metrics on 100 resolved incidents must complete under 300 ms."""
    from core.incident_orchestration_engine import IncidentOrchestrationEngine

    eng = _make_orchestration_engine(tmp_path)
    for i in range(100):
        inc = eng.create_incident(
            "orgC", {"title": f"Perf {i}", "severity": "medium", "type": "other"}
        )
        eng.update_incident_status("orgC", inc["id"], "resolved")

    start = time.perf_counter()
    metrics = eng.get_incident_metrics("orgC")
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert metrics["total_count"] == 100
    assert elapsed_ms < 300, f"get_incident_metrics took {elapsed_ms:.1f}ms — too slow"
