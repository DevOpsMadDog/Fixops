"""Perf regression test — PAMEngine persistent connection + stats aggregation.

Baseline (before): 0.363 ms per full-read-cycle (500 cycles × 4 ops each).
After fix:         0.022 ms per full-read-cycle.
Speedup:           ~16.5x

This test enforces a ceiling of 0.15 ms per cycle so we catch regressions
before they re-introduce per-call sqlite3.connect() overhead.
"""

from __future__ import annotations

import time
import tempfile
import os

import pytest
from core.pam_engine import PAMEngine


@pytest.fixture()
def populated_engine(tmp_path):
    db = str(tmp_path / "pam_perf.db")
    e = PAMEngine(db_path=db)
    e.register_account("org1", {"username": "svc-prod", "account_type": "service",
                                 "is_vaulted": True, "risk_score": 80})
    e.register_account("org1", {"username": "root-box", "account_type": "root",
                                 "risk_score": 20, "status": "expired"})
    e.create_policy("org1", {"name": "Baseline Policy"})
    sess = e.create_session("org1", {"account_id": "x", "requester": "alice"})
    e.approve_session("org1", sess["session_id"], "mgr", True)
    return e


def test_pam_full_read_cycle_performance(populated_engine):
    """500 read-cycles (list_accounts + list_sessions + list_policies + get_pam_stats)
    must complete in under 75 ms total (0.15 ms ceiling per cycle).

    Baseline before fix was 0.363 ms/cycle; after fix is ~0.022 ms/cycle.
    The 0.15 ms ceiling gives 6.8x headroom over the fixed value and still
    requires >2x improvement over the broken baseline.
    """
    e = populated_engine
    N = 500

    t0 = time.perf_counter()
    for _ in range(N):
        e.list_accounts("org1")
        e.list_sessions("org1")
        e.list_policies("org1")
        e.get_pam_stats("org1")
    elapsed_ms = (time.perf_counter() - t0) * 1000

    per_cycle_ms = elapsed_ms / N
    assert per_cycle_ms < 0.15, (
        f"PAMEngine read-cycle too slow: {per_cycle_ms:.3f} ms/cycle "
        f"(limit 0.15 ms — was 0.363 ms before persistent-connection fix)"
    )


def test_pam_stats_correctness_after_optimisation(populated_engine):
    """Collapsed 6-query get_pam_stats must still return correct values."""
    stats = populated_engine.get_pam_stats("org1")
    assert stats["total_accounts"] == 2
    assert stats["vaulted"] == 1
    assert stats["accounts_expired"] == 1
    assert stats["active_sessions"] == 1
    assert stats["pending_approvals"] == 0
    assert stats["avg_risk_score"] == 50.0


def test_pam_persistent_conn_reused(tmp_path):
    """Verify that repeated _conn() calls return the same connection object."""
    db = str(tmp_path / "pam_conn.db")
    e = PAMEngine(db_path=db)
    c1 = e._conn()
    c2 = e._conn()
    assert c1 is c2, "Expected persistent connection to be reused across calls"


def test_pam_stats_empty_org_after_optimisation():
    """get_pam_stats on an org with no data must return all-zero dict."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    try:
        e = PAMEngine(db_path=db)
        stats = e.get_pam_stats("org-ghost")
        assert stats["total_accounts"] == 0
        assert stats["vaulted"] == 0
        assert stats["active_sessions"] == 0
        assert stats["pending_approvals"] == 0
        assert stats["accounts_expired"] == 0
        assert stats["avg_risk_score"] == 0.0
    finally:
        os.unlink(db)
