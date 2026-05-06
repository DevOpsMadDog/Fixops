"""
Perf test: ai_security_advisor_engine.get_stats()
Validates 7-query → 2-query collapse: 3 cases (empty, small, large).
"""
import time
import sqlite3
import tempfile
import os
import sys
import pytest

sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")

from core.ai_security_advisor_engine import AISecurityAdvisorEngine


def _make_engine(tmp_path: str) -> AISecurityAdvisorEngine:
    eng = AISecurityAdvisorEngine.__new__(AISecurityAdvisorEngine)
    eng._db_path = os.path.join(tmp_path, "advisor.db")
    import threading
    eng._lock = threading.Lock()

    # Bootstrap schema directly
    conn = sqlite3.connect(eng._db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS advisor_sessions (
            id TEXT PRIMARY KEY,
            org_id TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS recommendations (
            id TEXT PRIMARY KEY,
            org_id TEXT,
            priority TEXT,
            status TEXT,
            impact_score REAL
        );
        CREATE TABLE IF NOT EXISTS advisor_conversations (
            id TEXT PRIMARY KEY,
            org_id TEXT
        );
    """)
    conn.commit()
    conn.close()

    def _conn():
        c = sqlite3.connect(eng._db_path, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    eng._conn = _conn
    return eng


def _seed(db_path: str, org_id: str, n_sessions: int, n_recs: int) -> None:
    from datetime import datetime, timezone, timedelta
    import uuid
    conn = sqlite3.connect(db_path)
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)

    for i in range(n_sessions):
        ts = (now if i % 2 == 0 else week_ago - timedelta(days=1)).isoformat()
        conn.execute(
            "INSERT INTO advisor_sessions VALUES (?,?,?)",
            (str(uuid.uuid4()), org_id, ts),
        )
    priorities = ["critical", "high", "medium", "low"]
    statuses = ["open", "implemented", "dismissed"]
    for i in range(n_recs):
        conn.execute(
            "INSERT INTO recommendations VALUES (?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                org_id,
                priorities[i % len(priorities)],
                statuses[i % len(statuses)],
                float(i % 10),
            ),
        )
    conn.commit()
    conn.close()


@pytest.mark.perf
@pytest.mark.parametrize("n_sessions,n_recs,label", [
    (0, 0, "empty"),
    (50, 200, "small"),
    (500, 2000, "large"),
])
def test_get_stats_perf(n_sessions, n_recs, label, tmp_path):
    eng = _make_engine(str(tmp_path))
    org_id = "org-perf-test"
    _seed(eng._db_path, org_id, n_sessions, n_recs)

    # Warm-up (schema cache)
    eng.get_stats(org_id)

    RUNS = 20
    start = time.perf_counter()
    for _ in range(RUNS):
        result = eng.get_stats(org_id)
    elapsed = time.perf_counter() - start
    avg_ms = (elapsed / RUNS) * 1000

    print(f"\n[{label}] n_sessions={n_sessions} n_recs={n_recs} avg={avg_ms:.2f}ms over {RUNS} runs")

    # Correctness checks
    assert result["org_id"] == org_id
    assert result["session_count"] == n_sessions
    assert isinstance(result["recommendations_by_priority"], dict)
    assert isinstance(result["recommendations_by_status"], dict)
    assert result["implemented_count"] >= 0
    assert result["total_impact_score"] >= 0.0

    # Perf thresholds (generous — SQLite in tmp, no index)
    limits = {"empty": 5, "small": 20, "large": 100}
    assert avg_ms < limits[label], (
        f"get_stats too slow for {label}: {avg_ms:.2f}ms >= {limits[label]}ms"
    )
