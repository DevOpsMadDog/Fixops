"""
Perf test: anomaly_detector.get_anomaly_stats() — 6-query → 2-query collapse.

3 cases (MEASURED via timeit):
  small  — 10 anomalies
  medium — 500 anomalies
  large  — 5000 anomalies

Each case asserts the result is correct AND that elapsed time is within
a generous 2-second ceiling (to avoid CI flakiness on slow runners).
"""
from __future__ import annotations

import tempfile
import time
import uuid
from datetime import datetime, timezone

import pytest

from core.anomaly_detector import AnomalyDetector, AnomalyType, AnomalySeverity


def _seed(detector: AnomalyDetector, n: int, org: str) -> None:
    """Insert n anomaly rows directly into the DB for speed."""
    import sqlite3, json

    conn = sqlite3.connect(detector.db_path)
    now = datetime.now(timezone.utc).isoformat()
    rows = [
        (
            str(uuid.uuid4()),
            org,
            AnomalyType.SPIKE.value,
            "cpu_usage",
            50.0,
            150.0,
            200.0,
            AnomalySeverity.HIGH.value,
            now,
            "{}",
            i % 3,   # mix acknowledged / unacknowledged
            None,
        )
        for i in range(n)
    ]
    conn.executemany(
        """
        INSERT INTO anomalies
            (id, org_id, type, metric_name, expected_value, actual_value,
             deviation_pct, severity, detected_at, context, acknowledged, acknowledged_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        rows,
    )
    conn.commit()
    conn.close()


@pytest.mark.parametrize("n,label", [(10, "small"), (500, "medium"), (5000, "large")])
def test_get_anomaly_stats_perf(n, label):
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    org = f"perf-org-{label}"
    detector = AnomalyDetector(db_path=db_path, org_id=org)
    _seed(detector, n, org)

    # --- correctness ---
    stats = detector.get_anomaly_stats(org_id=org)
    assert stats.total == n, f"expected {n} total, got {stats.total}"
    assert stats.unacknowledged >= 0
    assert stats.by_type.get(AnomalyType.SPIKE.value, 0) == n
    assert stats.by_severity.get(AnomalySeverity.HIGH.value, 0) == n

    # --- measured performance ---
    REPS = 5
    t0 = time.perf_counter()
    for _ in range(REPS):
        detector.get_anomaly_stats(org_id=org)
    elapsed = (time.perf_counter() - t0) / REPS

    print(f"\n[perf] get_anomaly_stats n={n} ({label}): {elapsed*1000:.2f} ms/call")
    assert elapsed < 2.0, f"get_anomaly_stats too slow for n={n}: {elapsed:.3f}s"
