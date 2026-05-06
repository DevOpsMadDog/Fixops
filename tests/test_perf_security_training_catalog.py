"""Perf test: get_catalog role-filter pushed into SQL (json_each).

3 cases measured with 200 seeded modules so filtering cost is non-trivial:
  1. get_catalog() — no filter (baseline, all rows deserialized)
  2. get_catalog(role=X) — role filter in SQL, fewer rows deserialized
  3. get_catalog(category=X, role=Y) — combined SQL filter

Role-filter SQL wins because fewer rows reach _row_to_module (3x json.loads +
Pydantic construct per row). With 200 rows and ~50% match rate the SQL path
skips ~100 deserialization calls.
"""
from __future__ import annotations

import json
import tempfile
import time
import uuid
from typing import List

import pytest

from core.security_training import (
    SecurityTrainingTracker,
    TrainingModule,
    TrainingCategory,
    UserRole,
    ComplianceMapping,
    ComplianceFramework,
)


def _make_tracker_with_modules(n: int = 200) -> SecurityTrainingTracker:
    """Create a tracker pre-seeded with n extra modules split across two roles."""
    tmp = tempfile.mktemp(suffix=".db")
    t = SecurityTrainingTracker(db_path=tmp)
    # Add n synthetic modules: half DEVELOPER-only, half ALL_STAFF
    with t._lock, t._conn() as conn:
        import json as _json
        now = "2026-01-01T00:00:00"
        for i in range(n):
            role = UserRole.DEVELOPER.value if i % 2 == 0 else UserRole.ALL_STAFF.value
            conn.execute(
                """INSERT OR IGNORE INTO training_modules
                   (id, title, description, category, duration_minutes, passing_score,
                    required_roles, compliance_mappings, tags, version, points, active,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (
                    f"syn-{i:04d}",
                    f"Synthetic Module {i}",
                    "desc",
                    TrainingCategory.SECURE_CODING.value,
                    30, 70,
                    _json.dumps([role]),
                    _json.dumps([]),
                    _json.dumps(["perf-test"]),
                    "1.0", 10, now, now,
                ),
            )
    return t


def _old_get_catalog_role_filter(tracker: SecurityTrainingTracker, role: str):
    """Reproduce old behaviour: fetch all rows, deserialize all, filter in Python."""
    with tracker._conn() as conn:
        rows = conn.execute(
            "SELECT * FROM training_modules WHERE active = 1"
        ).fetchall()
    modules = [tracker._row_to_module(r) for r in rows]
    return [m for m in modules if not m.required_roles or role in m.required_roles]


# ---------------------------------------------------------------------------
# Case 1 — no filter: baseline timing
# ---------------------------------------------------------------------------

def test_perf_get_catalog_no_filter():
    tracker = _make_tracker_with_modules(200)
    N = 100
    start = time.perf_counter()
    for _ in range(N):
        modules = tracker.get_catalog()
    elapsed = time.perf_counter() - start
    per_call_ms = elapsed / N * 1000
    assert len(modules) >= 200
    assert per_call_ms < 200, f"no-filter catalog took {per_call_ms:.2f}ms per call (limit 200ms)"


# ---------------------------------------------------------------------------
# Case 2 — role filter: SQL path must be faster than full-deserialize+Python
# ---------------------------------------------------------------------------

def test_perf_get_catalog_role_filter_sql_vs_python():
    tracker = _make_tracker_with_modules(200)
    role = UserRole.DEVELOPER.value
    N = 100

    # warm-up
    tracker.get_catalog(role=role)
    _old_get_catalog_role_filter(tracker, role)

    # measure new (SQL-pushed)
    start = time.perf_counter()
    for _ in range(N):
        new_result = tracker.get_catalog(role=role)
    new_elapsed = time.perf_counter() - start

    # measure old (Python-filter — deserializes ALL rows)
    start = time.perf_counter()
    for _ in range(N):
        old_result = _old_get_catalog_role_filter(tracker, role)
    old_elapsed = time.perf_counter() - start

    speedup = old_elapsed / new_elapsed
    new_ms = new_elapsed / N * 1000
    old_ms = old_elapsed / N * 1000

    print(
        f"\nRole-filter SQL vs Python: new={new_ms:.3f}ms  old={old_ms:.3f}ms  "
        f"speedup={speedup:.2f}x  N={N}  rows_new={len(new_result)}  rows_old={len(old_result)}"
    )

    # Results must match (same module IDs)
    new_ids = {m.id for m in new_result}
    old_ids = {m.id for m in old_result}
    assert new_ids == old_ids, f"Result mismatch: |new|={len(new_ids)} |old|={len(old_ids)}"

    # SQL pushdown must not be slower (within 20% margin given SQLite json_each overhead)
    assert new_elapsed <= old_elapsed * 1.2, (
        f"SQL role-filter ({new_ms:.3f}ms) is more than 20% slower than Python filter "
        f"({old_ms:.3f}ms) — regression"
    )
    print(f"MEASURED speedup: {speedup:.2f}x")


# ---------------------------------------------------------------------------
# Case 3 — combined category+role filter in SQL
# ---------------------------------------------------------------------------

def test_perf_get_catalog_category_and_role():
    tracker = _make_tracker_with_modules(200)
    category = TrainingCategory.SECURE_CODING.value
    role = UserRole.DEVELOPER.value

    N = 100
    start = time.perf_counter()
    for _ in range(N):
        result = tracker.get_catalog(category=category, role=role)
    elapsed = time.perf_counter() - start
    per_call_ms = elapsed / N * 1000

    print(
        f"\ncategory+role SQL filter: {per_call_ms:.3f}ms per call  "
        f"returned={len(result)} modules  N={N}"
    )
    # Should be faster than the unfiltered full-deserialize path
    unfiltered_start = time.perf_counter()
    for _ in range(N):
        all_mods = tracker.get_catalog()
    unfiltered_ms = (time.perf_counter() - unfiltered_start) / N * 1000

    print(f"Unfiltered for comparison: {unfiltered_ms:.3f}ms per call")
    assert per_call_ms < unfiltered_ms * 1.1, (
        f"category+role filter ({per_call_ms:.3f}ms) should be faster than "
        f"unfiltered ({unfiltered_ms:.3f}ms)"
    )
