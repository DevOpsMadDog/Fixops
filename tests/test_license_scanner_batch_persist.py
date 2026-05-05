"""
Regression + perf test for license_scanner N+1 fix.

Before fix: _persist_results() called conn.execute() N times (one per result).
After fix:  _persist_results() calls conn.executemany() once for all N results.

Same pattern applies to set_policy(): N execute() -> 1 executemany().
"""
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import List
from unittest.mock import patch

import pytest

from core.license_scanner import (
    LicenseScanner,
    LicenseResult,
    LicenseRisk,
    LicensePolicy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_results(n: int, org_id: str = "test-org") -> List[LicenseResult]:
    return [
        LicenseResult(
            id=str(uuid.uuid4()),
            package=f"pkg-{i}",
            version="1.0.0",
            license_name="MIT",
            spdx_id="MIT",
            risk_level=LicenseRisk.PERMISSIVE,
            policy_action=LicensePolicy.ALLOW,
            org_id=org_id,
            scanned_at=datetime.now(timezone.utc),
        )
        for i in range(n)
    ]


class _TrackingConn(sqlite3.Connection):
    """sqlite3.Connection subclass that counts executemany vs INSERT execute calls."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executemany_count = 0
        self.execute_insert_count = 0

    def executemany(self, sql, params=None):  # type: ignore[override]
        self.executemany_count += 1
        if params is None:
            return super().executemany(sql, [])
        return super().executemany(sql, params)

    def execute(self, sql, params=None):  # type: ignore[override]
        if "INSERT" in sql.upper():
            self.execute_insert_count += 1
        if params is None:
            return super().execute(sql)
        return super().execute(sql, params)


def _fresh_scanner(tmp_path):
    """Return a LicenseScanner backed by a _TrackingConn.

    We patch sqlite3.connect inside the license_scanner module so the thread-local
    singleton is a _TrackingConn from the very first call (including _init_db).
    We then return the scanner AND its connection so tests can inspect counters.
    The patch is applied for the duration of LicenseScanner.__init__ only; the
    resulting thread-local conn persists for the lifetime of the scanner.
    """
    import core.license_scanner as _ls_mod

    db_path = tmp_path / "lic.db"

    # Clear any leftover thread-local from a prior test in this thread
    tl = _ls_mod._THREAD_LOCAL
    if hasattr(tl, "license_scanner_conn"):
        del tl.license_scanner_conn

    with patch("core.license_scanner.sqlite3.connect", side_effect=lambda p, **kw: _TrackingConn(p)):
        scanner = LicenseScanner(db_path=db_path)

    conn = tl.license_scanner_conn
    assert isinstance(conn, _TrackingConn), "Thread-local conn is not a _TrackingConn"
    # Reset counters after _init_db (schema creation uses executescript, not tracked)
    conn.executemany_count = 0
    conn.execute_insert_count = 0
    return scanner, conn


# ---------------------------------------------------------------------------
# Test 1: _persist_results uses executemany, not N execute() INSERT calls
# ---------------------------------------------------------------------------

def test_persist_results_uses_executemany_not_loop(tmp_path):
    """_persist_results() must call executemany() once, not execute() N times."""
    scanner, conn = _fresh_scanner(tmp_path)
    results = _make_results(50)

    scanner._persist_results(results)

    assert conn.executemany_count == 1, (
        f"Expected 1 executemany call, got {conn.executemany_count}"
    )
    assert conn.execute_insert_count == 0, (
        f"Expected 0 individual INSERT execute() calls, got {conn.execute_insert_count} — N+1 regression"
    )


# ---------------------------------------------------------------------------
# Test 2: set_policy uses executemany, not N execute() INSERT calls
# ---------------------------------------------------------------------------

def test_set_policy_uses_executemany_not_loop(tmp_path):
    """set_policy() must call executemany() once for all rule keys."""
    scanner, conn = _fresh_scanner(tmp_path)
    rules = {f"rule_{i}": [f"LIC-{i}"] for i in range(50)}

    scanner.set_policy("org-test", rules)

    assert conn.executemany_count == 1, (
        f"Expected 1 executemany call, got {conn.executemany_count}"
    )
    assert conn.execute_insert_count == 0, (
        f"Expected 0 individual INSERT execute() calls, got {conn.execute_insert_count}"
    )


# ---------------------------------------------------------------------------
# Test 3: correctness — all rows actually persisted after _persist_results
# ---------------------------------------------------------------------------

def _clear_tl():
    """Clear thread-local license_scanner_conn so the next LicenseScanner gets a fresh connection."""
    import core.license_scanner as _ls_mod
    tl = _ls_mod._THREAD_LOCAL
    if hasattr(tl, "license_scanner_conn"):
        del tl.license_scanner_conn


def test_persist_results_correctness(tmp_path):
    """All N results must be retrievable after _persist_results()."""
    _clear_tl()
    scanner = LicenseScanner(db_path=tmp_path / "lic.db")
    results = _make_results(50, org_id="correctness-org")
    scanner._persist_results(results)

    conn = scanner._conn()
    count = conn.execute(
        "SELECT COUNT(*) FROM scan_results WHERE org_id = ?", ("correctness-org",)
    ).fetchone()[0]
    assert count == 50, f"Expected 50 rows, got {count}"


# ---------------------------------------------------------------------------
# Test 4: set_policy correctness — all keys persisted
# ---------------------------------------------------------------------------

def test_set_policy_correctness(tmp_path):
    """All rule keys must be persisted after set_policy()."""
    _clear_tl()
    scanner = LicenseScanner(db_path=tmp_path / "lic.db")
    rules = {f"rule_{i}": f"value_{i}" for i in range(30)}
    scanner.set_policy("org-policy", rules)

    conn = scanner._conn()
    count = conn.execute(
        "SELECT COUNT(*) FROM org_policies WHERE org_id = ?", ("org-policy",)
    ).fetchone()[0]
    assert count == 30, f"Expected 30 policy rows, got {count}"


# ---------------------------------------------------------------------------
# Test 5: perf — N=50 persist completes within 200ms
# ---------------------------------------------------------------------------

def test_persist_results_perf_n50(tmp_path):
    """_persist_results(N=50) must complete in under 200ms."""
    _clear_tl()
    scanner = LicenseScanner(db_path=tmp_path / "lic.db")
    results = _make_results(50)

    start = time.perf_counter()
    scanner._persist_results(results)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert elapsed_ms < 200, f"_persist_results(N=50) took {elapsed_ms:.1f}ms — too slow"


# ---------------------------------------------------------------------------
# Test 6: empty list is a no-op (guard clause)
# ---------------------------------------------------------------------------

def test_persist_results_empty_list(tmp_path):
    """Empty results list must not raise and must leave the DB row count unchanged."""
    import core.license_scanner as _ls_mod
    tl = _ls_mod._THREAD_LOCAL
    # Clear thread-local so this test gets a fresh connection to its own tmp_path DB
    if hasattr(tl, "license_scanner_conn"):
        del tl.license_scanner_conn

    scanner = LicenseScanner(db_path=tmp_path / "lic.db")
    before = scanner._conn().execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
    scanner._persist_results([])
    after = scanner._conn().execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
    assert after == before, f"Empty persist changed row count from {before} to {after}"
