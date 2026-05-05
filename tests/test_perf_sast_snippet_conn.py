"""Perf test: sast_engine snippet DB uses a persistent connection.

Regression: _snippet_conn() must return the same connection object on
repeated calls (not open a new file each time).

Perf gate: 50 consecutive _snippet_conn() calls must complete in <5 ms
total (vs ~25 ms with per-call sqlite3.connect on a cold filesystem).
"""

import sqlite3
import tempfile
import time
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_snippet_state(db_path: str) -> None:
    """Point the snippet subsystem at a temp DB and reset its cached state."""
    import importlib
    import sys

    # Ensure fresh import state doesn't carry over between test functions
    mod_name = "core.sast_engine"
    if mod_name in sys.modules:
        mod = sys.modules[mod_name]
        # Reset module-level globals directly to guarantee clean state
        mod._SNIPPET_DB_PATH = None  # type: ignore[attr-defined]
        if getattr(mod, "_SNIPPET_CONN", None) is not None:
            try:
                mod._SNIPPET_CONN.close()  # type: ignore[attr-defined]
            except Exception:
                pass
            mod._SNIPPET_CONN = None  # type: ignore[attr-defined]
        mod._snippet_set_db_path(db_path)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Regression: connection identity
# ---------------------------------------------------------------------------

def test_snippet_conn_is_persistent():
    """_snippet_conn() must return the same object on repeated calls."""
    from core.sast_engine import _snippet_conn, _snippet_set_db_path

    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "test_snippet.db")
        _snippet_set_db_path(db)

        c1 = _snippet_conn()
        c2 = _snippet_conn()
        c3 = _snippet_conn()

        assert c1 is c2, "Expected persistent connection — got different objects"
        assert c2 is c3, "Expected persistent connection — got different objects"
        assert isinstance(c1, sqlite3.Connection)


# ---------------------------------------------------------------------------
# Perf: 50 calls must be <5 ms
# ---------------------------------------------------------------------------

def test_snippet_conn_repeated_calls_fast():
    """50 _snippet_conn() calls must finish in under 5 ms (persistent conn)."""
    from core.sast_engine import _snippet_conn, _snippet_set_db_path

    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "perf_snippet.db")
        _snippet_set_db_path(db)

        # Warm-up: ensure connection is already open
        _snippet_conn()

        N = 50
        t0 = time.perf_counter()
        for _ in range(N):
            _snippet_conn()
        elapsed_ms = (time.perf_counter() - t0) * 1000

        assert elapsed_ms < 5.0, (
            f"{N} _snippet_conn() calls took {elapsed_ms:.2f} ms — "
            f"expected <5 ms with persistent connection"
        )


# ---------------------------------------------------------------------------
# Regression: _snippet_set_db_path resets the cached connection
# ---------------------------------------------------------------------------

def test_snippet_set_db_path_resets_connection():
    """Changing DB path via _snippet_set_db_path must open a fresh connection."""
    from core.sast_engine import _snippet_conn, _snippet_set_db_path

    with tempfile.TemporaryDirectory() as tmp:
        db1 = str(Path(tmp) / "db1.db")
        db2 = str(Path(tmp) / "db2.db")

        _snippet_set_db_path(db1)
        c1 = _snippet_conn()

        _snippet_set_db_path(db2)
        c2 = _snippet_conn()

        assert c1 is not c2, (
            "_snippet_set_db_path must reset the cached connection"
        )


# ---------------------------------------------------------------------------
# Functional: scan_snippet round-trip still works with persistent conn
# ---------------------------------------------------------------------------

def test_scan_snippet_roundtrip():
    """scan_snippet returns expected keys and caches the result."""
    from core.sast_engine import scan_snippet, _snippet_set_db_path

    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "roundtrip.db")
        _snippet_set_db_path(db)

        code = "import os\nos.system('ls')"
        result = scan_snippet("org-test", code, "python", "test")

        assert result["org_id"] == "org-test"
        assert result["language"] == "python"
        assert result["cached"] is False
        assert isinstance(result["findings"], list)

        # Second call with same code must be a cache hit
        result2 = scan_snippet("org-test", code, "python", "test")
        assert result2["cached"] is True
        assert result2["snippet_sha256"] == result["snippet_sha256"]
