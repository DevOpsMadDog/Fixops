"""The health check must notice data sitting where the product never looks.

A database can pass every integrity check and still be invisible: healthy file,
correct schema, real rows, wrong directory. That failure loses data as
thoroughly as corruption and far more quietly, because nothing errors.

Measured in this repo: 61 duplicated database names, 23 holding rows in more
than one copy, 2 where both copies were written recently — meaning two live
configurations disagree about where the data lives.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sqlite3
import time

REPO = pathlib.Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "check_sqlite_health", REPO / "scripts" / "check_sqlite_health.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _db(path: pathlib.Path, rows: int, age_days: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (v INTEGER)")
    conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(rows)])
    conn.commit()
    conn.close()
    if age_days:
        old = time.time() - age_days * 86400
        import os
        os.utime(path, (old, old))


def test_two_populated_copies_are_reported(tmp_path) -> None:
    mod = _load()
    _db(tmp_path / "a" / "cases.db", 500)
    _db(tmp_path / "b" / "cases.db", 12)

    findings = mod.split_stores(tmp_path)
    names = {name for name, _entries, _live in findings}
    assert "cases.db" in names

    entries = next(e for n, e, _l in findings if n == "cases.db")
    assert [rows for _p, rows, _age in entries] == [500, 12], "biggest copy first"


def test_one_populated_copy_is_not_a_conflict(tmp_path) -> None:
    """An empty second copy is normal — an engine that initialised a schema and
    was never used. Reporting it would bury the real conflicts in noise."""
    mod = _load()
    _db(tmp_path / "a" / "solo.db", 100)
    _db(tmp_path / "b" / "solo.db", 0)
    assert not [f for f in mod.split_stores(tmp_path) if f[0] == "solo.db"]


def test_only_recently_written_copies_count_as_LIVE(tmp_path) -> None:
    """Recency is what separates a live conflict from historical debris.

    Most duplicates here are 91-day-old copies from a process once started in
    the wrong directory. Those are worth listing but not worth acting on; a
    checker that flagged them equally would train the operator to ignore it.
    """
    mod = _load()
    _db(tmp_path / "a" / "old.db", 900, age_days=200)
    _db(tmp_path / "b" / "old.db", 5, age_days=180)
    _db(tmp_path / "a" / "now.db", 900)
    _db(tmp_path / "b" / "now.db", 5)

    live = {name for name, _e, is_live in mod.split_stores(tmp_path) if is_live}
    assert "now.db" in live
    assert "old.db" not in live


def test_an_unreadable_copy_does_not_crash_the_scan(tmp_path) -> None:
    """This runs against a possibly-corrupt deployment by definition."""
    mod = _load()
    _db(tmp_path / "a" / "x.db", 10)
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "x.db").write_bytes(b"not a database at all")
    mod.split_stores(tmp_path)  # must not raise
