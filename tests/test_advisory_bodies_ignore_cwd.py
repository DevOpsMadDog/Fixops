"""Which database answers must not depend on where the process was started.

This repo has 61 database NAMES at more than one path, 58 of them with rows in
more than one copy — the application warns about it at boot ("the others age
silently and their contents will never appear in the product"). ``feeds.db`` is
one of them, and the two copies are not stale duplicates of each other:

    data/feeds/feeds.db            327,252 EPSS rows   118 advisory bodies
    suite-api/data/feeds/feeds.db  327,809 EPSS rows   NO advisory_details

The lookup used RELATIVE paths and took the first candidate that *existed*
rather than one that could *answer*. Started from ``suite-api/`` it therefore
opened the copy with more EPSS rows and no advisory table, raised "no such
table: advisory_details", swallowed it and returned ``{}``. Reproduced exactly
before the fix.

Nothing would have reported this. TypeScript reachability would have fallen
from 65% back to 57% — the ecosystem the advisory bodies exist to serve — and
the only symptom would have been a number nobody could explain.
"""

from __future__ import annotations

import os
import pathlib
import sqlite3

import pytest

from apps.api.scanner_ingest_router import _local_advisory_bodies

REPO = pathlib.Path(__file__).resolve().parents[1]


def _stored_ids(limit: int = 3) -> list[str]:
    db = REPO / "data" / "feeds" / "feeds.db"
    if not db.is_file():
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        return [
            r[0] for r in conn.execute(
                "SELECT advisory_id FROM advisory_details "
                "WHERE length(details) > 0 LIMIT ?", (limit,)
            )
        ]
    except sqlite3.DatabaseError:
        return []


@pytest.mark.parametrize("start_dir", ["", "suite-api", "suite-core"])
def test_bodies_are_found_from_any_working_directory(start_dir, monkeypatch) -> None:
    ids = _stored_ids()
    if not ids:
        pytest.skip("no advisory bodies stored locally")

    monkeypatch.chdir(REPO / start_dir if start_dir else REPO)
    monkeypatch.delenv("FIXOPS_DATA_DIR", raising=False)

    bodies = _local_advisory_bodies([{"rule_id": advisory} for advisory in ids])
    assert len(bodies) == len(ids), (
        f"started from {start_dir or 'repo root'}, the lookup resolved to a "
        f"feeds.db that could not answer — cwd decided the result"
    )


def test_a_copy_without_the_table_does_not_end_the_search(tmp_path, monkeypatch) -> None:
    """The failure mode was structural, not incidental.

    Picking the first candidate that EXISTS means one older bundle earlier in
    the list hides every later copy that does have the bodies. Point
    FIXOPS_DATA_DIR at a feeds.db with no advisory_details and the repo copy
    must still answer.
    """
    ids = _stored_ids()
    if not ids:
        pytest.skip("no advisory bodies stored locally")

    empty = tmp_path / "feeds"
    empty.mkdir()
    conn = sqlite3.connect(empty / "feeds.db")
    conn.execute("CREATE TABLE epss_scores (cve_id TEXT)")
    conn.commit()

    monkeypatch.chdir(REPO)
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    bodies = _local_advisory_bodies([{"rule_id": advisory} for advisory in ids])
    assert len(bodies) == len(ids), "an older bundle first in the list hid the bodies"


def test_missing_everything_returns_empty_not_an_exception(tmp_path, monkeypatch) -> None:
    """Degrading to the title is correct; raising during ingest is not."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path / "nope"))
    assert _local_advisory_bodies([{"rule_id": "GHSA-does-not-exist"}]) == {}
