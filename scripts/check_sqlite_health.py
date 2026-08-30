#!/usr/bin/env python3
"""Report the integrity of every SQLite database in the deployment.

Two corrupt databases surfaced on 2026-08-30, and neither announced itself:

* ``data/trustgraph.db`` — duplicate rows behind a damaged index. Every
  ``KnowledgeStore.ingest`` failed for ten days; the failure was swallowed by
  ``_safe_ingest`` and logged as a warning, so scanner ingest kept reporting
  success while correlating nothing.
* ``data/fixops_brain.db`` — pages missing entirely (error 522), unreadable past
  ``.recover``. It reached a customer as an opaque HTTP 500 "Internal server
  error / database" with a correlation id and no cause.

Corruption is not rare in this deployment shape (many small SQLite files, a
container and a host process that can both reach the same directory), and it
degrades in a way that looks like "no data yet" rather than "broken". A one-line
health check is the difference between noticing in seconds and chasing an
opaque 500 for an hour.

Usage
-----
    python scripts/check_sqlite_health.py                # scan the usual places
    python scripts/check_sqlite_health.py --root .       # scan a tree
    python scripts/check_sqlite_health.py --quiet        # only report problems

Exit code is non-zero when any database fails its integrity check, so this can
gate a deploy.
"""

from __future__ import annotations

import argparse
import pathlib
import sqlite3
import sys
from typing import List, Tuple

DEFAULT_DIRS = ("data", ".fixops_data", "suite-api/data", ".")


def _databases(root: pathlib.Path, recurse: bool) -> List[pathlib.Path]:
    if recurse:
        return sorted(
            p for p in root.rglob("*.db")
            if "node_modules" not in p.parts and ".git" not in p.parts
        )
    found: List[pathlib.Path] = []
    for d in DEFAULT_DIRS:
        directory = root / d
        if directory.is_dir():
            found.extend(sorted(directory.glob("*.db")))
    # A file can be reached by two of the paths above; report it once.
    seen, unique = set(), []
    for p in found:
        resolved = p.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(p)
    return unique


SQLITE_MAGIC = b"SQLite format 3\x00"


def _is_sqlite(path: pathlib.Path) -> bool:
    """A .db extension is a naming convention, not a format.

    ``ruvector.db`` is a **redb** file (magic ``redb``) written by a Rust
    embedded store. Reporting it as CORRUPT because SQLite cannot open it is
    exactly the false alarm this script exists to prevent — a health check that
    cries wolf gets ignored, and then the real corruption goes unnoticed too.
    """
    try:
        with path.open("rb") as handle:
            return handle.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def check(path: pathlib.Path) -> Tuple[bool, str, int]:
    """Return (healthy, detail, table_count).

    ``integrity_check`` alone is not enough. A database can pass it and still
    hold rows that violate a PRIMARY KEY when the index covering that key is the
    damaged part — which is exactly what hid the trustgraph duplicates. So the
    tables are counted too, with ``NOT INDEXED`` to avoid reading through the
    structure being tested.
    """
    # Check the database WITH its -wal/-shm sidecars, on a copy.
    #
    # A read-only open does not replay the write-ahead log, so a database whose
    # committed pages are fine but whose WAL is damaged reports "ok" — and then
    # fails for real the moment the server opens it. That happened here:
    # data/fixops_brain.db threw "disk I/O error" on every write, and the .db
    # file alone read back 464 nodes perfectly once copied without its sidecars.
    # The state that mattered was never in the file being inspected.
    #
    # Copying rather than opening the live file read-write keeps this safe to
    # run against a deployment that is serving traffic.
    import shutil
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="sqlite-health-")
    staged = pathlib.Path(tmpdir) / path.name
    try:
        shutil.copy2(path, staged)
        for suffix in ("-wal", "-shm"):
            sidecar = path.with_name(path.name + suffix)
            if sidecar.exists():
                shutil.copy2(sidecar, staged.with_name(staged.name + suffix))
    except OSError as exc:
        return False, f"cannot stage for inspection: {exc}", 0

    try:
        conn = sqlite3.connect(str(staged))
    except sqlite3.Error as exc:
        return False, f"cannot open: {exc}", 0

    try:
        result = conn.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        return False, f"unreadable: {exc}", 0

    tables = [
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    ]
    unreadable = []
    for table in tables:
        try:
            conn.execute(f"SELECT COUNT(*) FROM {table} NOT INDEXED").fetchone()
        except sqlite3.DatabaseError:
            unreadable.append(table)

    has_wal = path.with_name(path.name + "-wal").exists()
    if result != "ok":
        detail = result.splitlines()[0][:80]
        return False, detail + (" [has -wal]" if has_wal else ""), len(tables)
    if unreadable:
        return False, f"integrity ok but unreadable tables: {', '.join(unreadable[:3])}", len(tables)
    return True, "ok", len(tables)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--recurse", action="store_true", help="scan the whole tree")
    parser.add_argument("--quiet", action="store_true", help="only print problems")
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()
    databases = _databases(root, args.recurse)
    if not databases:
        print(f"no SQLite databases found under {root}")
        return 0

    bad: List[pathlib.Path] = []
    skipped = 0
    for path in databases:
        if not _is_sqlite(path):
            skipped += 1
            if not args.quiet:
                print(f"  skip    {path}  (not a SQLite file)")
            continue
        healthy, detail, tables = check(path)
        if not healthy:
            bad.append(path)
            print(f"  BROKEN  {path}  ({tables} tables)  {detail}")
        elif not args.quiet:
            size_mb = path.stat().st_size / 1_048_576
            print(f"  ok      {path}  ({tables} tables, {size_mb:.1f} MB)")

    checked = len(databases) - skipped
    print(f"\n{checked - len(bad)}/{checked} healthy" + (f" ({skipped} not SQLite)" if skipped else ""))
    if bad:
        print("\nRepair: scripts/repair_trustgraph_db.py handles the trustgraph schema.")
        print("For others, try `sqlite3 <db> .recover` into a fresh file and compare")
        print("row counts before swapping. Back up first — a failed repair must cost")
        print("nothing.")
        print("\nIf a database was healthy an hour ago, check whether two processes")
        print("are writing it (a container AND a host process on the same directory")
        print("corrupts SQLite across a bind mount).")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
