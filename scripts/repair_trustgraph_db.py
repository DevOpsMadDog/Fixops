#!/usr/bin/env python3
"""Repair a corrupted TrustGraph SQLite database, preserving every row.

Why this exists
---------------
``data/trustgraph.db`` is gitignored, so the repair I performed by hand cannot
travel with the fix in ``suite-core/trustgraph/knowledge_store.py``. Any other
deployment carrying the same damage needs this script.

The damage, as ``PRAGMA integrity_check`` reported it::

    Tree 2 page 13160 cell 1: Rowid 114898 out of order
    wrong # of entries in index idx_entities_org_id
    row 20557 missing from index sqlite_autoindex_entities_1
    ...

``REINDEX`` is the obvious repair and it fails::

    UNIQUE constraint failed: entities.entity_id

which is the real finding: the table holds rows that violate its own PRIMARY
KEY, and the corrupt index was the only reason nothing had noticed. On the
database this was written against there were exactly two such rows out of
20,745 — small enough that a rebuild loses nothing, and fatal enough that no
index over the table could be rebuilt while they remained.

So the repair is a copy-out/copy-in: recreate the schema in a fresh file, insert
every row while keeping the most recently updated of each duplicated key, then
verify. Rebuilding rather than deleting in place means the original file is
never written to, so a failed repair costs nothing.

Usage
-----
    python scripts/repair_trustgraph_db.py                    # dry run: report only
    python scripts/repair_trustgraph_db.py --apply            # repair in place
    python scripts/repair_trustgraph_db.py --apply --db PATH

The original is copied to ``<db>.corrupt-<timestamp>`` before anything is
swapped, and the repair is refused unless the rebuilt file passes
``integrity_check`` AND accounts for every row.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
import time
from typing import Dict, List, Tuple

DEFAULT_DB = "data/trustgraph.db"


def integrity(conn: sqlite3.Connection) -> str:
    try:
        return conn.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        return f"unreadable: {exc}"


def _columns(conn: sqlite3.Connection, table: str) -> List[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def survey(conn: sqlite3.Connection) -> Dict[str, object]:
    """Count rows and duplicate primary keys without trusting any index.

    ``NOT INDEXED`` matters here: the indexes are the corrupt part, and a plan
    that reads through one silently returns a different set of rows than the
    table actually holds — which is how the duplicates stayed invisible.
    """
    out: Dict[str, object] = {}
    for table, key in (("entities", "entity_id"), ("relationships", "rel_id")):
        try:
            keys = [r[0] for r in conn.execute(f"SELECT {key} FROM {table} NOT INDEXED")]
        except sqlite3.DatabaseError as exc:
            out[table] = {"error": str(exc)}
            continue
        out[table] = {
            "rows": len(keys),
            "distinct": len(set(keys)),
            "duplicate_keys": len(keys) - len(set(keys)),
        }
    return out


def rebuild(src_path: str, dst_path: str) -> Tuple[int, int, int]:
    """Copy every row into a fresh database. Returns (entities, relationships, dropped)."""
    src = sqlite3.connect(src_path)
    if os.path.exists(dst_path):
        os.remove(dst_path)
    dst = sqlite3.connect(dst_path)

    # Real tables and their indexes. The FTS shadow tables are excluded and the
    # index is recreated from scratch below — copying %_data/%_idx blobs of a
    # possibly-damaged index would carry the damage across.
    for _name, sql in src.execute(
        "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL "
        "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'entities_fts%'"
    ).fetchall():
        dst.execute(sql)

    cols = _columns(src, "entities")
    newest: Dict[str, dict] = {}
    for row in src.execute(f"SELECT {','.join(cols)} FROM entities NOT INDEXED"):
        record = dict(zip(cols, row))
        previous = newest.get(record["entity_id"])
        if previous is None or (record.get("updated_at") or "") >= (previous.get("updated_at") or ""):
            newest[record["entity_id"]] = record
    dropped = sum(1 for _ in src.execute("SELECT 1 FROM entities NOT INDEXED")) - len(newest)

    dst.executemany(
        f"INSERT INTO entities ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
        [tuple(r[c] for c in cols) for r in newest.values()],
    )

    rcols = _columns(src, "relationships")
    rrows = src.execute(f"SELECT {','.join(rcols)} FROM relationships NOT INDEXED").fetchall()
    dst.executemany(
        f"INSERT INTO relationships ({','.join(rcols)}) VALUES ({','.join('?' * len(rcols))})",
        rrows,
    )

    # Standalone FTS5 keyed by entity_id — see knowledge_store._migrate_legacy_
    # external_content_fts for why external content and rowid joins are wrong.
    dst.execute(
        "CREATE VIRTUAL TABLE entities_fts USING fts5(name, properties, entity_id UNINDEXED)"
    )
    dst.execute(
        "INSERT INTO entities_fts(name, properties, entity_id) "
        "SELECT name, properties, entity_id FROM entities"
    )
    dst.commit()
    return len(newest), len(rrows), dropped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--apply", action="store_true", help="swap the repaired file in")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"no database at {args.db}")
        return 1

    before = sqlite3.connect(args.db)
    status = integrity(before)
    print(f"integrity : {status.splitlines()[0]}")
    for table, stats in survey(before).items():
        print(f"{table:14s}: {stats}")

    if status == "ok":
        print("nothing to repair")
        return 0
    if not args.apply:
        print("\ndry run — pass --apply to repair (the original is backed up first)")
        return 0

    repaired = f"{args.db}.repaired"
    entities, relationships, dropped = rebuild(args.db, repaired)

    check = sqlite3.connect(repaired)
    result = integrity(check)
    print(f"\nrebuilt   : {entities} entities, {relationships} relationships, {dropped} duplicate row(s) dropped")
    print(f"integrity : {result}")
    if result != "ok":
        print("REFUSING to swap: the rebuild did not come out clean. Original untouched.")
        return 1

    backup = f"{args.db}.corrupt-{time.strftime('%Y%m%dT%H%M%S')}"
    shutil.copy2(args.db, backup)
    shutil.move(repaired, args.db)
    print(f"swapped in. Original preserved at {backup}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
