#!/usr/bin/env python3
"""Store advisory prose locally, so symbol extraction works offline.

Measured 2026-08-31: on 23 real npm advisories, the symbol extractor recovered
**0 of 8** symbols from what ``npm audit --json`` supplies (a title) and **8 of
8** from the same advisories' OSV bodies. That single missing field is why
TypeScript reachability eliminates 57% where Python eliminates 82–84% — the gap
is data, not analysis.

A live lookup at ingest would fix it for connected sites and quietly do nothing
for air-gapped ones, which are the deployments we sell hardest. So the bodies
are fetched **here**, on a connected host, into ``feeds.db`` — the same database
``scripts/feed_bundle.py`` already exports, signs and carries across an air gap.

    python scripts/fetch_advisory_bodies.py --from-npm-audit audit.json
    python scripts/fetch_advisory_bodies.py --ids GHSA-xxxx-yyyy-zzzz PYSEC-2026-1
    python scripts/fetch_advisory_bodies.py --from-pip-audit env.json

Rows are keyed by advisory id (GHSA / PYSEC / OSV / CVE), because that is the
identifier a finding actually carries — the same lesson that cost four defects
when deduplication and the pipeline keyed on ``cve_id`` while the SARIF
normaliser wrote ``rule_id``.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

OSV_API = "https://api.osv.dev/v1/vulns/"

SCHEMA = """
CREATE TABLE IF NOT EXISTS advisory_details (
    advisory_id TEXT PRIMARY KEY,
    summary     TEXT NOT NULL DEFAULT '',
    details     TEXT NOT NULL DEFAULT '',
    aliases     TEXT NOT NULL DEFAULT '',
    fetched_at  TEXT NOT NULL
)
"""


def _feeds_db(explicit: str | None) -> pathlib.Path:
    if explicit:
        return pathlib.Path(explicit)
    root = os.environ.get("FIXOPS_DATA_DIR", "data")
    return pathlib.Path(root) / "feeds" / "feeds.db"


def _ids_from_npm_audit(path: pathlib.Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    ids: list[str] = []
    for _name, entry in (data.get("vulnerabilities") or {}).items():
        for via in entry.get("via", []):
            if not isinstance(via, dict):
                continue
            url = via.get("url") or ""
            advisory = url.rstrip("/").rsplit("/", 1)[-1]
            if advisory.startswith(("GHSA", "CVE", "PYSEC", "OSV")):
                ids.append(advisory)
    return ids


def _ids_from_pip_audit(path: pathlib.Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        vuln["id"]
        for dep in data.get("dependencies", [])
        for vuln in dep.get("vulns", [])
        if vuln.get("id")
    ]


def _fetch(advisory_id: str, timeout: int) -> dict | None:
    try:
        with urllib.request.urlopen(OSV_API + advisory_id, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None          # not every id is in OSV; that is not an error
        raise
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db")
    parser.add_argument("--ids", nargs="*", default=[])
    parser.add_argument("--from-npm-audit")
    parser.add_argument("--from-pip-audit")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--refresh", action="store_true",
                        help="re-fetch advisories already stored")
    args = parser.parse_args()

    ids = list(args.ids)
    if args.from_npm_audit:
        ids += _ids_from_npm_audit(pathlib.Path(args.from_npm_audit))
    if args.from_pip_audit:
        ids += _ids_from_pip_audit(pathlib.Path(args.from_pip_audit))
    ids = list(dict.fromkeys(i for i in ids if i))
    if not ids:
        print("no advisory ids given")
        return 1

    db = _feeds_db(args.db)
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.execute(SCHEMA)

    have = {
        row[0] for row in conn.execute("SELECT advisory_id FROM advisory_details")
    } if not args.refresh else set()

    fetched = skipped = missing = 0
    for advisory_id in ids:
        if advisory_id in have:
            skipped += 1
            continue
        record = _fetch(advisory_id, args.timeout)
        if record is None:
            missing += 1
            continue
        conn.execute(
            "INSERT OR REPLACE INTO advisory_details "
            "(advisory_id, summary, details, aliases, fetched_at) VALUES (?,?,?,?,?)",
            (
                advisory_id,
                record.get("summary") or "",
                record.get("details") or "",
                json.dumps(record.get("aliases") or []),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        fetched += 1
        time.sleep(0.05)
    conn.commit()

    total = conn.execute("SELECT COUNT(*) FROM advisory_details").fetchone()[0]
    with_details = conn.execute(
        "SELECT COUNT(*) FROM advisory_details WHERE length(details) > 0"
    ).fetchone()[0]
    print(f"  requested {len(ids)}  fetched {fetched}  already had {skipped}  not in OSV {missing}")
    print(f"  stored    {total} advisories, {with_details} carry a prose body")
    print(f"  db        {db}")
    print("\n  These travel with scripts/feed_bundle.py export — an air-gapped site")
    print("  gets the same symbol extraction as a connected one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
