#!/usr/bin/env python3
"""Check all SQLite databases in the ALDECI data directory.

Reports:
  - File sizes
  - Table names and row counts
  - Integrity check results (PRAGMA integrity_check)

Usage:
    python scripts/check_databases.py
    python scripts/check_databases.py --data-dir /var/lib/fixops/data
    python scripts/check_databases.py --data-dir data --json
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check all SQLite databases in the ALDECI data directory."
    )
    parser.add_argument(
        "--data-dir",
        default="data",
        help="Directory containing .db files (default: data)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON output instead of human-readable text",
    )
    return parser.parse_args()


def _human_size(size_bytes: int) -> str:
    """Format byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes //= 1024
    return f"{size_bytes:.1f} TB"


def check_database(db_path: Path) -> dict:
    """Inspect a single SQLite file. Returns a result dict."""
    result: dict = {
        "path": str(db_path),
        "size_bytes": db_path.stat().st_size,
        "size_human": _human_size(db_path.stat().st_size),
        "tables": [],
        "total_rows": 0,
        "integrity_ok": False,
        "integrity_errors": [],
        "error": None,
    }

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row

        # Integrity check
        rows = conn.execute("PRAGMA integrity_check").fetchall()
        integrity_msgs = [r[0] for r in rows]
        if integrity_msgs == ["ok"]:
            result["integrity_ok"] = True
        else:
            result["integrity_errors"] = integrity_msgs

        # Tables and row counts
        table_rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()

        tables = []
        total_rows = 0
        for tr in table_rows:
            tname = tr["name"]
            count = conn.execute(f'SELECT COUNT(*) FROM "{tname}"').fetchone()[0]
            tables.append({"table": tname, "rows": count})
            total_rows += count

        result["tables"] = tables
        result["total_rows"] = total_rows
        conn.close()

    except sqlite3.DatabaseError as exc:
        result["error"] = str(exc)
        result["integrity_ok"] = False
        result["integrity_errors"] = [str(exc)]

    return result


def check_all(data_dir: str) -> list[dict]:
    """Scan data_dir for .db files and check each one."""
    data_path = Path(data_dir)
    if not data_path.exists():
        return []

    db_files = sorted(data_path.glob("**/*.db"))
    return [check_database(p) for p in db_files]


def print_report(results: list[dict], data_dir: str) -> None:
    """Print a human-readable report to stdout."""
    print(f"\nDatabase report for: {Path(data_dir).resolve()}")
    print(f"{'─' * 70}")

    if not results:
        print("  No .db files found.\n")
        return

    corrupted = 0
    for r in results:
        name = Path(r["path"]).name
        status = "CORRUPT" if not r["integrity_ok"] else "OK"
        marker = "  [!!]" if not r["integrity_ok"] else "  [OK]"
        print(f"{marker} {name}  ({r['size_human']})  integrity={status}")

        if r["error"]:
            print(f"         ERROR: {r['error']}")
        elif r["integrity_errors"]:
            for msg in r["integrity_errors"]:
                print(f"         integrity issue: {msg}")
            corrupted += 1
        else:
            if r["tables"]:
                for t in r["tables"]:
                    print(f"         {t['table']:40s}  {t['rows']:>8} rows")
            else:
                print("         (no tables)")

    total = len(results)
    ok_count = sum(1 for r in results if r["integrity_ok"])
    print(f"{'─' * 70}")
    print(f"Total: {total} databases — {ok_count} OK, {total - ok_count} corrupted\n")


def main() -> int:
    args = parse_args()
    results = check_all(args.data_dir)

    if args.as_json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results, args.data_dir)

    corrupted = sum(1 for r in results if not r["integrity_ok"])
    return 1 if corrupted > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
