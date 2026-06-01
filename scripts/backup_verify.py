#!/usr/bin/env python3
"""
REQ-008-02: Backup verification script for ALDECI / FixOps critical SQLite DBs.

Enumerates the critical DBs, checks whether a real replica snapshot exists
at the configured replica target (FIXOPS_REPLICA_PATH or ./data/replicas),
and reports each DB as PROTECTED or UNPROTECTED.

Exit code:
  0 — all critical (tier-1) DBs are protected
  1 — one or more critical DBs are unprotected (or DB missing + no replica)

This script is READ-ONLY and fast. It does not write, modify, or touch any DB.
It reports honestly — "UNPROTECTED" until litestream has actually run and
created snapshot files.

Usage:
  python scripts/backup_verify.py
  python scripts/backup_verify.py --json          # machine-readable output
  python scripts/backup_verify.py --tier 1        # only check tier-1 DBs
  FIXOPS_REPLICA_PATH=/mnt/nas/replicas python scripts/backup_verify.py
"""

from __future__ import annotations

import argparse
import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup — allow running from repo root or scripts/ dir
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
# Add suite-core to path so we can import db_durability
for _p in [
    str(_REPO_ROOT / "suite-core"),
    str(_REPO_ROOT / "suite-core" / "core"),
    str(_REPO_ROOT),
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _import_durability():
    """Import db_durability, with a fallback if suite-core path resolution fails."""
    try:
        from core.db_durability import durability_status, CRITICAL_DBS
        return durability_status, CRITICAL_DBS
    except ImportError:
        # Try direct import
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "db_durability",
            _REPO_ROOT / "suite-core" / "core" / "db_durability.py",
        )
        if spec is None or spec.loader is None:
            raise ImportError("Cannot locate suite-core/core/db_durability.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod.durability_status, mod.CRITICAL_DBS


# ---------------------------------------------------------------------------
# ANSI colour helpers (disabled when stdout is not a tty or NO_COLOR is set)
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if _USE_COLOR else s


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m" if _USE_COLOR else s


def _yellow(s: str) -> str:
    return f"\033[33m{s}\033[0m" if _USE_COLOR else s


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m" if _USE_COLOR else s


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify ALDECI SQLite DB backup / replica state."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--tier",
        type=int,
        choices=[1, 2, 3],
        default=None,
        help="Only check DBs at or above this tier (1=critical, 2=important).",
    )
    parser.add_argument(
        "--fail-on-missing-db",
        action="store_true",
        help=(
            "Also exit non-zero when a critical DB file does not exist on disk "
            "(normally a fresh install with no data yet is not an error)."
        ),
    )
    args = parser.parse_args(argv)

    durability_status, CRITICAL_DBS = _import_durability()

    status = durability_status()
    checked_at = status["checked_at"]
    replica_base = status["replica_base"]
    dbs = status["dbs"]

    # Filter by tier if requested
    tier_filter = args.tier
    if tier_filter is not None:
        filtered_keys = {
            k for k, v in dbs.items() if v["tier"] <= tier_filter
        }
    else:
        filtered_keys = set(dbs.keys())

    # Build report rows
    rows = []
    unprotected_tier1: list[str] = []
    for key, info in dbs.items():
        if key not in filtered_keys:
            continue

        db_exists = info["db_exists"]
        replicated = info["replicated"]
        tier = info["tier"]
        db_path = info["db_path"] or "(not found on disk)"
        target = info["target"]
        last_snap = info["last_snapshot"] or "none"
        note = info.get("note") or ""

        if replicated:
            protection = "PROTECTED"
        elif not db_exists:
            protection = "NO-DB-YET"  # DB doesn't exist yet, not a loss risk
        else:
            protection = "UNPROTECTED"

        rows.append({
            "key": key,
            "tier": tier,
            "db_exists": db_exists,
            "db_path": db_path,
            "replicated": replicated,
            "protection": protection,
            "target": target,
            "last_snapshot": last_snap,
            "note": note,
        })

        # Tier-1 unprotected = exit non-zero
        if tier == 1 and not replicated:
            if db_exists or args.fail_on_missing_db:
                unprotected_tier1.append(key)

    if args.json:
        out = {
            "checked_at": checked_at,
            "replica_base": replica_base,
            "durability_configured": status["durability_configured"],
            "tier1_all_protected": status["tier1_all_protected"],
            "exit_code": 1 if unprotected_tier1 else 0,
            "unprotected_tier1": unprotected_tier1,
            "dbs": rows,
        }
        print(json.dumps(out, indent=2))
        return 1 if unprotected_tier1 else 0

    # Human-readable output
    print()
    print(_bold("ALDECI SQLite Backup Verification Report"))
    print(f"Checked at  : {checked_at}")
    print(f"Replica base: {replica_base}")
    print()

    col_w = 34
    print(
        f"  {'DB Key':<{col_w}}  {'Tier'}  {'Status':<14}  {'Last Snapshot':<30}  Note"
    )
    print("  " + "-" * (col_w + 2 + 6 + 16 + 32 + 20))

    for row in rows:
        prot = row["protection"]
        if prot == "PROTECTED":
            prot_str = _green(f"{'PROTECTED':<14}")
        elif prot == "NO-DB-YET":
            prot_str = _yellow(f"{'NO-DB-YET':<14}")
        else:
            prot_str = _red(f"{'UNPROTECTED':<14}")

        snap = row["last_snapshot"]
        if snap != "none" and len(snap) > 28:
            snap = snap[:28]

        print(
            f"  {row['key']:<{col_w}}  T{row['tier']}    {prot_str}  {snap:<30}  {row['note']}"
        )

    print()

    if not status["durability_configured"]:
        print(
            _red(
                "WARNING: Durability NOT configured — no replica snapshots found."
            )
        )
        print(
            "         Run: litestream replicate -config docker/litestream.yml"
        )
        print(
            "         See: scripts/restore_runbook.md"
        )
    elif not status["tier1_all_protected"]:
        print(
            _yellow(
                f"WARNING: {len(unprotected_tier1)} tier-1 DB(s) unprotected: "
                + ", ".join(unprotected_tier1)
            )
        )
    else:
        print(_green("All tier-1 DBs are protected."))

    if unprotected_tier1:
        print()
        print(f"Exit code: 1 (unprotected tier-1 DBs: {', '.join(unprotected_tier1)})")
        return 1

    print()
    print("Exit code: 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
