#!/usr/bin/env python3
"""scripts/purge_deleted_orgs.py — GDPR hard-purge job for soft-deleted orgs.

Run by ops team (cron / one-shot):
    python scripts/purge_deleted_orgs.py [--dry-run]

Finds all orgs with status=DELETED whose deleted_at is >= 30 days ago and
calls OrgEngine.hard_purge_org() for each one, removing all rows from
findings / incidents / audit_events / users tables across engine databases.

Exit codes:
    0 — success (including zero orgs eligible)
    1 — one or more purges failed
"""

from __future__ import annotations

import argparse
import logging
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap sys.path so we can import suite-core modules without install
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SUITE_CORE = _REPO_ROOT / "suite-core"
for _p in (_SUITE_CORE, _REPO_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
_logger = logging.getLogger("purge_deleted_orgs")

_DEFAULT_DB = _REPO_ROOT / "data" / "orgs.db"
_PURGE_WINDOW_DAYS = 30


def _find_eligible_orgs(db_path: Path) -> list[dict]:
    """Return orgs with status=DELETED and deleted_at >= 30 days ago."""
    if not db_path.exists():
        _logger.warning("orgs.db not found at %s — nothing to purge", db_path)
        return []

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    eligible: list[dict] = []
    try:
        # Check required columns exist
        cols = [c[1] for c in conn.execute("PRAGMA table_info(orgs)").fetchall()]
        if "deleted_at" not in cols or "status" not in cols:
            _logger.info("No soft-delete columns found in orgs table — nothing eligible")
            return []

        cutoff = (datetime.now(timezone.utc) - timedelta(days=_PURGE_WINDOW_DAYS)).isoformat()
        rows = conn.execute(
            "SELECT org_id, name, deleted_at FROM orgs "
            "WHERE status = 'DELETED' AND deleted_at IS NOT NULL AND deleted_at <= ?",
            (cutoff,),
        ).fetchall()
        eligible = [dict(r) for r in rows]
    finally:
        conn.close()
    return eligible


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GDPR hard-purge for soft-deleted orgs")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print eligible orgs without purging them",
    )
    parser.add_argument(
        "--db",
        default=str(_DEFAULT_DB),
        help=f"Path to orgs.db (default: {_DEFAULT_DB})",
    )
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    eligible = _find_eligible_orgs(db_path)

    if not eligible:
        _logger.info("No orgs eligible for purge (deleted_at >= %d days ago)", _PURGE_WINDOW_DAYS)
        return 0

    _logger.info("Found %d org(s) eligible for hard purge", len(eligible))
    for entry in eligible:
        _logger.info("  org_id=%s  name=%s  deleted_at=%s", entry["org_id"], entry["name"], entry["deleted_at"])

    if args.dry_run:
        _logger.info("DRY RUN — no data removed")
        return 0

    from core.org_engine import OrgEngine

    engine = OrgEngine(db_path=str(db_path))
    failed = 0

    for entry in eligible:
        org_id = entry["org_id"]
        try:
            result = engine.hard_purge_org(org_id, _force=True)
            _logger.info(
                "Purged org_id=%s — rows_deleted=%d tables=%s",
                org_id,
                result.get("rows_deleted", 0),
                result.get("tables_purged", []),
            )
        except Exception as exc:  # noqa: BLE001
            _logger.error("Failed to purge org_id=%s: %s", org_id, exc)
            failed += 1

    if failed:
        _logger.error("%d purge(s) failed", failed)
        return 1

    _logger.info("Purge complete — %d org(s) removed", len(eligible))
    return 0


if __name__ == "__main__":
    sys.exit(main())
