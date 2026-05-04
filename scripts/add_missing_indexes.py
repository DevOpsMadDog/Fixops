#!/usr/bin/env python3
"""
One-shot migration: add missing indexes to pre-existing SQLite DBs.

Safe to re-run — all statements use CREATE INDEX IF NOT EXISTS.
Run from repo root:
    python scripts/add_missing_indexes.py
"""
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent

MIGRATIONS: list[tuple[str, list[str]]] = [
    # ── cisa_kev.db ────────────────────────────────────────────────────────
    # kev_entries: only PK autoindex existed; feed_correlator + vuln_prioritizer
    # query by date_added, ransomware flag, vendor_project, and due_date.
    (
        "data/cisa_kev.db",
        [
            "CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_entries(date_added)",
            "CREATE INDEX IF NOT EXISTS idx_kev_ransomware  ON kev_entries(known_ransomware_use)",
            "CREATE INDEX IF NOT EXISTS idx_kev_vendor      ON kev_entries(vendor_project)",
            "CREATE INDEX IF NOT EXISTS idx_kev_due_date    ON kev_entries(due_date)",
        ],
    ),
    # ── report_schedules.db ────────────────────────────────────────────────
    # schedules: hottest query is WHERE org_id=? AND active=1 ORDER BY created_at
    # delivery_log: hottest query is WHERE org_id=? ORDER BY delivered_at DESC
    (
        "data/report_schedules.db",
        [
            "CREATE INDEX IF NOT EXISTS idx_sched_org_active  ON schedules (org_id, active)",
            "CREATE INDEX IF NOT EXISTS idx_sched_next_run    ON schedules (next_run_at)",
            "CREATE INDEX IF NOT EXISTS idx_dlog_org_delivered ON delivery_log (org_id, delivered_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_dlog_schedule     ON delivery_log (schedule_id)",
        ],
    ),
    # ── sbom.db ────────────────────────────────────────────────────────────
    # Legacy table used by older sbom ingest path; org_id + created_at are
    # the natural query axes.
    (
        "data/sbom.db",
        [
            "CREATE INDEX IF NOT EXISTS idx_sboms_org_created ON sboms (org_id, created_at DESC)",
        ],
    ),
    # ── hibp.db ────────────────────────────────────────────────────────────
    # Breach lookup by domain (most common), breach_date range, and
    # is_verified filter.
    (
        "data/hibp.db",
        [
            "CREATE INDEX IF NOT EXISTS idx_hibp_domain       ON breaches (domain)",
            "CREATE INDEX IF NOT EXISTS idx_hibp_breach_date  ON breaches (breach_date)",
            "CREATE INDEX IF NOT EXISTS idx_hibp_verified     ON breaches (is_verified)",
        ],
    ),
    # ── deduplication.db ───────────────────────────────────────────────────
    # clusters: status filter ('open'/'closed') and updated_at for age-based
    # sweep queries.
    (
        "data/deduplication.db",
        [
            "CREATE INDEX IF NOT EXISTS idx_clusters_status     ON clusters (status)",
            "CREATE INDEX IF NOT EXISTS idx_clusters_updated_at ON clusters (updated_at)",
        ],
    ),
    # ── analytics.db ───────────────────────────────────────────────────────
    # Live DB uses the older schema (no org_id column). idx_metrics_type and
    # idx_metrics_timestamp already exist. Add a composite on (metric_type,
    # metric_name) to speed up GROUP BY / WHERE metric_type=? AND metric_name=?
    # queries, and a standalone idx_metrics_name for metric_name-only lookups.
    (
        "data/analytics.db",
        [
            "CREATE INDEX IF NOT EXISTS idx_metrics_type_name ON metrics (metric_type, metric_name)",
            "CREATE INDEX IF NOT EXISTS idx_metrics_name       ON metrics (metric_name)",
        ],
    ),
    # ── feeds/feeds.db (feeds_service) ─────────────────────────────────────
    # kev_entries in the feeds DB also lacked indexes; mirror what _init_db
    # now creates so existing on-disk files get patched.
    (
        "data/feeds/feeds.db",
        [
            "CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_entries(date_added)",
            "CREATE INDEX IF NOT EXISTS idx_kev_ransomware  ON kev_entries(known_ransomware_campaign_use)",
            "CREATE INDEX IF NOT EXISTS idx_kev_vendor      ON kev_entries(vendor_project)",
            "CREATE INDEX IF NOT EXISTS idx_kev_due_date    ON kev_entries(due_date)",
        ],
    ),
]


def migrate(db_rel: str, stmts: list[str]) -> bool:
    db_path = ROOT / db_rel
    if not db_path.exists():
        print(f"  SKIP  {db_rel} (file not found)")
        return True
    try:
        conn = sqlite3.connect(db_path)
        try:
            for stmt in stmts:
                conn.execute(stmt)
            conn.commit()
            print(f"  OK    {db_rel} — {len(stmts)} index(es) applied")
        finally:
            conn.close()
        return True
    except sqlite3.OperationalError as exc:
        print(f"  ERROR {db_rel}: {exc}", file=sys.stderr)
        return False


def main() -> int:
    print("add_missing_indexes.py — SQLite index migration")
    print("=" * 55)
    ok = True
    for db_rel, stmts in MIGRATIONS:
        ok = migrate(db_rel, stmts) and ok
    print("=" * 55)
    if ok:
        print("Done — all migrations applied successfully.")
        return 0
    else:
        print("One or more migrations failed — see errors above.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
