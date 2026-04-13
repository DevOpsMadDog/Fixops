#!/usr/bin/env python3
"""Seed ALDECI demo data on first startup.

Invoked automatically when ALDECI_SEED_DEMO=1 is set.
Idempotent: skips seeding if data already present.

Usage:
    python scripts/seed_demo_data.py
    ALDECI_SEED_DEMO=1 python scripts/seed_demo_data.py
"""

import os
import sys
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DATA_DIR = Path(os.environ.get("FIXOPS_DATA_DIR", "/app/data"))
SEED_MARKER = DATA_DIR / ".demo_seeded"


def _already_seeded() -> bool:
    return SEED_MARKER.exists()


def _mark_seeded() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SEED_MARKER.write_text(datetime.now(timezone.utc).isoformat())


def _db_path(name: str) -> Path:
    return DATA_DIR / name


def _exec(db: Path, sql: str, params: tuple = ()) -> None:
    with sqlite3.connect(str(db)) as conn:
        conn.execute(sql, params)
        conn.commit()


def seed_findings() -> None:
    """Insert sample security findings."""
    db = _db_path("analytics.db")
    if not db.exists():
        print("  [SKIP] analytics.db not found — skipping findings seed")
        return
    sample_findings = [
        ("CVE-2024-0001", "critical", "SQL injection in auth module", "auth-service"),
        ("CVE-2024-0002", "high",     "Unpatched log4j dependency",   "payment-service"),
        ("CVE-2024-0003", "medium",   "Missing CSRF token",            "web-frontend"),
        ("CVE-2024-0004", "low",      "Verbose error messages",        "api-gateway"),
        ("CVE-2024-0005", "critical", "Remote code execution via deserialization", "data-pipeline"),
    ]
    with sqlite3.connect(str(db)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS demo_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                component TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        existing = conn.execute("SELECT COUNT(*) FROM demo_findings").fetchone()[0]
        if existing == 0:
            now = datetime.now(timezone.utc).isoformat()
            conn.executemany(
                "INSERT INTO demo_findings (cve_id, severity, description, component, created_at) VALUES (?,?,?,?,?)",
                [(cve, sev, desc, comp, now) for cve, sev, desc, comp in sample_findings],
            )
            conn.commit()
            print(f"  [OK]  Seeded {len(sample_findings)} demo findings")
        else:
            print(f"  [SKIP] demo_findings already has {existing} rows")


def seed_assets() -> None:
    """Insert sample asset inventory."""
    db = _db_path("inventory.db")
    if not db.exists():
        print("  [SKIP] inventory.db not found — skipping assets seed")
        return
    sample_assets = [
        ("web-frontend",    "web",        "10.0.0.1", "production"),
        ("api-gateway",     "service",    "10.0.0.2", "production"),
        ("auth-service",    "service",    "10.0.0.3", "production"),
        ("payment-service", "service",    "10.0.0.4", "production"),
        ("data-pipeline",   "batch",      "10.0.0.5", "production"),
        ("dev-server",      "web",        "10.1.0.1", "development"),
        ("ci-runner",       "infra",      "10.1.0.2", "development"),
    ]
    with sqlite3.connect(str(db)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS demo_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                environment TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        existing = conn.execute("SELECT COUNT(*) FROM demo_assets").fetchone()[0]
        if existing == 0:
            now = datetime.now(timezone.utc).isoformat()
            conn.executemany(
                "INSERT INTO demo_assets (name, asset_type, ip_address, environment, created_at) VALUES (?,?,?,?,?)",
                [(name, atype, ip, env, now) for name, atype, ip, env in sample_assets],
            )
            conn.commit()
            print(f"  [OK]  Seeded {len(sample_assets)} demo assets")
        else:
            print(f"  [SKIP] demo_assets already has {existing} rows")


def seed_audit_events() -> None:
    """Insert sample audit log entries."""
    db = _db_path("audit.db")
    if not db.exists():
        print("  [SKIP] audit.db not found — skipping audit events seed")
        return
    sample_events = [
        ("login",           "admin",   "10.0.0.1", "success"),
        ("scan_triggered",  "admin",   "10.0.0.1", "success"),
        ("finding_closed",  "analyst", "10.0.0.5", "success"),
        ("report_exported", "ciso",    "10.0.0.9", "success"),
        ("login_failed",    "unknown", "1.2.3.4",  "failure"),
    ]
    with sqlite3.connect(str(db)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS demo_audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                outcome TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        existing = conn.execute("SELECT COUNT(*) FROM demo_audit_events").fetchone()[0]
        if existing == 0:
            now = datetime.now(timezone.utc).isoformat()
            conn.executemany(
                "INSERT INTO demo_audit_events (action, actor, source_ip, outcome, created_at) VALUES (?,?,?,?,?)",
                [(action, actor, ip, outcome, now) for action, actor, ip, outcome in sample_events],
            )
            conn.commit()
            print(f"  [OK]  Seeded {len(sample_events)} demo audit events")
        else:
            print(f"  [SKIP] demo_audit_events already has {existing} rows")


def main() -> int:
    if _already_seeded():
        print("Demo data already seeded — skipping.")
        return 0

    print(f"\nSeeding demo data into: {DATA_DIR.resolve()}")
    print("─" * 60)

    seed_findings()
    seed_assets()
    seed_audit_events()

    _mark_seeded()
    print("─" * 60)
    print("Demo data seeding complete.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
