#!/usr/bin/env python3
"""Background log monitor for ALdeci/FixOps. Checks every 15s for errors."""
import os
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = Path(".fixops_data/api_detailed_logs.db")
_base = os.environ.get("FIXOPS_API_URL", "http://localhost:8000")
HEALTH_URL = f"{_base}/api/v1/health"
API_KEY = os.environ.get("FIXOPS_API_TOKEN", "")
if not API_KEY:
    print("ERROR: FIXOPS_API_TOKEN env var not set. Export your enterprise token first.")
    sys.exit(2)
CHECK_INTERVAL = 15  # seconds
LOOKBACK = 20  # seconds


def check():
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'='*50}")
    print(f"LOG CHECK @ {ts}")
    print(f"{'='*50}")

    # 1. Check server health
    try:
        req = urllib.request.Request(HEALTH_URL, headers={"X-API-Key": API_KEY})
        resp = urllib.request.urlopen(req, timeout=3)
        print(f"  Server: UP (HTTP {resp.status})")
    except Exception as e:
        print(f"  SERVER DOWN: {e}")

    # 2. Check log DB for recent errors
    if not DB_PATH.exists():
        print("  Log DB not found")
        return

    db = sqlite3.connect(str(DB_PATH))
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=LOOKBACK)).isoformat()
        errors = list(
            db.execute(
                "SELECT ts, method, path, status_code, duration_ms "
                "FROM api_logs WHERE status_code >= 400 AND ts > ? ORDER BY id DESC LIMIT 10",
                (cutoff,),
            )
        )
        if errors:
            print(f"  ERRORS: {len(errors)} in last {LOOKBACK}s:")
            for r in errors:
                dur = f"{r[4]:.0f}ms" if r[4] else "?"
                print(f"    {r[1]} {r[2]} -> {r[3]} ({dur})")
        else:
            print(f"  No new errors in last {LOOKBACK}s")

        # 3. Overall stats
        row = db.execute(
            "SELECT COUNT(*), "
            "SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END), "
            "AVG(duration_ms) FROM api_logs"
        ).fetchone()
        print(
            f"  Totals: {row[0]} logs | {row[1]} 4xx+ | {row[2]} 5xx | avg {row[3]:.1f}ms"
        )
    finally:
        db.close()


if __name__ == "__main__":
    print("ALdeci Log Monitor started. Ctrl+C to stop.")
    try:
        while True:
            check()
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
