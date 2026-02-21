#!/usr/bin/env python3
"""Quick log analysis - check current state of API logs. Writes to /tmp/fixops_log_report.txt"""
import os
import sqlite3
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
OUT = os.path.join(PROJECT_DIR, "log_report.txt")
DB_PATH = os.path.join(PROJECT_DIR, ".fixops_data", "api_detailed_logs.db")

if not os.path.exists(DB_PATH):
    with open(OUT, "w") as f:
        f.write(f"ERROR: DB not found at {DB_PATH}\n")
    sys.exit(1)

f = open(OUT, "w")
db = sqlite3.connect(DB_PATH)

total = db.execute("SELECT COUNT(*) FROM api_logs").fetchone()[0]
recent = db.execute(
    "SELECT COUNT(*) FROM api_logs WHERE ts > datetime('now', '-5 minutes')"
).fetchone()[0]
errors_recent = db.execute(
    "SELECT COUNT(*) FROM api_logs WHERE status_code >= 400 AND ts > datetime('now', '-5 minutes')"
).fetchone()[0]

f.write("=" * 70 + "\n")
f.write("  API LOG ANALYSIS\n")
f.write("=" * 70 + "\n")
f.write(f"Total logs: {total}\n")
f.write(
    f"Last 5 min: {recent} requests, {errors_recent} errors ({errors_recent/max(recent, 1)*100:.1f}%)\n"
)
f.write("\n")

# Recent errors
f.write("--- RECENT ERRORS (last 5 min) ---\n")
rows = db.execute(
    """
    SELECT ts, method, path, status_code, resp_body, duration_ms
    FROM api_logs WHERE status_code >= 400 AND ts > datetime('now', '-5 minutes')
    ORDER BY ts DESC LIMIT 20
"""
).fetchall()
if not rows:
    f.write("  (none)\n")
for r in rows:
    body = r[4][:200] if r[4] else "null"
    f.write(f"  {r[0][-12:]} {r[1]:4s} {r[2]:<55s} -> {r[3]} ({r[5]:.0f}ms)\n")
    f.write(f"           RSP: {body}\n\n")

# Recent errors (last 30 min for broader view)
f.write("\n--- RECENT ERRORS (last 30 min) ---\n")
rows30 = db.execute(
    """
    SELECT ts, method, path, status_code, resp_body, duration_ms
    FROM api_logs WHERE status_code >= 400 AND ts > datetime('now', '-30 minutes')
    ORDER BY ts DESC LIMIT 30
"""
).fetchall()
if not rows30:
    f.write("  (none)\n")
for r in rows30:
    body = r[4][:200] if r[4] else "null"
    f.write(f"  {r[0][-12:]} {r[1]:4s} {r[2]:<55s} -> {r[3]} ({r[5]:.0f}ms)\n")
    f.write(f"           RSP: {body}\n\n")

# Empty 200 responses
f.write("--- EMPTY 200 RESPONSES (last 30 min) ---\n")
rows = db.execute(
    """
    SELECT ts, method, path, resp_body
    FROM api_logs WHERE status_code = 200
    AND ts > datetime('now', '-30 minutes')
    AND (resp_body IS NULL OR resp_body = '' OR resp_body = 'null'
         OR resp_body = '{}' OR resp_body = '[]'
         OR resp_body LIKE '%"count":0%' OR resp_body LIKE '%"total":0%'
         OR resp_body LIKE '%"items":[]%')
    AND path NOT LIKE '%/health%' AND path NOT LIKE '%/logs%'
    ORDER BY ts DESC LIMIT 20
"""
).fetchall()
if not rows:
    f.write("  (none)\n")
for r in rows:
    body = r[3][:200] if r[3] else "null"
    f.write(f"  {r[0][-12:]} {r[1]:4s} {r[2]:<50s} -> {body}\n")

# Last 50 requests
f.write("\n--- LAST 50 REQUESTS ---\n")
for r in db.execute(
    """
    SELECT ts, method, path, status_code, duration_ms, resp_body
    FROM api_logs ORDER BY id DESC LIMIT 50
"""
).fetchall():
    body = r[5][:120] if r[5] else "null"
    icon = "OK" if r[3] < 400 else "ERR"
    f.write(
        f"  [{icon:>3}] {r[0][-12:]} {r[1]:4s} {r[2]:<55s} {r[3]} ({r[4]:.0f}ms) {body}\n"
    )

# Error summary by endpoint (all time)
f.write("\n--- ERROR SUMMARY BY ENDPOINT (all time) ---\n")
for r in db.execute(
    """
    SELECT method, path, status_code, COUNT(*) as cnt
    FROM api_logs WHERE status_code >= 400
    GROUP BY method, path, status_code
    ORDER BY cnt DESC LIMIT 20
"""
).fetchall():
    f.write(f"  [{r[3]:>3}x] {r[0]:4s} {r[1]:<55s} -> {r[2]}\n")

db.close()
f.close()
print(f"Report written to {OUT}")
