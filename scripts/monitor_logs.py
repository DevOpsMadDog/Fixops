#!/usr/bin/env python3
"""Live log monitor - writes report to log_report.txt"""
import sqlite3, json, os, sys
from datetime import datetime, timedelta, timezone

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(PROJECT, '.fixops_data', 'api_detailed_logs.db')
OUT = os.path.join(PROJECT, 'log_report.txt')

if not os.path.exists(DB):
    with open(OUT, 'w') as f:
        f.write(f"ERROR: DB not found at {DB}\n")
    sys.exit(1)

db = sqlite3.connect(DB)
lines = []
def p(s=''):
    lines.append(s)

p(f"=== LOG REPORT {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
p()

# Stats
total = db.execute("SELECT COUNT(*) FROM api_logs").fetchone()[0]
recent = db.execute("SELECT COUNT(*) FROM api_logs WHERE ts > datetime('now', '-5 minutes')").fetchone()[0]
errors_recent = db.execute("SELECT COUNT(*) FROM api_logs WHERE status_code >= 400 AND ts > datetime('now', '-5 minutes')").fetchone()[0]
p(f"Total logs: {total} | Last 5 min: {recent} requests, {errors_recent} errors ({errors_recent/max(recent,1)*100:.1f}%)")
p()

# Recent errors
p("=== RECENT 4xx/5xx ERRORS (last 5 min) ===")
rows = db.execute("""
    SELECT method, path, status_code, resp_body, COUNT(*) as cnt
    FROM api_logs WHERE status_code >= 400 AND ts > datetime('now', '-5 minutes')
    GROUP BY method, path, status_code ORDER BY cnt DESC LIMIT 30
""").fetchall()
if not rows:
    p("  (none)")
for r in rows:
    body = (r[3][:250] if r[3] else 'null')
    p(f"  [{r[4]:>3}x] {r[0]:4s} {r[1]:<55s} -> {r[2]}")
    p(f"         {body}")
    p()

# Empty 200 responses
p("=== EMPTY/NULL 200 RESPONSES (last 5 min) ===")
rows = db.execute("""
    SELECT method, path, resp_body, COUNT(*) as cnt
    FROM api_logs WHERE status_code = 200 AND ts > datetime('now', '-5 minutes')
    AND (resp_body IS NULL OR resp_body = '' OR resp_body = 'null' OR resp_body = '{}'
         OR resp_body = '[]' OR resp_body LIKE '%"count":0%' OR resp_body LIKE '%"total":0%'
         OR resp_body LIKE '%"items":[]%' OR resp_body LIKE '%"results":[]%'
         OR resp_body LIKE '%"nodes":[]%' OR resp_body LIKE '%"runs":[]%')
    AND path NOT LIKE '%/health%' AND path NOT LIKE '%/logs%'
    GROUP BY method, path ORDER BY cnt DESC LIMIT 20
""").fetchall()
if not rows:
    p("  (none)")
for r in rows:
    body = (r[2][:250] if r[2] else 'null')
    p(f"  [{r[3]:>3}x] {r[0]:4s} {r[1]:<55s}")
    p(f"         {body}")
    p()

# All recent requests (last 50)
p("=== LAST 50 REQUESTS ===")
for r in db.execute("""
    SELECT ts, method, path, status_code, duration_ms, resp_body
    FROM api_logs ORDER BY id DESC LIMIT 50
""").fetchall():
    icon = 'OK' if r[3] < 400 else 'ERR'
    body = (r[5][:120] if r[5] else 'null')
    p(f"  [{icon}] {r[0][-12:]} {r[1]:4s} {r[2]:<55s} -> {r[3]} ({r[4]:.0f}ms)")
    p(f"         {body}")

# Feeds-specific
p()
p("=== FEEDS ENDPOINTS ===")
for r in db.execute("""
    SELECT ts, method, path, status_code, resp_body
    FROM api_logs WHERE path LIKE '%/feeds%'
    ORDER BY rowid DESC LIMIT 10
""").fetchall():
    body = (r[4][:200] if r[4] else 'null')
    p(f"  {r[0][-12:]} {r[1]:4s} {r[2]:<50s} -> {r[3]}")
    p(f"         {body}")

# Demo/mock in responses
p()
p("=== DEMO/MOCK/FAKE IN RESPONSES ===")
for r in db.execute("""
    SELECT DISTINCT method, path, resp_body
    FROM api_logs WHERE status_code = 200
    AND (resp_body LIKE '%demo%' OR resp_body LIKE '%mock%' OR resp_body LIKE '%fake%')
    AND path NOT LIKE '%/logs%' AND path NOT LIKE '%/overlay%'
    ORDER BY path LIMIT 10
""").fetchall():
    body = (r[2][:200] if r[2] else 'null')
    p(f"  {r[0]:4s} {r[1]}")
    p(f"         {body}")

db.close()

with open(OUT, 'w') as f:
    f.write('\n'.join(lines) + '\n')

print(f"Report written to {OUT} ({len(lines)} lines)")

