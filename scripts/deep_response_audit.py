#!/usr/bin/env python3
"""Deep audit of all API responses - find nulls, empties, broken data."""
import sqlite3, json, os, sys

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(PROJECT, ".fixops_data", "api_detailed_logs.db")
OUT = os.path.join(PROJECT, "response_audit.txt")

db = sqlite3.connect(DB)
f = open(OUT, "w")

def p(s=""):
    f.write(s + "\n")

p("=" * 90)
p("DEEP RESPONSE AUDIT - Every 200 OK with empty/null/zero/broken data")
p("=" * 90)

# 1. Empty/null/zero responses
p("\n--- 1. 200 OK but EMPTY/NULL/ZERO responses ---")
rows = db.execute("""
    SELECT method, path, resp_body, COUNT(*) as cnt
    FROM api_logs WHERE status_code = 200
    AND path NOT LIKE '%/health%' AND path NOT LIKE '%/logs%'
    AND path NOT LIKE '%/docs%' AND path NOT LIKE '%/openapi%'
    AND path NOT LIKE '%/static%' AND path NOT LIKE '%/favicon%'
    GROUP BY method, path
    ORDER BY cnt DESC
""").fetchall()

empty_paths = []
for method, path, body, cnt in rows:
    if not body or body in ('null', '{}', '[]', '""', "''"):
        empty_paths.append((method, path, cnt, body or "NULL"))
        continue
    try:
        d = json.loads(body)
    except Exception:
        continue
    is_empty = False
    if isinstance(d, dict):
        for k, v in d.items():
            if v in ([], {}, None, 0, "", "null") and k not in ("error",):
                is_empty = True
                break
            if isinstance(v, dict) and all(vv in (0, [], None, {}, "") for vv in v.values()):
                is_empty = True
                break
    elif isinstance(d, list) and len(d) == 0:
        is_empty = True
    if is_empty:
        empty_paths.append((method, path, cnt, (body or "")[:300]))

for method, path, cnt, body in sorted(empty_paths, key=lambda x: -x[2]):
    p(f"  [{cnt:>3}x] {method:4s} {path}")
    p(f"         RSP: {body[:300]}")
    p()

# 2. All 4xx/5xx errors
p("\n--- 2. ALL 4xx/5xx ERRORS ---")
for r in db.execute("""
    SELECT method, path, status_code, resp_body, COUNT(*) as cnt
    FROM api_logs WHERE status_code >= 400
    GROUP BY method, path, status_code ORDER BY cnt DESC LIMIT 30
""").fetchall():
    body = (r[3] or "")[:200]
    p(f"  [{r[4]:>3}x] {r[0]:4s} {r[1]:<55s} -> {r[2]}  body={body}")

# 3. Feeds-specific analysis
p("\n--- 3. FEEDS ENDPOINTS (all calls) ---")
for r in db.execute("""
    SELECT ts, method, path, status_code, resp_body, duration_ms
    FROM api_logs WHERE path LIKE '%/feeds%'
    ORDER BY rowid DESC LIMIT 20
""").fetchall():
    body = (r[4] or "")[:250]
    p(f"  {r[0][-19:]} {r[1]:4s} {r[2]:<45s} -> {r[3]} ({r[5]:.0f}ms)")
    p(f"         RSP: {body}")
    p()

# 4. All unique GET 200 endpoints with response preview
p("\n--- 4. ALL GET 200 ENDPOINTS (response preview) ---")
for r in db.execute("""
    SELECT path, resp_body, COUNT(*) as cnt, AVG(duration_ms) as avg_dur
    FROM api_logs WHERE method = 'GET' AND status_code = 200
    AND path NOT LIKE '%/logs%' AND path NOT LIKE '%/health%'
    AND path NOT LIKE '%/docs%' AND path NOT LIKE '%/openapi%'
    GROUP BY path ORDER BY path
""").fetchall():
    body = (r[1] or "NULL")[:200]
    p(f"  [{r[2]:>3}x {r[3]:>6.0f}ms] {r[0]}")
    p(f"        {body}")
    p()

# 5. POST responses
p("\n--- 5. ALL POST 200 ENDPOINTS (req+resp preview) ---")
for r in db.execute("""
    SELECT path, req_body, resp_body, COUNT(*) as cnt
    FROM api_logs WHERE method = 'POST' AND status_code BETWEEN 200 AND 299
    AND path NOT LIKE '%/logs%'
    GROUP BY path ORDER BY path
""").fetchall():
    req = (r[1] or "NULL")[:150]
    resp = (r[2] or "NULL")[:200]
    p(f"  [{r[3]:>3}x] POST {r[0]}")
    p(f"        REQ:  {req}")
    p(f"        RSP:  {resp}")
    p()

# 6. Recent errors (last 5 min)
p("\n--- 6. RECENT ERRORS (last 5 min) ---")
for r in db.execute("""
    SELECT ts, method, path, status_code, resp_body
    FROM api_logs WHERE status_code >= 400
    AND ts > datetime('now', '-5 minutes')
    ORDER BY ts DESC LIMIT 20
""").fetchall():
    body = (r[4] or "")[:200]
    p(f"  {r[0][-19:]} {r[1]:4s} {r[2]:<50s} -> {r[3]}")
    p(f"         {body}")

# Summary
total = db.execute("SELECT COUNT(*) FROM api_logs").fetchone()[0]
errors = db.execute("SELECT COUNT(*) FROM api_logs WHERE status_code >= 400").fetchone()[0]
p(f"\n--- SUMMARY ---")
p(f"Total logs: {total}")
p(f"Total errors: {errors} ({errors/max(total,1)*100:.1f}%)")
p(f"Empty/null 200 paths: {len(empty_paths)}")

db.close()
f.close()
print(f"Report written to {OUT} ({os.path.getsize(OUT)} bytes)")

