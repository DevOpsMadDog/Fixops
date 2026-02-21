#!/usr/bin/env python3
"""Deep analysis of all API logs - find empty, fake, broken responses."""
import json
import sqlite3

DB = ".fixops_data/api_detailed_logs.db"
db = sqlite3.connect(DB)

print("=" * 80)
print("DEEP LOG ANALYSIS")
print("=" * 80)

# 1. Empty/null 200 responses
print("\n--- 1. EMPTY/NULL 200 OK RESPONSES ---")
rows = db.execute(
    """
    SELECT method, path, resp_body, COUNT(*) as cnt
    FROM api_logs WHERE status_code = 200
    AND path NOT LIKE '%/logs%' AND path NOT LIKE '%/health%'
    AND path NOT LIKE '%/openapi%' AND path NOT LIKE '%/docs%'
    GROUP BY method, path ORDER BY cnt DESC
"""
).fetchall()
for method, path, body, cnt in rows:
    if not body or body == "null":
        print(f"  [{cnt:>3}x] {method:4s} {path} -> NULL BODY")
        continue
    try:
        d = json.loads(body)
    except Exception:
        continue
    if isinstance(d, dict):
        empty_keys = []
        for k, v in d.items():
            if v == [] or v == 0 or v is None:
                empty_keys.append(f"{k}={v}")
            elif isinstance(v, dict) and not v:
                empty_keys.append(f"{k}={{}}")
        if empty_keys:
            print(f"  [{cnt:>3}x] {method:4s} {path}")
            print(f"         EMPTY FIELDS: {', '.join(empty_keys[:8])}")
    elif isinstance(d, list) and len(d) == 0:
        print(f"  [{cnt:>3}x] {method:4s} {path} -> EMPTY LIST []")

# 2. All errors
print("\n--- 2. ALL ERRORS (4xx/5xx) ---")
for r in db.execute(
    """
    SELECT method, path, status_code, resp_body, COUNT(*) as cnt
    FROM api_logs WHERE status_code >= 400
    GROUP BY method, path, status_code ORDER BY cnt DESC LIMIT 25
"""
):
    body = (r[3] or "")[:150]
    print(f"  [{r[4]:>3}x] {r[0]:4s} {r[1]:<55s} -> {r[2]}")
    if body:
        print(f"         {body}")

# 3. Feeds endpoints
print("\n--- 3. FEEDS ENDPOINTS ---")
for r in db.execute(
    """
    SELECT ts, method, path, status_code, resp_body, duration_ms
    FROM api_logs WHERE path LIKE '%feed%'
    ORDER BY rowid DESC LIMIT 15
"""
):
    body = (r[4] or "")[:200]
    dur = f"{r[5]:.0f}ms" if r[5] else "?"
    print(f"  {r[0][-12:]} {r[1]:4s} {r[2]:<50s} -> {r[3]} ({dur})")
    if body:
        print(f"         {body}")

# 4. Demo/mock/fake markers
print("\n--- 4. DEMO/MOCK/FAKE IN RESPONSES ---")
for r in db.execute(
    """
    SELECT method, path, resp_body, COUNT(*) as cnt
    FROM api_logs WHERE status_code = 200
    AND (resp_body LIKE '%"demo"%' OR resp_body LIKE '%demo_mode%'
         OR resp_body LIKE '%"mock"%' OR resp_body LIKE '%"fake"%'
         OR resp_body LIKE '%demo-token%' OR resp_body LIKE '%FIXOPS_MODE%')
    AND path NOT LIKE '%/logs%'
    GROUP BY method, path ORDER BY cnt DESC LIMIT 15
"""
):
    body = (r[2] or "")[:250]
    print(f"  [{r[3]:>3}x] {r[0]:4s} {r[1]}")
    print(f"         {body}")
    print()

# 5. Most recent 30 requests (your UI activity)
print("\n--- 5. LAST 30 REQUESTS (YOUR ACTIVITY) ---")
for r in db.execute(
    """
    SELECT ts, method, path, status_code, duration_ms, resp_body
    FROM api_logs
    WHERE path NOT LIKE '%/logs%' AND path NOT LIKE '%/health%'
    ORDER BY rowid DESC LIMIT 30
"""
):
    dur = f"{r[4]:.0f}ms" if r[4] else "?"
    body = (r[5] or "")[:120]
    emoji = "ERR" if r[3] >= 400 else "OK "
    print(f"  {emoji} {r[0][-12:]} {r[1]:4s} {r[2]:<50s} {r[3]} ({dur})")
    if r[3] >= 400 or (
        body and ("null" in body or '"count": 0' in body or '"count":0' in body)
    ):
        print(f"       RSP: {body}")

# 6. Config/overlay endpoint
print("\n--- 6. CONFIG/OVERLAY ENDPOINT ---")
for r in db.execute(
    """
    SELECT method, path, status_code, resp_body
    FROM api_logs WHERE path LIKE '%overlay%' OR path LIKE '%config%' OR path LIKE '%mode%'
    ORDER BY rowid DESC LIMIT 5
"""
):
    body = (r[3] or "")[:300]
    print(f"  {r[0]:4s} {r[1]} -> {r[2]}")
    print(f"       {body}")

db.close()
