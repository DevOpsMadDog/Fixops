#!/usr/bin/env python3
"""Check recent API logs for errors and empty responses."""
import sqlite3, json

db = sqlite3.connect('.fixops_data/api_detailed_logs.db')

total = db.execute("SELECT COUNT(*) FROM api_logs WHERE ts > datetime('now', '-30 minutes')").fetchone()[0]
errors = db.execute("SELECT COUNT(*) FROM api_logs WHERE status_code >= 400 AND ts > datetime('now', '-30 minutes')").fetchone()[0]

print(f"=== RECENT LOGS (last 30 min) ===")
print(f"Total: {total}, Errors: {errors}, Error Rate: {errors/max(total,1)*100:.1f}%")
print()

rows = db.execute("""
    SELECT method, path, status_code, COUNT(*) as cnt
    FROM api_logs
    WHERE status_code >= 400
    AND ts > datetime('now', '-30 minutes')
    GROUP BY method, path, status_code
    ORDER BY cnt DESC
    LIMIT 20
""").fetchall()

if rows:
    print("Error endpoints:")
    for r in rows:
        print(f"  [{r[3]:>3}x] {r[0]:4s} {r[1]:<55s} -> {r[2]}")
else:
    print("✅ NO ERRORS in last 30 minutes")

# Check for empty 200 responses
empty = db.execute("""
    SELECT method, path, COUNT(*) as cnt
    FROM api_logs
    WHERE status_code = 200
    AND (resp_body = '[]' OR resp_body = '{}' OR resp_body = 'null' OR resp_body IS NULL)
    AND ts > datetime('now', '-30 minutes')
    AND path NOT LIKE '%/health%'
    AND path NOT LIKE '%/logs%'
    AND path NOT LIKE '%/docs%'
    GROUP BY method, path
    ORDER BY cnt DESC
    LIMIT 10
""").fetchall()

if empty:
    print()
    print("Empty 200 responses:")
    for r in empty:
        print(f"  [{r[2]:>3}x] {r[0]:4s} {r[1]}")

# Status code distribution
print()
print("Status code distribution (last 30 min):")
for r in db.execute("""
    SELECT status_code, COUNT(*) as cnt
    FROM api_logs
    WHERE ts > datetime('now', '-30 minutes')
    GROUP BY status_code
    ORDER BY cnt DESC
""").fetchall():
    print(f"  HTTP {r[0]}: {r[1]}")

db.close()

