#!/usr/bin/env python3
"""Analyze API logs for errors and empty responses."""
import sqlite3
import json

db = sqlite3.connect('.fixops_data/api_detailed_logs.db')

print("=== ALL 4xx/5xx ERRORS (recent first, last 50) ===")
for r in db.execute(
    "SELECT method, path, status_code, resp_body, ts "
    "FROM api_logs WHERE status_code >= 400 ORDER BY ts DESC LIMIT 50"
).fetchall():
    method, path, status, body, ts = r
    body_str = (body[:200] if body else "null")
    print(f"  {ts} {method:4s} {path:<55s} -> {status} {body_str}")

print("\n=== ERROR SUMMARY BY ENDPOINT ===")
for r in db.execute(
    "SELECT method, path, status_code, COUNT(*) as cnt "
    "FROM api_logs WHERE status_code >= 400 "
    "GROUP BY method, path, status_code ORDER BY cnt DESC LIMIT 30"
).fetchall():
    print(f"  [{r[3]:>3}x] {r[0]:4s} {r[1]:<55s} -> {r[2]}")

print("\n=== 200 OK but EMPTY/NULL/ZERO responses ===")
for r in db.execute(
    "SELECT method, path, resp_body, ts FROM api_logs "
    "WHERE status_code = 200 AND ("
    "resp_body IS NULL OR resp_body = '' OR resp_body = 'null' "
    "OR resp_body = '{}' OR resp_body = '[]' "
    "OR resp_body LIKE '%\"items\":[]%' "
    "OR resp_body LIKE '%\"count\":0%' "
    "OR resp_body LIKE '%\"total\":0%'"
    ") ORDER BY ts DESC LIMIT 30"
).fetchall():
    body = (r[2][:200] if r[2] else "null")
    print(f"  {r[3]} {r[0]:4s} {r[1]:<50s} -> {body}")

print("\n=== TOTAL LOG STATS ===")
total = db.execute("SELECT COUNT(*) FROM api_logs").fetchone()[0]
errors = db.execute("SELECT COUNT(*) FROM api_logs WHERE status_code >= 400").fetchone()[0]
ok = db.execute("SELECT COUNT(*) FROM api_logs WHERE status_code < 400").fetchone()[0]
print(f"  Total logs: {total}")
print(f"  Success (< 400): {ok}")
print(f"  Errors (>= 400): {errors}")
print(f"  Error rate: {errors/total*100:.1f}%")

db.close()

