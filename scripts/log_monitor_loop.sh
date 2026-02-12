#!/bin/bash
cd /Users/devops.ai/developement/fixops/Fixops
while true; do
  .venv/bin/python3 -c "
import sqlite3, json
from datetime import datetime, timedelta, timezone
db = sqlite3.connect('.fixops_data/api_detailed_logs.db')
cutoff = (datetime.now(timezone.utc) - timedelta(seconds=20)).isoformat()

errors = list(db.execute(
    'SELECT ts, method, path, status_code, resp_body, duration_ms FROM api_logs WHERE status_code >= 400 AND ts > ? ORDER BY id DESC LIMIT 10',
    (cutoff,)))

empty = list(db.execute('''
    SELECT ts, method, path, resp_body FROM api_logs
    WHERE status_code = 200 AND ts > ?
    AND (resp_body = '[]' OR resp_body = '{}' OR resp_body = 'null' OR resp_body IS NULL
         OR resp_body LIKE '%\"count\":0%' OR resp_body LIKE '%\"total\":0%' OR resp_body LIKE '%\"items\":[]%')
    AND path NOT LIKE '%/health%' AND path NOT LIKE '%/logs%' AND path NOT LIKE '%/status%'
    ORDER BY id DESC LIMIT 10
''', (cutoff,)))

recent = list(db.execute(
    'SELECT ts, method, path, status_code, duration_ms, resp_body FROM api_logs WHERE ts > ? ORDER BY id DESC LIMIT 15',
    (cutoff,)))

row = db.execute('SELECT COUNT(*) FROM api_logs').fetchone()

print(f'--- LOG CHECK {datetime.now().strftime(\"%H:%M:%S\")} | Total DB: {row[0]} ---')

if errors:
    print(f'  ERRORS ({len(errors)}):')
    for r in errors:
        body = (r[4][:150] if r[4] else 'null')
        print(f'    {r[1]:4s} {r[2]:<55s} -> {r[3]} ({r[5]:.0f}ms)')
        print(f'         {body}')
else:
    print('  No errors in last 20s')

if empty:
    print(f'  EMPTY 200s ({len(empty)}):')
    for r in empty:
        body = (r[3][:120] if r[3] else 'null')
        print(f'    {r[1]:4s} {r[2]:<55s} -> {body}')

if recent:
    print(f'  Recent ({len(recent)} requests):')
    for r in recent:
        icon = 'OK' if r[3] < 400 else 'ERR'
        print(f'    [{icon}] {r[1]:4s} {r[2]:<55s} -> {r[3]} ({r[4]:.0f}ms)')

db.close()
" 2>&1
  sleep 15
done

