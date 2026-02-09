#!/usr/bin/env python3
"""Quick API test to verify endpoints are working."""
import requests

BASE_URL = "http://localhost:8000"
headers = {"X-API-Key": "demo-token", "Content-Type": "application/json"}

endpoints = [
    ("GET", "/health", None),
    ("GET", "/api/v1/analytics/dashboard/overview?org_id=default", None),
    ("GET", "/api/v1/analytics/dashboard/trends?org_id=default", None),
    ("GET", "/api/v1/deduplication/clusters?org_id=default", None),
    ("GET", "/api/v1/feeds/epss", None),
    ("GET", "/api/v1/feeds/kev", None),
    ("GET", "/api/v1/llm/status", None),
    ("GET", "/api/v1/llm/providers", None),
    ("GET", "/api/v1/copilot/health", None),
    ("GET", "/api/v1/webhooks/outbox", None),
    ("GET", "/api/v1/webhooks/events", None),
    ("GET", "/api/v1/integrations", None),
    ("GET", "/api/v1/teams", None),
    ("GET", "/api/v1/users", None),
    ("GET", "/api/v1/policies", None),
    ("GET", "/api/v1/workflows", None),
    ("GET", "/api/v1/reports", None),
    ("GET", "/api/v1/audit/logs", None),
    ("GET", "/api/v1/inventory/applications", None),
    ("GET", "/api/v1/remediation/tasks?org_id=default", None),
    ("GET", "/api/v1/mpte/requests", None),
    ("GET", "/evidence/", None),
    ("GET", "/api/v1/secrets", None),
    ("GET", "/api/v1/iac", None),
    ("GET", "/graph/", None),
]

passed = 0
failed = 0
for method, endpoint, data in endpoints:
    try:
        if method == "GET":
            resp = requests.get(f"{BASE_URL}{endpoint}", headers=headers, timeout=10)
        else:
            resp = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=data, timeout=10)
        status = resp.status_code
        if status in [200, 201]:
            print(f"OK  {status} {method} {endpoint}")
            passed += 1
        else:
            err = resp.text[:60].replace("\n", " ")
            print(f"ERR {status} {method} {endpoint}: {err}")
            failed += 1
    except Exception as e:
        print(f"EXC {method} {endpoint}: {str(e)[:60]}")
        failed += 1

print(f"\n=== {passed}/{passed+failed} passed ({100*passed/(passed+failed):.1f}%) ===")
