#!/usr/bin/env python3
"""Phase 18 verification - check all endpoints return real data."""
import json
import urllib.request
import sys

BASE = "http://localhost:8000"
HEADERS = {"X-API-Key": "test-token-123"}

def get(path):
    req = urllib.request.Request(f"{BASE}{path}", headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
            return resp.status, json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def post(path, data=None):
    body = json.dumps(data or {}).encode() if data else b"{}"
    req = urllib.request.Request(f"{BASE}{path}", data=body, headers={**HEADERS, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

passed = 0
failed = 0

checks = [
    ("GET",  "/api/v1/health", lambda s, d: s == 200),
    ("GET",  "/api/v1/nerve-center/overlay", lambda s, d: s == 200 and d.get("api_config", {}).get("mode") == "enterprise"),
    ("GET",  "/api/v1/nerve-center/pulse", lambda s, d: s == 200 and "score" in str(d)),
    ("GET",  "/api/v1/brain/stats", lambda s, d: s == 200 and d.get("total_nodes", 0) > 0),
    ("GET",  "/api/v1/brain/all-edges", lambda s, d: s == 200 and isinstance(d, dict) and len(d.get("edges", [])) > 0),
    ("GET",  "/api/v1/feeds/health", lambda s, d: s == 200 and any(f.get("total_records", 0) > 0 for f in d.get("feeds", []))),
    ("GET",  "/api/v1/feeds/stats", lambda s, d: s == 200 and d.get("total_cves", 0) > 0),
    ("GET",  "/api/v1/feeds/kev", lambda s, d: s == 200 and isinstance(d, dict)),
    ("GET",  "/api/v1/analytics/findings", lambda s, d: s == 200 and isinstance(d, list) and len(d) > 0),
    ("GET",  "/api/v1/analytics/dashboard/overview", lambda s, d: s == 200),
    ("GET",  "/api/v1/inventory/applications", lambda s, d: s == 200 and (isinstance(d, list) and len(d) > 0 or isinstance(d, dict) and d.get("total", 0) > 0)),
    ("GET",  "/api/v1/evidence/stats", lambda s, d: s == 200 and d.get("total_releases", 0) > 0),
    ("GET",  "/api/v1/evidence/", lambda s, d: s == 200 and d.get("count", 0) > 0),
    ("GET",  "/api/v1/provenance/", lambda s, d: s == 200 and isinstance(d, list) and len(d) > 0),
    ("GET",  "/api/v1/mpte/results", lambda s, d: s == 200 and d.get("total", 0) > 0),
    ("GET",  "/api/v1/mpte/configs", lambda s, d: s == 200 and d.get("total", 0) > 0),
    ("GET",  "/api/v1/collaboration/notifications/pending", lambda s, d: s == 200 and d.get("count", 0) >= 0),
    ("GET",  "/api/v1/ml/status", lambda s, d: s == 200 and "models" in str(d)),
    ("GET",  "/api/v1/ml/stats", lambda s, d: s == 200 and d.get("total_requests", 0) > 0),
    ("GET",  "/api/v1/ml/analytics/stats", lambda s, d: s == 200),
    ("GET",  "/api/v1/vulns/discovered", lambda s, d: s == 200 and isinstance(d, list)),
    ("GET",  "/api/v1/remediation/tasks", lambda s, d: s == 200),
    ("GET",  "/api/v1/brain/pipeline/runs", lambda s, d: s == 200),
    ("GET",  "/api/v1/attack-sim/health", lambda s, d: s == 200),
    ("GET",  "/api/v1/integrations/", lambda s, d: s == 200),
]

print("=" * 70)
print("PHASE 18 ENDPOINT VERIFICATION")
print("=" * 70)

for method, path, check in checks:
    if method == "GET":
        status, data = get(path)
    else:
        status, data = post(path)
    
    ok = False
    try:
        ok = check(status, data)
    except Exception:
        pass
    
    icon = "✅" if ok else "❌"
    if ok:
        passed += 1
    else:
        failed += 1
    
    detail = ""
    if not ok:
        detail = f" (HTTP {status})"
        if isinstance(data, dict) and "detail" in data:
            detail += f" {data['detail']}"
    
    print(f"  {icon} {method:4s} {path:<50s} {detail}")

print()
print(f"RESULTS: {passed}/{passed+failed} passed, {failed} failed")
if failed == 0:
    print("🎉 ALL CHECKS PASSED")
else:
    print(f"⚠️  {failed} checks need attention")
    sys.exit(1)

