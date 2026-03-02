#!/usr/bin/env python3
"""Quick API health check - hits every major endpoint."""
import urllib.request
import sys

TOKEN = "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh"
BASE = "http://localhost:8000"

ENDPOINTS = [
    "health",
    "api/v1/brain/status",
    "api/v1/brain/pipeline/status",
    "api/v1/findings?limit=3",
    "api/v1/exposure-cases?limit=3",
    "api/v1/deduplication/stats",
    "api/v1/integrations",
    "api/v1/connectors",
    "api/v1/autofix/status",
    "api/v1/mpte/status",
    "api/v1/micro-pentest/status",
    "api/v1/fail/status",
    "api/v1/feeds/status",
    "api/v1/evidence/",
    "api/v1/compliance/frameworks",
    "api/v1/scanners/sast/status",
    "api/v1/scanners/dast/status",
    "api/v1/scanners/secrets/status",
    "api/v1/scanners/container/status",
    "api/v1/iac/status",
    "api/v1/mcp-server/status",
    "api/v1/mcp/tools",
    "api/v1/analytics/dashboard",
    "api/v1/workflows",
    "api/v1/policies",
    "api/v1/reports",
    "api/v1/cases",
    "api/v1/audit/logs",
    "api/v1/remediation/tasks",
    "api/v1/inventory/applications",
    "api/v1/users",
    "api/v1/teams",
    "api/v1/collaboration/comments",
    "api/v1/knowledge-graph/stats",
    "api/v1/predictions/status",
    "api/v1/scanner-ingest/supported",
    "api/v1/sandbox/health",
]

ok = 0
fail = 0
errors = []
for ep in ENDPOINTS:
    try:
        req = urllib.request.Request(
            f"{BASE}/{ep}",
            headers={"X-API-Key": TOKEN},
        )
        resp = urllib.request.urlopen(req, timeout=5)
        code = resp.getcode()
        body = resp.read()
        print(f"  {code} [{len(body):>6}B] {ep}")
        ok += 1
    except Exception as e:
        code = getattr(e, "code", "ERR")
        msg = str(e)[:80]
        print(f"  {code} {ep} -- {msg}")
        errors.append((ep, code, msg))
        fail += 1

print(f"\n--- {ok} OK, {fail} FAILED out of {len(ENDPOINTS)} ---")
if errors:
    print("\nFailed endpoints:")
    for ep, code, msg in errors:
        print(f"  {code} {ep}")
sys.exit(1 if fail > 0 else 0)
