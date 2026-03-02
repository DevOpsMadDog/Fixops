#!/usr/bin/env python3
"""Probe all major API routes with corrected paths."""
import urllib.request

TOKEN = "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh"
BASE = "http://localhost:8000"

ENDPOINTS = [
    # Health
    "health",
    # Brain / Pipeline
    "api/v1/brain/status",
    "api/v1/brain/pipeline/status",
    "api/v1/brain/stats",
    # Findings / Cases
    "api/v1/findings",
    "api/v1/findings?limit=3",
    "api/v1/exposure-cases",
    "api/v1/exposure-cases?limit=3",
    # Scanners (corrected paths - /api/v1/sast not /api/v1/scanners/sast)
    "api/v1/sast/status",
    "api/v1/sast/scan",
    "api/v1/dast/status",
    "api/v1/secrets/status",
    "api/v1/container/status",
    "api/v1/cspm/status",
    # Core engines
    "api/v1/autofix/status",
    "api/v1/mpte/status",
    "api/v1/mpte/scans",
    "api/v1/micro-pentest/status",
    "api/v1/fail/status",
    "api/v1/fail/scores",
    # Feeds
    "api/v1/feeds/status",
    "api/v1/feeds/nvd/status",
    # Evidence / Compliance
    "api/v1/evidence/",
    "api/v1/compliance/frameworks",
    "api/v1/compliance-engine/frameworks",
    # MCP
    "api/v1/mcp-server/status",
    "api/v1/mcp/tools",
    "api/v1/mcp-protocol/status",
    # Analytics
    "api/v1/analytics/dashboard",
    "api/v1/analytics/summary",
    # Operational
    "api/v1/deduplication/stats",
    "api/v1/connectors",
    "api/v1/integrations",
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
    "api/v1/predictions/models",
    "api/v1/scanner-ingest/supported",
    "api/v1/sandbox/health",
    # Pipeline
    "api/v1/pipeline/status",
]

ok_eps = []
fail_eps = []

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
        ok_eps.append(ep)
    except Exception as e:
        code = getattr(e, "code", "ERR")
        try:
            detail = e.read().decode()[:80]
        except Exception:
            detail = str(e)[:80]
        print(f"  {code} {ep} -> {detail}")
        fail_eps.append((ep, code))

print(f"\n=== {len(ok_eps)} OK, {len(fail_eps)} FAILED out of {len(ENDPOINTS)} ===")
if fail_eps:
    print("\nFailed:")
    for ep, code in fail_eps:
        print(f"  {code} {ep}")
