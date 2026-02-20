#!/usr/bin/env python3
"""FixOps Enterprise Smoke Test — hits every major endpoint, prints PASS/FAIL."""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

API = os.environ.get("FIXOPS_API_URL", "http://localhost:8000")
KEY = os.environ.get("FIXOPS_API_TOKEN", "")
if not KEY:
    print("ERROR: FIXOPS_API_TOKEN must be set")
    sys.exit(1)

PASS = FAIL = 0


def hit(method, path, data=None, desc=None):
    global PASS, FAIL
    desc = desc or f"{method} {path}"
    try:
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(
            f"{API}{path}",
            data=body,
            headers={"X-API-Key": KEY, "Content-Type": "application/json"},
            method=method,
        )
        resp = urllib.request.urlopen(req, timeout=30)
        code = resp.status
        if 200 <= code < 400:
            print(f"  \u2705 {code} {desc}")
            PASS += 1
            return json.loads(resp.read().decode()) if resp.read else {}
        else:
            print(f"  \u274c {code} {desc}")
            FAIL += 1
    except urllib.error.HTTPError as e:
        if 200 <= e.code < 400:
            print(f"  \u2705 {e.code} {desc}")
            PASS += 1
        else:
            print(f"  \u274c {e.code} {desc}")
            FAIL += 1
    except Exception as e:
        print(f"  \u274c ERR {desc}: {type(e).__name__}")
        FAIL += 1
    time.sleep(0.5)  # prevent overwhelming single-worker server


print("=" * 65)
print(f"  FixOps Enterprise Smoke Test — {datetime.now():%Y-%m-%d %H:%M:%S}")
print(f"  Server: {API}  |  Token: {KEY[:8]}...")
print("=" * 65)

print("\n── Health ──")
for ep in ["/health", "/api/v1/feeds/health", "/api/v1/brain/health",
           "/api/v1/decisions/core-components"]:
    hit("GET", ep)

print("\n── Feeds (Threat Intel) ──")
for ep in ["/api/v1/feeds/epss?limit=2", "/api/v1/feeds/kev?limit=2",
           "/api/v1/feeds/categories", "/api/v1/feeds/sources",
           "/api/v1/feeds/exploit-confidence/CVE-2021-44228",
           "/api/v1/feeds/geo-risk/CVE-2021-44228"]:
    hit("GET", ep)
hit("POST", "/api/v1/feeds/enrich",
    {"findings": [{"cve_id": "CVE-2021-44228"}, {"cve_id": "CVE-2023-0286"}]})

print("\n── Knowledge Brain ──")
for ep in ["/api/v1/brain/nodes", "/api/v1/brain/stats",
           "/api/v1/brain/meta/entity-types", "/api/v1/brain/meta/edge-types",
           "/api/v1/brain/all-edges"]:
    hit("GET", ep)
hit("POST", "/api/v1/brain/ingest/cve",
    {"cve_id": "CVE-2021-44228", "severity": "critical", "description": "Log4Shell RCE"})
hit("POST", "/api/v1/brain/ingest/asset",
    {"asset_id": "web-app", "name": "web-app", "criticality": 0.9, "type": "service"})

print("\n── Brain Pipeline ──")
hit("GET", "/api/v1/brain/pipeline/runs")
hit("POST", "/api/v1/brain/pipeline/run",
    {"org_id": "smoke-org", "findings": [{"id": "f1", "cve_id": "CVE-2021-44228",
     "severity": "critical", "title": "Log4Shell"}],
     "assets": [{"id": "a1", "name": "web-app", "criticality": 0.95}]})

print("\n── Decisions (SSVC) ──")
for ep in ["/api/v1/decisions/core-components", "/api/v1/decisions/recent",
           "/api/v1/decisions/metrics"]:
    hit("GET", ep)
hit("POST", "/api/v1/decisions/make-decision",
    {"cve_id": "CVE-2021-44228", "asset_name": "web-app", "severity": "critical",
     "title": "Log4Shell RCE"})

print("\n── Attack Surface ──")
for ep in ["/api/v1/attack-sim/health", "/api/v1/vulns/health",
           "/api/v1/micro-pentest/health", "/api/v1/pentagi/health",
           "/api/v1/dast/status"]:
    hit("GET", ep)

print("\n── Evidence & Risk ──")
for ep in ["/api/v1/reachability/health", "/api/v1/graph/",
           "/api/v1/graph/kev-components"]:
    hit("GET", ep)

print("\n── Core Intelligence ──")
for ep in ["/api/v1/nerve-center/overlay", "/api/v1/copilot/health",
           "/api/v1/copilot/agents/health", "/api/v1/copilot/agents/status",
           "/api/v1/marketplace/browse", "/api/v1/reports"]:
    hit("GET", ep)

print("\n── Integrations ──")
for ep in ["/api/v1/integrations", "/api/v1/secrets/scanners/status"]:
    hit("GET", ep)

print("\n── Enterprise ──")
for ep in ["/api/v1/audit/compliance/frameworks",
           "/api/v1/llm/health", "/api/v1/intelligent-engine/mindsdb/status",
           "/api/v1/autofix/health", "/api/v1/ml/status",
           "/api/v1/intelligent-engine/status"]:
    hit("GET", ep)
hit("POST", "/api/v1/predictions/bayesian/risk-assessment",
    {"cve_id": "CVE-2021-44228", "severity": "critical"})

TOTAL = PASS + FAIL
print("\n" + "=" * 65)
print(f"  RESULTS: {TOTAL} total | \u2705 {PASS} pass | \u274c {FAIL} fail")
if FAIL == 0:
    print("  STATUS: ALL PASSING \u2705")
else:
    print(f"  STATUS: {FAIL} FAILURES \u274c")
print("=" * 65)
sys.exit(1 if FAIL > 0 else 0)

