#!/usr/bin/env python3
"""ALDECI Self-Test: The platform scans and assesses its own codebase."""
import json
import os
import time
from typing import Optional, Dict, Any, List

import requests

API = os.getenv("ALDECI_URL", "http://localhost:8000")
KEY = os.getenv("FIXOPS_API_TOKEN", "")
H = {"X-API-Key": KEY, "Content-Type": "application/json"}
DELAY = 0.7
results = []


def api(method, path, data=None):
    time.sleep(DELAY)
    try:
        if method == "POST":
            r = requests.post(f"{API}{path}", json=data, headers=H, timeout=15)
        else:
            r = requests.get(f"{API}{path}", headers=H, timeout=15)
        body = r.json() if r.text and r.headers.get("content-type", "").startswith("application/json") else r.text[:200]
        return r.status_code, body
    except Exception as e:
        return 0, str(e)


def test(label, method, path, data=None, expect=200):
    code, body = api(method, path, data)
    ok = code == expect or (expect == 200 and code == 201)
    summary = ""
    if isinstance(body, dict):
        summary = json.dumps(body, default=str)[:150]
    elif isinstance(body, list):
        summary = f"[{len(body)} items]"
    else:
        summary = str(body)[:150]
    results.append({"label": label, "method": method, "path": path, "status": code, "ok": ok, "summary": summary})
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {code} {method} {path} — {summary[:80]}")
    return code, body


print("=" * 70)
print("ALDECI SELF-ASSESSMENT — Platform Scanning Its Own Codebase")
print("=" * 70)

# ── 1. Register ALDECI as an asset ──────────────────────────────────
print("\n## 1. ASSET REGISTRATION")
test("Register ALDECI as asset", "POST", "/api/v1/brain/ingest/asset", {
    "asset_id": "aldeci-self", "name": "ALDECI Security Platform",
    "type": "application", "metadata": {"repo": "DevOpsMadDog/Fixops", "language": "Python"}
})

# ── 2. Ingest scanner results (Bandit, Semgrep, Trivy) ─────────────
print("\n## 2. SCANNER INGESTION (Bandit, Semgrep, Trivy)")
for scanner, path in [("bandit", "/tmp/bandit_fixops.json"), ("semgrep", "/tmp/semgrep_fixops.json"), ("trivy", "/tmp/trivy_fixops.json")]:
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        count = len(data.get("results", data.get("Results", [])))
        test(f"Ingest {scanner} ({count} findings)", "POST", f"/api/v1/scanner-ingest/webhook/{scanner}", data)
    else:
        print(f"  [SKIP] {scanner} — {path} not found")

# ── 3. Query platform about itself ─────────────────────────────────
print("\n## 3. PLATFORM SELF-ASSESSMENT")

# Findings
code, body = test("Total findings", "GET", "/api/v1/findings")
findings_total = body.get("total", 0) if isinstance(body, dict) else 0

# Scanner stats
test("Scanner ingestion stats", "GET", "/api/v1/scanner-ingest/stats")

# SBOM
code, sbom = test("SBOM license breakdown", "GET", "/api/v1/sbom/licenses")

# Risk overview
test("Risk overview", "GET", "/api/v1/risk/overview")

# Compliance
test("Compliance status", "GET", "/api/v1/compliance/status")

# Remediation
test("Remediation statuses", "GET", "/api/v1/remediation/statuses")

# Security posture
test("Security posture", "GET", "/api/v1/posture-scoring/controls?org_id=aldeci-self")

# KPIs
test("Security KPIs", "GET", "/api/v1/kpi-tracking/kpis?org_id=aldeci-self")

# ── 4. Threat Intelligence about our own dependencies ──────────────
print("\n## 4. THREAT INTEL (Own Dependencies)")

test("CVE enrichment cache", "GET", "/api/v1/cve/cache/stats")
test("Threat intel feeds", "GET", "/api/v1/ti-automation/feeds?org_id=aldeci-self")
test("CTI reports", "GET", "/api/v1/cyber-threat-intel/reports?org_id=aldeci-self")

# ── 5. Supply Chain assessment ─────────────────────────────────────
print("\n## 5. SUPPLY CHAIN")

test("Supply chain suppliers", "GET", "/api/v1/supply-chain-monitoring/suppliers?org_id=aldeci-self")
test("Supply chain attacks", "GET", "/api/v1/supply-chain-attacks/packages?org_id=aldeci-self")

# ── 6. Advanced engine checks ──────────────────────────────────────
print("\n## 6. ADVANCED SECURITY ENGINES")

test("Vulnerability workflow", "GET", "/api/v1/vuln-workflow/tickets?org_id=aldeci-self")
test("Alert triage queue", "GET", "/api/v1/alert-triage/alerts?org_id=aldeci-self")
test("Incident orchestration", "GET", "/api/v1/incident-orchestration/incidents?org_id=aldeci-self")
test("Security automation rules", "GET", "/api/v1/security-automation/rules?org_id=aldeci-self")
test("Security scoreboard", "GET", "/api/v1/security-scoreboard/leaderboard?org_id=aldeci-self")
test("Architecture review", "GET", "/api/v1/arch-review/reviews?org_id=aldeci-self")
test("Ransomware protection", "GET", "/api/v1/ransomware-protection/detections?org_id=aldeci-self")
test("Dark web monitoring", "GET", "/api/v1/dark-web/mentions?org_id=aldeci-self")
test("AI SOC detections", "GET", "/api/v1/ai-soc/detections?org_id=aldeci-self")
test("Quantum crypto assessment", "GET", "/api/v1/quantum-crypto/assets?org_id=aldeci-self")

# ── 7. Self-scan endpoint ──────────────────────────────────────────
print("\n## 7. SELF-SCAN ENDPOINT")
test("Self-scan status", "GET", "/api/v1/self-scan/")

# ── REPORT ─────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("ALDECI SELF-ASSESSMENT REPORT")
print("=" * 70)

passed = sum(1 for r in results if r["ok"])
failed = sum(1 for r in results if not r["ok"])
total = len(results)

print(f"\nEndpoints tested: {total}")
print(f"Passed: {passed}/{total} ({100*passed//total}%)")
print(f"Failed: {failed}/{total}")

if failed:
    print("\nFailed endpoints:")
    for r in results:
        if not r["ok"]:
            print(f"  [{r['status']}] {r['method']} {r['path']} — {r['summary'][:60]}")

print(f"\nPlatform self-scan: {'HEALTHY' if passed >= total * 0.8 else 'NEEDS ATTENTION'}")
print("=" * 70)
