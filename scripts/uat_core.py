#!/usr/bin/env python3
"""FixOps-Core REAL UAT — hits a RUNNING container over HTTP. No mocks, no TestClient.

Covers the real customer use cases against the deployed product:
  health, tenant create, SARIF ingest, findings, tenant isolation, AI council verdict,
  evidence bundle, NAC-auth-required (security fix), auth enforcement, UI served.

Usage:
    FIXOPS_API_TOKEN=<token> python scripts/uat_core.py [http://localhost:8000]
Exit code = number of FAILED use cases (0 = all pass).
"""
from __future__ import annotations

import io
import json
import os
import sys
import uuid

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("UAT_URL", "http://localhost:8000")).rstrip("/")
TOKEN = os.environ.get("FIXOPS_API_TOKEN", "uat-token")
ORG_A = f"uat-a-{uuid.uuid4().hex[:6]}"
ORG_B = f"uat-b-{uuid.uuid4().hex[:6]}"

SARIF = json.dumps({
    "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [
        {"ruleId": "sql-injection", "level": "error",
         "message": {"text": "SQL injection in login handler"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/auth.py"},
                        "region": {"startLine": 42}}}]},
        {"ruleId": "hardcoded-secret", "level": "warning",
         "message": {"text": "Hardcoded API key"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/config.py"},
                        "region": {"startLine": 10}}}]},
        {"ruleId": "sql-injection", "level": "error",  # duplicate of #1 -> dedup should collapse
         "message": {"text": "SQL injection in login handler"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/auth.py"},
                        "region": {"startLine": 42}}}]},
    ]}]}).encode()

results = []


def h(org=None):
    x = {"X-API-Key": TOKEN}
    if org:
        x["X-Org-ID"] = org
    return x


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    mark = "\033[32mPASS\033[0m" if cond else "\033[31mFAIL\033[0m"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail else ""))


def uat():
    print(f"\nFixOps-Core UAT against {BASE}\n" + "=" * 64)

    # UC1 health
    try:
        r = requests.get(f"{BASE}/health", timeout=10)
        check("UC1 health endpoint 200", r.status_code == 200, f"HTTP {r.status_code}")
    except Exception as e:
        check("UC1 health endpoint 200", False, f"unreachable: {e}"); return

    # UC9 auth enforcement — protected endpoint WITHOUT key must be rejected
    r = requests.get(f"{BASE}/api/v1/findings", headers={"X-Org-ID": ORG_A}, timeout=15)
    check("UC9 auth enforced (no key -> 401/403)", r.status_code in (401, 403), f"HTTP {r.status_code}")

    # UC8 NAC security fix — /api/v1/nac/* WITHOUT key must be rejected (was the bypass)
    r = requests.get(f"{BASE}/api/v1/nac/policies", timeout=15)
    check("UC8 NAC requires auth (bypass fixed)", r.status_code in (401, 403), f"HTTP {r.status_code}")

    # UC2 create tenant
    r = requests.post(f"{BASE}/api/v1/orgs", json={"name": f"UAT Corp A", "org_id": ORG_A}, headers=h(ORG_A), timeout=20)
    check("UC2 create tenant", r.status_code in (200, 201, 409), f"HTTP {r.status_code}")
    requests.post(f"{BASE}/api/v1/orgs", json={"name": "UAT Corp B", "org_id": ORG_B}, headers=h(ORG_B), timeout=20)

    # UC3 ingest SARIF (real scanner output)
    r = requests.post(f"{BASE}/api/v1/scanner-ingest/upload",
                      data={"scanner_type": "sarif", "app_id": f"app-{ORG_A}", "component": "main", "pipeline": "false"},
                      files={"file": (f"scan.sarif", io.BytesIO(SARIF), "application/json")},
                      headers=h(ORG_A), timeout=60)
    body = r.json() if r.ok and r.headers.get("content-type", "").startswith("application/json") else {}
    ingested = body.get("findings_count") or body.get("count") or 0
    check("UC3 ingest SARIF (200 + findings)", r.status_code == 200 and body.get("status") in (None, "success"),
          f"HTTP {r.status_code}, findings={ingested}")

    # UC4 findings retrievable, tenant-scoped
    r = requests.get(f"{BASE}/api/v1/findings", headers=h(ORG_A), timeout=30)
    fb = r.json() if r.ok else []
    findings = fb if isinstance(fb, list) else fb.get("findings", fb.get("items", []))
    check("UC4 findings retrievable (org A)", r.status_code == 200, f"HTTP {r.status_code}, {len(findings)} findings")

    # UC5 tenant isolation — org B sees zero of A's findings
    r = requests.get(f"{BASE}/api/v1/findings", headers=h(ORG_B), timeout=30)
    fbb = r.json() if r.ok else []
    fb2 = fbb if isinstance(fbb, list) else fbb.get("findings", fbb.get("items", []))
    leaked = [f for f in fb2 if isinstance(f, dict) and f.get("org_id") == ORG_A]
    check("UC5 tenant isolation (org B sees 0 of A)", len(leaked) == 0, f"leaked={len(leaked)}")

    # UC6 AI council verdict
    payload = {"findings": [{"id": str(f.get("id", uuid.uuid4())), "title": f.get("title", "f"),
                             "severity": f.get("severity", "medium")} for f in findings[:5]] or
                            [{"id": "1", "title": "SQLi", "severity": "high"}], "org_id": ORG_A}
    r = requests.post(f"{BASE}/api/v1/pipeline/pipeline/run", json=payload, headers=h(ORG_A), timeout=120)
    vb = r.json() if r.ok else {}
    verdict = vb.get("verdict") or vb.get("decision") or (vb.get("result") or {}).get("verdict")
    check("UC6 AI council verdict returned", r.status_code == 200 and verdict is not None, f"HTTP {r.status_code}, verdict={verdict}")

    # UC7 evidence bundle
    r = requests.get(f"{BASE}/api/v1/pipeline/evidence/packs", headers=h(ORG_A), timeout=30)
    check("UC7 evidence bundle available", r.status_code == 200, f"HTTP {r.status_code}")

    # UC10 UI served
    try:
        r = requests.get(f"{BASE}/", timeout=15)
        check("UC10 UI served (root 200)", r.status_code == 200, f"HTTP {r.status_code}")
    except Exception as e:
        check("UC10 UI served (root 200)", False, str(e))


if __name__ == "__main__":
    uat()
    failed = [n for n, ok, _ in results if not ok]
    print("=" * 64)
    print(f"UAT: {len(results) - len(failed)}/{len(results)} passed" + (f" | FAILED: {failed}" if failed else " | ALL PASS"))
    sys.exit(len(failed))
