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

    # UC1 health — retry through container startup flap (workers spinning up)
    import time
    status = None
    for _ in range(12):
        try:
            r = requests.get(f"{BASE}/health", timeout=10)
            status = r.status_code
            if status == 200:
                break
        except Exception:
            status = None
        time.sleep(5)
    check("UC1 health endpoint 200", status == 200, f"HTTP {status}")
    if status != 200:
        return

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
    # The count must be ASSERTED, not merely printed. Checking only the status
    # code means a silently-broken ingest still passes: the SARIF above carries
    # 3 results of which #3 duplicates #1, so a healthy run stores 2.
    check("UC3 ingest SARIF (200 + findings)",
          r.status_code == 200 and body.get("status") in (None, "success") and ingested >= 1,
          f"HTTP {r.status_code}, findings={ingested}")

    # UC4 findings retrievable, tenant-scoped
    r = requests.get(f"{BASE}/api/v1/findings", headers=h(ORG_A), timeout=30)
    fb = r.json() if r.ok else []
    findings = fb if isinstance(fb, list) else fb.get("findings", fb.get("items", []))
    # HTTP 200 with an empty list is the failure this demo most needs to catch,
    # because it looks identical to success on a slide. Dedup collapses the
    # duplicate, so org A must hold exactly 2.
    check("UC4 findings retrievable (org A)",
          r.status_code == 200 and len(findings) == 2,
          f"HTTP {r.status_code}, {len(findings)} findings (expected 2 after dedup)")

    # UC5 tenant isolation — org B sees zero of A's findings
    r = requests.get(f"{BASE}/api/v1/findings", headers=h(ORG_B), timeout=30)
    fbb = r.json() if r.ok else []
    fb2 = fbb if isinstance(fbb, list) else fbb.get("findings", fbb.get("items", []))
    leaked = [f for f in fb2 if isinstance(f, dict) and f.get("org_id") == ORG_A]
    # "B sees none of A" is satisfied trivially when the endpoint returns nothing
    # to ANYONE, so isolation is only meaningful alongside A actually having
    # data. Without the second half this check passes on a totally broken store.
    check("UC5 tenant isolation (org B sees 0 of A)",
          len(leaked) == 0 and len(findings) > 0,
          f"leaked={len(leaked)}, org A holds {len(findings)} (isolation is vacuous if A is empty)")

    # UC6 AI council verdict
    # NO FABRICATED FALLBACK. This used to append
    #     or [{"id": "1", "title": "SQLi", "severity": "high"}]
    # so that an empty store still produced a council verdict — which is the one
    # thing a demo must never do. The prospect would be shown a real AI decision
    # about a finding that does not exist. The council runs on what was actually
    # ingested, and if nothing was, the check fails and says so.
    council_findings = [
        {"id": str(f.get("id", uuid.uuid4())), "title": f.get("title", "f"),
         "severity": f.get("severity", "medium")}
        for f in findings[:5]
    ]
    # generate_evidence defaults to False, so the demo never produced the SOC2
    # pack it then went on to "verify" — UC7 was listing an empty store and
    # passing on it. Ask for the artifact the product is sold on.
    payload = {"findings": council_findings, "org_id": ORG_A, "generate_evidence": True}
    r = requests.post(f"{BASE}/api/v1/pipeline/run", json=payload, headers=h(ORG_A), timeout=180)
    vb = r.json() if r.ok else {}
    verdict = vb.get("verdict") or {}
    decision = verdict.get("decision") if isinstance(verdict, dict) else verdict
    source = verdict.get("source") if isinstance(verdict, dict) else None
    check("UC6 AI council verdict returned",
          bool(council_findings) and r.status_code == 200 and decision is not None,
          f"HTTP {r.status_code}, decision={decision}, source={source}, "
          f"on {len(council_findings)} REAL ingested findings")
    # UC6b: with a key present, the verdict must come from the REAL council, not the heuristic fallback
    check("UC6b verdict is REAL council (not heuristic)", source in ("council", "consensus"),
          f"source={source} (heuristic fallback = key not wired / no findings critical)")

    # UC7 evidence bundle
    r = requests.get(f"{BASE}/api/v1/pipeline/evidence/packs", headers=h(ORG_A), timeout=30)
    pb = r.json() if r.ok else {}
    packs = pb.get("packs", []) if isinstance(pb, dict) else []
    # A pack must not contradict itself. The listing used to serve
    # score=0.0 / status="not_assessed" ALONGSIDE controls_summary saying
    # 3 assessed and 2 effective, because two code paths built packs and only
    # one computed the headline. HTTP 200 said nothing about that.
    consistent = True
    detail = f"HTTP {r.status_code}, {len(packs)} pack(s)"
    for pk in packs:
        assessed = (pk.get("controls_summary") or {}).get("assessed", 0)
        status = pk.get("overall_status")
        if assessed > 0 and status == "not_assessed":
            consistent = False
            detail += f" — {pk.get('pack_id')} claims {assessed} assessed but status={status!r}"
            break
        if pk.get("org_id") != ORG_A:
            consistent = False
            detail += f" — pack {pk.get('pack_id')} belongs to org {pk.get('org_id')!r}"
            break
    if packs:
        detail += f", status={packs[0].get('overall_status')!r} score={packs[0].get('overall_score')}"
    # An empty listing is the failure this check exists to catch. It passed on
    # zero packs for as long as the pipeline was never asked to generate one.
    check("UC7 evidence pack generated + org-scoped + self-consistent",
          r.status_code == 200 and len(packs) >= 1 and consistent, detail)

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
