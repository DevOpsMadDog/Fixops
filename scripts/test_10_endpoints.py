"""Test all 10 NOT-FIXED endpoints from fake_make_it_real.md."""
import json
import sys

import os
import requests

TOKEN = os.getenv("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
BASE = "http://localhost:8000/api/v1"
H = {"X-API-Key": TOKEN, "Content-Type": "application/json"}

tests = [
    (
        "1 generate-poc",
        "POST",
        "/copilot/agents/pentest/generate-poc",
        {
            "cve_id": "CVE-2024-3094",
            "target_type": "linux_server",
            "language": "python",
        },
    ),
    (
        "2 reachability",
        "POST",
        "/copilot/agents/pentest/reachability",
        {"cve_id": "CVE-2024-3094", "asset_ids": ["web-server-01", "db-server-02"]},
    ),
    ("3 evidence", "GET", "/copilot/agents/pentest/evidence/finding-001", None),
    (
        "4 schedule",
        "POST",
        "/copilot/agents/pentest/schedule?schedule=immediate",
        {"target_ids": ["app.example.com"], "cve_ids": ["CVE-2024-3094"]},
    ),
    (
        "5 map-findings",
        "POST",
        "/copilot/agents/compliance/map-findings",
        {"frameworks": ["pci-dss"], "finding_ids": ["f-001"]},
    ),
    (
        "6 gap-analysis",
        "POST",
        "/copilot/agents/compliance/gap-analysis",
        {"framework": "pci-dss"},
    ),
    ("7 controls", "GET", "/copilot/agents/compliance/controls/pci-dss", None),
    ("8 dashboard", "GET", "/copilot/agents/compliance/dashboard", None),
    (
        "9 generate-report",
        "POST",
        "/copilot/agents/compliance/generate-report?framework=pci-dss",
        {"framework": "pci-dss"},
    ),
    ("10 capabilities", "GET", "/mpte-orchestrator/capabilities", None),
]

results = []
for name, method, path, data in tests:
    url = BASE + path
    print(f"\n{'='*60}")
    print(f"=== {name} ({method} {path}) ===")
    try:
        if method == "POST":
            r = requests.post(url, headers=H, json=data, timeout=10)
        else:
            r = requests.get(url, headers=H, timeout=10)
        code = r.status_code
        try:
            body = r.json()
        except Exception:
            body = r.text
        is_stub = False
        if isinstance(body, dict):
            if body.get("status") == "integration_required":
                is_stub = True
            if body.get("integration_required") is True:
                is_stub = True
            if "controls" in body and body["controls"] == []:
                is_stub = True
        status = (
            "STUB" if is_stub else ("PASS" if 200 <= code < 300 else f"FAIL-{code}")
        )
        results.append((name, status, code))
        if isinstance(body, dict):
            print(f"  HTTP {code} | status={body.get('status', 'N/A')}")
            for key in [
                "source",
                "poc_language",
                "message",
                "campaign_id",
                "total_returned",
                "overall_posture",
                "integration_required",
            ]:
                if key in body:
                    print(f"  {key}: {str(body[key])[:200]}")
            if "controls" in body and isinstance(body["controls"], list):
                print(f"  controls: [{len(body['controls'])} items]")
                if body["controls"]:
                    print(f"    first: {json.dumps(body['controls'][0])[:150]}")
            if "capabilities" in body and isinstance(body["capabilities"], dict):
                for ck, cv in body["capabilities"].items():
                    av = cv.get("available", "?") if isinstance(cv, dict) else "?"
                    print(f"    cap.{ck}: available={av}")
            if "frameworks" in body and isinstance(body["frameworks"], list):
                print(f"  frameworks: [{len(body['frameworks'])} items]")
            if "reachability_results" in body:
                rr = body["reachability_results"]
                print(f"  reachability_results: [{len(rr)} items]")
            if "poc_code" in body:
                print(f"  poc_code: {str(body['poc_code'])[:100]}...")
        else:
            print(f"  HTTP {code} | {str(body)[:200]}")
        print(f"  >>> RESULT: {status}")
    except Exception as e:
        results.append((name, "ERROR", 0))
        print(f"  ERROR: {e}")

print(f"\n{'='*60}")
print("SUMMARY")
print(f"{'='*60}")
passed = sum(1 for _, s, _ in results if s == "PASS")
for n, s, c in results:
    icon = "+" if s == "PASS" else "-"
    print(f"  [{icon}] {n}: {s} (HTTP {c})")
print(f"\n  Total: {passed}/{len(results)} PASS")
sys.exit(0 if passed == len(results) else 1)
