#!/usr/bin/env python3
"""Test all 20 agent endpoints that were wired in Phase 5."""
import json
import os
import socket
import sys
import urllib.error
import urllib.request

TOKEN = open("/tmp/fixops_enterprise_token.txt").read().strip()
BASE = "http://localhost:8000/api/v1/copilot/agents"
OUT = os.path.join(os.path.dirname(__file__), "..", "_agent_results.txt")


def req(method, path, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("X-API-Key", TOKEN)
    if data:
        r.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.getcode(), json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            b = json.loads(e.read())
        except Exception:
            b = {"raw": str(e)}
        return e.code, b
    except (socket.timeout, urllib.error.URLError) as e:
        return 0, {"error": f"timeout/connection: {e}"}
    except Exception as e:
        return 0, {"error": str(e)}


tests = [
    # Group A: Compliance (5) -- note: enum is "pci-dss" not "pci_dss"
    ("POST", "/compliance/gap-analysis", {"framework": "pci-dss"}),
    ("POST", "/compliance/audit-evidence", {"framework": "pci-dss", "format": "json"}),
    (
        "POST",
        "/compliance/regulatory-alerts",
        {"industries": ["technology"], "jurisdictions": ["US"]},
    ),
    ("GET", "/compliance/dashboard", None),
    ("POST", "/compliance/generate-report?framework=pci-dss", None),
    # Group B: Remediation AutoFix (3)
    (
        "POST",
        "/remediation/generate-fix",
        {"finding_id": "f1", "language": "python", "include_tests": True},
    ),
    (
        "POST",
        "/remediation/create-pr",
        {
            "finding_ids": ["f1"],
            "repository": "org/repo",
            "branch": "fix/vuln",
            "auto_merge": False,
        },
    ),
    (
        "POST",
        "/remediation/update-dependencies",
        {"sbom_id": "sbom-1", "package_ids": ["lodash"], "update_strategy": "minor"},
    ),
    # Group C: Remediation DB/Playbook (4)
    (
        "POST",
        "/remediation/playbook",
        {
            "finding_ids": ["f1", "f2"],
            "audience": "developer",
            "include_rollback": True,
        },
    ),
    ("GET", "/remediation/recommendations/test-finding-1", None),
    (
        "POST",
        "/remediation/verify?verification_type=scan",
        ["test-finding-1", "test-finding-2"],
    ),
    ("GET", "/remediation/queue", None),
    # Group D: Analyst (2)
    (
        "POST",
        "/analyst/attack-path",
        {"asset_id": "server-01", "depth": 3, "include_lateral": True},
    ),
    ("GET", "/analyst/risk-score/server-01", None),
    # Group E: Status + Health (2)
    ("GET", "/status", None),
    ("GET", "/health", None),
    # Existing real endpoints (4)
    ("GET", "/analyst/cve/CVE-2024-3094", None),
    ("GET", "/analyst/trending", None),
    ("GET", "/compliance/controls/pci-dss", None),
    (
        "POST",
        "/orchestrate",
        {
            "objective": "Assess CVE-2024-3094",
            "agents": ["security_analyst"],
            "parameters": {},
        },
    ),
]

passed = 0
failed = 0
lines = []
lines.append("=" * 60)
lines.append("AGENT ENDPOINT TEST RESULTS")
lines.append("=" * 60)

for i, (method, path, body) in enumerate(tests, 1):
    code, data = req(method, path, body)
    status_field = data.get("status", "") if isinstance(data, dict) else ""
    # "integration_required" = old stub.  "engine_unavailable" / "error" / "no_graph_data" = wired but engine not loaded = OK
    is_stub = status_field in ("integration_required",)
    ok = code in (200, 201) and not is_stub
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    msg = ""
    if isinstance(data, dict):
        msg = data.get("message", data.get("status", ""))
        if isinstance(msg, str) and len(msg) > 80:
            msg = msg[:80]
    line = f"{tag} | {i:2d} | {method:4s} {path:50s} | {code} | {msg}"
    lines.append(line)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()

lines.append("")
lines.append(f"TOTAL: {len(tests)}  PASS: {passed}  FAIL: {failed}")
lines.append(f"RATE: {passed}/{len(tests)} = {100*passed/len(tests):.1f}%")
lines.append("=" * 60)

with open(OUT, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"\nResults written to {OUT}")
