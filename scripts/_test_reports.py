#!/usr/bin/env python3
"""Test reports router - real file generation."""
import json
import os
import urllib.request

TOKEN = open("/tmp/fixops_enterprise_token.txt").read().strip()
BASE = "http://127.0.0.1:8000/api/v1/reports"
RESULTS = []


def post(name, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        BASE,
        data=data,
        headers={"X-API-Key": TOKEN, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read())
        status_ok = result.get("status") == "completed"
        file_size = result.get("file_size", 0) or 0
        file_path = result.get("file_path", "")
        real_file = file_size > 0 and file_path != ""
        passed = status_ok and real_file
        RESULTS.append(
            (
                "PASS" if passed else "FAIL",
                name,
                f"status={result.get('status')} size={file_size} path={file_path}",
            )
        )
        return result
    except Exception as e:
        RESULTS.append(("FAIL", name, str(e)))
        return None


def get_json(url):
    req = urllib.request.Request(url, headers={"X-API-Key": TOKEN})
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())


# Test 1: JSON report
print("Testing JSON report...")
r1 = post(
    "JSON report",
    {
        "name": "Security Summary Q1",
        "report_type": "security_summary",
        "format": "json",
        "parameters": {"severity": "critical", "limit": 50},
    },
)

# Test 2: CSV report
print("Testing CSV report...")
r2 = post(
    "CSV report",
    {
        "name": "Vulnerability CSV Export",
        "report_type": "vulnerability",
        "format": "csv",
        "parameters": {},
    },
)

# Test 3: HTML report
print("Testing HTML report...")
r3 = post(
    "HTML report",
    {
        "name": "Risk Assessment HTML",
        "report_type": "risk_assessment",
        "format": "html",
        "parameters": {},
    },
)

# Test 4: SARIF report
print("Testing SARIF report...")
r4 = post(
    "SARIF report",
    {
        "name": "SARIF Security Report",
        "report_type": "vulnerability",
        "format": "sarif",
        "parameters": {},
    },
)

# Test 5: PDF report
print("Testing PDF report...")
r5 = post(
    "PDF report",
    {
        "name": "Compliance PDF Report",
        "report_type": "compliance",
        "format": "pdf",
        "parameters": {},
    },
)

# Test 6: Download a report file (using JSON report ID)
if r1:
    rid = r1["id"]
    print(f"Testing download for report {rid}...")
    try:
        dl = get_json(f"{BASE}/{rid}/download")
        has_url = "download_url" in dl
        RESULTS.append(
            (
                "PASS" if has_url else "FAIL",
                "Download endpoint",
                f"download_url={dl.get('download_url', '')}",
            )
        )
    except Exception as e:
        RESULTS.append(("FAIL", "Download endpoint", str(e)))

    # Test 7: Actually fetch the file
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:8000/api/v1/reports/{rid}/file",
            headers={"X-API-Key": TOKEN},
        )
        resp = urllib.request.urlopen(req, timeout=10)
        content = resp.read()
        RESULTS.append(
            (
                "PASS" if len(content) > 0 else "FAIL",
                "File download",
                f"file_bytes={len(content)}",
            )
        )
    except Exception as e:
        RESULTS.append(("FAIL", "File download", str(e)))

# Test 8: /generate alias
print("Testing /generate alias...")
try:
    data = json.dumps(
        {"name": "Generate Alias Test", "report_type": "audit", "format": "json"}
    ).encode()
    req = urllib.request.Request(
        f"{BASE}/generate",
        data=data,
        headers={"X-API-Key": TOKEN, "Content-Type": "application/json"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=15)
    result = json.loads(resp.read())
    ok = result.get("status") == "completed" and (result.get("file_size") or 0) > 0
    RESULTS.append(
        (
            "PASS" if ok else "FAIL",
            "/generate alias",
            f"status={result.get('status')} size={result.get('file_size')}",
        )
    )
except Exception as e:
    RESULTS.append(("FAIL", "/generate alias", str(e)))

# Write results
out = os.path.join(os.path.dirname(os.path.dirname(__file__)), "report_test_output.txt")
with open(out, "w") as f:
    for status, name, detail in RESULTS:
        f.write(f"{status} | {name} | {detail}\n")
    passed = sum(1 for s, _, _ in RESULTS if s == "PASS")
    total = len(RESULTS)
    f.write(f"\n{passed}/{total} PASSED\n")

print(f"Done. Results written to {out}")
