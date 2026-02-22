#!/usr/bin/env python3
"""Test all 5 bulk endpoints + seed data. Writes results to /tmp/bulk_results.txt"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

TOKEN = open("/tmp/fixops_enterprise_token.txt").read().strip()
BASE = "http://127.0.0.1:8000/api/v1/bulk"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(SCRIPT_DIR, "..", "bulk_test_output.txt")
results = []


def log(msg):
    results.append(msg)
    print(msg, flush=True)


def api(method, path, body=None, timeout=10):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-API-Key", TOKEN)
    req.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()) if e.read() else {}
    except Exception as e:
        return 0, {"error": str(e)}


def seed():
    log("=== SEEDING DATA ===")
    from core.analytics_db import AnalyticsDB
    from core.analytics_models import Finding, FindingSeverity, FindingStatus
    from core.policy_db import PolicyDB
    from core.policy_models import Policy, PolicyStatus

    db = AnalyticsDB()
    pdb = PolicyDB()
    sevs = [
        FindingSeverity.CRITICAL,
        FindingSeverity.HIGH,
        FindingSeverity.MEDIUM,
        FindingSeverity.LOW,
        FindingSeverity.INFO,
    ]
    for i in range(1, 6):
        f = Finding(
            id=f"test-finding-{i:03d}",
            application_id="payment-service",
            service_id="payment-api",
            rule_id=f"SEC-{i:03d}",
            severity=sevs[i - 1],
            status=FindingStatus.OPEN,
            title=f"Test Finding {i}",
            description=f"Test vuln {i}",
            source="sast",
            cve_id=f"CVE-2024-{1000+i}",
            cvss_score=round(10.0 - i * 1.5, 1),
            epss_score=round(0.95 - i * 0.15, 4),
            exploitable=i <= 3,
        )
        try:
            db.create_finding(f)
            log(f"  Created {f.id}")
        except Exception:
            existing = db.get_finding(f.id)
            if existing:
                existing.status = FindingStatus.OPEN
                existing.metadata = {}
                db.update_finding(existing)
                log(f"  Reset {f.id}")
    # Delete by ID and also clean up any policies with same name (UNIQUE constraint on name)
    try:
        pdb.delete_policy("policy-block-critical")
    except Exception:
        pass
    # Remove any existing policies with the same name to avoid UNIQUE constraint violation
    import sqlite3 as _sqlite3

    _conn = _sqlite3.connect(str(pdb.db_path))
    _conn.execute("DELETE FROM policies WHERE name = ?", ("Block Critical CVEs",))
    _conn.commit()
    _conn.close()
    p = Policy(
        id="policy-block-critical",
        name="Block Critical CVEs",
        description="Block critical",
        policy_type="guardrail",
        status=PolicyStatus.ACTIVE,
        rules={"max_severity": "high"},
        created_by="admin",
    )
    pdb.create_policy(p)
    log(f"  Created policy: {p.id}")
    check = pdb.get_policy("policy-block-critical")
    log(f"  Verify policy: found={check is not None}")
    log("")


def test(name, method, path, body, expected=200):
    code, resp = api(method, path, body)
    status = "PASS" if code == expected else "FAIL"
    log(f"[{status}] {name}: HTTP {code}")
    log(f"  Response: {json.dumps(resp)[:300]}")
    return status == "PASS"


# Wait for server
log("Checking server...")
for attempt in range(10):
    try:
        req = urllib.request.Request("http://127.0.0.1:8000/api/v1/health")
        req.add_header("X-API-Key", TOKEN)
        urllib.request.urlopen(req, timeout=3)
        log("Server is UP\n")
        break
    except Exception:
        if attempt == 9:
            log("SERVER DOWN - cannot test")
            with open(OUT, "w") as f:
                f.write("\n".join(results))
            sys.exit(1)
        time.sleep(2)

seed()

passed = 0
total = 5

log("=== TEST 1: /findings/update ===")
if test(
    "Bulk Update",
    "POST",
    "/findings/update",
    {
        "ids": ["test-finding-001", "test-finding-002"],
        "updates": {"status": "in_progress"},
    },
):
    passed += 1

log("\n=== TEST 2: /findings/delete ===")
if test(
    "Bulk Delete",
    "POST",
    "/findings/delete",
    {"ids": ["test-finding-005", "nonexistent-xxx"]},
):
    passed += 1

log("\n=== TEST 3: /findings/assign ===")
if test(
    "Bulk Assign",
    "POST",
    "/findings/assign",
    {
        "ids": ["test-finding-002", "test-finding-003"],
        "assignee": "john.doe",
        "assignee_email": "john@co.com",
    },
):
    passed += 1

log("\n=== TEST 4: /policies/apply ===")
if test(
    "Bulk Apply Policies",
    "POST",
    "/policies/apply",
    {
        "policy_ids": ["policy-block-critical"],
        "target_ids": ["test-finding-001", "test-finding-002"],
    },
):
    passed += 1

log("\n=== TEST 5: /export (json) ===")
if test(
    "Bulk Export JSON",
    "POST",
    "/export",
    {
        "ids": ["test-finding-001", "test-finding-002", "test-finding-003"],
        "format": "json",
        "org_id": "test-org",
    },
):
    passed += 1

log(f"\n{'='*40}")
log(f"RESULTS: {passed}/{total} PASSED")
log(f"{'='*40}")

with open(OUT, "w") as f:
    f.write("\n".join(results))
log(f"Results written to {OUT}")
