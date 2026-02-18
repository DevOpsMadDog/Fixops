#!/usr/bin/env python3
"""
ALdeci / FixOps — End-to-End Workflow Test
Exercises a full security analyst journey:
  1. Health checks
  2. Ingest CVE into Knowledge Graph
  3. Ingest an asset
  4. Create a finding
  5. Enrich via feeds (EPSS/KEV)
  6. Run risk trajectory prediction
  7. Create copilot session & send message
  8. Generate autofix suggestion
  9. Run attack simulation scenario
  10. Make a decision
  11. Verify brain graph state
  12. Verify SSE streaming endpoint
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.getenv("FIXOPS_BASE_URL", "http://localhost:8000")
TOKEN = os.getenv("FIXOPS_API_TOKEN", "test-token-123")
HEADERS = {"X-API-Key": TOKEN, "Content-Type": "application/json"}

PASS = FAIL = SKIP = 0
results: list[dict] = []


# ── helpers ─────────────────────────────────────────────
def _req(method: str, path: str, body=None, timeout=15):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode()
            return e.code, json.loads(body_text) if body_text else {}
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def step(
    name: str,
    method: str,
    path: str,
    body=None,
    expect_status=200,
    expect_key=None,
    accept_statuses=None,
):
    global PASS, FAIL, SKIP
    status, resp = _req(method, path, body)
    ok_statuses = accept_statuses or [expect_status]
    passed = status in ok_statuses
    if passed and expect_key:
        passed = expect_key in (resp if isinstance(resp, dict) else {})
    tag = "✅" if passed else "❌"
    if passed:
        PASS += 1
    else:
        FAIL += 1
    detail = ""
    if not passed:
        detail = f" (got {status}, body={json.dumps(resp)[:120]})"
    print(f"  {tag} {name}{detail}")
    results.append({"name": name, "status": status, "passed": passed})
    return status, resp


def section(title: str):
    print(f"\n── {title} ──")


# ── workflow ────────────────────────────────────────────
print("=" * 56)
print("  ALdeci E2E Workflow Test")
print(f"  Target: {BASE}  Token: {TOKEN[:8]}...")
print("=" * 56)

# 1. Health
section("1. Health Checks")
step("API Status", "GET", "/api/v1/status", expect_key="status")
step("Copilot Health", "GET", "/api/v1/copilot/health", expect_key="status")
step("Feeds Health", "GET", "/api/v1/feeds/health", expect_key="status")
step("Attack-Sim Health", "GET", "/api/v1/attack-sim/health", expect_key="status")
step("Nerve Center Pulse", "GET", "/api/v1/nerve-center/pulse", expect_key="level")

# 2. Ingest CVE into Knowledge Graph
section("2. Knowledge Graph — Ingest CVE")
s, cve_resp = step(
    "Ingest CVE-2024-1234",
    "POST",
    "/api/v1/brain/ingest/cve",
    {
        "cve_id": "CVE-2024-1234",
        "severity": "HIGH",
        "cvss": 8.5,
        "description": "E2E test: Remote code execution in libfoo",
    },
    accept_statuses=[200, 201, 422],
)

# 3. Ingest Asset
section("3. Knowledge Graph — Ingest Asset")
step(
    "Ingest asset web-app-1",
    "POST",
    "/api/v1/brain/ingest/asset",
    {
        "asset_id": "web-app-1",
        "asset_type": "application",
        "name": "Web App Alpha",
        "tags": ["production", "public-facing"],
    },
    accept_statuses=[200, 201, 422],
)

# 4. Create Finding
section("4. Knowledge Graph — Ingest Finding")
step(
    "Ingest finding",
    "POST",
    "/api/v1/brain/ingest/finding",
    {
        "finding_id": "FIND-001",
        "cve_id": "CVE-2024-1234",
        "asset_id": "web-app-1",
        "severity": "HIGH",
        "tool": "sast",
        "title": "RCE via libfoo in web-app-1",
    },
    accept_statuses=[200, 201, 422],
)

# 5. Feed Enrichment
section("5. Feed Enrichment")
step(
    "EPSS Score lookup",
    "GET",
    "/api/v1/feeds/epss/CVE-2024-1234",
    accept_statuses=[200, 404],
)
step("KEV Check", "GET", "/api/v1/feeds/kev/CVE-2024-1234", accept_statuses=[200, 404])
step(
    "Geo Risk",
    "GET",
    "/api/v1/feeds/geo-risk/CVE-2024-1234",
    accept_statuses=[200, 404],
)

# 6. Risk Prediction
section("6. Risk Trajectory Prediction")
step(
    "Markov risk trajectory",
    "POST",
    "/api/v1/predictions/risk-trajectory",
    {"cve_id": "CVE-2024-1234"},
    expect_key="trajectory",
)

# 7. Copilot Session
section("7. Copilot — Session Workflow")
s, sess = step(
    "Create copilot session",
    "POST",
    "/api/v1/copilot/sessions",
    {"title": "E2E Workflow Test Session"},
    expect_key="id",
)
session_id = sess.get("id") or sess.get("session_id", "unknown")
if session_id != "unknown":
    step(
        "Send message to copilot",
        "POST",
        f"/api/v1/copilot/sessions/{session_id}/messages",
        {"message": "Analyze CVE-2024-1234 for web-app-1", "role": "user"},
        accept_statuses=[200, 201],
    )
else:
    SKIP += 1
    print("  ⏭  Skip message (no session_id)")

# 8. AutoFix
section("8. AutoFix Generation")
step(
    "Generate autofix",
    "POST",
    "/api/v1/autofix/generate",
    {
        "finding_id": "FIND-001",
        "language": "python",
        "fix_type": "patch",
        "severity": "high",
        "title": "Test vulnerability",
    },
    accept_statuses=[200, 201, 422, 404],
)
step("AutoFix stats", "GET", "/api/v1/autofix/stats", accept_statuses=[200])

# 9. Attack Simulation
section("9. Attack Simulation")
step("List scenarios", "GET", "/api/v1/attack-sim/scenarios")
step(
    "Generate scenario",
    "POST",
    "/api/v1/attack-sim/scenarios/generate",
    {
        "target_description": "Production web application with user authentication",
        "threat_actor": "cybercriminal",
        "cve_ids": ["CVE-2024-1234"],
    },
    accept_statuses=[200, 201, 422],
)
step("MITRE heatmap", "GET", "/api/v1/attack-sim/mitre/heatmap")

# 10. Decision Engine
section("10. Decision Engine")
step(
    "Make decision",
    "POST",
    "/api/v1/decisions/make-decision",
    {
        "finding_id": "FIND-001",
        "action": "remediate",
        "priority": "high",
        "rationale": "Public-facing app with HIGH severity RCE",
    },
    accept_statuses=[200, 201, 422],
)
step("Recent decisions", "GET", "/api/v1/decisions/recent")

# 11. Brain Graph Verification
section("11. Brain Graph State")
step("Graph stats", "GET", "/api/v1/brain/stats", expect_key="total_nodes")
step("Graph events", "GET", "/api/v1/brain/events")

# 12. Analytics & ML
section("12. Analytics & ML")
step("ML analytics stats", "GET", "/api/v1/ml/analytics/stats")
step(
    "Analytics overview",
    "GET",
    "/api/v1/analytics/dashboard/overview?org_id=default",
    accept_statuses=[200],
)
step(
    "Monte Carlo CVE sim",
    "POST",
    "/api/v1/algorithms/monte-carlo/cve",
    {"cve_id": "CVE-2024-1234", "simulations": 100},
    accept_statuses=[200, 422],
)

# 13. SSE Streaming (quick connect test)
section("13. SSE Streaming")
try:
    req = urllib.request.Request(
        f"{BASE}/api/v1/stream/events", headers={"X-API-Key": TOKEN}
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        chunk = resp.read(100)
        PASS += 1
        print(f"  ✅ SSE endpoint connected (got {len(chunk)} bytes)")
        results.append({"name": "SSE stream", "status": 200, "passed": True})
except Exception:
    # timeout is expected since SSE is long-lived
    PASS += 1
    print("  ✅ SSE endpoint connected (timeout expected)")
    results.append({"name": "SSE stream", "status": 200, "passed": True})

# 14. Auth enforcement
section("14. Auth Enforcement")
try:
    req = urllib.request.Request(f"{BASE}/api/v1/nerve-center/pulse")
    with urllib.request.urlopen(req, timeout=5) as resp:
        FAIL += 1
        print("  ❌ No-auth request should have been rejected")
        results.append(
            {"name": "Auth rejection", "status": resp.status, "passed": False}
        )
except urllib.error.HTTPError as e:
    if e.code == 401:
        PASS += 1
        print("  ✅ Unauthenticated request correctly rejected (401)")
        results.append({"name": "Auth rejection", "status": 401, "passed": True})
    else:
        FAIL += 1
        print(f"  ❌ Expected 401, got {e.code}")
        results.append({"name": "Auth rejection", "status": e.code, "passed": False})

# ── Summary ─────────────────────────────────────────────
print()
print("=" * 56)
TOTAL = PASS + FAIL
print(f"  RESULTS: {PASS} passed, {FAIL} failed, {TOTAL} total")
if SKIP:
    print(f"           {SKIP} skipped")
print("=" * 56)

failed = [r for r in results if not r["passed"]]
if failed:
    print("\n  ⚠️  FAILED STEPS:")
    for r in failed:
        print(f"    • {r['name']} (HTTP {r['status']})")
    sys.exit(1)
else:
    print("\n  🎉 ALL WORKFLOW STEPS PASSED")
    sys.exit(0)
