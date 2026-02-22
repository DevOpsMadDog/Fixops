#!/usr/bin/env python3
"""End-to-end verification script for ALdeci Phase 16.

Tests every feature area with the correct API key.
"""
import os
import sys

import requests

_token = os.environ.get("FIXOPS_API_TOKEN", "")
if not _token:
    print(
        "ERROR: FIXOPS_API_TOKEN env var not set. Export your enterprise token first."
    )
    sys.exit(2)
BASE = os.environ.get("FIXOPS_API_URL", "http://localhost:8000")
H = {"X-API-Key": _token, "Content-Type": "application/json"}

passed = 0
failed = 0
total = 0


def check(name, method, path, expected_status=200, body=None):
    global passed, failed, total
    total += 1
    try:
        if method == "GET":
            r = requests.get(f"{BASE}{path}", headers=H, timeout=10)
        else:
            r = requests.post(f"{BASE}{path}", headers=H, json=body or {}, timeout=10)
        ok = r.status_code == expected_status
        if ok:
            passed += 1
            print(f"  ✅ {name} [{r.status_code}]")
        else:
            failed += 1
            detail = ""
            try:
                detail = r.json().get("detail", "")[:60]
            except Exception:
                pass
            print(f"  ❌ {name} [{r.status_code}] expected {expected_status} - {detail}")
    except Exception as e:
        failed += 1
        print(f"  ❌ {name} [ERROR] {e}")


print("🧪 ALdeci E2E Verification\n")

# ── Core Health ──
print("── Core Health ──")
check("Health", "GET", "/api/v1/health")
check("Status", "GET", "/api/v1/status")
check("Ready", "GET", "/api/v1/ready")
check("Version", "GET", "/api/v1/version")

# ── Nerve Center ──
print("\n── Nerve Center ──")
check("Pulse", "GET", "/api/v1/nerve-center/pulse")
check("State", "GET", "/api/v1/nerve-center/state")
check("Overlay Config", "GET", "/api/v1/nerve-center/overlay")

# ── Knowledge Brain ──
print("\n── Knowledge Brain ──")
check("Brain Nodes", "GET", "/api/v1/brain/nodes")
check(
    "Brain Edges",
    "POST",
    "/api/v1/brain/edges",
    expected_status=201,
    body={
        "source_id": "cve:CVE-2024-3094",
        "target_id": "asset:web-api-gateway",
        "edge_type": "AFFECTS",
    },
)
check("Brain Stats", "GET", "/api/v1/brain/stats")
check(
    "Ingest CVE",
    "POST",
    "/api/v1/brain/ingest/cve",
    body={"cve_id": "CVE-2024-99999", "title": "Test CVE", "severity": "low"},
)

# ── ML/MindsDB ──
print("\n── ML/MindsDB ──")
check("ML Status", "GET", "/api/v1/ml/status")
check("ML Models", "GET", "/api/v1/ml/models")
check("ML Analytics Stats", "GET", "/api/v1/ml/analytics/stats")
check("ML Analytics Anomalies", "GET", "/api/v1/ml/analytics/anomalies")
check(
    "ML Predict Anomaly",
    "POST",
    "/api/v1/ml/predict/anomaly",
    body={
        "method": "GET",
        "path": "/test",
        "status_code": 200,
        "duration_ms": 100,
        "request_size": 50,
        "response_size": 200,
    },
)

# ── Copilot ──
print("\n── Copilot ──")
check("Copilot Create Session", "POST", "/api/v1/copilot/sessions")
check("Copilot List Sessions", "GET", "/api/v1/copilot/sessions")

# ── MPTE / Attack ──
print("\n── MPTE / Attack ──")
check("MPTE Requests", "GET", "/api/v1/mpte/requests")
check(
    "MPTE Create",
    "POST",
    "/api/v1/mpte/requests",
    expected_status=201,
    body={
        "finding_id": "test-e2e",
        "target_url": "http://test.local",
        "vulnerability_type": "xss",
        "test_case": "e2e-verify",
        "priority": "low",
    },
)
check("Attack Sim Campaigns", "GET", "/api/v1/attack-sim/campaigns")

# ── Feeds ──
print("\n── Feeds ──")
check("Feeds NVD Recent", "GET", "/api/v1/feeds/nvd/recent")
check("Feeds EPSS", "GET", "/api/v1/feeds/epss")
check("Feeds KEV", "GET", "/api/v1/feeds/kev")
check("Feeds Health", "GET", "/api/v1/feeds/health")

# ── AutoFix ──
print("\n── AutoFix ──")
check("AutoFix Stats", "GET", "/api/v1/autofix/stats")
check("AutoFix History", "GET", "/api/v1/autofix/history")
check("AutoFix Fix Types", "GET", "/api/v1/autofix/fix-types")

# ── Evidence / Compliance ──
print("\n── Evidence / Compliance ──")
check("Evidence Packs", "GET", "/api/v1/pipeline/evidence/packs")
check(
    "Evidence Generate",
    "POST",
    "/api/v1/pipeline/evidence/generate",
    body={"framework": "soc2", "org_id": "test-org"},
)

# ── Algorithms ──
print("\n── Algorithms ──")
check("Algorithm Status", "GET", "/api/v1/algorithms/status")
check("Decision Metrics", "GET", "/api/v1/decisions/metrics")

# ── Pipeline ──
print("\n── Pipeline ──")
check("Pipeline Runs", "GET", "/api/v1/pipeline/pipeline/runs")
check("Pipeline Evidence Packs", "GET", "/api/v1/pipeline/evidence/packs")

# ── Inventory ──
print("\n── Inventory ──")
check("Inventory Assets", "GET", "/api/v1/inventory/assets")
check("Vulnerabilities Health", "GET", "/api/v1/vulns/health")

# ── Auth ──
print("\n── Auth ──")
check("Auth SSO", "GET", "/api/v1/auth/sso")

# ── Integrations ──
print("\n── Integrations ──")
check("Integrations List", "GET", "/api/v1/integrations")

# ── Code Security ──
print("\n── Code Security ──")
check("SAST Status", "GET", "/api/v1/sast/status")
check("Secrets Status", "GET", "/api/v1/secrets/status")

# ── Reports ──
print("\n── Reports ──")
check("Reports List", "GET", "/api/v1/reports")
check("Reports Stats", "GET", "/api/v1/reports/stats")

print(f"\n{'='*50}")
print(f"📊 Results: {passed}/{total} passed, {failed} failed")
if failed == 0:
    print("🎉 ALL TESTS PASSED!")
else:
    print(f"⚠️  {failed} test(s) need attention")
sys.exit(0 if failed == 0 else 1)
