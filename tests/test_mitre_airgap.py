#!/usr/bin/env python3
"""
FixOps MITRE ATT&CK + Air-Gap Feature Tests
Tests the new application-layer MITRE mapping and air-gapped deployment features.
"""

import os
import sys
import requests
import pytest

API = os.getenv("FIXOPS_API", "http://localhost:8000/api/v1")
KEY = os.getenv("FIXOPS_API_KEY", "fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U")
HEADERS = {"X-API-Key": KEY, "Content-Type": "application/json"}

# Skip all tests if the live API server is not running
def _server_available():
    try:
        requests.get(f"{API}/health", headers=HEADERS, timeout=2)
        return True
    except Exception:
        return False

pytestmark = pytest.mark.skipif(not _server_available(), reason="Live API server not running (start with uvicorn)")

passed = 0
failed = 0
total = 0

def test(name, fn):
    global passed, failed, total
    total += 1
    try:
        fn()
        passed += 1
        print(f"  ✓ {name}")
    except Exception as e:
        failed += 1
        print(f"  ✗ {name}: {e}")

# =========================================================================
#  MITRE ATT&CK TESTS
# =========================================================================
print("\n" + "=" * 60)
print("  MITRE ATT&CK APPLICATION-LAYER MAPPING")
print("=" * 60)

def test_mitre_health():
    r = requests.get(f"{API}/mitre/health", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "healthy"
    assert d["capabilities"]["total_techniques"] >= 50
    assert d["capabilities"]["total_tactics"] == 14
    assert d["capabilities"]["cwe_mappings"] >= 50
    assert d["capabilities"]["air_gapped_safe"] is True

test("MITRE Health Check", test_mitre_health)

def test_mitre_tactics():
    r = requests.get(f"{API}/mitre/tactics", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    tactics = d.get("tactics", [])
    assert len(tactics) == 14, f"Expected 14 tactics, got {len(tactics)}"
    tactic_names = [t.get("name", t.get("tactic_name", "")) for t in tactics]
    required = ["Initial Access", "Execution", "Persistence", "Impact"]
    for req in required:
        assert any(req in n for n in tactic_names), f"Missing tactic: {req}"

test("MITRE 14 Tactics Present", test_mitre_tactics)

def test_mitre_techniques():
    r = requests.get(f"{API}/mitre/techniques", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    techniques = d.get("techniques", [])
    assert len(techniques) >= 50, f"Expected >=50 techniques, got {len(techniques)}"

test("MITRE 50+ Techniques", test_mitre_techniques)

def test_mitre_cwe_89():
    """SQL Injection should map to T1190 (Exploit Public-Facing App)"""
    r = requests.get(f"{API}/mitre/cwe/89", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert d["total_techniques"] >= 1
    technique_ids = [t["technique_id"] for t in d["techniques"]]
    assert "T1190" in technique_ids, f"CWE-89 should map to T1190, got {technique_ids}"

test("CWE-89 → T1190 Mapping", test_mitre_cwe_89)

def test_mitre_cwe_79():
    """XSS should map to relevant techniques"""
    r = requests.get(f"{API}/mitre/cwe/79", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert d["total_techniques"] >= 1

test("CWE-79 (XSS) Mapping", test_mitre_cwe_79)

def test_mitre_cwe_120():
    """Buffer overflow should map to T1068 or T1203"""
    r = requests.get(f"{API}/mitre/cwe/120", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert d["total_techniques"] >= 1

test("CWE-120 (Buffer Overflow) Mapping", test_mitre_cwe_120)

def test_mitre_map_findings():
    """Map multiple findings to techniques"""
    r = requests.post(f"{API}/mitre/map-findings", headers=HEADERS, json={
        "findings": [
            {"id": "f1", "title": "SQL Injection", "cwe_id": "89", "severity": "critical"},
            {"id": "f2", "title": "XSS", "cwe_id": "79", "severity": "high"},
            {"id": "f3", "title": "Buffer Overflow", "cwe_id": "120", "severity": "critical"},
            {"id": "f4", "title": "SSRF", "cwe_id": "918", "severity": "high"},
            {"id": "f5", "title": "Deserialization", "cwe_id": "502", "severity": "critical"},
        ]
    })
    assert r.status_code == 200
    d = r.json()
    assert d["total_findings"] == 5
    assert d["total_techniques"] >= 5
    assert d["total_tactics_covered"] >= 3

test("Map 5 Findings → Techniques", test_mitre_map_findings)

def test_mitre_cve_log4j():
    """Log4Shell CVE should map to techniques"""
    r = requests.post(f"{API}/mitre/map-findings", headers=HEADERS, json={
        "findings": [
            {"id": "f1", "title": "Log4j RCE", "cve_id": "CVE-2021-44228", "severity": "critical"}
        ]
    })
    assert r.status_code == 200
    d = r.json()
    assert d["total_techniques"] >= 1

test("CVE-2021-44228 (Log4Shell) Mapping", test_mitre_cve_log4j)

def test_mitre_kill_chain():
    """Kill chain analysis should show 14 phases"""
    r = requests.post(f"{API}/mitre/kill-chain", headers=HEADERS, json={
        "findings": [
            {"id": "f1", "title": "SQL Injection", "cwe_id": "89", "severity": "critical"},
            {"id": "f2", "title": "XSS", "cwe_id": "79", "severity": "high"},
            {"id": "f3", "title": "Buffer Overflow", "cwe_id": "120", "severity": "critical"},
        ]
    })
    assert r.status_code == 200
    d = r.json()
    assert d["total_tactics"] == 14
    assert d["coverage_percentage"] > 0

test("Kill Chain Analysis (14 phases)", test_mitre_kill_chain)

def test_mitre_navigator_json():
    """Navigator JSON should be valid ATT&CK Navigator format"""
    r = requests.post(f"{API}/mitre/navigator-json", headers=HEADERS, json={
        "findings": [
            {"id": "f1", "title": "SQL Injection", "cwe_id": "89", "severity": "critical"}
        ],
        "layer_name": "Test Assessment"
    })
    assert r.status_code == 200
    d = r.json()
    # Response wraps navigator layer or returns it directly
    layer = d.get("navigator_layer", d)
    assert "domain" in layer or "versions" in layer or "techniques" in layer or "name" in layer
    if "navigator_layer" in d:
        assert d["techniques_count"] >= 1

test("ATT&CK Navigator JSON Export", test_mitre_navigator_json)

def test_mitre_no_auth():
    """MITRE endpoints should reject unauthenticated requests"""
    r = requests.get(f"{API}/mitre/health")
    assert r.status_code in [401, 403], f"Expected 401/403, got {r.status_code}"

test("MITRE Auth Required", test_mitre_no_auth)

# =========================================================================
#  AIR-GAP TESTS
# =========================================================================
print("\n" + "=" * 60)
print("  AIR-GAP / OFFLINE MODE OPERATIONS")
print("=" * 60)

def test_airgap_status():
    r = requests.get(f"{API}/airgap/status", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert "mode" in d
    assert "classification_level" in d
    assert "fips" in d

test("Air-Gap Status", test_airgap_status)

def test_airgap_health():
    r = requests.get(f"{API}/airgap/health", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert "checks" in d
    assert "mode" in d

test("Air-Gap Health Check", test_airgap_health)

def test_airgap_classification():
    r = requests.get(f"{API}/airgap/classification", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert "classification_level" in d
    assert "banner" in d

test("Air-Gap Classification", test_airgap_classification)

def test_airgap_set_classification():
    """Set classification to SECRET"""
    r = requests.post(f"{API}/airgap/configure", headers=HEADERS, json={
        "classification_level": "SECRET"
    })
    assert r.status_code == 200
    d = r.json()
    assert d["classification_level"] == "SECRET"

test("Set Classification to SECRET", test_airgap_set_classification)

def test_airgap_secret_banner():
    """Verify SECRET banner is correct"""
    r = requests.get(f"{API}/airgap/classification", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert d["classification_level"] == "SECRET"
    assert "SECRET" in d["banner"]["banner_text"]

test("SECRET Banner Verification", test_airgap_secret_banner)

def test_airgap_fips_status():
    r = requests.get(f"{API}/airgap/fips/status", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert "fips_status" in d
    assert "approved_hash_algorithms" in d
    algos = d["approved_hash_algorithms"]
    assert "sha256" in algos
    assert "md5" not in algos  # MD5 must NOT be FIPS approved

test("FIPS Algorithm Whitelist (no MD5)", test_airgap_fips_status)

def test_airgap_dependencies():
    r = requests.get(f"{API}/airgap/dependencies", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert "dependencies" in d or "external_dependencies" in d or isinstance(d, list)

test("Air-Gap Dependencies List", test_airgap_dependencies)

def test_airgap_reset():
    """Reset to UNCLASSIFIED"""
    r = requests.post(f"{API}/airgap/configure", headers=HEADERS, json={
        "classification_level": "UNCLASSIFIED"
    })
    assert r.status_code == 200

test("Reset to UNCLASSIFIED", test_airgap_reset)

def test_airgap_no_auth():
    """Air-Gap endpoints should reject unauthenticated requests"""
    r = requests.get(f"{API}/airgap/status")
    assert r.status_code in [401, 403], f"Expected 401/403, got {r.status_code}"

test("Air-Gap Auth Required", test_airgap_no_auth)

# =========================================================================
#  RESULTS
# =========================================================================
print("\n" + "=" * 60)
print("  RESULTS")
print("=" * 60)
pct = (passed / total * 100) if total else 0
print(f"\n  Passed: {passed}/{total} ({pct:.1f}%)")
print(f"  Failed: {failed}/{total}")
status = "🟢 ALL TESTS PASSED" if failed == 0 else "🔴 SOME TESTS FAILED"
print(f"\n  {status}")
print()

if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
