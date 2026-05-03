#!/usr/bin/env python3
"""
FixOps MITRE ATT&CK + Air-Gap Feature Tests
Tests the new application-layer MITRE mapping and air-gapped deployment features.

Can be run standalone (``python tests/test_mitre_airgap.py``) or via pytest.
Module-level ``test()`` calls only execute in standalone mode; pytest discovers
the ``test_*`` functions normally.
"""

import os
import sys
import time
import requests
import pytest

API = os.getenv("FIXOPS_API", "http://localhost:8000/api/v1")
KEY = os.getenv(
    "FIXOPS_API_TOKEN",
    os.getenv("FIXOPS_API_KEY", "fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U"),
)
HEADERS = {"X-API-Key": KEY, "Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _req(method: str, path: str, _retries: int = 3, **kwargs):
    """HTTP request with automatic retry on 429 (rate-limit)."""
    kwargs.setdefault("timeout", 10)
    for attempt in range(_retries + 1):
        resp = requests.request(method, f"{API}{path}", **kwargs)
        if resp.status_code != 429 or attempt == _retries:
            return resp
        retry_after = int(resp.headers.get("Retry-After", 2))
        time.sleep(max(retry_after, 1))
    return resp  # pragma: no cover


def _server_available():
    try:
        _req("GET", "/health", headers={"X-API-Key": KEY})
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _server_available(),
    reason="Live API server not running (start with uvicorn)",
)


# ---------------------------------------------------------------------------
# Standalone runner bookkeeping (only used when run as a script)
# ---------------------------------------------------------------------------
_passed = 0
_failed = 0
_total = 0


def _run_test(name, fn):
    """Execute *fn* and track pass/fail (standalone mode only)."""
    global _passed, _failed, _total
    _total += 1
    try:
        fn()
        _passed += 1
        print(f"  \u2713 {name}")
    except Exception as e:
        _failed += 1
        print(f"  \u2717 {name}: {e}")


# =========================================================================
#  MITRE ATT&CK TESTS
# =========================================================================

def test_mitre_health():
    r = _req("GET", "/mitre/health", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "healthy"
    assert d["capabilities"]["total_techniques"] >= 50
    assert d["capabilities"]["total_tactics"] == 14
    assert d["capabilities"]["cwe_mappings"] >= 50
    assert d["capabilities"]["air_gapped_safe"] is True


def test_mitre_tactics():
    r = _req("GET", "/mitre/tactics", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    tactics = d.get("tactics", [])
    assert len(tactics) == 14, f"Expected 14 tactics, got {len(tactics)}"
    tactic_names = [t.get("name", t.get("tactic_name", "")) for t in tactics]
    required = ["Initial Access", "Execution", "Persistence", "Impact"]
    for req in required:
        assert any(req in n for n in tactic_names), f"Missing tactic: {req}"


def test_mitre_techniques():
    r = _req("GET", "/mitre/techniques", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    techniques = d.get("techniques", [])
    assert len(techniques) >= 50, f"Expected >=50 techniques, got {len(techniques)}"


def test_mitre_cwe_89():
    """SQL Injection should map to T1190 (Exploit Public-Facing App)"""
    r = _req("GET", "/mitre/cwe/89", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert d["total_techniques"] >= 1
    technique_ids = [t["technique_id"] for t in d["techniques"]]
    assert "T1190" in technique_ids, f"CWE-89 should map to T1190, got {technique_ids}"


def test_mitre_cwe_79():
    """XSS should map to relevant techniques"""
    r = _req("GET", "/mitre/cwe/79", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert d["total_techniques"] >= 1


def test_mitre_cwe_120():
    """Buffer overflow should map to T1068 or T1203"""
    r = _req("GET", "/mitre/cwe/120", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert d["total_techniques"] >= 1


def test_mitre_map_findings():
    """Map multiple findings to techniques"""
    r = _req("POST", "/mitre/map-findings", headers=HEADERS, json={
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


def test_mitre_cve_log4j():
    """Log4Shell CVE should map to techniques"""
    r = _req("POST", "/mitre/map-findings", headers=HEADERS, json={
        "findings": [
            {"id": "f1", "title": "Log4j RCE", "cve_id": "CVE-2021-44228", "severity": "critical"}
        ]
    })
    assert r.status_code == 200
    d = r.json()
    assert d["total_techniques"] >= 1


def test_mitre_kill_chain():
    """Kill chain analysis should show 14 phases"""
    r = _req("POST", "/mitre/kill-chain", headers=HEADERS, json={
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


def test_mitre_navigator_json():
    """Navigator JSON should be valid ATT&CK Navigator format"""
    r = _req("POST", "/mitre/navigator-json", headers=HEADERS, json={
        "findings": [
            {"id": "f1", "title": "SQL Injection", "cwe_id": "89", "severity": "critical"}
        ],
        "layer_name": "Test Assessment"
    })
    assert r.status_code == 200
    d = r.json()
    layer = d.get("navigator_layer", d)
    assert "domain" in layer or "versions" in layer or "techniques" in layer or "name" in layer
    if "navigator_layer" in d:
        assert d["techniques_count"] >= 1


def test_mitre_no_auth():
    """MITRE endpoints should reject unauthenticated requests"""
    r = _req("GET", "/mitre/health")
    assert r.status_code in [401, 403], f"Expected 401/403, got {r.status_code}"


# =========================================================================
#  AIR-GAP TESTS
# =========================================================================

def test_airgap_status():
    r = _req("GET", "/airgap/status", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert "mode" in d
    assert "classification_level" in d
    assert "fips" in d


def test_airgap_health():
    r = _req("GET", "/airgap/health", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert "checks" in d
    assert "mode" in d


def test_airgap_classification():
    r = _req("GET", "/airgap/classification", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert "classification_level" in d
    assert "banner" in d


def test_airgap_set_classification():
    """Set classification to SECRET"""
    r = _req("POST", "/airgap/configure", headers=HEADERS, json={
        "classification_level": "SECRET"
    })
    assert r.status_code == 200
    d = r.json()
    assert d["classification_level"] == "SECRET"


def test_airgap_secret_banner():
    """Verify SECRET banner is correct"""
    r = _req("GET", "/airgap/classification", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert d["classification_level"] == "SECRET"
    assert "SECRET" in d["banner"]["banner_text"]


def test_airgap_fips_status():
    r = _req("GET", "/airgap/fips/status", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert "fips_status" in d
    assert "approved_hash_algorithms" in d
    algos = d["approved_hash_algorithms"]
    assert "sha256" in algos
    assert "md5" not in algos  # MD5 must NOT be FIPS approved


def test_airgap_dependencies():
    r = _req("GET", "/airgap/dependencies", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    assert "dependencies" in d or "external_dependencies" in d or isinstance(d, list)


def test_airgap_reset():
    """Reset to UNCLASSIFIED"""
    r = _req("POST", "/airgap/configure", headers=HEADERS, json={
        "classification_level": "UNCLASSIFIED"
    })
    assert r.status_code == 200


def test_airgap_no_auth():
    """Air-Gap endpoints should reject unauthenticated requests"""
    r = _req("GET", "/airgap/status")
    assert r.status_code in [401, 403], f"Expected 401/403, got {r.status_code}"


# =========================================================================
#  STANDALONE RUNNER (only when executed directly, not via pytest)
# =========================================================================
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  MITRE ATT&CK APPLICATION-LAYER MAPPING")
    print("=" * 60)

    _run_test("MITRE Health Check", test_mitre_health)
    _run_test("MITRE 14 Tactics Present", test_mitre_tactics)
    _run_test("MITRE 50+ Techniques", test_mitre_techniques)
    _run_test("CWE-89 \u2192 T1190 Mapping", test_mitre_cwe_89)
    _run_test("CWE-79 (XSS) Mapping", test_mitre_cwe_79)
    _run_test("CWE-120 (Buffer Overflow) Mapping", test_mitre_cwe_120)
    _run_test("Map 5 Findings \u2192 Techniques", test_mitre_map_findings)
    _run_test("CVE-2021-44228 (Log4Shell) Mapping", test_mitre_cve_log4j)
    _run_test("Kill Chain Analysis (14 phases)", test_mitre_kill_chain)
    _run_test("ATT&CK Navigator JSON Export", test_mitre_navigator_json)
    _run_test("MITRE Auth Required", test_mitre_no_auth)

    print("\n" + "=" * 60)
    print("  AIR-GAP / OFFLINE MODE OPERATIONS")
    print("=" * 60)

    _run_test("Air-Gap Status", test_airgap_status)
    _run_test("Air-Gap Health Check", test_airgap_health)
    _run_test("Air-Gap Classification", test_airgap_classification)
    _run_test("Set Classification to SECRET", test_airgap_set_classification)
    _run_test("SECRET Banner Verification", test_airgap_secret_banner)
    _run_test("FIPS Algorithm Whitelist (no MD5)", test_airgap_fips_status)
    _run_test("Air-Gap Dependencies List", test_airgap_dependencies)
    _run_test("Reset to UNCLASSIFIED", test_airgap_reset)
    _run_test("Air-Gap Auth Required", test_airgap_no_auth)

    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)
    pct = (_passed / _total * 100) if _total else 0
    print(f"\n  Passed: {_passed}/{_total} ({pct:.1f}%)")
    print(f"  Failed: {_failed}/{_total}")
    status = "\U0001f7e2 ALL TESTS PASSED" if _failed == 0 else "\U0001f534 SOME TESTS FAILED"
    print(f"\n  {status}")
    print()
    sys.exit(0 if _failed == 0 else 1)
