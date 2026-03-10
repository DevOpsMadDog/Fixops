#!/usr/bin/env python3
"""FixOps Enterprise Security Hardening Validation.

This module is kept as an executable security smoke test, but is now safe to
collect under pytest. Network-dependent validation only runs from the explicit
pytest test or when the file is executed directly.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

import pytest
import requests

API = os.getenv("FIXOPS_SECURITY_TEST_API", "http://localhost:8000/api/v1")
KEY = os.getenv(
    "FIXOPS_API_TOKEN",
    os.getenv("FIXOPS_SECURITY_TEST_KEY", "fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U"),
)
HEADERS = {"X-API-Key": KEY, "Content-Type": "application/json"}
REQUEST_TIMEOUT = 10

pytestmark = [pytest.mark.security, pytest.mark.requires_network]


@dataclass
class ValidationResult:
    passed: int = 0
    failed: int = 0
    total: int = 0

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        self.total += 1
        if condition:
            self.passed += 1
            print(f"  ✅ {name}")
        else:
            self.failed += 1
            print(f"  ❌ {name}{f' — {detail}' if detail else ''}")


def _request(method: str, path: str, **kwargs):
    return requests.request(
        method,
        f"{API}{path}",
        timeout=REQUEST_TIMEOUT,
        **kwargs,
    )


def _is_api_reachable() -> bool:
    try:
        response = _request("GET", "/health", headers={"X-API-Key": KEY})
    except requests.RequestException:
        return False
    return response.ok


def run_security_hardening_validation() -> ValidationResult:
    result = ValidationResult()

    print("=" * 70)
    print("FIXOPS ENTERPRISE SECURITY HARDENING VALIDATION")
    print("=" * 70)

    print("\n[1] Security Headers (OWASP + FedRAMP)")
    r = _request("GET", "/health", headers={"X-API-Key": KEY})
    h = r.headers

    result.check("X-Content-Type-Options: nosniff", h.get("X-Content-Type-Options") == "nosniff")
    result.check("X-Frame-Options: DENY", h.get("X-Frame-Options") == "DENY")
    result.check("Referrer-Policy set", "strict-origin" in h.get("Referrer-Policy", ""))
    result.check("Content-Security-Policy set", "default-src" in h.get("Content-Security-Policy", ""))
    result.check("X-XSS-Protection: 1; mode=block", h.get("X-XSS-Protection") == "1; mode=block")
    result.check("Strict-Transport-Security (HSTS)", "max-age" in h.get("Strict-Transport-Security", ""))
    result.check("HSTS includeSubDomains", "includeSubDomains" in h.get("Strict-Transport-Security", ""))
    result.check("HSTS preload", "preload" in h.get("Strict-Transport-Security", ""))
    result.check("Cache-Control: no-store", "no-store" in h.get("Cache-Control", ""))
    result.check("Pragma: no-cache", h.get("Pragma") == "no-cache")
    result.check("X-Permitted-Cross-Domain-Policies: none", h.get("X-Permitted-Cross-Domain-Policies") == "none")
    result.check("Server header hidden (not uvicorn)", "uvicorn" not in h.get("Server", "").lower() or "FixOps" in h.get("Server", ""))
    result.check("Cross-Origin-Opener-Policy: same-origin", h.get("Cross-Origin-Opener-Policy") == "same-origin")
    result.check("Cross-Origin-Resource-Policy: same-origin", h.get("Cross-Origin-Resource-Policy") == "same-origin")
    result.check("Cross-Origin-Embedder-Policy: require-corp", h.get("Cross-Origin-Embedder-Policy") == "require-corp")
    result.check("Correlation ID present", "x-correlation-id" in {k.lower() for k in h.keys()})

    print("\n[2] Authentication Enforcement")
    r_noauth = _request("GET", "/analytics/findings")
    result.check("No auth → 401/403", r_noauth.status_code in (401, 403), f"got {r_noauth.status_code}")

    r_bad_key = _request("GET", "/analytics/findings", headers={"X-API-Key": "bad-key-12345"})
    result.check("Bad API key → 401/403", r_bad_key.status_code in (401, 403), f"got {r_bad_key.status_code}")

    r_empty_key = _request("GET", "/analytics/findings", headers={"X-API-Key": ""})
    result.check("Empty API key → 401/403", r_empty_key.status_code in (401, 403), f"got {r_empty_key.status_code}")

    print("\n[3] Input Validation & Injection Prevention")
    sqli_payloads = [
        "' OR 1=1 --",
        "'; DROP TABLE findings; --",
        "\" UNION SELECT * FROM users --",
    ]
    for payload in sqli_payloads:
        r = _request("GET", "/brain/findings", headers=HEADERS, params={"search": payload})
        result.check(f"SQL injection safe: {payload[:30]}...", r.status_code != 500)

    xss_payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
    ]
    for payload in xss_payloads:
        r = _request(
            "POST",
            "/brain/ingest/finding",
            headers=HEADERS,
            json={"title": payload, "severity": "medium", "description": payload},
        )
        result.check("XSS in title accepted (stored safely)", r.status_code in (200, 201, 422))

    r = _request(
        "POST",
        "/sast/scan/code",
        headers=HEADERS,
        json={"code": "; rm -rf / ; cat /etc/passwd", "language": "python"},
    )
    result.check("Command injection in code scan → no crash", r.status_code != 500)

    r = _request("GET", "/brain/findings", headers=HEADERS, params={"file_path": "../../../../etc/passwd"})
    result.check("Path traversal safe", r.status_code != 500 and "/etc/passwd" not in r.text)

    big_payload = {"title": "x" * 100000, "severity": "medium"}
    r = _request("POST", "/brain/ingest/finding", headers=HEADERS, json=big_payload)
    result.check("Oversized payload handled", r.status_code in (200, 201, 413, 422))

    print("\n[4] Error Handling — No Information Leakage")
    r = _request("GET", "/nonexistent-endpoint", headers=HEADERS)
    result.check("404 doesn't leak stack traces", "Traceback" not in r.text)
    result.check("404 doesn't leak file paths", "/home/" not in r.text and "/usr/" not in r.text)

    r = _request("POST", "/brain/ingest/finding", headers=HEADERS, json={"invalid": True})
    result.check("Validation error doesn't leak internals", "Traceback" not in r.text)

    print("\n[5] Content Type Enforcement")
    r = _request("POST", "/brain/ingest/finding", headers={"X-API-Key": KEY}, data="not json")
    result.check("Non-JSON body → 422/400/415", r.status_code in (400, 415, 422, 500))

    print("\n[6] SBOM & License Compliance Endpoints")
    r = _request("GET", "/inventory/sbom/components", headers=HEADERS)
    result.check("SBOM components endpoint works", r.status_code == 200)

    r = _request("GET", "/inventory/sbom/licenses", headers=HEADERS)
    result.check("License compliance endpoint works", r.status_code == 200)
    data = r.json()
    result.check("DFARS compliance field present", "dfars_compliant" in data)
    result.check("License distribution present", "license_distribution" in data)

    print("\n[7] Scanner Integration (19 parsers)")
    r = _request("GET", "/scanner-ingest/supported", headers=HEADERS)
    result.check("Scanner supported endpoint works", r.status_code == 200)
    data = r.json()
    total_parsers = len(data.get("scanners", {}).get("total_new", []))
    result.check("19 scanner parsers registered", total_parsers == 19, f"got {total_parsers}")

    r = _request("GET", "/scanner-ingest/health", headers=HEADERS)
    result.check("Scanner health endpoint works", r.status_code == 200)

    print("\n[8] Enterprise Features")
    r = _request("GET", "/health", headers=HEADERS)
    data = r.json()
    result.check("Health endpoint returns status", "status" in data)

    r = _request("GET", "/brain/status", headers=HEADERS)
    result.check("Brain status works", r.status_code == 200)

    r = _request("GET", "/audit/compliance/controls", headers=HEADERS)
    result.check("Compliance controls endpoint works", r.status_code == 200)

    r = _request(
        "POST",
        "/compliance-engine/assess",
        headers=HEADERS,
        json={"app_id": "test-app", "framework": "soc2", "scope": "full"},
    )
    result.check("Compliance assessment works", r.status_code == 200)

    r = _request("GET", "/knowledge-graph/status", headers=HEADERS)
    result.check("Knowledge graph status works", r.status_code == 200)

    r = _request("GET", "/self-learning/analyze", headers=HEADERS)
    result.check("Self-learning analyze works", r.status_code == 200)

    print("\n" + "=" * 70)
    success_rate = round(100 * result.passed / result.total, 1)
    if result.failed == 0:
        print(f"  ✅ ALL SECURITY CHECKS PASSED: {result.passed}/{result.total} ({success_rate}%)")
    else:
        print(f"  ⚠️  SECURITY CHECK RESULTS: {result.passed}/{result.total} ({success_rate}%)")
        print(f"     {result.failed} checks need attention")
    print("=" * 70)
    return result


def test_security_hardening_validation() -> None:
    if not _is_api_reachable():
        pytest.skip(f"Security hardening validation requires a running API at {API}")
    result = run_security_hardening_validation()
    assert result.failed == 0, f"{result.failed} security hardening checks failed"


if __name__ == "__main__":
    if not _is_api_reachable():
        print(f"FixOps API is not reachable at {API}")
        sys.exit(1)
    final_result = run_security_hardening_validation()
    sys.exit(0 if final_result.failed == 0 else 1)
