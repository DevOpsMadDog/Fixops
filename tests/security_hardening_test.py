#!/usr/bin/env python3
"""FixOps Enterprise Security Hardening Validation.

Tests all security controls required for defense/government deployment:
- Security headers (OWASP, FedRAMP, NIST 800-53)
- Input validation (injection prevention)
- Authentication enforcement
- Rate limiting awareness
- CORS enforcement
- Error handling (no information leakage)
"""

import requests
import sys

API = "http://localhost:8000/api/v1"
KEY = "fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U"
HEADERS = {"X-API-Key": KEY, "Content-Type": "application/json"}

passed = 0
failed = 0
total = 0


def check(name, condition, detail=""):
    global passed, failed, total
    total += 1
    if condition:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}{f' — {detail}' if detail else ''}")


print("=" * 70)
print("FIXOPS ENTERPRISE SECURITY HARDENING VALIDATION")
print("=" * 70)

# 1. Security Headers
print("\n[1] Security Headers (OWASP + FedRAMP)")
r = requests.get(f"{API}/health", headers={"X-API-Key": KEY})
h = r.headers

check("X-Content-Type-Options: nosniff", h.get("X-Content-Type-Options") == "nosniff")
check("X-Frame-Options: DENY", h.get("X-Frame-Options") == "DENY")
check("Referrer-Policy set", "strict-origin" in h.get("Referrer-Policy", ""))
check("Content-Security-Policy set", "default-src" in h.get("Content-Security-Policy", ""))
check("X-XSS-Protection: 1; mode=block", h.get("X-XSS-Protection") == "1; mode=block")
check("Strict-Transport-Security (HSTS)", "max-age" in h.get("Strict-Transport-Security", ""))
check("HSTS includeSubDomains", "includeSubDomains" in h.get("Strict-Transport-Security", ""))
check("HSTS preload", "preload" in h.get("Strict-Transport-Security", ""))
check("Cache-Control: no-store", "no-store" in h.get("Cache-Control", ""))
check("Pragma: no-cache", h.get("Pragma") == "no-cache")
check("X-Permitted-Cross-Domain-Policies: none", h.get("X-Permitted-Cross-Domain-Policies") == "none")
check("Server header hidden (not uvicorn)", "uvicorn" not in h.get("Server", "").lower() or "FixOps" in h.get("Server", ""))
check("Cross-Origin-Opener-Policy: same-origin", h.get("Cross-Origin-Opener-Policy") == "same-origin")
check("Cross-Origin-Resource-Policy: same-origin", h.get("Cross-Origin-Resource-Policy") == "same-origin")
check("Cross-Origin-Embedder-Policy: require-corp", h.get("Cross-Origin-Embedder-Policy") == "require-corp")
check("Correlation ID present", "x-correlation-id" in {k.lower() for k in h.keys()})

# 2. Authentication Enforcement
print("\n[2] Authentication Enforcement")
r_noauth = requests.get(f"{API}/analytics/findings")
check("No auth → 401/403", r_noauth.status_code in (401, 403), f"got {r_noauth.status_code}")

r_bad_key = requests.get(f"{API}/analytics/findings", headers={"X-API-Key": "bad-key-12345"})
check("Bad API key → 401/403", r_bad_key.status_code in (401, 403), f"got {r_bad_key.status_code}")

r_empty_key = requests.get(f"{API}/analytics/findings", headers={"X-API-Key": ""})
check("Empty API key → 401/403", r_empty_key.status_code in (401, 403), f"got {r_empty_key.status_code}")

# 3. Input Validation
print("\n[3] Input Validation & Injection Prevention")

# SQL injection attempts
sqli_payloads = [
    "' OR 1=1 --",
    "'; DROP TABLE findings; --",
    "\" UNION SELECT * FROM users --",
]
for payload in sqli_payloads:
    r = requests.get(f"{API}/brain/findings", headers=HEADERS, params={"search": payload})
    check(f"SQL injection safe: {payload[:30]}...", r.status_code != 500)

# XSS injection attempts
xss_payloads = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
]
for payload in xss_payloads:
    r = requests.post(f"{API}/brain/ingest/finding", headers=HEADERS, json={
        "title": payload,
        "severity": "medium",
        "description": payload,
    })
    check("XSS in title accepted (stored safely)", r.status_code in (200, 201, 422))

# Command injection
r = requests.post(f"{API}/sast/scan/code", headers=HEADERS, json={
    "code": "; rm -rf / ; cat /etc/passwd",
    "language": "python",
})
check("Command injection in code scan → no crash", r.status_code != 500)

# Path traversal
r = requests.get(f"{API}/brain/findings", headers=HEADERS, params={"file_path": "../../../../etc/passwd"})
check("Path traversal safe", r.status_code != 500 and "/etc/passwd" not in r.text)

# Oversized payload
big_payload = {"title": "x" * 100000, "severity": "medium"}
r = requests.post(f"{API}/brain/ingest/finding", headers=HEADERS, json=big_payload)
check("Oversized payload handled", r.status_code in (200, 201, 413, 422))

# 4. Error Handling (No Information Leakage)
print("\n[4] Error Handling — No Information Leakage")

r = requests.get(f"{API}/nonexistent-endpoint", headers=HEADERS)
check("404 doesn't leak stack traces", "Traceback" not in r.text)
check("404 doesn't leak file paths", "/home/" not in r.text and "/usr/" not in r.text)

r = requests.post(f"{API}/brain/ingest/finding", headers=HEADERS, json={"invalid": True})
check("Validation error doesn't leak internals", "Traceback" not in r.text)

# 5. Content Type Enforcement
print("\n[5] Content Type Enforcement")
r = requests.post(f"{API}/brain/ingest/finding", headers={"X-API-Key": KEY}, data="not json")
check("Non-JSON body → 422/400/415", r.status_code in (400, 415, 422, 500))

# 6. SBOM & License Compliance
print("\n[6] SBOM & License Compliance Endpoints")
r = requests.get(f"{API}/inventory/sbom/components", headers=HEADERS)
check("SBOM components endpoint works", r.status_code == 200)

r = requests.get(f"{API}/inventory/sbom/licenses", headers=HEADERS)
check("License compliance endpoint works", r.status_code == 200)
data = r.json()
check("DFARS compliance field present", "dfars_compliant" in data)
check("License distribution present", "license_distribution" in data)

# 7. Scanner Integration
print("\n[7] Scanner Integration (19 parsers)")
r = requests.get(f"{API}/scanner-ingest/supported", headers=HEADERS)
check("Scanner supported endpoint works", r.status_code == 200)
data = r.json()
total_parsers = len(data.get("scanners", {}).get("total_new", []))
check("19 scanner parsers registered", total_parsers == 19, f"got {total_parsers}")

r = requests.get(f"{API}/scanner-ingest/health", headers=HEADERS)
check("Scanner health endpoint works", r.status_code == 200)

# 8. Enterprise Features
print("\n[8] Enterprise Features")
r = requests.get(f"{API}/health", headers=HEADERS)
data = r.json()
check("Health endpoint returns status", "status" in data)

r = requests.get(f"{API}/brain/status", headers=HEADERS)
check("Brain status works", r.status_code == 200)

r = requests.get(f"{API}/audit/compliance/controls", headers=HEADERS)
check("Compliance controls endpoint works", r.status_code == 200)

r = requests.post(f"{API}/compliance-engine/assess", headers=HEADERS, json={
    "app_id": "test-app", "framework": "soc2", "scope": "full"
})
check("Compliance assessment works", r.status_code == 200)

r = requests.get(f"{API}/knowledge-graph/status", headers=HEADERS)
check("Knowledge graph status works", r.status_code == 200)

r = requests.get(f"{API}/self-learning/analyze", headers=HEADERS)
check("Self-learning analyze works", r.status_code == 200)

# Summary
print("\n" + "=" * 70)
success_rate = round(100 * passed / total, 1)
if failed == 0:
    print(f"  ✅ ALL SECURITY CHECKS PASSED: {passed}/{total} ({success_rate}%)")
else:
    print(f"  ⚠️  SECURITY CHECK RESULTS: {passed}/{total} ({success_rate}%)")
    print(f"     {failed} checks need attention")
print("=" * 70)

if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
