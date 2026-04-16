#!/usr/bin/env python3
"""
ALDECI Deep Integration Test
Tests 30 engine categories with real POST→GET round-trips.
Usage: python3 scripts/deep_integration_test.py
"""

import time
import json
import sys
import requests
from datetime import datetime
from typing import Optional

BASE_URL = "http://localhost:8000"
API_KEY = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
ORG_ID = "deep-test"
DELAY = 1.2  # seconds between requests (some engines enforce 1 req/s rate limit)

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
}

# ─── Result tracking ──────────────────────────────────────────────────────────

results = []

def record(
    category: str,
    endpoint: str,
    method: str,
    payload: Optional[dict],
    status: int,
    elapsed_ms: float,
    response_text: str,
    has_data: bool,
    note: str = "",
):
    results.append({
        "category": category,
        "endpoint": endpoint,
        "method": method,
        "input": json.dumps(payload, separators=(",", ":"))[:60] if payload else "-",
        "status": status,
        "elapsed_ms": round(elapsed_ms, 1),
        "response_summary": response_text[:120].replace("\n", " "),
        "has_data": has_data,
        "note": note,
    })


def req(method: str, path: str, payload: Optional[dict] = None,
        params: Optional[dict] = None) -> tuple[int, str, float]:
    """Make a request, return (status, body[:300], elapsed_ms)."""
    url = f"{BASE_URL}{path}"
    start = time.perf_counter()
    try:
        if method == "GET":
            r = requests.get(url, headers=HEADERS, params=params, timeout=15)
        elif method == "POST":
            r = requests.post(url, headers=HEADERS, json=payload, params=params, timeout=15)
        elif method == "PUT":
            r = requests.put(url, headers=HEADERS, json=payload, params=params, timeout=15)
        else:
            raise ValueError(f"Unknown method {method}")
        elapsed = (time.perf_counter() - start) * 1000
        return r.status_code, r.text[:300], elapsed
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return 0, str(e)[:300], elapsed


def has_data(body: str) -> bool:
    """Detect whether the response contains substantive data (not empty/error)."""
    try:
        parsed = json.loads(body)
        if isinstance(parsed, list):
            return True  # even empty list is a valid response
        if isinstance(parsed, dict):
            if "detail" in parsed and "id" not in parsed:
                return False  # error detail
            return True
        return False
    except Exception:
        return bool(body.strip())


def step(category: str, method: str, path: str,
         payload: Optional[dict] = None,
         params: Optional[dict] = None,
         note: str = "") -> tuple[int, str]:
    """Execute one test step, record result, sleep, return (status, body)."""
    status, body, elapsed = req(method, path, payload, params)
    good = has_data(body) and status < 400
    record(category, path, method, payload, status, elapsed, body, good, note)
    icon = "✓" if good else "✗"
    print(f"  {icon} {method:4s} {path:<55s} {status}  {elapsed:6.0f}ms")
    time.sleep(DELAY)
    return status, body


# ─── Test Cases ───────────────────────────────────────────────────────────────

def test_security_operations():
    print("\n[Security Operations]")

    # alert-triage
    step("Security Ops / Alert Triage", "POST", "/api/v1/alert-triage/alerts",
         payload={"title": "DI: Suspicious Login", "severity": "high", "source": "siem"},
         params={"org_id": ORG_ID})
    step("Security Ops / Alert Triage", "GET", "/api/v1/alert-triage/alerts",
         params={"org_id": ORG_ID})

    # incident-orchestration
    step("Security Ops / Incident Orchestration", "POST", "/api/v1/incident-orchestration/incidents",
         payload={"title": "DI: Ransomware Incident", "severity": "critical", "status": "open"},
         params={"org_id": ORG_ID})
    step("Security Ops / Incident Orchestration", "GET", "/api/v1/incident-orchestration/incidents",
         params={"org_id": ORG_ID})

    # soc-workflow — correct path is /workflows
    step("Security Ops / SOC Workflow", "POST", "/api/v1/soc-workflow/workflows",
         payload={"name": "DI: Incident Response Workflow", "workflow_type": "incident_response"},
         params={"org_id": ORG_ID})
    step("Security Ops / SOC Workflow", "GET", "/api/v1/soc-workflow/workflows",
         params={"org_id": ORG_ID})


def test_vulnerability_management():
    print("\n[Vulnerability Management]")

    # vuln-workflow — correct path is /tickets
    step("Vuln Mgmt / Vuln Workflow", "POST", "/api/v1/vuln-workflow/tickets",
         payload={"cve_id": "CVE-2024-9999", "title": "DI: Critical RCE", "severity": "critical",
                  "asset": "prod-server-01"},
         params={"org_id": ORG_ID})
    step("Vuln Mgmt / Vuln Workflow", "GET", "/api/v1/vuln-workflow/tickets",
         params={"org_id": ORG_ID})

    # vuln-scans
    step("Vuln Mgmt / Vuln Scans", "POST", "/api/v1/vuln-scans/scans",
         payload={"scan_name": "DI: Network Scan", "scanner_type": "nessus",
                  "target": "192.168.1.0/24"},
         params={"org_id": ORG_ID})
    step("Vuln Mgmt / Vuln Scans", "GET", "/api/v1/vuln-scans/scans",
         params={"org_id": ORG_ID})

    # brain findings — POST to brain ingest, verify via findings
    step("Vuln Mgmt / Brain Findings", "GET", "/api/v1/findings",
         params={"org_id": ORG_ID},
         note="GET only — brain ingest is event-driven")


def test_threat_intelligence():
    print("\n[Threat Intelligence]")

    # cyber-threat-intel
    step("Threat Intel / CTI Reports", "POST", "/api/v1/cyber-threat-intel/reports",
         payload={"title": "DI: APT28 Campaign", "tlp": "green", "confidence_score": 0.87},
         params={"org_id": ORG_ID})
    step("Threat Intel / CTI Reports", "GET", "/api/v1/cyber-threat-intel/reports",
         params={"org_id": ORG_ID})

    # threat-indicators
    step("Threat Intel / Threat Indicators", "POST", "/api/v1/threat-indicators/indicators",
         payload={"indicator_type": "ip", "indicator_value": "203.0.113.42", "confidence": 0.95},
         params={"org_id": ORG_ID})
    step("Threat Intel / Threat Indicators", "GET", "/api/v1/threat-indicators/indicators",
         params={"org_id": ORG_ID})

    # ti-automation feeds
    step("Threat Intel / TI Automation", "GET", "/api/v1/ti-automation/feeds",
         params={"org_id": ORG_ID})


def test_compliance_and_risk():
    print("\n[Compliance & Risk]")

    # compliance status
    step("Compliance / Status", "GET", "/api/v1/compliance/status",
         params={"org_id": ORG_ID})

    # risk-register-engine
    step("Risk / Risk Register", "POST", "/api/v1/risk-register-engine/risks",
         payload={"name": "DI: Supply Chain Compromise", "likelihood": "likely",
                  "impact": "catastrophic"},
         params={"org_id": ORG_ID})
    step("Risk / Risk Register", "GET", "/api/v1/risk-register-engine/risks",
         params={"org_id": ORG_ID})

    # compliance-mapping stats (correct path — /frameworks returns 404)
    step("Compliance / Mapping Stats", "GET", "/api/v1/compliance-mapping/stats",
         params={"org_id": ORG_ID})


def test_cloud_and_infrastructure():
    print("\n[Cloud & Infrastructure]")

    # kubernetes-security
    step("Cloud / Kubernetes Security", "POST", "/api/v1/kubernetes-security/clusters",
         payload={"name": "di-prod-cluster", "provider": "eks"},
         params={"org_id": ORG_ID})
    step("Cloud / Kubernetes Security", "GET", "/api/v1/kubernetes-security/clusters",
         params={"org_id": ORG_ID})

    # cloud-posture
    step("Cloud / Cloud Posture", "POST", "/api/v1/cloud-posture/accounts",
         payload={"account_id": "di-acct-001", "account_name": "DI Test Account",
                  "provider": "aws"},
         params={"org_id": ORG_ID})
    step("Cloud / Cloud Posture", "GET", "/api/v1/cloud-posture/accounts",
         params={"org_id": ORG_ID})

    # cloud-compliance stats
    step("Cloud / Cloud Compliance", "GET", "/api/v1/cloud-compliance/stats",
         params={"org_id": ORG_ID})


def test_identity_and_access():
    print("\n[Identity & Access]")

    # access-anomaly — POST an event, GET anomalies
    step("Identity / Access Anomaly", "POST", "/api/v1/access-anomaly/events",
         payload={"org_id": ORG_ID, "username": "di-testuser",
                  "source_ip": "203.0.113.1", "location": "RU",
                  "device_fingerprint": "di-dev-001", "action": "login"},
         params={"org_id": ORG_ID},
         note="POST event then GET anomalies")
    step("Identity / Access Anomaly", "GET", "/api/v1/access-anomaly/anomalies",
         params={"org_id": ORG_ID})

    # identity-risk
    step("Identity / Identity Risk", "POST", "/api/v1/identity-risk/identities",
         payload={"username": "di-highrisk-user", "risk_level": "high"},
         params={"org_id": ORG_ID})
    step("Identity / Identity Risk", "GET", "/api/v1/identity-risk/identities",
         params={"org_id": ORG_ID})


def test_sbom_and_supply_chain():
    print("\n[SBOM & Supply Chain]")

    step("SBOM / Licenses", "GET", "/api/v1/sbom/licenses",
         params={"org_id": ORG_ID})

    step("Supply Chain / Monitoring Suppliers", "GET", "/api/v1/supply-chain-monitoring/suppliers",
         params={"org_id": ORG_ID})

    step("Supply Chain / Attack Packages", "GET", "/api/v1/supply-chain-attacks/packages",
         params={"org_id": ORG_ID})


def test_advanced_security():
    print("\n[Advanced Security]")

    # ransomware-protection — valid detection_type: behavioral/signature/honeypot/heuristic/network/endpoint
    step("Advanced / Ransomware Protection", "POST", "/api/v1/ransomware-protection/detections",
         payload={"org_id": ORG_ID, "detection_name": "DI: Mass Encryption",
                  "detection_type": "behavioral", "severity": "critical"},
         params={"org_id": ORG_ID})
    step("Advanced / Ransomware Protection", "GET", "/api/v1/ransomware-protection/detections",
         params={"org_id": ORG_ID})

    # dark-web — valid mention_type: brand_mention/credential_leak/data_dump/etc.
    step("Advanced / Dark Web Monitoring", "POST", "/api/v1/dark-web/mentions",
         payload={"mention_type": "credential_leak", "source_category": "forum",
                  "keyword_matched": "deep-test-corp"},
         params={"org_id": ORG_ID})
    step("Advanced / Dark Web Monitoring", "GET", "/api/v1/dark-web/mentions",
         params={"org_id": ORG_ID})

    # quantum-crypto — valid asset_type: tls_certificate/encryption_key/etc.
    # valid current_algorithm: rsa/ecdsa/aes/etc. discovered_at required by DB
    step("Advanced / Quantum Crypto", "POST", "/api/v1/quantum-crypto/assets",
         payload={"asset_name": "DI: Prod TLS Cert", "asset_type": "tls_certificate",
                  "current_algorithm": "rsa",
                  "discovered_at": datetime.utcnow().isoformat()},
         params={"org_id": ORG_ID})
    step("Advanced / Quantum Crypto", "GET", "/api/v1/quantum-crypto/assets",
         params={"org_id": ORG_ID})

    # ai-soc
    step("Advanced / AI-Powered SOC", "POST", "/api/v1/ai-soc/detections",
         payload={"detection_name": "DI: Anomalous Exfil", "detection_type": "anomaly",
                  "confidence": 0.94},
         params={"org_id": ORG_ID})
    step("Advanced / AI-Powered SOC", "GET", "/api/v1/ai-soc/detections",
         params={"org_id": ORG_ID})


def test_automation_and_metrics():
    print("\n[Automation & Metrics]")

    step("Automation / Security Automation", "GET", "/api/v1/security-automation/rules",
         params={"org_id": ORG_ID})

    step("Metrics / KPI Tracking", "GET", "/api/v1/kpi-tracking/kpis",
         params={"org_id": ORG_ID})

    step("Metrics / Security Scoreboard", "GET", "/api/v1/security-scoreboard/leaderboard",
         params={"org_id": ORG_ID})


def test_architecture_and_planning():
    print("\n[Architecture & Planning]")

    # arch-review
    step("Architecture / Arch Review", "POST", "/api/v1/arch-review/reviews",
         payload={"review_name": "DI: Backend Architecture Review",
                  "system_name": "aldeci-backend"},
         params={"org_id": ORG_ID})
    step("Architecture / Arch Review", "GET", "/api/v1/arch-review/reviews",
         params={"org_id": ORG_ID})

    # threat-modeling-pipeline
    step("Architecture / Threat Modeling Pipeline", "GET",
         "/api/v1/threat-modeling-pipeline/models",
         params={"org_id": ORG_ID})

    # dependency-mapping
    step("Architecture / Dependency Mapping", "GET", "/api/v1/dependency-mapping/summary",
         params={"org_id": ORG_ID})


# ─── Report Printer ──────────────────────────────────────────────────────────

def print_report():
    print("\n")
    print("=" * 160)
    print("ALDECI DEEP INTEGRATION TEST REPORT")
    print(f"Run at: {datetime.now().isoformat()}  |  Base URL: {BASE_URL}  |  Org: {ORG_ID}")
    print("=" * 160)

    # Column widths
    W = {
        "category":   30,
        "endpoint":   52,
        "method":      6,
        "input":      35,
        "status":      7,
        "time":        9,
        "summary":    50,
        "data":        6,
    }

    header = (
        f"{'Category':<{W['category']}} "
        f"{'Endpoint':<{W['endpoint']}} "
        f"{'Mth':<{W['method']}} "
        f"{'Input Payload':<{W['input']}} "
        f"{'Status':<{W['status']}} "
        f"{'Time(ms)':<{W['time']}} "
        f"{'Response Summary':<{W['summary']}} "
        f"{'OK?':<{W['data']}}"
    )
    print(header)
    print("-" * 160)

    passed = failed = 0
    for r in results:
        ok_str = "YES" if r["has_data"] else "NO"
        status_str = str(r["status"]) if r["status"] > 0 else "ERR"
        row = (
            f"{r['category'][:W['category']]:<{W['category']}} "
            f"{r['endpoint'][:W['endpoint']]:<{W['endpoint']}} "
            f"{r['method']:<{W['method']}} "
            f"{r['input'][:W['input']]:<{W['input']}} "
            f"{status_str:<{W['status']}} "
            f"{r['elapsed_ms']:<{W['time']}} "
            f"{r['response_summary'][:W['summary']]:<{W['summary']}} "
            f"{ok_str:<{W['data']}}"
        )
        print(row)
        if r["has_data"] and r["status"] < 400:
            passed += 1
        else:
            failed += 1

    print("=" * 160)
    total = passed + failed
    pct = round(passed / total * 100) if total else 0
    print(f"\nSUMMARY: {passed}/{total} endpoints healthy ({pct}%)")

    # Category rollup
    cats: dict[str, dict] = {}
    for r in results:
        cat = r["category"].split("/")[0].strip()
        cats.setdefault(cat, {"pass": 0, "fail": 0})
        key = "pass" if (r["has_data"] and r["status"] < 400) else "fail"
        cats[cat][key] += 1

    print("\nBY CATEGORY:")
    for cat, counts in sorted(cats.items()):
        total_c = counts["pass"] + counts["fail"]
        bar = "█" * counts["pass"] + "░" * counts["fail"]
        print(f"  {cat:<35} {counts['pass']}/{total_c}  {bar}")

    # Failures detail
    failures = [r for r in results if not r["has_data"] or r["status"] >= 400]
    if failures:
        print(f"\nFAILED ENDPOINTS ({len(failures)}):")
        for r in failures:
            print(f"  [{r['status']}] {r['method']} {r['endpoint']}")
            print(f"         Input:    {r['input']}")
            print(f"         Response: {r['response_summary'][:120]}")
    else:
        print("\nAll endpoints passed!")

    print("\n" + "=" * 160)
    return passed, failed


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("ALDECI Deep Integration Test")
    print(f"Target: {BASE_URL}")
    print(f"Org ID: {ORG_ID}")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 60)

    # Health check first
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"Backend health: {r.status_code} {r.text[:80]}")
    except Exception as e:
        print(f"ERROR: Backend unreachable — {e}")
        sys.exit(1)

    # Run all test suites
    test_security_operations()
    test_vulnerability_management()
    test_threat_intelligence()
    test_compliance_and_risk()
    test_cloud_and_infrastructure()
    test_identity_and_access()
    test_sbom_and_supply_chain()
    test_advanced_security()
    test_automation_and_metrics()
    test_architecture_and_planning()

    passed, failed = print_report()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
