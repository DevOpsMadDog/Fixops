#!/usr/bin/env python3
"""
ALDECI Engine Write → Read → Verify Round-Trip Test
Tests 15 representative engines with real payloads against http://localhost:8000

Results are written to /tmp/e2e_engine_results.json (bypasses OMNI stdout compression)
and also printed in human-readable form.
"""

import time
import json
import sys
import os
import requests
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

BASE_URL = "http://localhost:8000"
API_KEY = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
ORG_ID = "e2e-test"
DELAY = 0.7
RESULTS_FILE = "/tmp/e2e_engine_results.json"
REPORT_FILE  = "/tmp/e2e_engine_report.txt"

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class EngineResult:
    name: str
    write_url: str
    write_payload: Dict[str, Any]
    read_url: str = ""
    write_status: int = 0
    write_body: Any = None
    read_status: int = 0
    read_body: Any = None
    verify_fields: List[str] = field(default_factory=list)
    match: Optional[bool] = None
    mismatch_details: List[str] = field(default_factory=list)
    error: str = ""


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def http_post(url: str, payload: Dict[str, Any], params: Dict = None) -> Tuple[int, Any]:
    try:
        r = requests.post(
            f"{BASE_URL}{url}", json=payload, headers=HEADERS,
            params=params or {}, timeout=10,
        )
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def http_get(url: str, params: Dict = None) -> Tuple[int, Any]:
    try:
        r = requests.get(
            f"{BASE_URL}{url}", headers=HEADERS,
            params=params or {}, timeout=10,
        )
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


# ---------------------------------------------------------------------------
# Field verification
# ---------------------------------------------------------------------------

def check_fields(expected: Dict, response: Any, fields: List[str]) -> Tuple[bool, List[str]]:
    """Verify that all expected fields appear with correct values in response.

    Handles:
    - Direct dict response
    - List response (uses first element)
    - Wrapper dicts like {"assessment": {...}}
    - Nested lists (e.g. {"recent_events": [{...}]}) — searches first element
    """
    mismatches = []
    data = response

    # Unwrap top-level list → first element
    if isinstance(data, list):
        data = data[0] if data else {}

    # Unwrap single-key wrapper dicts or find nested dict containing our fields
    if isinstance(data, dict):
        # First check if fields exist at top level
        if not any(f in data for f in fields):
            # Try direct sub-dicts
            for key, val in data.items():
                if isinstance(val, dict) and any(f in val for f in fields):
                    data = val
                    break
                # Try first element of list sub-values (e.g. recent_events)
                elif isinstance(val, list) and val and isinstance(val[0], dict):
                    if any(f in val[0] for f in fields):
                        data = val[0]
                        break

    for f in fields:
        exp_val = expected.get(f)
        act_val = data.get(f) if isinstance(data, dict) else None

        if act_val is None:
            mismatches.append(f"'{f}' missing from response")
        elif exp_val is not None and act_val != exp_val:
            mismatches.append(f"'{f}': expected={exp_val!r} got={act_val!r}")

    return len(mismatches) == 0, mismatches


# ---------------------------------------------------------------------------
# ID extraction helper
# ---------------------------------------------------------------------------

ID_KEYS = (
    "id", "assessment_id", "indicator_id", "detection_id", "mention_id",
    "asset_id", "alert_id", "incident_id", "risk_id", "cluster_id",
    "account_id", "identity_id", "report_id", "event_id", "review_id",
)

def extract_id(body: Any) -> Optional[str]:
    if not isinstance(body, dict):
        return None
    for k in ID_KEYS:
        if k in body:
            return str(body[k])
    return None


# ---------------------------------------------------------------------------
# Test case definitions
# ---------------------------------------------------------------------------

# (name, write_url, payload, verify_fields, org_in_query, read_list_url)
TEST_SPECS = [
    (
        "Privacy Impact Assessment",
        "/api/v1/privacy-impact/assessments",
        {
            "project_name": "GDPR E2E Assessment",
            "assessment_type": "dpia",
            "data_controller": "ALDECI Corp",
            "data_categories": ["PII", "financial"],
            "data_subjects": ["employees", "customers"],
        },
        ["project_name", "assessment_type"],
        True,   # org_id in query
        "/api/v1/privacy-impact/assessments",
    ),
    (
        "Threat Indicators",
        "/api/v1/threat-indicators/indicators",
        {
            "indicator_value": "192.168.1.100",
            "indicator_type": "ip",
            "confidence": 0.85,
            "source": "bandit-scan",
            "severity": "high",
        },
        ["indicator_value", "indicator_type"],
        True,
        "/api/v1/threat-indicators/indicators",
    ),
    (
        "Ransomware Protection",
        "/api/v1/ransomware-protection/detections",
        {
            "org_id": ORG_ID,
            "detection_name": "E2E Encryption Behavior",
            "detection_type": "behavioral",
            "affected_systems": ["server-01"],
            "severity": "critical",
            "confidence": 0.9,
        },
        ["detection_name", "detection_type"],
        False,  # org_id in body
        "/api/v1/ransomware-protection/detections",
    ),
    (
        "Dark Web Monitoring",
        "/api/v1/dark-web/mentions",
        {
            "mention_type": "credential_leak",
            "source_category": "forum",
            "keyword_matched": "aldeci.io",
            "severity": "high",
            "content_preview": "credentials found for aldeci.io",
        },
        ["keyword_matched", "severity"],
        True,
        "/api/v1/dark-web/mentions",
    ),
    (
        "Quantum Safe Crypto",
        "/api/v1/quantum-crypto/assets",
        {
            "org_id": ORG_ID,
            "asset_name": "TLS Certificate RSA-2048",
            "asset_type": "tls_certificate",
            "current_algorithm": "rsa",
            "key_size": 2048,
            "risk_level": "high",
            "discovered_at": "2026-04-16T00:00:00Z",
        },
        ["asset_name", "current_algorithm", "key_size"],
        False,
        "/api/v1/quantum-crypto/assets",
    ),
    (
        "AI-Powered SOC",
        "/api/v1/ai-soc/detections",
        {
            "detection_name": "E2E Anomaly Detection",
            "model_type": "anomaly_detection",
            "confidence_score": 92.0,
            "severity": "high",
            "source_data_type": "logs",
        },
        ["detection_name", "model_type"],
        True,
        "/api/v1/ai-soc/detections",
    ),
    (
        "Alert Triage",
        "/api/v1/alert-triage/alerts",
        {
            "title": "Suspicious login from Russia",
            "source_system": "siem",
            "severity": "high",
        },
        ["title", "severity"],
        True,
        "/api/v1/alert-triage/alerts",
    ),
    (
        "Incident Orchestration",
        "/api/v1/incident-orchestration/incidents",
        {
            "title": "Data breach investigation",
            "severity": "critical",
            "status": "open",
        },
        ["title", "severity"],
        True,
        "/api/v1/incident-orchestration/incidents",
    ),
    (
        "Risk Register",
        "/api/v1/risks",
        {
            "title": "Third-party data exposure",
            "category": "operational",
            "likelihood": 4,
            "impact": 5,
            "org_id": ORG_ID,
        },
        ["title", "likelihood", "impact"],
        False,
        "/api/v1/risks",
    ),
    (
        "Kubernetes Security",
        "/api/v1/kubernetes-security/clusters",
        {
            "cluster_name": "prod-us-east",
            "provider": "eks",
            "k8s_version": "1.28",
            "node_count": 10,
        },
        ["cluster_name", "provider", "k8s_version"],
        True,
        "/api/v1/kubernetes-security/clusters",
    ),
    (
        "Cloud Posture",
        "/api/v1/cloud-posture/accounts",
        {
            "org_id": ORG_ID,
            "account_id": "aws-prod-e2e-001",
            "account_name": "AWS Production",
            "provider": "aws",
            "region": "us-east-1",
        },
        ["account_name", "provider"],
        False,
        "/api/v1/cloud-posture/accounts",
    ),
    (
        "Identity Risk",
        "/api/v1/identity-risk/identities",
        {
            "username": "admin@aldeci.io",
            "email": "admin@aldeci.io",
            "identity_type": "human",
            "risk_score": 0.85,
            "mfa_enabled": False,
            "status": "active",
        },
        ["username", "email"],
        True,
        "/api/v1/identity-risk/identities",
    ),
    (
        "Cyber Threat Intelligence",
        "/api/v1/cyber-threat-intel/reports",
        {
            "title": "APT29 Campaign Analysis",
            "intel_type": "strategic",
            "tlp": "amber",
            "confidence_score": 0.88,
            "summary": "APT29 targeting critical infrastructure",
        },
        ["title", "tlp", "confidence_score"],
        True,
        "/api/v1/cyber-threat-intel/reports",
    ),
    (
        # Write: POST /events to record an access event
        # Read:  GET /users/{username}/profile — returns username + recent events
        # Verify: username present in profile response
        "Access Anomaly",
        "/api/v1/access-anomaly/events",
        {
            "org_id": ORG_ID,
            "username": "user-42",
            "source_ip": "10.0.0.42",
            "country": "RU",
            "city": "Moscow",
            "resource": "/api/v1/admin",
            "action": "login",
            "success": 1,
        },
        ["username", "source_ip"],
        False,
        "/api/v1/access-anomaly/users/user-42/profile",
    ),
    (
        "Architecture Review",
        "/api/v1/arch-review/reviews",
        {
            "review_name": "Microservices Migration Review",
            "system_name": "ALDECI Core",
            "review_type": "full",
            "reviewer": "e2e-tester",
        },
        ["review_name", "system_name"],
        True,
        "/api/v1/arch-review/reviews",
    ),
]


# ---------------------------------------------------------------------------
# Run single engine test
# ---------------------------------------------------------------------------

def run_engine(name, write_url, payload, verify_fields, org_in_query, read_list_url) -> EngineResult:
    tc = EngineResult(
        name=name,
        write_url=write_url,
        write_payload=payload,
        verify_fields=verify_fields,
    )

    write_params = {"org_id": ORG_ID} if org_in_query else {}
    tc.write_status, tc.write_body = http_post(write_url, payload, params=write_params)
    time.sleep(DELAY)

    # Try single-record read using returned ID
    created_id = extract_id(tc.write_body)
    read_params = {"org_id": ORG_ID}

    if created_id:
        single_url = f"{read_list_url}/{created_id}"
        s, b = http_get(single_url, params=read_params)
        if s == 200:
            tc.read_status, tc.read_body = s, b
            tc.read_url = f"GET {single_url}?org_id={ORG_ID}"
        else:
            tc.read_status, tc.read_body = http_get(read_list_url, params=read_params)
            tc.read_url = f"GET {read_list_url}?org_id={ORG_ID}"
    else:
        tc.read_status, tc.read_body = http_get(read_list_url, params=read_params)
        tc.read_url = f"GET {read_list_url}?org_id={ORG_ID}"

    # Verify
    if tc.write_status in (200, 201) and tc.read_status == 200:
        ok, mismatches = check_fields(payload, tc.read_body, verify_fields)
        tc.match = ok
        tc.mismatch_details = mismatches
    else:
        tc.match = None
        tc.mismatch_details = [
            f"write_status={tc.write_status}",
            f"read_status={tc.read_status}",
        ]

    return tc


# ---------------------------------------------------------------------------
# Report generation (written to file, not stdout)
# ---------------------------------------------------------------------------

def truncate(obj: Any, max_len: int = 400) -> str:
    s = json.dumps(obj, default=str)
    return s[:max_len] + " ..." if len(s) > max_len else s


def generate_report(results: List[EngineResult]) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("ALDECI ENGINE WRITE → READ → VERIFY REPORT")
    lines.append(f"Backend: {BASE_URL}  |  Org: {ORG_ID}")
    lines.append("=" * 70)

    for tc in results:
        lines.append("")
        lines.append(f"Engine: {tc.name}")
        lines.append(f"  WRITE: POST {tc.write_url}")
        lines.append(f"         Payload : {truncate(tc.write_payload)}")
        lines.append(f"         Response: {tc.write_status} {truncate(tc.write_body)}")
        lines.append(f"  READ:  {tc.read_url}")
        lines.append(f"         Response: {tc.read_status} {truncate(tc.read_body)}")
        if tc.match is True:
            lines.append(f"  VERIFY: MATCH  (checked: {', '.join(tc.verify_fields)})")
        elif tc.match is False:
            lines.append(f"  VERIFY: MISMATCH")
            for m in tc.mismatch_details:
                lines.append(f"          - {m}")
        else:
            lines.append(f"  VERIFY: SKIPPED (write or read failed)")
            for m in tc.mismatch_details:
                lines.append(f"          - {m}")

    # Summary table
    lines.append("")
    lines.append("=" * 70)
    lines.append("SUMMARY TABLE")
    lines.append("=" * 70)
    lines.append(f"{'Engine':<35} {'WRITE':>7} {'READ':>7} {'VERIFY':>10}")
    lines.append(f"{'-'*35} {'-'*7} {'-'*7} {'-'*10}")

    passed = failed = skipped = 0
    for tc in results:
        w = "OK" if tc.write_status in (200, 201) else f"ERR({tc.write_status})"
        r = "OK" if tc.read_status == 200 else f"ERR({tc.read_status})"
        if tc.match is True:
            v = "MATCH"; passed += 1
        elif tc.match is False:
            v = "MISMATCH"; failed += 1
        else:
            v = "SKIPPED"; skipped += 1
        lines.append(f"{tc.name:<35} {w:>7} {r:>7} {v:>10}")

    lines.append("-" * 70)
    lines.append(f"Results: {passed} MATCH  |  {failed} MISMATCH  |  {skipped} SKIPPED")
    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # Connectivity check
    try:
        r = requests.get(
            f"{BASE_URL}/api/v1/privacy-impact/assessments",
            headers=HEADERS, params={"org_id": ORG_ID}, timeout=5,
        )
        sys.stderr.write(f"Backend reachable: HTTP {r.status_code}\n")
    except Exception as e:
        sys.stderr.write(f"ERROR: Cannot reach {BASE_URL}: {e}\n")
        return 1

    results: List[EngineResult] = []

    for i, spec in enumerate(TEST_SPECS, 1):
        name = spec[0]
        sys.stderr.write(f"[{i:02d}/15] {name}... ")
        sys.stderr.flush()
        tc = run_engine(*spec)
        results.append(tc)
        icon = "MATCH" if tc.match is True else ("MISMATCH" if tc.match is False else "SKIPPED")
        sys.stderr.write(f"{icon}\n")
        sys.stderr.flush()
        time.sleep(DELAY)

    # Save full JSON to file
    json_data = []
    for tc in results:
        json_data.append({
            "name": tc.name,
            "write_url": f"POST {tc.write_url}",
            "write_payload": tc.write_payload,
            "write_status": tc.write_status,
            "write_body": tc.write_body,
            "read_url": tc.read_url,
            "read_status": tc.read_status,
            "read_body": tc.read_body,
            "verify_fields": tc.verify_fields,
            "match": tc.match,
            "mismatch_details": tc.mismatch_details,
        })

    with open(RESULTS_FILE, "w") as f:
        json.dump(json_data, f, indent=2, default=str)

    # Save human-readable report
    report = generate_report(results)
    with open(REPORT_FILE, "w") as f:
        f.write(report)

    sys.stderr.write(f"\nJSON results -> {RESULTS_FILE}\n")
    sys.stderr.write(f"Report       -> {REPORT_FILE}\n")

    any_failed = any(r.match is not True for r in results)
    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main())
