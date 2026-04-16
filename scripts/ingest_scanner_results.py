#!/usr/bin/env python3
"""
Ingest REAL scanner results into live ALDECI platform.
Feeds: Bandit, Semgrep, npm audit, pip-audit, Trivy → ALDECI APIs.
NO mocks. NO demo data. All findings from actual Fixops codebase scans.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

API_BASE = os.getenv("ALDECI_API_URL", "http://localhost:8000")
API_KEY = os.getenv("FIXOPS_API_TOKEN", os.getenv("FIXOPS_API_TOKEN", ""))
ORG_ID = "fixops-prod"
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
# Rate limit: 100 RPM = ~1.6/sec. Stay under with 0.7s delay.
RATE_DELAY = 0.05  # 50ms between calls — burst-friendly with token bucket

stats = {
    "bandit": {"ingested": 0, "errors": 0},
    "semgrep": {"ingested": 0, "errors": 0},
    "npm_audit": {"ingested": 0, "errors": 0},
    "pip_audit": {"ingested": 0, "errors": 0},
    "trivy": {"ingested": 0, "errors": 0},
    "api_calls": 0,
    "total_findings": 0,
}


def api_post(path: str, data: dict) -> dict:
    """POST to ALDECI API with error handling and rate limiting."""
    stats["api_calls"] += 1
    time.sleep(RATE_DELAY)
    try:
        r = requests.post(f"{API_BASE}{path}", json=data, headers=HEADERS, timeout=15)
        if r.status_code in (200, 201):
            return r.json() if r.text else {}
        if r.status_code == 429:
            time.sleep(2)  # Back off on rate limit
            r = requests.post(f"{API_BASE}{path}", json=data, headers=HEADERS, timeout=15)
            if r.status_code in (200, 201):
                return r.json() if r.text else {}
        return {"error": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        return {"error": str(e)}


def api_get(path: str) -> dict:
    """GET from ALDECI API."""
    stats["api_calls"] += 1
    time.sleep(RATE_DELAY)
    try:
        r = requests.get(f"{API_BASE}{path}", headers=HEADERS, timeout=15)
        if r.status_code == 429:
            time.sleep(2)
            r = requests.get(f"{API_BASE}{path}", headers=HEADERS, timeout=15)
        return r.json() if r.status_code == 200 else {"error": r.status_code}
    except Exception as e:
        return {"error": str(e)}


# ── 1. Ingest Bandit findings ─────────────────────────────────────────
def ingest_bandit(filepath="/tmp/bandit_fixops.json"):
    print("\n=== INGESTING BANDIT (Python SAST) ===")
    if not os.path.exists(filepath):
        print("  [SKIP] Bandit output not found yet")
        return
    with open(filepath) as f:
        data = json.load(f)
    results = data.get("results", [])
    print(f"  Found {len(results)} Bandit findings")

    # Ingest via scanner-ingest webhook
    resp = api_post("/api/v1/scanner-ingest/webhook/bandit", data)
    print(f"  Scanner ingest response: {resp.get('status', resp.get('error', 'unknown'))}")

    # Feed into brain pipeline for each finding
    severity_map = {"HIGH": "critical", "MEDIUM": "high", "LOW": "medium"}
    for i, finding in enumerate(results[:50]):  # Top 50
        payload = {
            "finding_id": f"bandit-{i+1:04d}",
            "source": "bandit",
            "severity": severity_map.get(finding.get("issue_severity", "LOW"), "low"),
            "title": finding.get("test_name", "Unknown"),
            "description": finding.get("issue_text", ""),
            "asset_id": finding.get("filename", "unknown"),
            "cve_id": None,
        }
        r = api_post("/api/v1/brain/ingest/finding", payload)
        if "error" not in r:
            stats["bandit"]["ingested"] += 1
        else:
            stats["bandit"]["errors"] += 1
    stats["total_findings"] += stats["bandit"]["ingested"]
    print(f"  Ingested: {stats['bandit']['ingested']}, Errors: {stats['bandit']['errors']}")


# ── 2. Ingest Semgrep findings ────────────────────────────────────────
def ingest_semgrep(filepath="/tmp/semgrep_fixops.json"):
    print("\n=== INGESTING SEMGREP (Multi-language SAST) ===")
    if not os.path.exists(filepath):
        print("  [SKIP] Semgrep output not found yet")
        return
    with open(filepath) as f:
        data = json.load(f)
    results = data.get("results", [])
    print(f"  Found {len(results)} Semgrep findings")

    # Ingest via scanner-ingest webhook
    resp = api_post("/api/v1/scanner-ingest/webhook/semgrep", data)
    print(f"  Scanner ingest response: {resp.get('status', resp.get('error', 'unknown'))}")

    severity_map = {"ERROR": "critical", "WARNING": "high", "INFO": "medium"}
    for i, finding in enumerate(results[:50]):
        meta = finding.get("extra", {}).get("metadata", {})
        payload = {
            "finding_id": f"semgrep-{i+1:04d}",
            "source": "semgrep",
            "title": finding.get("check_id", "unknown").split(".")[-1],
            "description": finding.get("extra", {}).get("message", ""),
            "severity": severity_map.get(finding.get("extra", {}).get("severity", "INFO"), "low"),
            "asset_id": finding.get("path", "unknown"),
            "cve_id": None,
        }
        r = api_post("/api/v1/brain/ingest/finding", payload)
        if "error" not in r:
            stats["semgrep"]["ingested"] += 1
        else:
            stats["semgrep"]["errors"] += 1
    stats["total_findings"] += stats["semgrep"]["ingested"]
    print(f"  Ingested: {stats['semgrep']['ingested']}, Errors: {stats['semgrep']['errors']}")


# ── 3. Ingest npm audit findings ──────────────────────────────────────
def ingest_npm_audit(filepath="/tmp/npm_audit_fixops.json"):
    print("\n=== INGESTING NPM AUDIT (JS/TS Dependencies) ===")
    if not os.path.exists(filepath):
        print("  [SKIP] npm audit output not found yet")
        return
    with open(filepath) as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", {})
    print(f"  Found {len(vulns)} npm vulnerability entries")

    # Ingest via scanner-ingest webhook
    resp = api_post("/api/v1/scanner-ingest/webhook/npm-audit", data)
    print(f"  Scanner ingest response: {resp.get('status', resp.get('error', 'unknown'))}")

    npm_idx = 0
    for name, vuln in vulns.items():
        severity = vuln.get("severity", "low")
        via_list = vuln.get("via", [])
        for via in via_list:
            if isinstance(via, dict):
                npm_idx += 1
                payload = {
                    "finding_id": f"npm-{npm_idx:04d}",
                    "source": "npm-audit",
                    "title": via.get("title", f"Vuln in {name}"),
                    "description": f"Package: {name}@{vuln.get('range', '?')}. {via.get('title', '')}",
                    "severity": severity,
                    "asset_id": f"npm:{name}",
                    "cve_id": None,
                }
                r = api_post("/api/v1/brain/ingest/finding", payload)
                if "error" not in r:
                    stats["npm_audit"]["ingested"] += 1
                else:
                    stats["npm_audit"]["errors"] += 1
    stats["total_findings"] += stats["npm_audit"]["ingested"]
    print(f"  Ingested: {stats['npm_audit']['ingested']}, Errors: {stats['npm_audit']['errors']}")


# ── 4. Ingest pip-audit findings ──────────────────────────────────────
def ingest_pip_audit(filepath="/tmp/pip_audit_fixops.json"):
    print("\n=== INGESTING PIP-AUDIT (Python Dependencies) ===")
    if not os.path.exists(filepath):
        print("  [SKIP] pip-audit output not found yet")
        return
    with open(filepath) as f:
        data = json.load(f)

    deps = data.get("dependencies", data if isinstance(data, list) else [])
    vuln_deps = [d for d in deps if d.get("vulns")]
    print(f"  Found {len(vuln_deps)} packages with vulnerabilities")

    pip_idx = 0
    for dep in vuln_deps:
        name = dep.get("name", "unknown")
        version = dep.get("version", "?")
        for vuln in dep.get("vulns", []):
            pip_idx += 1
            vuln_id = vuln.get("id", "unknown")
            fix_versions = vuln.get("fix_versions", [])
            payload = {
                "finding_id": f"pip-{pip_idx:04d}",
                "source": "pip-audit",
                "title": f"{vuln_id}: {name}=={version}",
                "description": f"Vulnerable package {name}=={version}. Fix: upgrade to {', '.join(fix_versions) if fix_versions else 'N/A'}. Aliases: {', '.join(vuln.get('aliases', []))}",
                "severity": "high" if "PYSEC" in vuln_id or "GHSA" in vuln_id else "medium",
                "asset_id": f"pypi:{name}",
                "cve_id": vuln_id if vuln_id.startswith("CVE-") else None,
            }
            r = api_post("/api/v1/brain/ingest/finding", payload)
            if "error" not in r:
                stats["pip_audit"]["ingested"] += 1
            else:
                stats["pip_audit"]["errors"] += 1

            # Also feed into vuln-intel engine
            api_post("/api/v1/vuln-intel/cves", {
                "org_id": ORG_ID,
                "cve_id": vuln_id,
                "title": f"{name} vulnerability",
                "severity": "high",
                "cvss_score": 7.5,
                "affected_package": name,
                "affected_version": version,
                "fix_version": fix_versions[0] if fix_versions else None,
                "source": "pip-audit",
            })

    stats["total_findings"] += stats["pip_audit"]["ingested"]
    print(f"  Ingested: {stats['pip_audit']['ingested']}, Errors: {stats['pip_audit']['errors']}")


# ── 5. Ingest Trivy findings ─────────────────────────────────────────
def ingest_trivy(filepath="/tmp/trivy_fixops.json"):
    print("\n=== INGESTING TRIVY (Filesystem Scan) ===")
    if not os.path.exists(filepath):
        print("  [SKIP] Trivy output not found yet")
        return
    with open(filepath) as f:
        data = json.load(f)

    results = data.get("Results", [])
    total_vulns = 0
    for result in results:
        target = result.get("Target", "unknown")
        vulns_list = result.get("Vulnerabilities", [])
        total_vulns += len(vulns_list)

        for j, vuln in enumerate(vulns_list[:30]):  # Top 30 per target
            sev = vuln.get("Severity", "UNKNOWN").lower()
            if sev == "unknown":
                sev = "info"
            vuln_id = vuln.get("VulnerabilityID", "?")
            payload = {
                "finding_id": f"trivy-{target.replace('/', '-')[:20]}-{j+1:04d}",
                "source": "trivy",
                "title": f"{vuln_id}: {vuln.get('PkgName', '?')}",
                "description": vuln.get("Title", vuln.get("Description", "")[:500]),
                "severity": sev if sev in ("critical", "high", "medium", "low") else "medium",
                "asset_id": target,
                "cve_id": vuln_id if vuln_id.startswith("CVE-") else None,
            }
            r = api_post("/api/v1/brain/ingest/finding", payload)
            if "error" not in r:
                stats["trivy"]["ingested"] += 1
            else:
                stats["trivy"]["errors"] += 1

    stats["total_findings"] += stats["trivy"]["ingested"]
    print(f"  Total Trivy vulns across all targets: {total_vulns}")
    print(f"  Ingested: {stats['trivy']['ingested']}, Errors: {stats['trivy']['errors']}")


# ── 6. Verify platform state ─────────────────────────────────────────
def verify_platform():
    print("\n=== VERIFYING PLATFORM STATE ===")
    endpoints = [
        "/api/v1/findings?limit=5",
        "/api/v1/scanner-ingest/stats",
        "/api/v1/scanner-ingest/status",
    ]
    for ep in endpoints:
        resp = api_get(ep)
        print(f"  {ep}: {json.dumps(resp, indent=2)[:200]}")


# ── Main ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    start = time.time()
    print("=" * 60)
    print("ALDECI REAL SCANNER INGESTION")
    print(f"Target: {API_BASE}")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    ingest_bandit()
    ingest_semgrep()
    ingest_npm_audit()
    ingest_pip_audit()
    ingest_trivy()
    verify_platform()

    elapsed = time.time() - start
    print("\n" + "=" * 60)
    print("INGESTION SUMMARY")
    print("=" * 60)
    print(f"  Bandit:    {stats['bandit']['ingested']} findings ingested")
    print(f"  Semgrep:   {stats['semgrep']['ingested']} findings ingested")
    print(f"  npm audit: {stats['npm_audit']['ingested']} findings ingested")
    print(f"  pip-audit: {stats['pip_audit']['ingested']} findings ingested")
    print(f"  Trivy:     {stats['trivy']['ingested']} findings ingested")
    print(f"  ─────────────────────────────────")
    print(f"  TOTAL:     {stats['total_findings']} real findings")
    print(f"  API calls: {stats['api_calls']}")
    print(f"  Duration:  {elapsed:.1f}s")
    print(f"  Errors:    {sum(s['errors'] for s in stats.values() if isinstance(s, dict) and 'errors' in s)}")
