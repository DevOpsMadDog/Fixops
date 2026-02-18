#!/usr/bin/env python3
"""Seed real vulnerability data into ALdeci via the RUNNING API server.

Usage:  python scripts/seed_via_api.py
"""

import requests

BASE = "http://localhost:8000"
HEADERS = {"X-API-Key": "test-token-123", "Content-Type": "application/json"}


def post(path, data):
    r = requests.post(f"{BASE}{path}", json=data, headers=HEADERS, timeout=10)
    return (
        r.status_code,
        r.json()
        if r.headers.get("content-type", "").startswith("application/json")
        else r.text,
    )


def main():
    # ── 1. Seed CVEs ──
    cves = [
        ("CVE-2024-3094", "XZ Utils Backdoor", "critical", 10.0),
        ("CVE-2024-4577", "PHP CGI Argument Injection", "critical", 9.8),
        ("CVE-2024-6387", "regreSSHion OpenSSH Race Condition", "high", 8.1),
        ("CVE-2024-21762", "Fortinet FortiOS RCE", "critical", 9.6),
        ("CVE-2024-24576", "Rust Command Injection on Windows", "critical", 10.0),
        ("CVE-2024-47575", "FortiManager Missing Auth", "critical", 9.8),
        ("CVE-2024-0012", "PAN-OS Auth Bypass", "critical", 9.3),
        ("CVE-2024-21887", "Ivanti Connect Secure Command Injection", "critical", 9.1),
        ("CVE-2024-23897", "Jenkins CLI Arbitrary File Read", "critical", 9.8),
        ("CVE-2025-0282", "Ivanti Connect Secure Stack Overflow", "critical", 9.0),
        ("CVE-2024-1709", "ScreenConnect Auth Bypass", "critical", 10.0),
        ("CVE-2024-27198", "TeamCity Auth Bypass", "critical", 9.8),
        ("CVE-2024-29824", "Ivanti EPM SQL Injection", "critical", 9.6),
        ("CVE-2024-36401", "GeoServer RCE via OGC filter", "critical", 9.8),
        ("CVE-2024-40711", "Veeam Backup RCE", "critical", 9.8),
    ]
    print("🛡️  Seeding 15 CVEs...")
    for cve_id, title, severity, cvss in cves:
        code, resp = post(
            "/api/v1/brain/ingest/cve",
            {"cve_id": cve_id, "title": title, "severity": severity, "cvss": cvss},
        )
        nid = resp.get("node_id", "?") if isinstance(resp, dict) else "?"
        print(f"  [{code}] {nid}")

    # ── 2. Seed Findings ──
    print("\n🔍 Seeding 10 findings...")
    scanners = ["trivy", "semgrep", "snyk", "grype", "bandit"]
    for i in range(10):
        cve_id = cves[i][0]
        code, resp = post(
            "/api/v1/brain/ingest/finding",
            {
                "finding_id": f"FIND-2024-{1001+i}",
                "title": f"Vuln in component-{i+1} ({cves[i][1]})",
                "severity": cves[i][2],
                "status": "open",
                "scanner": scanners[i % len(scanners)],
                "cve_id": cve_id,
            },
        )
        nid = resp.get("node_id", "?") if isinstance(resp, dict) else "?"
        print(f"  [{code}] {nid}")

    # ── 3. Seed Assets ──
    print("\n🏗️  Seeding 5 assets...")
    assets = [
        ("web-api-gateway", "API Gateway", "service"),
        ("auth-service", "Auth Microservice", "service"),
        ("payment-svc", "Payment Service", "service"),
        ("postgres-main", "PostgreSQL Primary", "database"),
        ("k8s-prod", "Kubernetes Production", "container"),
    ]
    for asset_id, name, atype in assets:
        code, resp = post(
            "/api/v1/brain/ingest/asset",
            {
                "asset_id": asset_id,
                "name": name,
                "type": atype,
                "environment": "production",
            },
        )
        nid = resp.get("node_id", "?") if isinstance(resp, dict) else "?"
        print(f"  [{code}] {nid}")

    # ── 4. Train all 4 ML models ──
    print("\n🧠 Training all ML models...")
    code, resp = post("/api/v1/ml/train", {})
    if isinstance(resp, dict):
        for name, info in resp.items():
            st = info.get("status", "?")
            acc = info.get("accuracy", 0)
            samp = info.get("samples_trained", 0)
            print(f"  {name}: status={st}, accuracy={acc:.4f}, samples={samp}")
    else:
        print(f"  [{code}] {resp}")

    # ── 5. Verify brain state ──
    print("\n📈 Verifying brain state...")
    r = requests.get(f"{BASE}/api/v1/brain/nodes", headers=HEADERS, timeout=10)
    nodes = r.json().get("nodes", [])
    from collections import Counter

    types = Counter(n["node_type"] for n in nodes)
    print(f"  Total nodes: {len(nodes)}")
    for t, c in types.most_common():
        print(f"    {t}: {c}")

    # ── 6. Verify ML models ──
    print("\n🤖 Verifying ML models...")
    r = requests.get(f"{BASE}/api/v1/ml/models", headers=HEADERS, timeout=10)
    for m in r.json().get("models", []):
        print(
            f"  {m['model_id']}: status={m['status']}, accuracy={m['accuracy']}, samples={m['predictions_count']}"
        )

    print("\n✅ Seed complete!")


if __name__ == "__main__":
    main()
