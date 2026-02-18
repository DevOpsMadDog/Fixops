#!/usr/bin/env python3
"""Seed real vulnerability data into ALdeci Knowledge Brain + train ML models.

Usage:
    PYTHONPATH=. python scripts/seed_real_data.py

Seeds:
  - 20 real CVEs (from NVD 2024-2025 high-profile vulnerabilities)
  - 15 findings linked to CVEs
  - 8 assets (services, repos, containers)
  - 3 scans linking findings
  - Trains all 4 ML models on existing API traffic
"""
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Real CVE data (high-profile 2024-2025 vulnerabilities) ──────────────────
CVES = [
    {
        "cve_id": "CVE-2024-3094",
        "severity": "critical",
        "cvss": 10.0,
        "title": "XZ Utils Backdoor",
        "package": "xz-utils",
        "epss": 0.97,
    },
    {
        "cve_id": "CVE-2024-4577",
        "severity": "critical",
        "cvss": 9.8,
        "title": "PHP CGI Argument Injection",
        "package": "php",
        "epss": 0.95,
    },
    {
        "cve_id": "CVE-2024-21762",
        "severity": "critical",
        "cvss": 9.6,
        "title": "Fortinet FortiOS RCE",
        "package": "fortios",
        "epss": 0.93,
    },
    {
        "cve_id": "CVE-2024-24576",
        "severity": "critical",
        "cvss": 10.0,
        "title": "Rust Command Injection on Windows",
        "package": "rust-std",
        "epss": 0.42,
    },
    {
        "cve_id": "CVE-2024-6387",
        "severity": "high",
        "cvss": 8.1,
        "title": "regreSSHion - OpenSSH Race Condition",
        "package": "openssh",
        "epss": 0.87,
    },
    {
        "cve_id": "CVE-2024-38077",
        "severity": "critical",
        "cvss": 9.8,
        "title": "Windows RRAS RCE",
        "package": "windows-rras",
        "epss": 0.45,
    },
    {
        "cve_id": "CVE-2024-47575",
        "severity": "critical",
        "cvss": 9.8,
        "title": "FortiManager Missing Auth",
        "package": "fortimanager",
        "epss": 0.91,
    },
    {
        "cve_id": "CVE-2024-0012",
        "severity": "critical",
        "cvss": 9.3,
        "title": "PAN-OS Auth Bypass",
        "package": "pan-os",
        "epss": 0.89,
    },
    {
        "cve_id": "CVE-2024-21887",
        "severity": "critical",
        "cvss": 9.1,
        "title": "Ivanti Connect Secure Command Injection",
        "package": "ivanti-cs",
        "epss": 0.94,
    },
    {
        "cve_id": "CVE-2024-23897",
        "severity": "critical",
        "cvss": 9.8,
        "title": "Jenkins CLI Arbitrary File Read",
        "package": "jenkins",
        "epss": 0.88,
    },
    {
        "cve_id": "CVE-2025-0282",
        "severity": "critical",
        "cvss": 9.0,
        "title": "Ivanti Connect Secure Stack Overflow",
        "package": "ivanti-cs",
        "epss": 0.91,
    },
    {
        "cve_id": "CVE-2024-1709",
        "severity": "critical",
        "cvss": 10.0,
        "title": "ScreenConnect Auth Bypass",
        "package": "screenconnect",
        "epss": 0.96,
    },
    {
        "cve_id": "CVE-2024-27198",
        "severity": "critical",
        "cvss": 9.8,
        "title": "TeamCity Auth Bypass",
        "package": "teamcity",
        "epss": 0.90,
    },
    {
        "cve_id": "CVE-2024-20353",
        "severity": "high",
        "cvss": 8.6,
        "title": "Cisco ASA WebVPN DoS",
        "package": "cisco-asa",
        "epss": 0.72,
    },
    {
        "cve_id": "CVE-2024-29824",
        "severity": "critical",
        "cvss": 9.6,
        "title": "Ivanti EPM SQL Injection",
        "package": "ivanti-epm",
        "epss": 0.85,
    },
    {
        "cve_id": "CVE-2024-36401",
        "severity": "critical",
        "cvss": 9.8,
        "title": "GeoServer RCE via OGC filter eval",
        "package": "geoserver",
        "epss": 0.82,
    },
    {
        "cve_id": "CVE-2024-28986",
        "severity": "critical",
        "cvss": 9.8,
        "title": "SolarWinds Web Help Desk Java Deserialization",
        "package": "solarwinds-whd",
        "epss": 0.76,
    },
    {
        "cve_id": "CVE-2024-5806",
        "severity": "critical",
        "cvss": 9.1,
        "title": "MOVEit Transfer Auth Bypass",
        "package": "moveit",
        "epss": 0.83,
    },
    {
        "cve_id": "CVE-2024-40711",
        "severity": "critical",
        "cvss": 9.8,
        "title": "Veeam Backup & Replication RCE",
        "package": "veeam-br",
        "epss": 0.79,
    },
    {
        "cve_id": "CVE-2024-50623",
        "severity": "critical",
        "cvss": 9.8,
        "title": "Cleo File Transfer RCE",
        "package": "cleo-vltrader",
        "epss": 0.86,
    },
]

ASSETS = [
    {
        "asset_id": "web-api-gateway",
        "name": "API Gateway",
        "type": "service",
        "environment": "production",
        "criticality": "critical",
    },
    {
        "asset_id": "auth-service",
        "name": "Auth Microservice",
        "type": "service",
        "environment": "production",
        "criticality": "critical",
    },
    {
        "asset_id": "payment-service",
        "name": "Payment Service",
        "type": "service",
        "environment": "production",
        "criticality": "critical",
    },
    {
        "asset_id": "frontend-app",
        "name": "React Frontend",
        "type": "application",
        "environment": "production",
        "criticality": "high",
    },
    {
        "asset_id": "postgres-main",
        "name": "PostgreSQL Primary",
        "type": "database",
        "environment": "production",
        "criticality": "critical",
    },
    {
        "asset_id": "redis-cache",
        "name": "Redis Cache Cluster",
        "type": "service",
        "environment": "production",
        "criticality": "medium",
    },
    {
        "asset_id": "k8s-cluster-prod",
        "name": "Kubernetes Production",
        "type": "container",
        "environment": "production",
        "criticality": "critical",
    },
    {
        "asset_id": "ci-cd-pipeline",
        "name": "Jenkins CI/CD",
        "type": "pipeline",
        "environment": "staging",
        "criticality": "high",
    },
]


def main():
    from core.api_learning_store import TrafficRecord, get_learning_store
    from core.knowledge_brain import EdgeType, GraphEdge, get_brain

    brain = get_brain()
    store = get_learning_store()
    now = datetime.now(timezone.utc)

    # ── 1. Seed Assets ────────────────────────────────────────────────────
    print("🏗️  Seeding 8 assets...")
    for a in ASSETS:
        aid = a.pop("asset_id")
        brain.ingest_asset(aid, org_id="aldeci-demo", **a)
    print(f"   ✅ {len(ASSETS)} assets ingested")

    # ── 2. Seed CVEs ──────────────────────────────────────────────────────
    print("🛡️  Seeding 20 real CVEs...")
    for c in CVES:
        cid = c.pop("cve_id")
        brain.ingest_cve(cid, org_id="aldeci-demo", **c)
    print(f"   ✅ {len(CVES)} CVEs ingested")

    # ── 3. Seed Findings linked to CVEs and Assets ────────────────────────
    print("🔍 Seeding 15 findings...")
    severities = ["critical", "high", "high", "medium", "medium", "low"]
    finding_ids = []
    for i, cve in enumerate(CVES[:15]):
        fid = f"FIND-2024-{1000+i}"
        finding_ids.append(fid)
        sev = cve.get("severity", random.choice(severities))
        brain.ingest_finding(
            fid,
            org_id="aldeci-demo",
            cve_id=cve.get("cve_id", f"CVE-2024-{i}"),
            title=cve.get("title", f"Finding {i}"),
            severity=sev,
            status=random.choice(["open", "open", "open", "in_progress", "resolved"]),
            first_seen=(now - timedelta(days=random.randint(5, 90))).isoformat(),
            scanner=random.choice(["trivy", "semgrep", "snyk", "grype", "bandit"]),
        )
        # Link finding to random asset
        asset = random.choice(ASSETS)
        brain.add_edge(
            GraphEdge(
                source_id=f"finding:{fid}",
                target_id=f"asset:{asset.get('asset_id', asset.get('name', 'unknown'))}",
                edge_type=EdgeType.AFFECTS,
            )
        )
    print("   ✅ 15 findings ingested and linked")

    # ── 4. Seed Scans ────────────────────────────────────────────────────
    print("📡 Seeding 3 scans...")
    for i, scanner in enumerate(["trivy-weekly", "semgrep-ci", "snyk-monitor"]):
        scan_findings = finding_ids[i * 5 : (i + 1) * 5]
        brain.ingest_scan(
            scanner,
            org_id="aldeci-demo",
            findings=scan_findings,
            scanner=scanner.split("-")[0],
            completed_at=now.isoformat(),
        )
    print("   ✅ 3 scans ingested")

    # ── 5. Seed additional traffic data for ML ───────────────────────────
    print("📊 Seeding 500 additional traffic records for ML training...")
    paths = [
        "/api/v1/vulns",
        "/api/v1/health",
        "/api/v1/brain/nodes",
        "/api/v1/feeds/nvd",
        "/api/v1/ml/status",
        "/api/v1/evidence/",
        "/api/v1/nerve-center/pulse",
        "/api/v1/copilot/sessions",
        "/api/v1/attack-sim/simulations",
        "/api/v1/integrations/",
    ]
    methods = ["GET", "GET", "GET", "GET", "POST"]
    for j in range(500):
        ts = time.time() - random.uniform(0, 86400 * 7)  # last 7 days
        path = random.choice(paths)
        method = random.choice(methods)
        status = random.choices(
            [200, 200, 200, 201, 400, 401, 404, 500],
            weights=[50, 25, 15, 5, 2, 1, 1, 1],
        )[0]
        store.record(
            TrafficRecord(
                method=method,
                path=path,
                status_code=status,
                duration_ms=random.uniform(5, 800),
                request_size=random.randint(50, 5000),
                response_size=random.randint(100, 50000),
                client_ip=f"192.168.1.{random.randint(1, 254)}",
                user_agent="ALdeci-UI/2.0",
                timestamp=ts,
            )
        )
    store.flush()
    print("   ✅ 500 traffic records added")

    # ── 6. Train ML Models ───────────────────────────────────────────────
    print("🧠 Training all 4 ML models...")
    results = store.train_all_models()
    for name, info in results.items():
        print(
            f"   {name}: status={info.status.value}, samples={info.samples_trained}, accuracy={info.accuracy:.4f}"
        )
    print("   ✅ All models trained")

    # ── 7. Summary ───────────────────────────────────────────────────────
    stats = store.get_stats()
    print("\n📈 Final Stats:")
    print(f"   Brain: {brain.node_count()} nodes, {brain.edge_count()} edges")
    print(f"   Traffic: {stats.get('total_requests', '?')} records")
    print(f"   ML Models: {len(results)} trained")
    print("✅ Seed complete!")


if __name__ == "__main__":
    main()
