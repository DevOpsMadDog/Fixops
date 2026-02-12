#!/usr/bin/env python3
"""Seed realistic data into all ALdeci data stores.

Seeds: Inventory (applications), Analytics (findings, decisions, metrics),
MPTE (requests, results, configs), Remediation (tasks), Provenance (attestations),
and Collaboration (notifications).
"""
import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# Ensure suite paths are importable
ROOT = Path(__file__).resolve().parent.parent
for p in ["suite-api", "suite-core", "suite-attack", "suite-feeds",
          "suite-evidence-risk", "suite-integrations",
          "archive/legacy", "archive/enterprise_legacy"]:
    sys.path.insert(0, str(ROOT / p))
os.chdir(ROOT)

NOW = datetime.utcnow()


def ts(days_ago: int = 0, hours_ago: int = 0) -> str:
    return (NOW - timedelta(days=days_ago, hours=hours_ago)).isoformat()


# ═══════════════════════════════════════════════════════════════════════════
# 1. Inventory — Applications
# ═══════════════════════════════════════════════════════════════════════════
def seed_inventory():
    from core.inventory_db import InventoryDB
    from core.inventory_models import Application, ApplicationCriticality, ApplicationStatus

    db = InventoryDB()
    apps_data = [
        ("Payment Gateway", "Core payment processing microservice handling Stripe/PayPal integrations",
         "critical", "active", "platform-team", "https://github.com/acme/payment-gw", "production",
         ["pci-dss", "financial", "tier-0"]),
        ("User Auth Service", "OAuth2/OIDC authentication and authorization service",
         "critical", "active", "security-team", "https://github.com/acme/auth-svc", "production",
         ["auth", "iam", "tier-0"]),
        ("API Gateway", "Kong-based API gateway with rate limiting and WAF",
         "high", "active", "platform-team", "https://github.com/acme/api-gateway", "production",
         ["networking", "waf", "tier-1"]),
        ("Notification Service", "Email/SMS/Push notification delivery system",
         "medium", "active", "comms-team", "https://github.com/acme/notifications", "production",
         ["messaging", "tier-2"]),
        ("Customer Portal", "React-based customer-facing web application",
         "high", "active", "frontend-team", "https://github.com/acme/customer-portal", "production",
         ["frontend", "customer-facing", "tier-1"]),
        ("Data Pipeline", "Apache Kafka + Flink real-time data processing pipeline",
         "high", "active", "data-team", "https://github.com/acme/data-pipeline", "production",
         ["data", "streaming", "tier-1"]),
        ("Admin Dashboard", "Internal admin dashboard for operations team",
         "medium", "active", "ops-team", "https://github.com/acme/admin-dash", "staging",
         ["internal", "admin", "tier-2"]),
        ("Legacy Billing", "Legacy monolithic billing system (migration in progress)",
         "high", "deprecated", "platform-team", "https://github.com/acme/billing-legacy", "production",
         ["legacy", "billing", "tier-1"]),
        ("ML Inference API", "TensorFlow Serving based ML model inference endpoint",
         "medium", "active", "ml-team", "https://github.com/acme/ml-inference", "production",
         ["ml", "ai", "tier-2"]),
        ("Secrets Vault", "HashiCorp Vault integration for secrets management",
         "critical", "active", "security-team", "https://github.com/acme/secrets-vault", "production",
         ["secrets", "vault", "tier-0"]),
    ]

    created = 0
    for i, (name, desc, crit, status, team, repo, env, tags) in enumerate(apps_data):
        app_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, name))
        existing = db.get_application(app_id)
        if existing:
            continue
        app = Application(
            id=app_id, name=name, description=desc,
            criticality=ApplicationCriticality(crit),
            status=ApplicationStatus(status),
            owner_team=team, repository_url=repo,
            environment=env, tags=tags, metadata={"tier": tags[-1]},
            created_at=NOW - timedelta(days=90 - i * 5),
            updated_at=NOW - timedelta(days=i),
        )
        db.create_application(app)
        created += 1
    print(f"  ✅ Inventory: {created} applications seeded")
    return [str(uuid.uuid5(uuid.NAMESPACE_DNS, a[0])) for a in apps_data]


# ═══════════════════════════════════════════════════════════════════════════
# 2. Analytics — Findings, Decisions, Metrics
# ═══════════════════════════════════════════════════════════════════════════
def seed_analytics(app_ids):
    from core.analytics_db import AnalyticsDB
    from core.analytics_models import (
        Decision, DecisionOutcome, Finding, FindingSeverity, FindingStatus, Metric,
    )

    db = AnalyticsDB()

    # Check if data exists
    existing = db.list_findings(limit=1)
    if existing:
        print(f"  ⏭️  Analytics: already has data ({len(db.list_findings(limit=10000))} findings)")
        return [f.id for f in db.list_findings(limit=50)]

    cves = [
        ("CVE-2024-21626", "critical", 9.8, 0.97, True, "runc container escape"),
        ("CVE-2024-3094", "critical", 10.0, 0.95, True, "xz-utils backdoor (supply chain)"),
        ("CVE-2024-4577", "critical", 9.8, 0.94, True, "PHP CGI argument injection"),
        ("CVE-2024-27198", "critical", 9.8, 0.91, True, "JetBrains TeamCity auth bypass"),
        ("CVE-2024-1709", "critical", 10.0, 0.89, True, "ScreenConnect auth bypass"),
        ("CVE-2023-44487", "high", 7.5, 0.82, True, "HTTP/2 Rapid Reset DDoS"),
        ("CVE-2024-23897", "high", 8.8, 0.78, True, "Jenkins CLI arbitrary file read"),
        ("CVE-2024-0204", "critical", 9.8, 0.75, True, "GoAnywhere MFT auth bypass"),
        ("CVE-2024-20353", "high", 8.6, 0.72, False, "Cisco ASA DoS"),
        ("CVE-2024-3400", "critical", 10.0, 0.96, True, "Palo Alto PAN-OS command injection"),
        ("CVE-2024-27983", "high", 7.5, 0.45, False, "Node.js HTTP/2 DoS"),
        ("CVE-2024-29269", "medium", 6.1, 0.35, False, "Telesquare TLR-2005Ksh RCE"),
        ("CVE-2024-28255", "medium", 5.3, 0.22, False, "OpenMetadata auth bypass"),
        ("CVE-2024-22243", "medium", 6.5, 0.18, False, "Spring Framework SSRF"),
        ("CVE-2024-22259", "low", 3.7, 0.08, False, "Spring URL parsing issue"),
        ("CVE-2024-22262", "low", 4.3, 0.06, False, "Spring UriComponentsBuilder vuln"),
        ("CVE-2024-31228", "medium", 5.5, 0.15, False, "Redis Stack overflow"),
        ("CVE-2024-31449", "high", 7.0, 0.55, True, "Redis Lua sandbox escape"),
        ("CVE-2023-50164", "critical", 9.8, 0.88, True, "Apache Struts path traversal RCE"),
        ("CVE-2024-0507", "medium", 6.3, 0.12, False, "GitHub Enterprise SSRF"),
    ]

    finding_ids = []
    statuses = [FindingStatus.OPEN] * 8 + [FindingStatus.IN_PROGRESS] * 4 + \
               [FindingStatus.RESOLVED] * 5 + [FindingStatus.FALSE_POSITIVE] * 2 + \
               [FindingStatus.ACCEPTED_RISK] * 1
    sources = ["sast", "dast", "sca", "container-scan", "secret-scan", "iac-scan",
               "api-scan", "dependency-check", "osv-scanner", "trivy"]

    for i, (cve, sev, cvss, epss, exploit, title) in enumerate(cves):
        fid = str(uuid.uuid5(uuid.NAMESPACE_DNS, cve))
        finding_ids.append(fid)
        status = statuses[i % len(statuses)]
        resolved_at = (NOW - timedelta(days=i % 5)) if status == FindingStatus.RESOLVED else None

        f = Finding(
            id=fid, application_id=app_ids[i % len(app_ids)],
            service_id=None, rule_id=f"RULE-{cve.split('-')[1]}-{cve.split('-')[2][:2]}",
            severity=FindingSeverity(sev), status=status,
            title=f"{cve}: {title}", description=f"Detected {title} in application scan. CVSS: {cvss}, EPSS: {epss}",
            source=sources[i % len(sources)], cve_id=cve,
            cvss_score=cvss, epss_score=epss, exploitable=exploit,
            metadata={"scanner": sources[i % len(sources)], "component": f"lib-{i}"},
            created_at=NOW - timedelta(days=30 - i),
            updated_at=NOW - timedelta(days=max(0, 15 - i)),
            resolved_at=resolved_at,
        )
        db.create_finding(f)

    # Decisions
    outcomes = [DecisionOutcome.BLOCK, DecisionOutcome.ALERT, DecisionOutcome.ALLOW, DecisionOutcome.REVIEW]
    for i, fid in enumerate(finding_ids):
        d = Decision(
            id=str(uuid.uuid4()), finding_id=fid,
            outcome=outcomes[i % len(outcomes)],
            confidence=0.75 + (i % 5) * 0.05,
            reasoning=f"Multi-LLM consensus: GPT-4 and Claude agree on {outcomes[i % len(outcomes)].value} action",
            llm_votes={"gpt-4": outcomes[i % len(outcomes)].value,
                       "claude-3": outcomes[i % len(outcomes)].value,
                       "gemini": outcomes[(i + 1) % len(outcomes)].value},
            policy_matched=f"POL-{100 + i}",
            created_at=NOW - timedelta(days=25 - i),
        )
        db.create_decision(d)

    # Metrics
    metric_types = [
        ("vulnerability", "total_open", "count"),
        ("vulnerability", "mean_time_to_remediate", "hours"),
        ("vulnerability", "critical_exposure_window", "hours"),
        ("risk", "overall_risk_score", "score"),
        ("risk", "attack_surface_area", "endpoints"),
        ("compliance", "soc2_score", "percent"),
        ("compliance", "pci_dss_score", "percent"),
        ("performance", "scan_duration", "seconds"),
        ("performance", "false_positive_rate", "percent"),
        ("trend", "new_findings_daily", "count"),
    ]
    import random
    random.seed(42)
    for day in range(30):
        for mt, mn, unit in metric_types:
            base_vals = {"total_open": 45, "mean_time_to_remediate": 72,
                         "critical_exposure_window": 24, "overall_risk_score": 65,
                         "attack_surface_area": 1250, "soc2_score": 87,
                         "pci_dss_score": 92, "scan_duration": 180,
                         "false_positive_rate": 12, "new_findings_daily": 8}
            base = base_vals.get(mn, 50)
            value = base + random.uniform(-base * 0.15, base * 0.15)
            m = Metric(
                id=str(uuid.uuid4()), metric_type=mt, metric_name=mn,
                value=round(value, 2), unit=unit,
                timestamp=NOW - timedelta(days=30 - day),
                metadata={"source": "automated"},
            )
            db.create_metric(m)

    print(f"  ✅ Analytics: {len(cves)} findings, {len(cves)} decisions, {30 * len(metric_types)} metrics seeded")
    return finding_ids



# ═══════════════════════════════════════════════════════════════════════════════
# 3. MPTE — Pen Test Requests, Results, Configs
# ═══════════════════════════════════════════════════════════════════════════════
def seed_mpte(finding_ids):
    from core.mpte_db import MPTEDB
    from core.mpte_models import (
        ExploitabilityLevel, PenTestConfig, PenTestPriority,
        PenTestRequest, PenTestResult, PenTestStatus,
    )

    db = MPTEDB()
    existing = db.list_requests(limit=1)
    if existing:
        print(f"  ⏭️  MPTE: already has data")
        return

    # Delete any demo configs
    conn = db._get_connection()
    conn.execute("DELETE FROM pen_test_configs WHERE name LIKE '%demo%'")
    conn.commit()
    conn.close()

    # Create production config
    cfg = PenTestConfig(
        id="", name="ALdeci-MPTE-Production",
        mpte_url="http://localhost:8002/api/v1/mpte",
        api_key=None, enabled=True,
        max_concurrent_tests=10, timeout_seconds=600,
        auto_trigger=True,
        target_environments=["production", "staging"],
        metadata={"engine": "mpte-v2", "version": "2.1.0"},
    )
    db.create_config(cfg)

    targets = [
        ("https://api.acme.com/v1/payments", "sql_injection", "Verify SQLi in payment endpoint"),
        ("https://auth.acme.com/oauth/token", "auth_bypass", "Test OAuth token forgery"),
        ("https://portal.acme.com/upload", "file_upload", "Test unrestricted file upload"),
        ("https://api.acme.com/v1/users", "idor", "Test insecure direct object reference"),
        ("https://api.acme.com/graphql", "graphql_injection", "Test GraphQL injection"),
        ("https://admin.acme.com/api/config", "ssrf", "Test SSRF via config URL parameter"),
        ("https://api.acme.com/v1/export", "path_traversal", "Test path traversal in export"),
        ("https://portal.acme.com/search", "xss", "Test reflected XSS in search"),
    ]

    priorities = [PenTestPriority.CRITICAL, PenTestPriority.HIGH,
                  PenTestPriority.HIGH, PenTestPriority.MEDIUM,
                  PenTestPriority.MEDIUM, PenTestPriority.HIGH,
                  PenTestPriority.MEDIUM, PenTestPriority.LOW]
    statuses = [PenTestStatus.COMPLETED] * 5 + [PenTestStatus.RUNNING, PenTestStatus.PENDING, PenTestStatus.PENDING]
    exploitabilities = [
        ExploitabilityLevel.CONFIRMED_EXPLOITABLE,
        ExploitabilityLevel.CONFIRMED_EXPLOITABLE,
        ExploitabilityLevel.BLOCKED,
        ExploitabilityLevel.LIKELY_EXPLOITABLE,
        ExploitabilityLevel.UNEXPLOITABLE,
    ]

    for i, (url, vtype, tcase) in enumerate(targets):
        fid = finding_ids[i % len(finding_ids)]
        req = PenTestRequest(
            id="", finding_id=fid, target_url=url,
            vulnerability_type=vtype, test_case=tcase,
            priority=priorities[i], status=statuses[i],
            created_at=NOW - timedelta(days=15 - i),
            started_at=(NOW - timedelta(days=14 - i)) if statuses[i] != PenTestStatus.PENDING else None,
            completed_at=(NOW - timedelta(days=13 - i)) if statuses[i] == PenTestStatus.COMPLETED else None,
            mpte_job_id=f"mpte-job-{uuid.uuid4().hex[:8]}" if statuses[i] != PenTestStatus.PENDING else None,
        )
        created_req = db.create_request(req)

        if statuses[i] == PenTestStatus.COMPLETED:
            exploit_level = exploitabilities[i % len(exploitabilities)]
            result = PenTestResult(
                id="", request_id=created_req.id, finding_id=fid,
                exploitability=exploit_level,
                exploit_successful=exploit_level in [ExploitabilityLevel.CONFIRMED_EXPLOITABLE, ExploitabilityLevel.LIKELY_EXPLOITABLE],
                evidence=f"Automated pen test completed. Tested {vtype} against {url}. "
                         f"Result: {exploit_level.value}. Full trace in artifacts.",
                steps_taken=[
                    f"1. Reconnaissance: Scanned {url} for {vtype} vectors",
                    f"2. Payload crafting: Generated {vtype}-specific payloads",
                    f"3. Exploitation attempt: Sent {3 + i} test payloads",
                    f"4. Analysis: Evaluated responses for {vtype} indicators",
                    f"5. Verification: {'Exploit confirmed' if exploit_level == ExploitabilityLevel.CONFIRMED_EXPLOITABLE else 'No exploit confirmed'}",
                ],
                artifacts=[f"trace-{created_req.id}.pcap", f"payload-{created_req.id}.json", f"report-{created_req.id}.html"],
                confidence_score=0.85 + (i % 3) * 0.05,
                execution_time_seconds=12.5 + i * 3.2,
            )
            db.create_result(result)

    print(f"  ✅ MPTE: {len(targets)} requests, {sum(1 for s in statuses if s == PenTestStatus.COMPLETED)} results, 1 config seeded")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Remediation — Tasks with SLA tracking
# ═══════════════════════════════════════════════════════════════════════════════
def seed_remediation(app_ids, finding_ids):
    from core.services.remediation import RemediationService
    svc = RemediationService(Path("data/remediation/tasks.db"))

    existing = svc.get_tasks(org_id="default", limit=1)
    if existing:
        print(f"  ⏭️  Remediation: already has data")
        return

    tasks_data = [
        ("Patch runc container escape CVE-2024-21626", "critical", "Update runc to >=1.1.12. Rebuild all container images.", "alice@acme.com"),
        ("Remove xz-utils backdoor CVE-2024-3094", "critical", "Downgrade xz-utils to 5.4.x or upgrade to 5.6.2+.", "bob@acme.com"),
        ("Fix PHP CGI argument injection CVE-2024-4577", "critical", "Update PHP to latest patch version. Apply WAF rule.", "charlie@acme.com"),
        ("Remediate HTTP/2 Rapid Reset CVE-2023-44487", "high", "Update HTTP/2 libraries. Configure rate limiting.", "alice@acme.com"),
        ("Patch Jenkins CLI file read CVE-2024-23897", "high", "Update Jenkins to 2.442+. Restrict CLI access.", "dave@acme.com"),
        ("Fix Node.js HTTP/2 DoS CVE-2024-27983", "high", "Update Node.js to latest LTS. Enable connection limits.", "eve@acme.com"),
        ("Address Spring Framework SSRF CVE-2024-22243", "medium", "Update Spring Framework to 6.1.5+.", "charlie@acme.com"),
        ("Remediate Redis Lua sandbox escape CVE-2024-31449", "high", "Update Redis to 7.2.5+. Restrict Lua scripting.", "bob@acme.com"),
        ("Fix OpenMetadata auth bypass CVE-2024-28255", "medium", "Update OpenMetadata to 1.3.1+. Review auth configs.", "dave@acme.com"),
        ("Patch Palo Alto PAN-OS CVE-2024-3400", "critical", "Apply PAN-OS hotfix. Enable threat prevention signatures.", "alice@acme.com"),
    ]

    for i, (title, sev, desc, assignee) in enumerate(tasks_data):
        svc.create_task(
            cluster_id=f"cluster-{i % 3 + 1}",
            org_id="default",
            app_id=app_ids[i % len(app_ids)],
            title=title,
            severity=sev,
            description=desc,
            assignee=assignee.split("@")[0],
            assignee_email=assignee,
            metadata={"finding_id": finding_ids[i % len(finding_ids)], "source": "automated"},
        )

    print(f"  ✅ Remediation: {len(tasks_data)} tasks seeded with SLA tracking")



# ═══════════════════════════════════════════════════════════════════════════════
# 5. Provenance — SLSA Attestation files
# ═══════════════════════════════════════════════════════════════════════════════
def seed_provenance():
    import hashlib
    att_dir = ROOT / "data" / "artifacts" / "attestations"
    att_dir.mkdir(parents=True, exist_ok=True)

    if list(att_dir.glob("*.json")):
        print(f"  ⏭️  Provenance: already has attestations")
        return

    artifacts = [
        ("payment-gateway", "v2.4.1", "acme/payment-gw", "platform-team"),
        ("auth-service", "v3.1.0", "acme/auth-svc", "security-team"),
        ("api-gateway", "v1.8.2", "acme/api-gateway", "platform-team"),
        ("customer-portal", "v5.2.0", "acme/customer-portal", "frontend-team"),
        ("data-pipeline", "v2.0.3", "acme/data-pipeline", "data-team"),
    ]

    for name, version, repo, builder in artifacts:
        digest = hashlib.sha256(f"{name}:{version}".encode()).hexdigest()
        attestation = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": f"{name}:{version}", "digest": {"sha256": digest}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://aldeci.io/build/v1",
                    "externalParameters": {"repository": f"https://github.com/{repo}", "ref": f"refs/tags/{version}"},
                    "internalParameters": {"builder_id": f"aldeci-ci/{builder}"},
                },
                "runDetails": {
                    "builder": {"id": f"https://aldeci.io/builders/{builder}", "version": {"aldeci-ci": "2.1.0"}},
                    "metadata": {
                        "invocationId": str(uuid.uuid4()),
                        "startedOn": ts(days_ago=5),
                        "finishedOn": ts(days_ago=5, hours_ago=-1),
                    },
                },
            },
        }
        path = att_dir / f"{name}-{version}-provenance.json"
        path.write_text(json.dumps(attestation, indent=2))

    print(f"  ✅ Provenance: {len(artifacts)} SLSA attestations created")


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Evidence — Bundles and Manifests
# ═══════════════════════════════════════════════════════════════════════════════
def seed_evidence():
    bundle_dir = ROOT / "data" / "evidence" / "bundles"
    manifest_dir = ROOT / "data" / "evidence" / "manifests"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(parents=True, exist_ok=True)

    if list(manifest_dir.glob("*.json")):
        print(f"  ⏭️  Evidence: already has manifests")
        return

    releases = [
        ("release-2024-Q4", "2024 Q4 Security Assessment", ["sast", "dast", "sca", "pentest"]),
        ("release-2025-Q1", "2025 Q1 Compliance Bundle", ["soc2", "pci-dss", "hipaa", "gdpr"]),
        ("release-2025-Q2", "2025 Q2 Vulnerability Report", ["cve-scan", "container-scan", "iac-scan"]),
        ("incident-IR-2025-001", "Incident Response Evidence Pack", ["forensics", "timeline", "ioc", "remediation"]),
    ]

    for release_id, title, evidence_types in releases:
        manifest = {
            "id": release_id,
            "title": title,
            "created_at": ts(days_ago=10),
            "status": "complete",
            "evidence_count": len(evidence_types),
            "evidence_types": evidence_types,
            "attestation_ref": f"data/artifacts/attestations/{release_id}-provenance.json",
            "bundles": [],
        }
        for etype in evidence_types:
            bundle_id = f"{release_id}-{etype}"
            bundle = {
                "id": bundle_id,
                "release_id": release_id,
                "evidence_type": etype,
                "created_at": ts(days_ago=10),
                "items_count": 5 + hash(etype) % 20,
                "status": "verified",
                "summary": f"Automated {etype} evidence for {title}",
            }
            (bundle_dir / f"{bundle_id}.json").write_text(json.dumps(bundle, indent=2))
            manifest["bundles"].append(bundle_id)
        (manifest_dir / f"{release_id}.json").write_text(json.dumps(manifest, indent=2))

    print(f"  ✅ Evidence: {len(releases)} manifests, {sum(len(r[2]) for r in releases)} bundles seeded")


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Collaboration — Notifications
# ═══════════════════════════════════════════════════════════════════════════════
def seed_collaboration():
    from core.services.collaboration import CollaborationService
    svc = CollaborationService(Path("data/collaboration.db"))

    notifications = [
        ("finding", "FND-001", "new_critical_finding", "Critical: CVE-2024-21626 runc escape",
         "New critical vulnerability detected in Payment Gateway. CVSS 9.8, EPSS 0.97.", ["alice", "bob"], "urgent"),
        ("finding", "FND-002", "new_critical_finding", "Critical: CVE-2024-3094 xz-utils backdoor",
         "Supply chain attack detected. Immediate action required.", ["alice", "charlie", "security-team"], "urgent"),
        ("task", "TSK-001", "assignment", "Task assigned: Patch runc CVE-2024-21626",
         "You have been assigned to remediate CVE-2024-21626.", ["alice"], "high"),
        ("task", "TSK-003", "sla_breach", "SLA Warning: CVE-2024-4577 approaching deadline",
         "Remediation task has 4 hours remaining before SLA breach.", ["charlie", "ops-team"], "high"),
        ("finding", "FND-005", "status_change", "Finding resolved: CVE-2024-1709 ScreenConnect",
         "Vulnerability has been patched and verified.", ["alice", "bob", "dave"], "normal"),
    ]

    for entity_type, entity_id, ntype, title, msg, recipients, priority in notifications:
        svc.queue_notification(
            entity_type=entity_type, entity_id=entity_id,
            notification_type=ntype, title=title, message=msg,
            recipients=recipients, priority=priority,
        )

    print(f"  ✅ Collaboration: {len(notifications)} notifications queued")


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    print("🌱 ALdeci Data Seeding")
    print("=" * 60)

    print("\n📦 1/7 Seeding Inventory...")
    app_ids = seed_inventory()

    print("\n📊 2/7 Seeding Analytics...")
    finding_ids = seed_analytics(app_ids)

    print("\n🔫 3/7 Seeding MPTE...")
    seed_mpte(finding_ids)

    print("\n🔧 4/7 Seeding Remediation...")
    seed_remediation(app_ids, finding_ids)

    print("\n📜 5/7 Seeding Provenance...")
    seed_provenance()

    print("\n📁 6/7 Seeding Evidence...")
    seed_evidence()

    print("\n🔔 7/7 Seeding Collaboration...")
    seed_collaboration()

    print("\n" + "=" * 60)
    print("✅ All data stores seeded successfully!")


if __name__ == "__main__":
    main()
