#!/usr/bin/env python3
"""Idempotent demo data seeder for ALDECI — Multica #4134.

Seeds org demo-org-001 with:
  - 15 security findings (3 critical / 4 high / 5 medium / 3 low)
  - 3 incidents
  - 2 executive reports
  - 1 SOC2 assessment with 5 controls auto-collected

Uses only engine APIs — NO direct SQL. Safe to run multiple times.

Usage:
    python scripts/seed_demo_data.py
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "suite-core"))
sys.path.insert(0, _ROOT)

from core.security_findings_engine import SecurityFindingsEngine
from core.incident_response_engine import IncidentResponseEngine
from core.executive_reporting_engine import ExecutiveReportingEngine
from core.compliance_engine import ComplianceAutomationEngine

ORG_ID = "demo-org-001"

FINDINGS = [
    # critical x3
    dict(title="SQL Injection in /api/v1/search endpoint", finding_type="vulnerability",
         source_tool="SAST", severity="critical", cvss_score=9.8,
         asset_id="repo:aldeci-backend", asset_type="repository",
         description="Unsanitised user input passed to SQLite query. Exploitable via OR 1=1 payload.",
         remediation="Use parameterised queries (cursor.execute(sql, params)). Never concatenate user input."),
    dict(title="Hardcoded AWS credentials in config.py", finding_type="secret-exposure",
         source_tool="Semgrep", severity="critical", cvss_score=9.1,
         asset_id="repo:aldeci-backend", asset_type="repository",
         description="AWS_SECRET_ACCESS_KEY committed in plaintext. Key active as of scan date.",
         remediation="Revoke key immediately. Rotate to IAM role-based auth or env var."),
    dict(title="Container running as root with --privileged flag", finding_type="misconfiguration",
         source_tool="Trivy", severity="critical", cvss_score=9.0,
         asset_id="container:api-gateway", asset_type="container",
         description="api-gateway launched with --privileged. Full host kernel access possible.",
         remediation="Drop to non-root user (USER 1001). Remove --privileged. Add --cap-drop ALL."),
    # high x4
    dict(title="Missing HSTS header on public endpoints", finding_type="misconfiguration",
         source_tool="DAST", severity="high", cvss_score=7.5,
         asset_id="host:api.aldeci.io", asset_type="host",
         description="Strict-Transport-Security header absent. Downgrade attacks possible.",
         remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains via middleware."),
    dict(title="Insecure deserialization in report_builder.py", finding_type="vulnerability",
         source_tool="SAST", severity="high", cvss_score=8.1,
         asset_id="repo:aldeci-backend", asset_type="repository",
         description="pickle.loads() called on untrusted report data from Redis cache. RCE vector.",
         remediation="Replace pickle with json.loads(). Validate schema with Pydantic first."),
    dict(title="Overly permissive S3 bucket policy", finding_type="misconfiguration",
         source_tool="CSPM", severity="high", cvss_score=7.8,
         asset_id="aws:s3:aldeci-evidence-prod", asset_type="cloud-resource",
         description="S3 bucket allows s3:GetObject for Principal: '*'. Public read enabled.",
         remediation="Remove wildcard principal. Restrict to specific IAM roles via bucket policy."),
    dict(title="Outdated OpenSSL version with CVE-2024-5535", finding_type="vulnerability",
         source_tool="Trivy", severity="high", cvss_score=7.3,
         asset_id="container:api-gateway", asset_type="container",
         description="OpenSSL 3.0.11 in base image. CVE-2024-5535 SSL buffer over-read.",
         remediation="Rebuild from python:3.12-slim-bookworm which includes OpenSSL 3.0.13+."),
    # medium x5
    dict(title="Missing Content-Security-Policy header", finding_type="policy-violation",
         source_tool="DAST", severity="medium", cvss_score=5.3,
         asset_id="host:app.aldeci.io", asset_type="host",
         description="CSP header not present. XSS attacks not mitigated by browser policy.",
         remediation="Add CSP header: default-src 'self'; script-src 'self'; object-src 'none'."),
    dict(title="Unencrypted SQLite databases in .fixops_data/", finding_type="misconfiguration",
         source_tool="custom", severity="medium", cvss_score=5.0,
         asset_id="host:api-server-01", asset_type="host",
         description="Domain databases stored in plaintext. Host compromise exposes all tenant data.",
         remediation="Enable SQLite encryption via SQLCipher or migrate to encrypted volume."),
    dict(title="No rate limiting on /api/v1/auth/login", finding_type="misconfiguration",
         source_tool="DAST", severity="medium", cvss_score=5.9,
         asset_id="host:api.aldeci.io", asset_type="host",
         description="Login endpoint accepts unlimited requests. Brute-force possible.",
         remediation="Apply RateLimitMiddleware to auth routes. Threshold: 10 req/min per IP."),
    dict(title="npm lodash 4.17.20 prototype pollution CVE-2021-23337", finding_type="vulnerability",
         source_tool="Semgrep", severity="medium", cvss_score=5.6,
         asset_id="repo:aldeci-ui-new", asset_type="repository",
         description="lodash 4.17.20 vulnerable to prototype pollution (CVE-2021-23337).",
         remediation="Upgrade lodash to 4.17.21 or later: npm update lodash."),
    dict(title="Verbose error messages expose stack traces", finding_type="policy-violation",
         source_tool="DAST", severity="medium", cvss_score=4.3,
         asset_id="host:api.aldeci.io", asset_type="host",
         description="500 responses return full Python tracebacks including file paths.",
         remediation="Set DEBUG=False in production. Return only correlation_id on error."),
    # low x3
    dict(title="Missing X-Frame-Options header", finding_type="policy-violation",
         source_tool="DAST", severity="low", cvss_score=3.1,
         asset_id="host:app.aldeci.io", asset_type="host",
         description="X-Frame-Options absent. UI embeddable in cross-origin iframes (clickjacking).",
         remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."),
    dict(title="Server version disclosed in response headers", finding_type="policy-violation",
         source_tool="DAST", severity="low", cvss_score=2.6,
         asset_id="host:api.aldeci.io", asset_type="host",
         description="Server: uvicorn header exposes application server version.",
         remediation="Strip Server header in nginx config or custom middleware."),
    dict(title="Log rotation not configured — disk exhaustion risk", finding_type="misconfiguration",
         source_tool="custom", severity="low", cvss_score=2.2,
         asset_id="host:api-server-01", asset_type="host",
         description="Logs written to /var/log/aldeci/ with no rotation policy.",
         remediation="Configure logrotate: daily rotate 14 compress missingok."),
]

INCIDENTS = [
    dict(title="Suspected data exfiltration via compromised API key",
         description="Anomalous S3 GetObject spike — 14 GB to unknown IP in 4 hours.",
         incident_type="data_breach", severity="p1", status="containment",
         assigned_to="soc-analyst@demo-org-001.com"),
    dict(title="Phishing campaign targeting engineering team",
         description="5 engineers received credential-harvesting emails mimicking GitHub notifications.",
         incident_type="phishing", severity="p2", status="triage",
         assigned_to="ir-lead@demo-org-001.com"),
    dict(title="Dependency confusion attack on npm registry",
         description="Malicious package published with same name as internal @aldeci/utils.",
         incident_type="supply_chain", severity="p2", status="eradication",
         assigned_to="devsecops@demo-org-001.com"),
]

REPORTS = [
    dict(report_type="monthly", title="Security Posture Report — April 2026",
         period_start="2026-04-01", period_end="2026-04-30",
         created_by="ciso@demo-org-001.com",
         sections=["Executive Summary", "Findings Overview", "Incident Summary", "Remediation Progress"]),
    dict(report_type="board", title="Board Security Briefing — Q1 2026",
         period_start="2026-01-01", period_end="2026-03-31",
         created_by="ciso@demo-org-001.com",
         sections=["Risk Posture", "Compliance Status", "Key Incidents", "Investment Asks"]),
]

SOC2_CONTROLS = ["CC1.1", "CC2.1", "CC6.1", "CC7.1", "CC9.1"]


def main() -> None:
    print(f"[seed_demo_data] Seeding org={ORG_ID}")

    findings_eng = SecurityFindingsEngine()
    incident_eng = IncidentResponseEngine()
    reporting_eng = ExecutiveReportingEngine()
    compliance_eng = ComplianceAutomationEngine(org_id=ORG_ID)

    # Findings — idempotent via engine dedup (title+source_tool+asset_id)
    existing_count = len(findings_eng.list_findings(org_id=ORG_ID))
    if existing_count >= len(FINDINGS):
        print(f"  findings: {existing_count} already present — skip")
    else:
        for f in FINDINGS:
            findings_eng.record_finding(
                org_id=ORG_ID,
                title=f["title"], finding_type=f["finding_type"],
                source_tool=f["source_tool"], severity=f["severity"],
                cvss_score=f["cvss_score"], asset_id=f["asset_id"],
                asset_type=f["asset_type"], description=f["description"],
                remediation=f["remediation"],
            )
        print(f"  findings: seeded {len(FINDINGS)}")

    # Incidents — skip by title
    existing_titles = {i["title"] for i in incident_eng.list_incidents(org_id=ORG_ID)}
    i_seeded = sum(
        1 for inc in INCIDENTS
        if inc["title"] not in existing_titles
        and incident_eng.create_incident(org_id=ORG_ID, data=inc) is not None
    )
    print(f"  incidents: seeded {i_seeded} (existing skipped)")

    # Reports — skip by title
    existing_rep_titles = {r["title"] for r in reporting_eng.list_reports(org_id=ORG_ID)}
    r_seeded = sum(
        1 for rep in REPORTS
        if rep["title"] not in existing_rep_titles
        and reporting_eng.create_report(org_id=ORG_ID, data=rep) is not None
    )
    print(f"  reports: seeded {r_seeded} (existing skipped)")

    # SOC2 assessment — collect_evidence is idempotent
    ev_total = 0
    for ctrl_id in SOC2_CONTROLS:
        try:
            items = compliance_eng.collect_evidence(framework="SOC2", control_id=ctrl_id)
            ev_total += len(items)
        except Exception as exc:
            print(f"  SOC2 {ctrl_id}: skipped ({exc})")
    print(f"  SOC2 assessment: {ev_total} evidence items across {len(SOC2_CONTROLS)} controls")

    # Verification
    total = findings_eng.list_findings(org_id=ORG_ID)
    summary = findings_eng.get_findings_summary(org_id=ORG_ID)
    print(f"\n[seed_demo_data] Verification for {ORG_ID}:")
    print(f"  Total findings : {len(total)}")
    print(f"  Severity breakdown: {summary.get('severity_breakdown', {})}")
    print(f"  Source breakdown  : {summary.get('source_breakdown', {})}")
    print("[seed_demo_data] DONE")


if __name__ == "__main__":
    main()
