#!/usr/bin/env python3
"""
Seed enterprise-grade audit trail events for ALdeci FixOps platform.
Seeds 30+ realistic events spanning the last 30 days.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta, timezone

import requests

BASE_URL = "http://localhost:8000"
import os as _os
import sys as _sys
API_KEY = _os.environ.get("FIXOPS_API_TOKEN")
if not API_KEY:
    _sys.exit("ERROR: FIXOPS_API_TOKEN environment variable required.")
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

# Valid AuditEventType enum values from audit_models.py
# Maps conceptual event categories to valid API values:
#   COMPLIANCE_ASSESSMENT_RUN -> decision_made
#   SCAN_INITIATED / SCAN_COMPLETED -> api_access
#   REMEDIATION_ASSIGNED -> decision_made
#   POLICY_UPDATED -> policy_updated
#   EVIDENCE_EXPORTED -> report_generated
#   CONFIG_CHANGED -> config_changed
#   USER_LOGIN -> user_login
#   API_KEY_ROTATED -> config_changed
#   FRAMEWORK_ENABLED -> integration_configured
#   FINDING_TRIAGED / FINDING_SUPPRESSED -> decision_made
#   REPORT_GENERATED -> report_generated
#   INTEGRATION_CONFIGURED -> integration_configured


def ts(days_ago: float, hour: int = 9, minute: int = 0) -> str:
    """Return ISO timestamp for N days ago at the given hour/minute (UTC)."""
    base = datetime.now(timezone.utc) - timedelta(days=days_ago)
    base = base.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return base.isoformat()


EVENTS = [
    # ── Day 30: Framework onboarding & initial scan ───────────────────────────
    {
        "event_type": "integration_configured",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "compliance_framework",
        "resource_id": "framework-soc2-2026",
        "action": "SOC2 Type II framework enabled for Q1 2026 audit cycle",
        "details": {
            "framework": "SOC2 Type II",
            "audit_cycle": "Q1 2026",
            "controls_loaded": 64,
            "initiated_by": "sarah.chen@aldeci.com",
            "ticket": "SEC-1041",
        },
        "ip_address": "10.0.4.22",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "timestamp": ts(30, 8, 47),
    },
    {
        "event_type": "integration_configured",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "compliance_framework",
        "resource_id": "framework-iso27001-2026",
        "action": "ISO 27001:2022 framework enabled for annual certification",
        "details": {
            "framework": "ISO 27001:2022",
            "audit_cycle": "Annual 2026",
            "controls_loaded": 93,
            "initiated_by": "sarah.chen@aldeci.com",
            "ticket": "SEC-1042",
        },
        "ip_address": "10.0.4.22",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "timestamp": ts(30, 9, 12),
    },
    {
        "event_type": "api_access",
        "severity": "info",
        "user_id": "ci-pipeline@automation.aldeci.io",
        "resource_type": "scan_job",
        "resource_id": "scan-job-20260206-001",
        "action": "Full infrastructure SAST/DAST scan initiated — CI pipeline trigger",
        "details": {
            "scan_type": "SAST+DAST",
            "trigger": "ci-pipeline",
            "branch": "main",
            "commit": "a3c7e9f1b2d4",
            "pipeline_run_id": "gh-actions-run-14872",
            "target_repos": ["aldeci/api-gateway", "aldeci/scanner-engine", "aldeci/brain-pipeline"],
            "priority": "normal",
        },
        "ip_address": "10.0.10.5",
        "user_agent": "FixOps-CI-Agent/2.4.1",
        "timestamp": ts(30, 10, 0),
    },
    {
        "event_type": "api_access",
        "severity": "info",
        "user_id": "ci-pipeline@automation.aldeci.io",
        "resource_type": "scan_job",
        "resource_id": "scan-job-20260206-001",
        "action": "SAST/DAST scan completed — 14 findings identified (3 critical, 5 high)",
        "details": {
            "scan_type": "SAST+DAST",
            "findings_total": 14,
            "critical": 3,
            "high": 5,
            "medium": 4,
            "low": 2,
            "duration_seconds": 847,
            "pipeline_run_id": "gh-actions-run-14872",
        },
        "ip_address": "10.0.10.5",
        "user_agent": "FixOps-CI-Agent/2.4.1",
        "timestamp": ts(30, 10, 14),
    },
    # ── Day 28: Finding triage & remediation assignment ───────────────────────
    {
        "event_type": "decision_made",
        "severity": "critical",
        "user_id": "soc-analyst-01@aldeci.com",
        "resource_type": "finding",
        "resource_id": "SAST-fab3f5e0b22e",
        "action": "Critical SQL injection finding triaged and assigned to security-engineering team",
        "details": {
            "finding_id": "SAST-fab3f5e0b22e",
            "title": "SQL injection in /api/v2/search endpoint — unsanitised user input passed to raw query",
            "severity": "critical",
            "cvss_score": 9.8,
            "assigned_team": "security-engineering",
            "sla_hours": 72,
            "assignee": "david.kim@aldeci.com",
            "ticket": "VULN-2334",
        },
        "ip_address": "10.0.3.15",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(28, 9, 5),
    },
    {
        "event_type": "decision_made",
        "severity": "critical",
        "user_id": "soc-analyst-01@aldeci.com",
        "resource_type": "finding",
        "resource_id": "SAST-cc91a7d3f010",
        "action": "Critical RCE finding triaged — remote code execution in deserialization path",
        "details": {
            "finding_id": "SAST-cc91a7d3f010",
            "title": "Unsafe Java deserialization allowing RCE in compliance-engine service",
            "severity": "critical",
            "cvss_score": 9.1,
            "assigned_team": "platform-engineering",
            "sla_hours": 24,
            "assignee": "david.kim@aldeci.com",
            "ticket": "VULN-2335",
        },
        "ip_address": "10.0.3.15",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(28, 9, 22),
    },
    {
        "event_type": "decision_made",
        "severity": "info",
        "user_id": "soc-analyst-01@aldeci.com",
        "resource_type": "finding",
        "resource_id": "SAST-a12b3c4d5e6f",
        "action": "Low-severity informational finding suppressed — false positive confirmed",
        "details": {
            "finding_id": "SAST-a12b3c4d5e6f",
            "title": "Hardcoded credential pattern in test fixture — confirmed non-production",
            "severity": "low",
            "suppression_reason": "false_positive",
            "reviewed_by": "soc-analyst-01@aldeci.com",
            "ticket": "VULN-2336",
            "expiry_days": 180,
        },
        "ip_address": "10.0.3.15",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(28, 11, 30),
    },
    # ── Day 25: Policy update & config change ─────────────────────────────────
    {
        "event_type": "policy_updated",
        "severity": "warning",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "policy",
        "resource_id": "policy-vuln-sla-v3",
        "action": "Vulnerability SLA policy updated — critical findings reduced from 96h to 72h",
        "details": {
            "policy_name": "Vulnerability SLA Enforcement Policy v3",
            "change_summary": "Critical finding SLA window tightened from 96h to 72h per board directive",
            "previous_critical_sla_hours": 96,
            "new_critical_sla_hours": 72,
            "approved_by": "ciso@aldeci.com",
            "change_ticket": "GOVRC-0091",
            "effective_date": "2026-02-11T00:00:00Z",
        },
        "ip_address": "10.0.4.22",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(25, 14, 5),
    },
    {
        "event_type": "config_changed",
        "severity": "warning",
        "user_id": "david.kim@aldeci.com",
        "resource_type": "integration",
        "resource_id": "integration-crowdstrike-edr",
        "action": "CrowdStrike EDR integration config updated — API endpoint rotated to us-2 region",
        "details": {
            "integration": "CrowdStrike Falcon EDR",
            "change": "API endpoint migrated to us-2 region cluster",
            "previous_endpoint": "https://api.crowdstrike.com/us-1",
            "new_endpoint": "https://api.crowdstrike.com/us-2",
            "reason": "capacity_migration",
            "ticket": "INFRA-5521",
        },
        "ip_address": "10.0.2.88",
        "user_agent": "FixOps-WebUI/3.1.0 (Firefox/121)",
        "timestamp": ts(25, 16, 40),
    },
    # ── Day 22: Compliance assessment run ─────────────────────────────────────
    {
        "event_type": "decision_made",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "compliance_framework",
        "resource_id": "framework-soc2-2026",
        "action": "SOC2 Type II compliance assessment initiated for Q1 2026 audit cycle",
        "details": {
            "framework": "SOC2 Type II",
            "assessment_id": "assess-soc2-20260214",
            "controls_evaluated": 64,
            "initiated_by": "sarah.chen@aldeci.com",
            "audit_firm": "Deloitte & Touche LLP",
            "scope": "Production infrastructure and CI/CD pipeline",
            "ticket": "AUDIT-2026-Q1",
        },
        "ip_address": "10.0.4.22",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(22, 10, 0),
    },
    {
        "event_type": "report_generated",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "compliance_framework",
        "resource_id": "framework-soc2-2026",
        "action": "SOC2 Type II compliance gap report generated — 8 controls require remediation",
        "details": {
            "framework": "SOC2 Type II",
            "assessment_id": "assess-soc2-20260214",
            "report_id": "rpt-soc2-gap-20260214",
            "controls_passing": 56,
            "controls_failing": 8,
            "compliance_pct": 87.5,
            "critical_gaps": ["CC6.1", "CC6.3", "CC7.2"],
            "format": "PDF",
        },
        "ip_address": "10.0.4.22",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(22, 11, 47),
    },
    # ── Day 20: API key rotation ───────────────────────────────────────────────
    {
        "event_type": "config_changed",
        "severity": "warning",
        "user_id": "david.kim@aldeci.com",
        "resource_type": "api_key",
        "resource_id": "apikey-crowdstrike-prod-01",
        "action": "CrowdStrike production API key rotated — 90-day rotation policy",
        "details": {
            "key_name": "crowdstrike-prod-api-key",
            "rotation_reason": "scheduled_90d_rotation",
            "key_fingerprint_old": "sha256:3a7f9c2e1b4d",
            "key_fingerprint_new": "sha256:8b2d5a6c9e1f",
            "rotated_by": "david.kim@aldeci.com",
            "ticket": "SEC-1103",
        },
        "ip_address": "10.0.2.88",
        "user_agent": "FixOps-WebUI/3.1.0 (Firefox/121)",
        "timestamp": ts(20, 9, 15),
    },
    {
        "event_type": "config_changed",
        "severity": "warning",
        "user_id": "ci-pipeline@automation.aldeci.io",
        "resource_type": "api_key",
        "resource_id": "apikey-gh-actions-fixops-deploy",
        "action": "GitHub Actions deployment API key rotated — automated 60-day rotation",
        "details": {
            "key_name": "gh-actions-fixops-deploy",
            "rotation_reason": "automated_60d_rotation",
            "key_fingerprint_old": "sha256:6d1a3c8f2b9e",
            "key_fingerprint_new": "sha256:4f7e2a1b8c3d",
            "pipeline_run_id": "gh-actions-run-15001",
        },
        "ip_address": "10.0.10.5",
        "user_agent": "FixOps-CI-Agent/2.4.1",
        "timestamp": ts(20, 2, 5),
    },
    # ── Day 18: User logins ────────────────────────────────────────────────────
    {
        "event_type": "user_login",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "user_session",
        "resource_id": "session-sch-20260218-001",
        "action": "User authenticated via SSO — MFA verified",
        "details": {
            "auth_method": "saml2_sso",
            "mfa_method": "totp",
            "idp": "okta-aldeci.okta.com",
            "session_duration_hours": 8,
            "device_id": "mac-sch-m2-pro-01",
        },
        "ip_address": "10.0.4.22",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120",
        "timestamp": ts(18, 8, 31),
    },
    {
        "event_type": "user_login",
        "severity": "info",
        "user_id": "david.kim@aldeci.com",
        "resource_type": "user_session",
        "resource_id": "session-dki-20260218-001",
        "action": "User authenticated via SSO — MFA verified",
        "details": {
            "auth_method": "saml2_sso",
            "mfa_method": "hardware_key",
            "idp": "okta-aldeci.okta.com",
            "session_duration_hours": 8,
            "device_id": "linux-dki-workstation-01",
        },
        "ip_address": "10.0.2.88",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120",
        "timestamp": ts(18, 8, 55),
    },
    {
        "event_type": "user_login",
        "severity": "warning",
        "user_id": "soc-analyst-01@aldeci.com",
        "resource_type": "user_session",
        "resource_id": "session-soc1-20260218-001",
        "action": "User login from new IP — additional verification required",
        "details": {
            "auth_method": "saml2_sso",
            "mfa_method": "push_notification",
            "new_ip_flag": True,
            "previous_known_ip": "10.0.3.15",
            "risk_score": 45,
            "idp": "okta-aldeci.okta.com",
        },
        "ip_address": "198.51.100.47",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        "timestamp": ts(18, 7, 12),
    },
    # ── Day 15: Evidence export & remediation tracking ────────────────────────
    {
        "event_type": "report_generated",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "evidence_bundle",
        "resource_id": "evbundle-soc2-cc6-20260221",
        "action": "SOC2 CC6.1 evidence bundle exported for external audit submission",
        "details": {
            "bundle_id": "evbundle-soc2-cc6-20260221",
            "framework": "SOC2 Type II",
            "control": "CC6.1 — Logical and Physical Access Controls",
            "files_included": 23,
            "size_mb": 47.3,
            "recipient": "deloitte-audit-portal@deloitte.com",
            "encryption": "AES-256-GCM",
            "ticket": "AUDIT-2026-Q1",
        },
        "ip_address": "10.0.4.22",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(15, 14, 20),
    },
    {
        "event_type": "decision_made",
        "severity": "info",
        "user_id": "david.kim@aldeci.com",
        "resource_type": "remediation_task",
        "resource_id": "rem-VULN-2334-patch",
        "action": "Remediation task completed — SQL injection patched and verified in staging",
        "details": {
            "finding_id": "SAST-fab3f5e0b22e",
            "remediation_action": "Parameterized query implemented, input validation added",
            "verified_by": "soc-analyst-01@aldeci.com",
            "patch_commit": "d4e7b3a1c9f2e8d0",
            "staging_scan_clean": True,
            "ticket": "VULN-2334",
        },
        "ip_address": "10.0.2.88",
        "user_agent": "FixOps-WebUI/3.1.0 (Firefox/121)",
        "timestamp": ts(15, 16, 45),
    },
    # ── Day 12: Integration & scan cycle ──────────────────────────────────────
    {
        "event_type": "integration_configured",
        "severity": "info",
        "user_id": "david.kim@aldeci.com",
        "resource_type": "integration",
        "resource_id": "integration-wiz-cloud-posture",
        "action": "Wiz cloud security posture integration configured for AWS production account",
        "details": {
            "integration": "Wiz CSPM",
            "cloud_provider": "AWS",
            "account_id": "123456789012",
            "regions": ["us-east-1", "us-west-2", "eu-west-1"],
            "scan_frequency": "continuous",
            "ticket": "SEC-1121",
        },
        "ip_address": "10.0.2.88",
        "user_agent": "FixOps-WebUI/3.1.0 (Firefox/121)",
        "timestamp": ts(12, 11, 5),
    },
    {
        "event_type": "api_access",
        "severity": "info",
        "user_id": "ci-pipeline@automation.aldeci.io",
        "resource_type": "scan_job",
        "resource_id": "scan-job-20260224-002",
        "action": "Scheduled weekly dependency vulnerability scan initiated",
        "details": {
            "scan_type": "SCA",
            "trigger": "scheduled_weekly",
            "packages_scanned": 847,
            "pipeline_run_id": "gh-actions-run-15344",
            "manifest_files": ["package.json", "requirements.txt", "pom.xml", "go.mod"],
        },
        "ip_address": "10.0.10.5",
        "user_agent": "FixOps-CI-Agent/2.4.1",
        "timestamp": ts(12, 3, 0),
    },
    {
        "event_type": "api_access",
        "severity": "warning",
        "user_id": "ci-pipeline@automation.aldeci.io",
        "resource_type": "scan_job",
        "resource_id": "scan-job-20260224-002",
        "action": "Dependency scan completed — 2 critical CVEs in transitive dependencies",
        "details": {
            "scan_type": "SCA",
            "findings_total": 7,
            "critical": 2,
            "high": 3,
            "medium": 2,
            "critical_cves": ["CVE-2024-45490", "CVE-2025-21298"],
            "duration_seconds": 312,
            "pipeline_run_id": "gh-actions-run-15344",
        },
        "ip_address": "10.0.10.5",
        "user_agent": "FixOps-CI-Agent/2.4.1",
        "timestamp": ts(12, 3, 5),
    },
    # ── Day 9: Policy & compliance updates ────────────────────────────────────
    {
        "event_type": "policy_updated",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "policy",
        "resource_id": "policy-data-retention-v2",
        "action": "Data retention policy updated — audit log retention extended to 2 years for GDPR compliance",
        "details": {
            "policy_name": "Data Retention and Archival Policy v2",
            "change_summary": "Audit log retention extended from 1 year to 2 years per GDPR Article 30 requirement",
            "previous_retention_days": 365,
            "new_retention_days": 730,
            "approved_by": "dpo@aldeci.com",
            "change_ticket": "GOVRC-0107",
            "gdpr_article": "Art. 30 — Records of processing activities",
        },
        "ip_address": "10.0.4.22",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(9, 10, 30),
    },
    {
        "event_type": "decision_made",
        "severity": "info",
        "user_id": "soc-analyst-01@aldeci.com",
        "resource_type": "finding",
        "resource_id": "SCA-CVE-2024-45490",
        "action": "Critical CVE-2024-45490 triaged — lodash prototype pollution, patch available",
        "details": {
            "finding_id": "SCA-CVE-2024-45490",
            "cve": "CVE-2024-45490",
            "package": "lodash@4.17.20",
            "affected_services": ["api-gateway", "copilot-service"],
            "fix_version": "lodash@4.17.21",
            "cvss_score": 9.8,
            "assigned_team": "platform-engineering",
            "sla_hours": 48,
            "ticket": "VULN-2401",
        },
        "ip_address": "10.0.3.15",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(9, 14, 10),
    },
    # ── Day 6: Report generation & HIPAA assessment ───────────────────────────
    {
        "event_type": "report_generated",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "compliance_framework",
        "resource_id": "framework-iso27001-2026",
        "action": "ISO 27001:2022 quarterly compliance status report generated",
        "details": {
            "framework": "ISO 27001:2022",
            "report_id": "rpt-iso27001-q1-20260302",
            "controls_passing": 79,
            "controls_failing": 14,
            "compliance_pct": 84.9,
            "format": "PDF",
            "distributed_to": ["ciso@aldeci.com", "vp-engineering@aldeci.com"],
        },
        "ip_address": "10.0.4.22",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(6, 9, 0),
    },
    {
        "event_type": "integration_configured",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "compliance_framework",
        "resource_id": "framework-hipaa-2026",
        "action": "HIPAA Security Rule framework enabled for healthcare data processing audit",
        "details": {
            "framework": "HIPAA Security Rule",
            "audit_cycle": "Annual 2026",
            "controls_loaded": 45,
            "scope": "PHI data processing pipelines",
            "ticket": "COMPLIANCE-0334",
        },
        "ip_address": "10.0.4.22",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(6, 11, 20),
    },
    # ── Day 4: Config changes & user activity ─────────────────────────────────
    {
        "event_type": "config_changed",
        "severity": "info",
        "user_id": "david.kim@aldeci.com",
        "resource_type": "integration",
        "resource_id": "integration-splunk-siem",
        "action": "Splunk SIEM integration updated — CEF log forwarding enabled for audit trail",
        "details": {
            "integration": "Splunk Enterprise Security",
            "change": "CEF log forwarding activated; 3 new alert rules imported",
            "log_types": ["audit_trail", "finding_events", "policy_changes"],
            "splunk_index": "fixops_audit",
            "alert_rules_added": 3,
            "ticket": "INFRA-5598",
        },
        "ip_address": "10.0.2.88",
        "user_agent": "FixOps-WebUI/3.1.0 (Firefox/121)",
        "timestamp": ts(4, 15, 10),
    },
    {
        "event_type": "user_login",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "user_session",
        "resource_id": "session-sch-20260304-001",
        "action": "User authenticated via SSO — MFA verified",
        "details": {
            "auth_method": "saml2_sso",
            "mfa_method": "totp",
            "idp": "okta-aldeci.okta.com",
            "session_duration_hours": 8,
        },
        "ip_address": "10.0.4.22",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120",
        "timestamp": ts(4, 8, 59),
    },
    {
        "event_type": "user_login",
        "severity": "info",
        "user_id": "david.kim@aldeci.com",
        "resource_type": "user_session",
        "resource_id": "session-dki-20260304-001",
        "action": "User authenticated via SSO — MFA verified",
        "details": {
            "auth_method": "saml2_sso",
            "mfa_method": "hardware_key",
            "idp": "okta-aldeci.okta.com",
            "session_duration_hours": 8,
        },
        "ip_address": "10.0.2.88",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120",
        "timestamp": ts(4, 9, 22),
    },
    # ── Day 2: Recent scans & finding updates ─────────────────────────────────
    {
        "event_type": "api_access",
        "severity": "info",
        "user_id": "ci-pipeline@automation.aldeci.io",
        "resource_type": "scan_job",
        "resource_id": "scan-job-20260306-003",
        "action": "Pre-release security scan initiated for aldeci-api-gateway v2.14.0-rc1",
        "details": {
            "scan_type": "SAST+DAST+SCA",
            "trigger": "release_candidate",
            "version": "v2.14.0-rc1",
            "branch": "release/2.14",
            "commit": "f9e3a1c7b4d2",
            "pipeline_run_id": "gh-actions-run-15621",
        },
        "ip_address": "10.0.10.5",
        "user_agent": "FixOps-CI-Agent/2.4.1",
        "timestamp": ts(2, 1, 0),
    },
    {
        "event_type": "api_access",
        "severity": "info",
        "user_id": "ci-pipeline@automation.aldeci.io",
        "resource_type": "scan_job",
        "resource_id": "scan-job-20260306-003",
        "action": "Pre-release scan completed — release candidate cleared for staging deployment",
        "details": {
            "scan_type": "SAST+DAST+SCA",
            "findings_total": 3,
            "critical": 0,
            "high": 1,
            "medium": 2,
            "gate_status": "passed",
            "duration_seconds": 1142,
            "pipeline_run_id": "gh-actions-run-15621",
        },
        "ip_address": "10.0.10.5",
        "user_agent": "FixOps-CI-Agent/2.4.1",
        "timestamp": ts(2, 1, 19),
    },
    {
        "event_type": "decision_made",
        "severity": "info",
        "user_id": "david.kim@aldeci.com",
        "resource_type": "remediation_task",
        "resource_id": "rem-VULN-2401-patch",
        "action": "lodash upgrade deployed to production — CVE-2024-45490 remediated",
        "details": {
            "finding_id": "SCA-CVE-2024-45490",
            "remediation": "Upgraded lodash from 4.17.20 to 4.17.21 across 2 services",
            "services_patched": ["api-gateway", "copilot-service"],
            "deploy_pipeline": "gh-actions-run-15589",
            "verified_clean": True,
            "ticket": "VULN-2401",
        },
        "ip_address": "10.0.2.88",
        "user_agent": "FixOps-WebUI/3.1.0 (Firefox/121)",
        "timestamp": ts(2, 16, 30),
    },
    # ── Day 1: Most recent activity ────────────────────────────────────────────
    {
        "event_type": "report_generated",
        "severity": "info",
        "user_id": "sarah.chen@aldeci.com",
        "resource_type": "evidence_bundle",
        "resource_id": "evbundle-hipaa-164-2026",
        "action": "HIPAA §164.312 technical safeguards evidence bundle generated for internal review",
        "details": {
            "bundle_id": "evbundle-hipaa-164-2026",
            "framework": "HIPAA Security Rule",
            "controls": ["164.312(a)", "164.312(b)", "164.312(c)", "164.312(d)", "164.312(e)"],
            "files_included": 18,
            "size_mb": 29.7,
            "status": "pending_legal_review",
            "ticket": "COMPLIANCE-0334",
        },
        "ip_address": "10.0.4.22",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(1, 10, 5),
    },
    {
        "event_type": "user_login",
        "severity": "info",
        "user_id": "soc-analyst-01@aldeci.com",
        "resource_type": "user_session",
        "resource_id": "session-soc1-20260307-001",
        "action": "User authenticated via SSO — MFA verified",
        "details": {
            "auth_method": "saml2_sso",
            "mfa_method": "totp",
            "idp": "okta-aldeci.okta.com",
            "session_duration_hours": 8,
        },
        "ip_address": "10.0.3.15",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(1, 8, 42),
    },
    {
        "event_type": "decision_made",
        "severity": "high" if False else "warning",
        "user_id": "soc-analyst-01@aldeci.com",
        "resource_type": "finding",
        "resource_id": "DAST-7c3e9f1a2b4d",
        "action": "High-severity SSRF finding in evidence-service triaged — awaiting patch",
        "details": {
            "finding_id": "DAST-7c3e9f1a2b4d",
            "title": "SSRF vulnerability in evidence export endpoint allows internal network access",
            "severity": "high",
            "cvss_score": 8.1,
            "affected_service": "evidence-service",
            "assigned_team": "security-engineering",
            "sla_hours": 120,
            "assignee": "david.kim@aldeci.com",
            "ticket": "VULN-2445",
        },
        "ip_address": "10.0.3.15",
        "user_agent": "FixOps-WebUI/3.1.0 (Chrome/120)",
        "timestamp": ts(1, 14, 55),
    },
    {
        "event_type": "api_access",
        "severity": "info",
        "user_id": "ci-pipeline@automation.aldeci.io",
        "resource_type": "scan_job",
        "resource_id": "scan-job-20260308-004",
        "action": "Nightly container image vulnerability scan initiated across all production images",
        "details": {
            "scan_type": "container_image_scan",
            "trigger": "scheduled_nightly",
            "images_scanned": 34,
            "registry": "ghcr.io/aldeci",
            "pipeline_run_id": "gh-actions-run-15799",
        },
        "ip_address": "10.0.10.5",
        "user_agent": "FixOps-CI-Agent/2.4.1",
        "timestamp": ts(0.1, 2, 0),
    },
]


def post_event(event: dict) -> dict:
    """POST an audit event to the chain endpoint."""
    resp = requests.post(
        f"{BASE_URL}/api/v1/audit/logs/chain",
        headers=HEADERS,
        json=event,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def main():
    print(f"Seeding {len(EVENTS)} enterprise audit events to {BASE_URL} ...")
    success = 0
    failed = 0
    for i, event in enumerate(EVENTS, 1):
        try:
            result = post_event(event)
            print(f"  [{i:02d}/{len(EVENTS)}] ✓ {event['event_type']} | chain pos {result['chain_position']} | {event['action'][:70]}")
            success += 1
        except Exception as exc:
            print(f"  [{i:02d}/{len(EVENTS)}] ✗ FAILED: {exc} | event: {event['action'][:60]}", file=sys.stderr)
            failed += 1
        time.sleep(0.05)  # small delay to avoid overwhelming the server

    print(f"\nDone — {success} events seeded, {failed} failed.")

    # Verify count
    resp = requests.get(
        f"{BASE_URL}/api/v1/audit/logs",
        headers=HEADERS,
        params={"limit": 1000},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    total = data.get("total", len(data.get("items", [])))
    print(f"Verification: {total} audit events in database.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
