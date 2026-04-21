#!/usr/bin/env python3
"""
api_io_test.py — Comprehensive API input/output test for ALDECI/Fixops.

Tests the top 100 GET endpoints and top 30 POST endpoints:
  - Validates HTTP status codes
  - Validates JSON response
  - Validates expected fields present (non-empty)
  - Records: endpoint, status, response_time, has_data, field_count

Usage:
    python scripts/api_io_test.py

Output:
    .omc/reports/api_io_test_results.md
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_URL = "http://localhost:8000"
API_TOKEN = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
ORG_ID = "default"
DELAY = 0.5  # seconds between requests
TIMEOUT = 10  # seconds per request

HEADERS = {
    "X-API-Key": API_TOKEN,
    "Content-Type": "application/json",
}

REPORT_PATH = Path(__file__).parent.parent / ".omc" / "reports" / "api_io_test_results.md"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    method: str
    endpoint: str
    status_code: int
    response_time_ms: float
    is_json: bool
    has_data: bool
    field_count: int
    passed: bool
    error: str = ""
    note: str = ""


# ---------------------------------------------------------------------------
# Top 100 GET endpoint definitions
# Format: (path_with_query, min_expected_fields, description)
# ---------------------------------------------------------------------------

GET_ENDPOINTS: List[Tuple[str, int, str]] = [
    # --- Core platform ---
    ("/api/v1/version", 1, "API version"),
    ("/api/v1/health", 1, "Health check"),

    # --- Access Anomaly ---
    (f"/api/v1/access-anomaly/anomalies?org_id={ORG_ID}", 1, "Access anomaly list"),
    (f"/api/v1/access-anomaly/high-risk-users?org_id={ORG_ID}", 1, "High risk users"),
    (f"/api/v1/access-anomaly/summary?org_id={ORG_ID}", 1, "Access anomaly summary"),

    # --- Alert Triage ---
    (f"/api/v1/alert-triage/alerts?org_id={ORG_ID}", 1, "Alert triage list"),
    (f"/api/v1/alert-triage/queue?org_id={ORG_ID}", 1, "Alert triage queue"),
    (f"/api/v1/alert-triage/stats?org_id={ORG_ID}", 1, "Alert triage stats"),

    # --- Alert Enrichment ---
    (f"/api/v1/alert-enrichment/?org_id={ORG_ID}", 1, "Alert enrichment list"),
    (f"/api/v1/alert-enrichment/queue?org_id={ORG_ID}", 1, "Alert enrichment queue"),
    (f"/api/v1/alert-enrichment/summary?org_id={ORG_ID}", 1, "Alert enrichment summary"),
    (f"/api/v1/alert-enrichment/high-risk?org_id={ORG_ID}", 1, "Alert enrichment high risk"),

    # --- Ransomware Protection ---
    (f"/api/v1/ransomware-protection/detections?org_id={ORG_ID}", 1, "Ransomware detections"),
    (f"/api/v1/ransomware-protection/unvalidated-backups?org_id={ORG_ID}", 1, "Unvalidated backups"),
    (f"/api/v1/ransomware-protection/status?org_id={ORG_ID}", 1, "Ransomware protection status"),
    (f"/api/v1/ransomware-protection/summary?org_id={ORG_ID}", 1, "Ransomware summary"),

    # --- Threat Indicators ---
    (f"/api/v1/threat-indicators/?org_id={ORG_ID}", 1, "Threat indicators summary"),
    (f"/api/v1/threat-indicators/indicators?org_id={ORG_ID}", 1, "Threat indicators list"),
    (f"/api/v1/threat-indicators/expired?org_id={ORG_ID}", 1, "Expired indicators"),
    (f"/api/v1/threat-indicators/summary?org_id={ORG_ID}", 1, "Threat indicators summary detail"),

    # --- Privacy Impact Assessment ---
    (f"/api/v1/privacy-impact/assessments?org_id={ORG_ID}", 1, "PIA assessments list"),
    (f"/api/v1/privacy-impact/summary?org_id={ORG_ID}", 1, "PIA summary"),

    # --- Training Effectiveness ---
    (f"/api/v1/training-effectiveness/programs?org_id={ORG_ID}", 1, "Training programs list"),
    (f"/api/v1/training-effectiveness/summary?org_id={ORG_ID}", 1, "Training effectiveness summary"),

    # --- Cloud Cost Optimization ---
    (f"/api/v1/cost-optimization/?org_id={ORG_ID}", 1, "Cost optimization summary"),
    (f"/api/v1/cost-optimization/tools?org_id={ORG_ID}", 1, "Cost optimization tools"),
    (f"/api/v1/cost-optimization/underutilized?org_id={ORG_ID}", 1, "Underutilized tools"),
    (f"/api/v1/cost-optimization/portfolio?org_id={ORG_ID}", 1, "Cost optimization portfolio"),
    (f"/api/v1/cost-optimization/cost-per-risk?org_id={ORG_ID}", 1, "Cost per risk"),

    # --- Patch Management ---
    (f"/api/v1/patch-management/?org_id={ORG_ID}", 1, "Patch management summary"),
    (f"/api/v1/patch-management/patches?org_id={ORG_ID}", 1, "Patches list"),
    (f"/api/v1/patch-management/deployments?org_id={ORG_ID}", 1, "Patch deployments"),
    (f"/api/v1/patch-management/stats?org_id={ORG_ID}", 1, "Patch management stats"),

    # --- Vulnerability Scoring ---
    (f"/api/v1/vuln-scoring?org_id={ORG_ID}", 1, "Vuln scoring summary"),
    (f"/api/v1/vuln-scoring/scores?org_id={ORG_ID}", 1, "Vuln scores list"),
    (f"/api/v1/vuln-scoring/top?org_id={ORG_ID}", 1, "Top vulnerabilities"),
    (f"/api/v1/vuln-scoring/distribution?org_id={ORG_ID}", 1, "Vuln distribution"),

    # --- Security Benchmark ---
    (f"/api/v1/security-benchmarks/?org_id={ORG_ID}", 1, "Security benchmarks summary"),
    (f"/api/v1/security-benchmarks/benchmarks?org_id={ORG_ID}", 1, "Benchmarks list"),
    (f"/api/v1/security-benchmarks/summary?org_id={ORG_ID}", 1, "Benchmarks summary"),

    # --- Incident Costs ---
    (f"/api/v1/incident-costs/analytics?org_id={ORG_ID}", 1, "Incident cost analytics"),
    (f"/api/v1/incident-costs/summaries?org_id={ORG_ID}", 1, "Incident cost summaries"),

    # --- Digital Twin Security ---
    (f"/api/v1/digital-twin/twins?org_id={ORG_ID}", 1, "Digital twins list"),
    (f"/api/v1/digital-twin/simulations?org_id={ORG_ID}", 1, "Twin simulations"),
    (f"/api/v1/digital-twin/findings?org_id={ORG_ID}", 1, "Twin findings"),
    (f"/api/v1/digital-twin/stats?org_id={ORG_ID}", 1, "Twin stats"),

    # --- Cyber Threat Intelligence ---
    (f"/api/v1/cyber-threat-intel/reports?org_id={ORG_ID}", 1, "CTI reports"),
    (f"/api/v1/cyber-threat-intel/iocs?org_id={ORG_ID}", 1, "CTI IOCs"),
    (f"/api/v1/cyber-threat-intel/stats?org_id={ORG_ID}", 1, "CTI stats"),

    # --- SBOM Export ---
    (f"/api/v1/sbom-export/?org_id={ORG_ID}", 1, "SBOM export summary"),
    (f"/api/v1/sbom-export/projects?org_id={ORG_ID}", 1, "SBOM projects"),
    (f"/api/v1/sbom-export/formats?org_id={ORG_ID}", 1, "SBOM formats"),

    # --- Identity Lifecycle ---
    (f"/api/v1/identity-lifecycle/?org_id={ORG_ID}", 1, "Identity lifecycle summary"),
    (f"/api/v1/identity-lifecycle/accounts?org_id={ORG_ID}", 1, "Identity accounts"),

    # --- Cloud Incident Response ---
    (f"/api/v1/cloud-ir/incidents?org_id={ORG_ID}", 1, "Cloud IR incidents"),

    # --- Security Architecture Review ---
    (f"/api/v1/arch-review/reviews?org_id={ORG_ID}", 1, "Arch reviews list"),
    (f"/api/v1/arch-review/summary?org_id={ORG_ID}", 1, "Arch review summary"),

    # --- Hunting Playbooks ---
    (f"/api/v1/hunting-playbooks/playbooks?org_id={ORG_ID}", 1, "Hunting playbooks list"),
    (f"/api/v1/hunting-playbooks/stats?org_id={ORG_ID}", 1, "Hunting playbooks stats"),

    # --- Security Program Maturity ---
    (f"/api/v1/program-maturity/assessments?org_id={ORG_ID}", 1, "Program maturity assessments"),
    (f"/api/v1/program-maturity/summary?org_id={ORG_ID}", 1, "Program maturity summary"),

    # --- Dependency Mapping ---
    (f"/api/v1/dependency-mapping/components?org_id={ORG_ID}", 1, "Dependency components"),
    (f"/api/v1/dependency-mapping/summary?org_id={ORG_ID}", 1, "Dependency mapping summary"),

    # --- Risk Register ---
    (f"/api/v1/risk-register-engine/risks?org_id={ORG_ID}", 1, "Risk register risks"),
    (f"/api/v1/risk-register-engine/treatments?org_id={ORG_ID}", 1, "Risk treatments"),

    # --- Security OKRs ---
    (f"/api/v1/security-okrs/objectives?org_id={ORG_ID}", 1, "Security OKR objectives"),

    # --- Compliance Mapping ---
    (f"/api/v1/compliance-mapping/controls?org_id={ORG_ID}", 1, "Compliance mapping controls"),
    (f"/api/v1/compliance-mapping/mappings?org_id={ORG_ID}", 1, "Compliance mappings"),

    # --- Vuln Scans ---
    (f"/api/v1/vuln-scans/scans?org_id={ORG_ID}", 1, "Vuln scans list"),
    (f"/api/v1/vuln-scans/findings?org_id={ORG_ID}", 1, "Vuln scan findings"),

    # --- Patch Management (already covered above) ---
    # --- Container Posture ---
    (f"/api/v1/container-posture/clusters?org_id={ORG_ID}", 1, "Container posture clusters"),
    (f"/api/v1/container-posture/stats?org_id={ORG_ID}", 1, "Container posture stats"),

    # --- Alert Triage Queue (already covered) ---
    # --- Awareness Metrics ---
    (f"/api/v1/awareness-metrics/trends?org_id={ORG_ID}", 1, "Awareness metrics trends"),
    (f"/api/v1/awareness-metrics/summary?org_id={ORG_ID}", 1, "Awareness metrics summary"),

    # --- Cloud Cost Security ---
    (f"/api/v1/cloud-cost/anomalies?org_id={ORG_ID}", 1, "Cloud cost anomalies"),
    (f"/api/v1/cloud-cost/summary?org_id={ORG_ID}", 1, "Cloud cost summary"),

    # --- Security Health Scorecard ---
    (f"/api/v1/health-scorecard/snapshots?org_id={ORG_ID}", 1, "Health scorecard snapshots"),
    (f"/api/v1/health-scorecard/summary?org_id={ORG_ID}", 1, "Health scorecard summary"),

    # --- Compliance Calendar ---
    (f"/api/v1/compliance-calendar/events?org_id={ORG_ID}", 1, "Compliance calendar events"),
    (f"/api/v1/compliance-calendar/overdue?org_id={ORG_ID}", 1, "Overdue compliance events"),

    # --- Cyber Resilience ---
    (f"/api/v1/cyber-resilience/assessments?org_id={ORG_ID}", 1, "Cyber resilience assessments"),
    (f"/api/v1/cyber-resilience/summary?org_id={ORG_ID}", 1, "Cyber resilience summary"),

    # --- Asset Criticality ---
    (f"/api/v1/asset-criticality/assets?org_id={ORG_ID}", 1, "Asset criticality list"),
    (f"/api/v1/asset-criticality/summary?org_id={ORG_ID}", 1, "Asset criticality summary"),

    # --- Posture Maturity ---
    (f"/api/v1/posture-maturity/assessments?org_id={ORG_ID}", 1, "Posture maturity assessments"),
    (f"/api/v1/posture-maturity/roadmap?org_id={ORG_ID}", 1, "Posture maturity roadmap"),

    # --- Gap Analysis ---
    (f"/api/v1/gap-analysis/analyses?org_id={ORG_ID}", 1, "Gap analysis list"),
    (f"/api/v1/gap-analysis/summary?org_id={ORG_ID}", 1, "Gap analysis summary"),

    # --- Cloud Security Findings ---
    (f"/api/v1/cloud-findings/findings?org_id={ORG_ID}", 1, "Cloud security findings"),
    (f"/api/v1/cloud-findings/summary?org_id={ORG_ID}", 1, "Cloud findings summary"),

    # --- Vuln Age ---
    (f"/api/v1/vuln-age/vulnerabilities?org_id={ORG_ID}", 1, "Vuln age list"),
    (f"/api/v1/vuln-age/summary?org_id={ORG_ID}", 1, "Vuln age summary"),

    # --- Threat Response ---
    (f"/api/v1/threat-response/responses?org_id={ORG_ID}", 1, "Threat response list"),
    (f"/api/v1/threat-response/summary?org_id={ORG_ID}", 1, "Threat response summary"),
]


# ---------------------------------------------------------------------------
# Top 30 POST endpoint definitions
# Format: (path, payload, expected_status, description)
# ---------------------------------------------------------------------------

POST_ENDPOINTS: List[Tuple[str, Dict[str, Any], int, str]] = [
    # --- Access Anomaly: record event ---
    (
        f"/api/v1/access-anomaly/events",
        {
            "org_id": ORG_ID,
            "username": "testuser",
            "source_ip": "10.0.0.1",
            "country": "US",
            "city": "New York",
            "resource": "/api/v1/data",
            "action": "read",
            "success": 1,
        },
        200,
        "Record access event",
    ),
    # --- Ransomware: register detection ---
    (
        f"/api/v1/ransomware-protection/detections",
        {
            "org_id": ORG_ID,
            "detection_name": "TestRansomware-EICAR",
            "detection_type": "behavioral",
            "affected_systems": ["srv-01", "srv-02"],
            "file_extensions": [".locked", ".enc"],
            "confidence": 0.85,
            "severity": "critical",
        },
        200,
        "Register ransomware detection",
    ),
    # --- Ransomware: register backup ---
    (
        f"/api/v1/ransomware-protection/backups",
        {
            "org_id": ORG_ID,
            "system_name": "test-server-01",
            "backup_type": "full",
            "backup_location": "s3://backups/test-server-01",
            "immutable": True,
            "encrypted": True,
            "retention_days": 90,
        },
        200,
        "Register backup",
    ),
    # --- Threat Indicators: add indicator ---
    (
        f"/api/v1/threat-indicators/indicators?org_id={ORG_ID}",
        {
            "indicator_type": "ip",
            "value": "198.51.100.99",
            "severity": "high",
            "confidence": 0.9,
            "source": "threatfeed-test",
            "tags": ["apt", "scanner"],
            "ttl_days": 30,
        },
        201,
        "Add threat indicator",
    ),
    # --- Cloud Cost Optimization: register tool ---
    (
        f"/api/v1/cost-optimization/tools?org_id={ORG_ID}",
        {
            "tool_name": "test-siem-tool",
            "vendor": "TestVendor",
            "category": "siem",
            "monthly_cost": 500.0,
            "licenses": 25,
            "incidents_prevented_per_year": 12,
            "avg_incident_cost": 5000.0,
        },
        201,
        "Register cost optimization tool",
    ),
    # --- Patch Management: register patch ---
    (
        f"/api/v1/patch-management/patches?org_id={ORG_ID}",
        {
            "patch_name": "CVE-2024-0001-Fix",
            "patch_type": "security",
            "severity": "critical",
            "cve_ids": ["CVE-2024-0001"],
            "affected_systems": ["web-01", "web-02"],
            "vendor": "TestVendor",
            "description": "Critical security patch for test CVE",
        },
        200,
        "Register patch",
    ),
    # --- Alert Triage: ingest alert ---
    (
        f"/api/v1/alert-triage/alerts",
        {
            "title": "Suspicious login detected",
            "source_system": "siem",
            "severity": "high",
            "raw_alert_json": {"user": "admin", "ip": "10.0.0.99", "attempts": 5},
        },
        200,
        "Ingest alert for triage",
    ),
    # --- Alert Enrichment: enrich alert ---
    (
        f"/api/v1/alert-enrichment/enrich?org_id={ORG_ID}",
        {
            "alert_title": "Brute force attempt from 10.0.0.99",
            "source_ip": "10.0.0.99",
            "severity": "high",
            "raw_data": {"attempts": 50, "window": "5m"},
        },
        200,
        "Enrich alert",
    ),
    # --- Cyber Threat Intelligence: create report ---
    (
        f"/api/v1/cyber-threat-intel/reports?org_id={ORG_ID}",
        {
            "title": "Q2 Threat Landscape Report",
            "report_type": "weekly",
            "tlp": "amber",
            "summary": "Weekly threat summary for test org",
            "threat_actors": ["APT-TEST-1"],
            "affected_sectors": ["finance", "healthcare"],
            "confidence_score": 0.8,
        },
        200,
        "Create CTI report",
    ),
    # --- Digital Twin: create twin ---
    (
        f"/api/v1/digital-twin/twins?org_id={ORG_ID}",
        {
            "asset_name": "test-web-server-01",
            "asset_type": "server",
            "environment": "production",
            "properties": {"os": "ubuntu-22.04", "services": ["nginx", "postgresql"]},
        },
        200,
        "Create digital twin",
    ),
    # --- Security Benchmark: submit metric ---
    (
        f"/api/v1/security-benchmarks/metrics?org_id={ORG_ID}",
        {
            "metric_name": "mttd_hours",
            "value": 4.5,
            "industry": "technology",
            "company_size": "medium",
        },
        200,
        "Submit security benchmark metric",
    ),
    # --- Risk Register: create risk ---
    (
        f"/api/v1/risk-register-engine/risks?org_id={ORG_ID}",
        {
            "title": "Unpatched critical vulnerability on web tier",
            "risk_category": "technical",
            "likelihood": 4,
            "impact": 5,
            "description": "Test risk entry for API IO test",
            "owner": "security-team",
        },
        200,
        "Create risk register entry",
    ),
    # --- Security OKR: create objective ---
    (
        f"/api/v1/security-okrs/objectives?org_id={ORG_ID}",
        {
            "title": "Reduce MTTD to under 2 hours",
            "description": "Improve detection speed across all threat categories",
            "period": "Q2-2026",
            "owner": "soc-team",
        },
        200,
        "Create security OKR objective",
    ),
    # --- Compliance Mapping: add control ---
    (
        f"/api/v1/compliance-mapping/controls?org_id={ORG_ID}",
        {
            "framework": "nist_csf",
            "control_id": "ID.AM-1",
            "control_name": "Physical devices and systems inventoried",
            "description": "Physical devices and systems within the organization are inventoried",
            "control_status": "implemented",
        },
        200,
        "Add compliance control",
    ),
    # --- Identity Lifecycle: provision account ---
    (
        f"/api/v1/identity-lifecycle/accounts?org_id={ORG_ID}",
        {
            "username": f"testuser_{int(time.time())}",
            "full_name": "Test User",
            "email": "testuser@example.com",
            "department": "engineering",
            "role": "developer",
            "manager": "manager@example.com",
        },
        200,
        "Provision identity account",
    ),
    # --- Cloud IR: create incident ---
    (
        f"/api/v1/cloud-ir/incidents",
        {
            "org_id": ORG_ID,
            "title": "S3 bucket public access misconfiguration",
            "cloud_provider": "aws",
            "severity": "high",
            "affected_resources": ["s3://test-bucket-public"],
            "description": "Test cloud IR incident for API IO test",
        },
        200,
        "Create cloud IR incident",
    ),
    # --- Architecture Review: create review ---
    (
        f"/api/v1/arch-review/reviews?org_id={ORG_ID}",
        {
            "system_name": "Payment Gateway v2",
            "architecture_type": "microservices",
            "reviewer": "sec-architect-01",
            "scope": "Authentication and authorization flows",
        },
        200,
        "Create architecture review",
    ),
    # --- Hunting Playbook: create playbook ---
    (
        f"/api/v1/hunting-playbooks/playbooks?org_id={ORG_ID}",
        {
            "name": "Lateral Movement Hunt - SMB",
            "description": "Hunt for lateral movement via SMB protocol anomalies",
            "hypothesis": "Attacker is using SMB to move laterally",
            "tactics": ["lateral-movement", "discovery"],
            "steps": [
                "Collect SMB authentication logs",
                "Identify unusual auth patterns",
                "Correlate with endpoint telemetry",
            ],
        },
        200,
        "Create hunting playbook",
    ),
    # --- Posture Maturity: create assessment ---
    (
        f"/api/v1/posture-maturity/assessments?org_id={ORG_ID}",
        {
            "framework": "cmmi",
            "assessor": "sec-assessor-01",
            "scope": "Full security program",
            "domains": {
                "governance": 3,
                "risk_management": 2,
                "asset_management": 3,
                "vulnerability_management": 4,
            },
        },
        200,
        "Create posture maturity assessment",
    ),
    # --- Gap Analysis: create analysis ---
    (
        f"/api/v1/gap-analysis/analyses?org_id={ORG_ID}",
        {
            "framework": "nist_csf",
            "current_coverage": 65.0,
            "target_coverage": 90.0,
            "analyst": "gap-analyst-01",
            "notes": "Annual gap analysis for NIST CSF compliance",
        },
        200,
        "Create gap analysis",
    ),
    # --- Container Posture: register cluster ---
    (
        f"/api/v1/container-posture/clusters?org_id={ORG_ID}",
        {
            "cluster_name": "prod-k8s-01",
            "cluster_type": "kubernetes",
            "cloud_provider": "aws",
            "region": "us-east-1",
            "node_count": 10,
            "kubernetes_version": "1.28.0",
        },
        200,
        "Register container cluster",
    ),
    # --- Cyber Resilience: create assessment ---
    (
        f"/api/v1/cyber-resilience/assessments?org_id={ORG_ID}",
        {
            "framework": "nist_csf",
            "assessor": "resilience-lead",
            "domains": {
                "identify": 3,
                "protect": 3,
                "detect": 4,
                "respond": 3,
                "recover": 2,
                "govern": 3,
            },
        },
        200,
        "Create cyber resilience assessment",
    ),
    # --- Asset Criticality: register asset ---
    (
        f"/api/v1/asset-criticality/assets?org_id={ORG_ID}",
        {
            "asset_name": "prod-db-primary",
            "asset_type": "database",
            "business_impact": 5,
            "data_sensitivity": 5,
            "operational_dependency": 4,
            "regulatory_requirement": 3,
            "exposure_level": 2,
        },
        200,
        "Register asset criticality",
    ),
    # --- Health Scorecard: take snapshot ---
    (
        f"/api/v1/health-scorecard/snapshots?org_id={ORG_ID}",
        {
            "domains": {
                "vulnerability_management": 72,
                "incident_response": 68,
                "access_control": 85,
                "data_protection": 75,
                "network_security": 70,
            }
        },
        200,
        "Create health scorecard snapshot",
    ),
    # --- Compliance Calendar: create event ---
    (
        f"/api/v1/compliance-calendar/events?org_id={ORG_ID}",
        {
            "event_name": "Annual SOC 2 Audit",
            "event_type": "audit",
            "framework": "soc2",
            "due_date": "2026-06-30",
            "responsible_team": "compliance-team",
            "description": "Annual SOC 2 Type II audit",
        },
        200,
        "Create compliance calendar event",
    ),
    # --- Cloud Cost: register account ---
    (
        f"/api/v1/cloud-cost/accounts?org_id={ORG_ID}",
        {
            "account_id": f"test-account-{int(time.time())}",
            "account_name": "production-aws",
            "cloud_provider": "aws",
            "monthly_budget": 5000.0,
            "current_spend": 4200.0,
        },
        200,
        "Register cloud cost account",
    ),
    # --- Vuln Scan: create scan ---
    (
        f"/api/v1/vuln-scans/scans?org_id={ORG_ID}",
        {
            "scanner_type": "nessus",
            "scan_name": "Weekly Infrastructure Scan",
            "target_scope": ["10.0.0.0/24", "10.0.1.0/24"],
            "scan_profile": "full",
        },
        200,
        "Create vulnerability scan",
    ),
    # --- Cloud Findings: ingest finding ---
    (
        f"/api/v1/cloud-findings/findings?org_id={ORG_ID}",
        {
            "cloud_provider": "aws",
            "resource_type": "s3_bucket",
            "resource_id": "arn:aws:s3:::test-bucket",
            "title": "S3 bucket with public read access",
            "severity": "high",
            "check_id": "CIS-AWS-2.1.5",
            "description": "S3 bucket allows public read access",
        },
        200,
        "Ingest cloud security finding",
    ),
    # --- Threat Response: create response ---
    (
        f"/api/v1/threat-response/responses?org_id={ORG_ID}",
        {
            "threat_type": "ransomware",
            "title": "Ransomware Response Playbook Execution",
            "triggered_by": "detection-engine",
            "severity": "critical",
            "playbook_name": "Ransomware Containment v2",
        },
        200,
        "Create threat response",
    ),
    # --- Awareness Metrics: record metric ---
    (
        f"/api/v1/awareness-metrics/metrics?org_id={ORG_ID}",
        {
            "department": "engineering",
            "metric_type": "phishing_click_rate",
            "value": 4.2,
            "period": "2026-Q1",
            "benchmark_value": 3.0,
        },
        200,
        "Record awareness metric",
    ),
]


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def _count_fields(data: Any) -> int:
    """Count top-level fields in response (handles dict, list, nested)."""
    if isinstance(data, dict):
        return len(data)
    if isinstance(data, list):
        return len(data)
    return 1


def _has_data(data: Any) -> bool:
    """True if response contains non-empty data."""
    if data is None:
        return False
    if isinstance(data, dict):
        return len(data) > 0
    if isinstance(data, list):
        return True  # even empty list is valid data structure
    return True


def run_get(session: requests.Session, path: str, min_fields: int, desc: str) -> TestResult:
    url = BASE_URL + path
    try:
        t0 = time.monotonic()
        resp = session.get(url, headers=HEADERS, timeout=TIMEOUT)
        elapsed_ms = (time.monotonic() - t0) * 1000

        is_json = False
        data = None
        try:
            data = resp.json()
            is_json = True
        except Exception:
            pass

        field_cnt = _count_fields(data) if data is not None else 0
        has_d = _has_data(data)
        passed = (
            resp.status_code in (200, 201)
            and is_json
            and field_cnt >= min_fields
        )

        return TestResult(
            method="GET",
            endpoint=path,
            status_code=resp.status_code,
            response_time_ms=round(elapsed_ms, 1),
            is_json=is_json,
            has_data=has_d,
            field_count=field_cnt,
            passed=passed,
            note=desc,
        )
    except requests.exceptions.ConnectionError:
        return TestResult("GET", path, 0, 0, False, False, 0, False,
                          error="Connection refused", note=desc)
    except requests.exceptions.Timeout:
        return TestResult("GET", path, 0, TIMEOUT * 1000, False, False, 0, False,
                          error="Timeout", note=desc)
    except Exception as exc:
        return TestResult("GET", path, 0, 0, False, False, 0, False,
                          error=str(exc), note=desc)


def run_post(session: requests.Session, path: str, payload: Dict[str, Any],
             expected_status: int, desc: str) -> TestResult:
    url = BASE_URL + path
    try:
        t0 = time.monotonic()
        resp = session.post(url, headers=HEADERS, json=payload, timeout=TIMEOUT)
        elapsed_ms = (time.monotonic() - t0) * 1000

        is_json = False
        data = None
        try:
            data = resp.json()
            is_json = True
        except Exception:
            pass

        field_cnt = _count_fields(data) if data is not None else 0
        has_d = _has_data(data)
        passed = (
            resp.status_code in (200, 201)
            and is_json
            and field_cnt >= 1
        )

        return TestResult(
            method="POST",
            endpoint=path,
            status_code=resp.status_code,
            response_time_ms=round(elapsed_ms, 1),
            is_json=is_json,
            has_data=has_d,
            field_count=field_cnt,
            passed=passed,
            note=desc,
        )
    except requests.exceptions.ConnectionError:
        return TestResult("POST", path, 0, 0, False, False, 0, False,
                          error="Connection refused", note=desc)
    except requests.exceptions.Timeout:
        return TestResult("POST", path, 0, TIMEOUT * 1000, False, False, 0, False,
                          error="Timeout", note=desc)
    except Exception as exc:
        return TestResult("POST", path, 0, 0, False, False, 0, False,
                          error=str(exc), note=desc)


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def _status_icon(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def write_report(get_results: List[TestResult], post_results: List[TestResult]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    get_pass = sum(1 for r in get_results if r.passed)
    get_fail = len(get_results) - get_pass
    post_pass = sum(1 for r in post_results if r.passed)
    post_fail = len(post_results) - post_pass

    all_times = [r.response_time_ms for r in get_results + post_results if r.response_time_ms > 0]
    avg_time = round(sum(all_times) / len(all_times), 1) if all_times else 0
    max_time = round(max(all_times), 1) if all_times else 0
    min_time = round(min(all_times), 1) if all_times else 0

    total_pass = get_pass + post_pass
    total = len(get_results) + len(post_results)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# ALDECI API Input/Output Test Results",
        "",
        f"> Generated: {now}",
        f"> Server: {BASE_URL}",
        f"> Org ID: `{ORG_ID}`",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| **Total tests** | {total} |",
        f"| **Total passing** | {total_pass} / {total} ({round(total_pass/total*100)}%) |",
        f"| **GET passing** | {get_pass} / {len(get_results)} |",
        f"| **GET failing** | {get_fail} / {len(get_results)} |",
        f"| **POST passing** | {post_pass} / {len(post_results)} |",
        f"| **POST failing** | {post_fail} / {len(post_results)} |",
        f"| **Avg response time** | {avg_time} ms |",
        f"| **Min response time** | {min_time} ms |",
        f"| **Max response time** | {max_time} ms |",
        "",
        "---",
        "",
        "## GET Endpoints (Top 100)",
        "",
        "| # | Result | Status | Time (ms) | Fields | Has Data | Endpoint | Description |",
        "|---|--------|--------|-----------|--------|----------|----------|-------------|",
    ]

    for i, r in enumerate(get_results, 1):
        icon = _status_icon(r.passed)
        err = f" `{r.error}`" if r.error else ""
        lines.append(
            f"| {i} | **{icon}** | {r.status_code} | {r.response_time_ms} | "
            f"{r.field_count} | {'Y' if r.has_data else 'N'} | "
            f"`{r.endpoint[:70]}` | {r.note}{err} |"
        )

    lines += [
        "",
        "---",
        "",
        "## POST Endpoints (Top 30)",
        "",
        "| # | Result | Status | Time (ms) | Fields | Has Data | Endpoint | Description |",
        "|---|--------|--------|-----------|--------|----------|----------|-------------|",
    ]

    for i, r in enumerate(post_results, 1):
        icon = _status_icon(r.passed)
        err = f" `{r.error}`" if r.error else ""
        lines.append(
            f"| {i} | **{icon}** | {r.status_code} | {r.response_time_ms} | "
            f"{r.field_count} | {'Y' if r.has_data else 'N'} | "
            f"`{r.endpoint[:70]}` | {r.note}{err} |"
        )

    # Failed endpoints detail section
    all_failed = [r for r in get_results + post_results if not r.passed]
    if all_failed:
        lines += [
            "",
            "---",
            "",
            "## Failed Endpoints Detail",
            "",
        ]
        for r in all_failed:
            lines.append(f"### `{r.method} {r.endpoint}`")
            lines.append(f"- Description: {r.note}")
            lines.append(f"- HTTP Status: `{r.status_code}`")
            lines.append(f"- JSON: `{r.is_json}`")
            lines.append(f"- Field count: `{r.field_count}`")
            if r.error:
                lines.append(f"- Error: `{r.error}`")
            lines.append("")

    REPORT_PATH.write_text("\n".join(lines) + "\n")
    print(f"\nReport written to: {REPORT_PATH}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"ALDECI API I/O Test")
    print(f"Server : {BASE_URL}")
    print(f"Org ID : {ORG_ID}")
    print(f"Delay  : {DELAY}s between requests")
    print("=" * 60)

    session = requests.Session()

    # --- Verify server is reachable ---
    try:
        ping = session.get(f"{BASE_URL}/api/v1/version", headers=HEADERS, timeout=5)
        print(f"Server reachable — /api/v1/version => {ping.status_code}")
    except Exception as e:
        print(f"ERROR: Server not reachable at {BASE_URL}: {e}")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Run GET tests
    # -----------------------------------------------------------------------
    print(f"\nRunning {len(GET_ENDPOINTS)} GET tests...")
    get_results: List[TestResult] = []

    for i, (path, min_fields, desc) in enumerate(GET_ENDPOINTS, 1):
        result = run_get(session, path, min_fields, desc)
        get_results.append(result)
        icon = "OK " if result.passed else "ERR"
        print(f"  [{icon}] GET {path[:65]:<65} => {result.status_code} "
              f"({result.response_time_ms}ms, {result.field_count} fields)"
              + (f" | {result.error}" if result.error else ""))
        time.sleep(DELAY)

    get_pass = sum(1 for r in get_results if r.passed)
    print(f"\nGET: {get_pass}/{len(get_results)} passing")

    # -----------------------------------------------------------------------
    # Run POST tests
    # -----------------------------------------------------------------------
    print(f"\nRunning {len(POST_ENDPOINTS)} POST tests...")
    post_results: List[TestResult] = []

    for i, (path, payload, expected_status, desc) in enumerate(POST_ENDPOINTS, 1):
        result = run_post(session, path, payload, expected_status, desc)
        post_results.append(result)
        icon = "OK " if result.passed else "ERR"
        print(f"  [{icon}] POST {path[:60]:<60} => {result.status_code} "
              f"({result.response_time_ms}ms, {result.field_count} fields)"
              + (f" | {result.error}" if result.error else ""))
        time.sleep(DELAY)

    post_pass = sum(1 for r in post_results if r.passed)
    print(f"\nPOST: {post_pass}/{len(post_results)} passing")

    # -----------------------------------------------------------------------
    # Final summary
    # -----------------------------------------------------------------------
    total = len(get_results) + len(post_results)
    total_pass = get_pass + post_pass
    all_times = [r.response_time_ms for r in get_results + post_results if r.response_time_ms > 0]
    avg_time = round(sum(all_times) / len(all_times), 1) if all_times else 0

    print("\n" + "=" * 60)
    print(f"FINAL SUMMARY")
    print(f"  GET  : {get_pass}/{len(get_results)} passing")
    print(f"  POST : {post_pass}/{len(post_results)} passing")
    print(f"  TOTAL: {total_pass}/{total} passing ({round(total_pass/total*100)}%)")
    print(f"  Avg response time: {avg_time}ms")
    print("=" * 60)

    write_report(get_results, post_results)


if __name__ == "__main__":
    main()
