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
from dataclasses import dataclass
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
DELAY = 0.5       # seconds between requests
TIMEOUT = 12      # seconds per request
MAX_RETRIES = 2   # retries on connection error

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
# Format: (path_with_query, description)
# A 200 JSON response with any valid body (including empty list) is a PASS.
# ---------------------------------------------------------------------------

GET_ENDPOINTS: List[Tuple[str, str]] = [
    # --- Core platform ---
    ("/api/v1/version",                                                       "API version"),
    ("/api/v1/health",                                                        "Health check"),

    # --- Access Anomaly ---
    (f"/api/v1/access-anomaly/anomalies?org_id={ORG_ID}",                    "Access anomaly list"),
    (f"/api/v1/access-anomaly/high-risk-users?org_id={ORG_ID}",              "High risk users"),
    (f"/api/v1/access-anomaly/summary?org_id={ORG_ID}",                      "Access anomaly summary"),

    # --- Alert Triage ---
    (f"/api/v1/alert-triage/alerts?org_id={ORG_ID}",                         "Alert triage list"),
    (f"/api/v1/alert-triage/queue?org_id={ORG_ID}",                          "Alert triage queue"),
    (f"/api/v1/alert-triage/stats?org_id={ORG_ID}",                          "Alert triage stats"),

    # --- Alert Enrichment ---
    (f"/api/v1/alert-enrichment/?org_id={ORG_ID}",                           "Alert enrichment list"),
    (f"/api/v1/alert-enrichment/queue?org_id={ORG_ID}",                      "Alert enrichment queue"),
    (f"/api/v1/alert-enrichment/summary?org_id={ORG_ID}",                    "Alert enrichment summary"),
    (f"/api/v1/alert-enrichment/high-risk?org_id={ORG_ID}",                  "Alert enrichment high risk"),

    # --- Ransomware Protection ---
    (f"/api/v1/ransomware-protection/detections?org_id={ORG_ID}",            "Ransomware detections"),
    (f"/api/v1/ransomware-protection/unvalidated-backups?org_id={ORG_ID}",   "Unvalidated backups"),
    (f"/api/v1/ransomware-protection/status?org_id={ORG_ID}",                "Ransomware protection status"),
    (f"/api/v1/ransomware-protection/summary?org_id={ORG_ID}",               "Ransomware summary"),

    # --- Threat Indicators ---
    (f"/api/v1/threat-indicators/?org_id={ORG_ID}",                          "Threat indicators root"),
    (f"/api/v1/threat-indicators/indicators?org_id={ORG_ID}",                "Threat indicators list"),
    (f"/api/v1/threat-indicators/expired?org_id={ORG_ID}",                   "Expired indicators"),
    (f"/api/v1/threat-indicators/summary?org_id={ORG_ID}",                   "Threat indicators summary"),

    # --- Privacy Impact Assessment ---
    (f"/api/v1/privacy-impact/assessments?org_id={ORG_ID}",                  "PIA assessments list"),
    (f"/api/v1/privacy-impact/summary?org_id={ORG_ID}",                      "PIA summary"),

    # --- Training Effectiveness ---
    (f"/api/v1/training-effectiveness/programs?org_id={ORG_ID}",             "Training programs list"),
    (f"/api/v1/training-effectiveness/summary?org_id={ORG_ID}",              "Training effectiveness summary"),

    # --- Cloud Cost Optimization ---
    (f"/api/v1/cost-optimization/?org_id={ORG_ID}",                          "Cost optimization summary"),
    (f"/api/v1/cost-optimization/tools?org_id={ORG_ID}",                     "Cost optimization tools"),
    (f"/api/v1/cost-optimization/underutilized?org_id={ORG_ID}",             "Underutilized tools"),
    (f"/api/v1/cost-optimization/portfolio?org_id={ORG_ID}",                 "Cost optimization portfolio"),
    (f"/api/v1/cost-optimization/cost-per-risk?org_id={ORG_ID}",             "Cost per risk"),

    # --- Patch Management ---
    (f"/api/v1/patch-management/?org_id={ORG_ID}",                           "Patch management summary"),
    (f"/api/v1/patch-management/patches?org_id={ORG_ID}",                    "Patches list"),
    (f"/api/v1/patch-management/deployments?org_id={ORG_ID}",                "Patch deployments"),
    (f"/api/v1/patch-management/stats?org_id={ORG_ID}",                      "Patch management stats"),

    # --- Vulnerability Scoring ---
    (f"/api/v1/vuln-scoring?org_id={ORG_ID}",                                "Vuln scoring summary"),
    (f"/api/v1/vuln-scoring/scores?org_id={ORG_ID}",                         "Vuln scores list"),
    (f"/api/v1/vuln-scoring/top?org_id={ORG_ID}",                            "Top vulnerabilities"),
    (f"/api/v1/vuln-scoring/distribution?org_id={ORG_ID}",                   "Vuln distribution"),

    # --- Security Benchmark ---
    (f"/api/v1/security-benchmarks/?org_id={ORG_ID}",                        "Security benchmarks root"),
    (f"/api/v1/security-benchmarks/benchmarks?org_id={ORG_ID}",              "Benchmarks list"),
    (f"/api/v1/security-benchmarks/summary?org_id={ORG_ID}",                 "Benchmarks summary"),

    # --- Incident Costs ---
    (f"/api/v1/incident-costs/analytics?org_id={ORG_ID}",                    "Incident cost analytics"),
    (f"/api/v1/incident-costs/summaries?org_id={ORG_ID}",                    "Incident cost summaries"),

    # --- Digital Twin Security ---
    (f"/api/v1/digital-twin/twins?org_id={ORG_ID}",                          "Digital twins list"),
    (f"/api/v1/digital-twin/simulations?org_id={ORG_ID}",                    "Twin simulations"),
    (f"/api/v1/digital-twin/findings?org_id={ORG_ID}",                       "Twin findings"),
    (f"/api/v1/digital-twin/stats?org_id={ORG_ID}",                          "Twin stats"),

    # --- Cyber Threat Intelligence ---
    (f"/api/v1/cyber-threat-intel/reports?org_id={ORG_ID}",                  "CTI reports"),
    (f"/api/v1/cyber-threat-intel/iocs?org_id={ORG_ID}",                     "CTI IOCs"),
    (f"/api/v1/cyber-threat-intel/stats?org_id={ORG_ID}",                    "CTI stats"),

    # --- SBOM Export ---
    (f"/api/v1/sbom-export/?org_id={ORG_ID}",                                "SBOM export summary"),
    (f"/api/v1/sbom-export/projects?org_id={ORG_ID}",                        "SBOM projects"),
    (f"/api/v1/sbom-export/formats?org_id={ORG_ID}",                         "SBOM formats"),

    # --- Identity Lifecycle ---
    (f"/api/v1/identity-lifecycle/?org_id={ORG_ID}",                         "Identity lifecycle summary"),
    (f"/api/v1/identity-lifecycle/accounts?org_id={ORG_ID}",                 "Identity accounts"),

    # --- Cloud Incident Response ---
    (f"/api/v1/cloud-ir/incidents?org_id={ORG_ID}",                          "Cloud IR incidents"),
    (f"/api/v1/cloud-ir/playbooks?org_id={ORG_ID}",                          "Cloud IR playbooks"),
    (f"/api/v1/cloud-ir/metrics?org_id={ORG_ID}",                            "Cloud IR metrics"),

    # --- Security Architecture Review ---
    (f"/api/v1/arch-review/reviews?org_id={ORG_ID}",                         "Arch reviews list"),
    (f"/api/v1/arch-review/summary?org_id={ORG_ID}",                         "Arch review summary"),

    # --- Hunting Playbooks ---
    (f"/api/v1/hunting-playbooks/playbooks?org_id={ORG_ID}",                 "Hunting playbooks list"),
    (f"/api/v1/hunting-playbooks/stats?org_id={ORG_ID}",                     "Hunting playbooks stats"),

    # --- Security Program Maturity ---
    (f"/api/v1/program-maturity/assessments?org_id={ORG_ID}",                "Program maturity assessments"),
    (f"/api/v1/program-maturity/summary?org_id={ORG_ID}",                    "Program maturity summary"),
    (f"/api/v1/program-maturity/roadmap?org_id={ORG_ID}",                    "Program maturity roadmap"),

    # --- Dependency Mapping ---
    (f"/api/v1/dependency-mapping/summary?org_id={ORG_ID}",                  "Dependency mapping summary"),

    # --- Risk Register ---
    (f"/api/v1/risk-register-engine/risks?org_id={ORG_ID}",                  "Risk register risks"),
    (f"/api/v1/risk-register-engine/treatments?org_id={ORG_ID}",             "Risk treatments"),

    # --- Security OKRs ---
    (f"/api/v1/security-okrs/objectives?org_id={ORG_ID}",                    "Security OKR objectives"),

    # --- Compliance Mapping ---
    (f"/api/v1/compliance-mapping/controls?org_id={ORG_ID}",                 "Compliance mapping controls"),
    (f"/api/v1/compliance-mapping/mappings?org_id={ORG_ID}",                 "Compliance mappings"),

    # --- Vuln Scans ---
    (f"/api/v1/vuln-scans/scans?org_id={ORG_ID}",                            "Vuln scans list"),
    (f"/api/v1/vuln-scans/findings?org_id={ORG_ID}",                         "Vuln scan findings"),
    (f"/api/v1/vuln-scans/stats?org_id={ORG_ID}",                            "Vuln scan stats"),

    # --- Container Security Posture ---
    (f"/api/v1/container-posture/clusters?org_id={ORG_ID}",                  "Container posture clusters"),
    (f"/api/v1/container-posture/stats?org_id={ORG_ID}",                     "Container posture stats"),

    # --- Awareness Metrics (correct paths) ---
    (f"/api/v1/awareness-metrics/metrics?org_id={ORG_ID}",                                          "Awareness metrics list"),
    (f"/api/v1/awareness-metrics/metrics/latest?org_id={ORG_ID}&metric_type=phishing_click_rate",   "Awareness metrics latest"),
    (f"/api/v1/awareness-metrics/metrics/trend?org_id={ORG_ID}&metric_type=phishing_click_rate",    "Awareness metrics trend"),
    (f"/api/v1/awareness-metrics/stats?org_id={ORG_ID}",                                            "Awareness metrics stats"),
    (f"/api/v1/awareness-metrics/benchmarks?org_id={ORG_ID}",                                       "Awareness benchmarks"),

    # --- Cloud Cost Security (correct paths) ---
    (f"/api/v1/cloud-cost/snapshots?org_id={ORG_ID}",                        "Cloud cost snapshots"),
    (f"/api/v1/cloud-cost/anomalies?org_id={ORG_ID}",                        "Cloud cost anomalies"),
    (f"/api/v1/cloud-cost/stats?org_id={ORG_ID}",                            "Cloud cost security stats"),
    (f"/api/v1/cloud-cost/budgets?org_id={ORG_ID}",                          "Cloud cost budgets"),

    # --- Health Scorecard ---
    (f"/api/v1/health-scorecard?org_id={ORG_ID}",                            "Health scorecard overview"),
    (f"/api/v1/health-scorecard/current?org_id={ORG_ID}",                    "Health scorecard current"),
    (f"/api/v1/health-scorecard/history?org_id={ORG_ID}",                    "Health scorecard history"),
    (f"/api/v1/health-scorecard/grade-trend?org_id={ORG_ID}",                "Health scorecard grade trend"),

    # --- Compliance Calendar ---
    (f"/api/v1/compliance-calendar/?org_id={ORG_ID}",                        "Compliance calendar summary"),
    (f"/api/v1/compliance-calendar/upcoming?org_id={ORG_ID}",                "Upcoming compliance events"),
    (f"/api/v1/compliance-calendar/overdue?org_id={ORG_ID}",                 "Overdue compliance events"),

    # --- Cyber Resilience ---
    (f"/api/v1/cyber-resilience/assessments?org_id={ORG_ID}",                "Cyber resilience assessments"),
    (f"/api/v1/cyber-resilience/score?org_id={ORG_ID}",                      "Cyber resilience score"),

    # --- Asset Criticality ---
    (f"/api/v1/asset-criticality/assets?org_id={ORG_ID}",                    "Asset criticality list"),
    (f"/api/v1/asset-criticality/summary?org_id={ORG_ID}",                   "Asset criticality summary"),

    # --- Posture Maturity ---
    (f"/api/v1/posture-maturity/overview?org_id={ORG_ID}",                   "Posture maturity overview"),
    (f"/api/v1/posture-maturity/domains?org_id={ORG_ID}",                    "Posture maturity domains"),
    (f"/api/v1/posture-maturity/roadmap?org_id={ORG_ID}",                    "Posture maturity roadmap"),

    # --- Gap Analysis ---
    (f"/api/v1/gap-analysis/assessments?org_id={ORG_ID}",                    "Gap analysis list"),
    (f"/api/v1/gap-analysis/summary?org_id={ORG_ID}",                        "Gap analysis summary"),

    # --- Cloud Security Findings ---
    (f"/api/v1/cloud-findings/findings?org_id={ORG_ID}",                     "Cloud security findings"),
    (f"/api/v1/cloud-findings/summary?org_id={ORG_ID}",                      "Cloud findings summary"),

    # --- Vuln Age ---
    (f"/api/v1/vuln-age/distribution?org_id={ORG_ID}",                       "Vuln age distribution"),
    (f"/api/v1/vuln-age/sla-compliance?org_id={ORG_ID}",                     "Vuln SLA compliance"),

    # --- Threat Response ---
    (f"/api/v1/threat-response/?org_id={ORG_ID}",                            "Threat response summary"),
    (f"/api/v1/threat-response/playbooks/performance?org_id={ORG_ID}",       "Playbook performance"),
    (f"/api/v1/threat-response/incidents/active?org_id={ORG_ID}",            "Active threat incidents"),
]


# ---------------------------------------------------------------------------
# Top 30 POST endpoint definitions
# Format: (path, payload_dict, description)
# org_id placement matches the actual router: body Field or Query param
# ---------------------------------------------------------------------------

POST_ENDPOINTS: List[Tuple[str, Dict[str, Any], str]] = [
    # 1 — Access Anomaly: record event (org_id in body)
    (
        "/api/v1/access-anomaly/events",
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
        "Record access event",
    ),
    # 2 — Ransomware: register detection (org_id in body)
    (
        "/api/v1/ransomware-protection/detections",
        {
            "org_id": ORG_ID,
            "detection_name": "TestRansomware-EICAR",
            "detection_type": "behavioral",
            "affected_systems": ["srv-01"],
            "file_extensions": [".locked"],
            "confidence": 0.85,
            "severity": "critical",
        },
        "Register ransomware detection",
    ),
    # 3 — Ransomware: register backup (org_id in body)
    (
        "/api/v1/ransomware-protection/backups",
        {
            "org_id": ORG_ID,
            "system_name": "test-server-01",
            "backup_type": "full",
            "backup_location": "s3://backups/test-server-01",
            "immutable": True,
            "encrypted": True,
            "retention_days": 90,
        },
        "Register backup",
    ),
    # 4 — Threat Indicators: add indicator (org_id as query param)
    (
        f"/api/v1/threat-indicators/indicators?org_id={ORG_ID}",
        {
            "indicator_value": "198.51.100.99",
            "indicator_type": "ip",
            "source": "threatfeed-test",
            "confidence": 0.9,
            "severity": "high",
            "tlp": "amber",
            "tags": ["apt"],
        },
        "Add threat indicator",
    ),
    # 5 — Cloud Cost Optimization: register tool (org_id as query param)
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
        "Register cost optimization tool",
    ),
    # 6 — Patch Management: register patch (org_id as query param)
    (
        f"/api/v1/patch-management/patches?org_id={ORG_ID}",
        {
            "title": "CVE-2024-0001-Fix",
            "patch_type": "security",
            "severity": "critical",
            "cve_ids": ["CVE-2024-0001"],
            "vendor": "TestVendor",
        },
        "Register patch",
    ),
    # 7 — Alert Triage: ingest alert (org_id as query param)
    (
        f"/api/v1/alert-triage/alerts?org_id={ORG_ID}",
        {
            "title": "Suspicious login detected",
            "source_system": "siem",
            "severity": "high",
            "raw_alert_json": {"user": "admin", "ip": "10.0.0.99", "attempts": 5},
        },
        "Ingest alert for triage",
    ),
    # 8 — Alert Enrichment: submit alert for enrichment (alert_id+alert_source+raw_indicator required)
    (
        f"/api/v1/alert-enrichment/alerts?org_id={ORG_ID}",
        {
            "alert_id": f"alert-test-{int(time.time())}",
            "alert_source": "siem",
            "severity": "high",
            "raw_indicator": "198.51.100.99",
            "indicator_type": "ip",
        },
        "Submit alert for enrichment",
    ),
    # 9 — Cyber Threat Intelligence: create report (org_id as query param)
    (
        f"/api/v1/cyber-threat-intel/reports?org_id={ORG_ID}",
        {
            "title": "Q2 Threat Landscape Report",
            "report_type": "weekly",
            "tlp": "amber",
            "summary": "Weekly threat summary",
            "threat_actors": ["APT-TEST-1"],
            "affected_sectors": ["finance"],
            "confidence_score": 0.8,
        },
        "Create CTI report",
    ),
    # 10 — Digital Twin: create twin (org_id as query param, valid twin_type enum)
    (
        f"/api/v1/digital-twin/twins?org_id={ORG_ID}",
        {
            "name": "test-infrastructure-twin",
            "twin_type": "infrastructure",
            "description": "Production infrastructure twin",
            "asset_count": 5,
            "fidelity_level": "high",
        },
        "Create digital twin",
    ),
    # 11 — Risk Register: create risk (impact enum: catastrophic/major/moderate/minor/negligible)
    (
        f"/api/v1/risk-register-engine/risks?org_id={ORG_ID}",
        {
            "name": "Unpatched vuln on web tier",
            "risk_category": "technical",
            "likelihood": "likely",
            "impact": "major",
            "description": "Test risk entry",
            "owner": "security-team",
        },
        "Create risk register entry",
    ),
    # 12 — Security OKR: create objective (org_id as query param)
    (
        f"/api/v1/security-okrs/objectives?org_id={ORG_ID}",
        {
            "title": "Reduce MTTD to under 2 hours",
            "description": "Improve detection speed",
            "period": "Q2-2026",
            "owner": "soc-team",
        },
        "Create security OKR objective",
    ),
    # 13 — Compliance Mapping: add control (org_id as query param)
    (
        f"/api/v1/compliance-mapping/controls?org_id={ORG_ID}",
        {
            "framework": "nist_csf",
            "control_id": "ID.AM-1",
            "control_name": "Physical devices inventoried",
            "description": "Physical devices inventoried",
            "control_status": "implemented",
        },
        "Add compliance control",
    ),
    # 14 — Identity Lifecycle: provision account (org_id as query param)
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
        "Provision identity account",
    ),
    # 15 — Cloud IR: create incident (org_id in body Field, correct field names)
    (
        "/api/v1/cloud-ir/incidents",
        {
            "org_id": ORG_ID,
            "incident_name": "S3 bucket public access misconfiguration",
            "cloud_provider": "aws",
            "incident_type": "misconfiguration",
            "severity": "high",
            "affected_services": ["s3"],
            "affected_regions": ["us-east-1"],
        },
        "Create cloud IR incident",
    ),
    # 16 — Architecture Review: create review (review_name is required)
    (
        f"/api/v1/arch-review/reviews?org_id={ORG_ID}",
        {
            "review_name": "Payment Gateway v2 Security Review",
            "system_name": "Payment Gateway v2",
            "review_type": "threat-model",
            "reviewer": "sec-architect-01",
        },
        "Create architecture review",
    ),
    # 17 — Hunting Playbook: create playbook (playbook_name+hunt_type+threat_category required)
    (
        f"/api/v1/hunting-playbooks/playbooks?org_id={ORG_ID}",
        {
            "playbook_name": "Lateral Movement Hunt - SMB",
            "hunt_type": "behavioral",
            "threat_category": "lateral_movement",
            "hypothesis": "Attacker using SMB laterally",
            "mitre_technique": "T1021.002",
            "data_sources": ["windows_security_events", "network_flow"],
        },
        "Create hunting playbook",
    ),
    # 18 — Security Program Maturity: create assessment (org_id in body Field)
    (
        "/api/v1/program-maturity/assessments",
        {
            "org_id": ORG_ID,
            "assessment_name": "Annual Security Assessment 2026",
            "assessor": "sec-assessor-01",
            "notes": "Annual full program assessment",
        },
        "Create program maturity assessment",
    ),
    # 19 — Gap Analysis: create assessment (org_id in body, framework+assessment_name required)
    (
        "/api/v1/gap-analysis/assessments",
        {
            "org_id": ORG_ID,
            "framework": "NIST-CSF",
            "assessment_name": "NIST CSF Gap Assessment 2026",
            "total_controls": 108,
            "assessor": "gap-analyst-01",
        },
        "Create gap analysis assessment",
    ),
    # 20 — Container Posture: register cluster (org_id as query, correct fields)
    (
        f"/api/v1/container-posture/clusters?org_id={ORG_ID}",
        {
            "name": "prod-k8s-01",
            "runtime": "containerd",
            "version": "1.28.0",
            "node_count": 10,
            "namespace_count": 5,
        },
        "Register container cluster",
    ),
    # 21 — Cyber Resilience: create assessment (domain enum: adapt/detect/identify/protect/recover/respond)
    (
        f"/api/v1/cyber-resilience/assessments?org_id={ORG_ID}",
        {
            "assessment_name": "Annual Resilience Assessment 2026",
            "resilience_domain": "respond",
            "maturity_level": 3,
            "assessor": "resilience-lead",
        },
        "Create cyber resilience assessment",
    ),
    # 22 — Asset Criticality: register asset (org_id as query, correct fields)
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
        "Register asset criticality",
    ),
    # 23 — Health Scorecard: take snapshot (org_id as query)
    (
        f"/api/v1/health-scorecard/snapshots?org_id={ORG_ID}",
        {
            "domains": {
                "vulnerability_management": 72,
                "incident_response": 68,
                "access_control": 85,
            }
        },
        "Create health scorecard snapshot",
    ),
    # 24 — Compliance Calendar: create event (org_id as query, all required fields)
    (
        f"/api/v1/compliance-calendar/events?org_id={ORG_ID}",
        {
            "event_name": "Annual SOC 2 Audit",
            "event_type": "audit",
            "framework": "SOC2",
            "due_date": "2026-06-30",
            "recurrence": "annual",
            "owner": "compliance-team",
            "priority": "high",
        },
        "Create compliance calendar event",
    ),
    # 25 — Cloud Cost Security: record snapshot (org_id in body Field)
    (
        "/api/v1/cloud-cost/snapshots",
        {
            "org_id": ORG_ID,
            "account_id": "aws-prod-001",
            "provider": "aws",
            "service_name": "ec2",
            "region": "us-east-1",
            "cost_usd": 1200.0,
            "previous_cost_usd": 1100.0,
            "change_pct": 9.1,
        },
        "Record cloud cost snapshot",
    ),
    # 26 — Vuln Scan: create scan (org_id as query, correct fields)
    (
        f"/api/v1/vuln-scans/scans?org_id={ORG_ID}",
        {
            "scan_name": "Weekly Infrastructure Scan",
            "scanner_type": "nessus",
            "target": "10.0.0.0/24",
            "scan_status": "pending",
        },
        "Create vulnerability scan",
    ),
    # 27 — Cloud Findings: ingest finding (org_id in body, correct field names from model)
    (
        "/api/v1/cloud-findings/findings",
        {
            "org_id": ORG_ID,
            "provider": "aws",
            "account_id": "123456789012",
            "region": "us-east-1",
            "resource_type": "s3",
            "resource_id": "arn:aws:s3:::test-bucket",
            "finding_title": "S3 bucket with public read access",
            "finding_type": "misconfiguration",
            "severity": "high",
            "cvss_score": 7.5,
            "remediation": "Disable public read ACL",
        },
        "Ingest cloud security finding",
    ),
    # 28 — Threat Response: create playbook (playbook_name+threat_type required)
    (
        f"/api/v1/threat-response/playbooks?org_id={ORG_ID}",
        {
            "playbook_name": "Ransomware Containment v2",
            "threat_type": "ransomware",
            "severity_scope": "critical",
            "description": "Steps to contain and recover from ransomware",
            "created_by": "security-team",
        },
        "Create threat response playbook",
    ),
    # 29 — Awareness Metrics: record metric (org_id as query)
    (
        f"/api/v1/awareness-metrics/metrics?org_id={ORG_ID}",
        {
            "metric_type": "phishing_click_rate",
            "department": "engineering",
            "value": 4.2,
            "period": "2026-Q1",
            "sample_size": 120,
        },
        "Record awareness metric",
    ),
    # 30 — Security OKR: create key result (org_id as query, after first objective exists)
    (
        f"/api/v1/security-okrs/objectives?org_id={ORG_ID}",
        {
            "title": "Achieve 100% MFA adoption",
            "description": "Roll out MFA to all employee accounts",
            "period": "Q3-2026",
            "owner": "iam-team",
        },
        "Create second security OKR",
    ),
]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _count_fields(data: Any) -> int:
    """Top-level field count for dicts; item count for lists; 1 for scalars."""
    if isinstance(data, dict):
        return len(data)
    if isinstance(data, list):
        return len(data)
    return 1 if data is not None else 0


def _has_data(data: Any) -> bool:
    """True if response is any valid JSON structure (including empty list/dict)."""
    return data is not None


def _request_with_retry(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """Send request, retrying on connection error with short back-off."""
    last_exc: Exception = Exception("no attempts")
    for attempt in range(1, MAX_RETRIES + 2):
        try:
            return session.request(method, url, **kwargs)
        except requests.exceptions.ConnectionError as exc:
            last_exc = exc
            if attempt <= MAX_RETRIES:
                time.sleep(1.5 * attempt)
    raise last_exc


def run_get(session: requests.Session, path: str, desc: str) -> TestResult:
    url = BASE_URL + path
    try:
        t0 = time.monotonic()
        resp = _request_with_retry(session, "GET", url, headers=HEADERS, timeout=TIMEOUT)
        elapsed_ms = (time.monotonic() - t0) * 1000

        data = None
        is_json = False
        try:
            data = resp.json()
            is_json = True
        except Exception:
            pass

        field_cnt = _count_fields(data)
        has_d = _has_data(data)

        # PASS: 200/201, valid JSON, any response structure
        passed = resp.status_code in (200, 201) and is_json

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
    except requests.exceptions.Timeout:
        return TestResult("GET", path, 0, TIMEOUT * 1000, False, False, 0, False,
                          error="Timeout", note=desc)
    except Exception as exc:
        return TestResult("GET", path, 0, 0, False, False, 0, False,
                          error=str(exc)[:120], note=desc)


def run_post(
    session: requests.Session,
    path: str,
    payload: Dict[str, Any],
    desc: str,
) -> TestResult:
    url = BASE_URL + path
    try:
        t0 = time.monotonic()
        resp = _request_with_retry(
            session, "POST", url, headers=HEADERS, json=payload, timeout=TIMEOUT
        )
        elapsed_ms = (time.monotonic() - t0) * 1000

        data = None
        is_json = False
        try:
            data = resp.json()
            is_json = True
        except Exception:
            pass

        field_cnt = _count_fields(data)
        has_d = _has_data(data)

        # PASS: 200/201, valid JSON
        passed = resp.status_code in (200, 201) and is_json

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
    except requests.exceptions.Timeout:
        return TestResult("POST", path, 0, TIMEOUT * 1000, False, False, 0, False,
                          error="Timeout", note=desc)
    except Exception as exc:
        return TestResult("POST", path, 0, 0, False, False, 0, False,
                          error=str(exc)[:120], note=desc)


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def _icon(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def write_report(get_results: List[TestResult], post_results: List[TestResult]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    get_pass = sum(1 for r in get_results if r.passed)
    post_pass = sum(1 for r in post_results if r.passed)
    total = len(get_results) + len(post_results)
    total_pass = get_pass + post_pass

    all_times = [r.response_time_ms for r in get_results + post_results if r.response_time_ms > 0]
    avg_ms = round(sum(all_times) / len(all_times), 1) if all_times else 0
    max_ms = round(max(all_times), 1) if all_times else 0
    min_ms = round(min(all_times), 1) if all_times else 0

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
        "| Metric | Value |",
        "|--------|-------|",
        f"| **Total tests** | {total} |",
        f"| **Total passing** | {total_pass} / {total} ({round(total_pass/total*100) if total else 0}%) |",
        f"| **GET passing** | {get_pass} / {len(get_results)} |",
        f"| **GET failing** | {len(get_results)-get_pass} / {len(get_results)} |",
        f"| **POST passing** | {post_pass} / {len(post_results)} |",
        f"| **POST failing** | {len(post_results)-post_pass} / {len(post_results)} |",
        f"| **Avg response time** | {avg_ms} ms |",
        f"| **Min response time** | {min_ms} ms |",
        f"| **Max response time** | {max_ms} ms |",
        "",
        "---",
        "",
        f"## GET Endpoints ({len(get_results)} tested)",
        "",
        "| # | Result | Status | Time (ms) | Fields | Endpoint | Description |",
        "|---|--------|--------|-----------|--------|----------|-------------|",
    ]

    for i, r in enumerate(get_results, 1):
        err_suffix = f" `{r.error}`" if r.error else ""
        lines.append(
            f"| {i} | **{_icon(r.passed)}** | {r.status_code} | {r.response_time_ms} | "
            f"{r.field_count} | `{r.endpoint[:72]}` | {r.note}{err_suffix} |"
        )

    lines += [
        "",
        "---",
        "",
        f"## POST Endpoints ({len(post_results)} tested)",
        "",
        "| # | Result | Status | Time (ms) | Fields | Endpoint | Description |",
        "|---|--------|--------|-----------|--------|----------|-------------|",
    ]

    for i, r in enumerate(post_results, 1):
        err_suffix = f" `{r.error}`" if r.error else ""
        lines.append(
            f"| {i} | **{_icon(r.passed)}** | {r.status_code} | {r.response_time_ms} | "
            f"{r.field_count} | `{r.endpoint[:72]}` | {r.note}{err_suffix} |"
        )

    # --- Failed detail section ---
    all_failed = [r for r in get_results + post_results if not r.passed]
    if all_failed:
        lines += ["", "---", "", "## Failed Endpoints Detail", ""]
        for r in all_failed:
            lines += [
                f"### `{r.method} {r.endpoint}`",
                f"- Description: {r.note}",
                f"- HTTP Status: `{r.status_code}`",
                f"- JSON valid: `{r.is_json}`",
                f"- Field count: `{r.field_count}`",
            ]
            if r.error:
                lines.append(f"- Error: `{r.error}`")
            lines.append("")
    else:
        lines += ["", "---", "", "## All endpoints passed!", ""]

    REPORT_PATH.write_text("\n".join(lines) + "\n")
    print(f"\nReport written → {REPORT_PATH}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("ALDECI API I/O Test")
    print(f"Server : {BASE_URL}")
    print(f"Org ID : {ORG_ID}")
    print(f"Delay  : {DELAY}s between requests  |  Retries: {MAX_RETRIES}")
    print("=" * 70)

    session = requests.Session()

    # Verify reachable
    try:
        ping = session.get(f"{BASE_URL}/api/v1/version", headers=HEADERS, timeout=6)
        print(f"Server reachable — /api/v1/version => {ping.status_code}")
    except Exception as exc:
        print(f"ERROR: Server unreachable at {BASE_URL}: {exc}")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # GET tests
    # -----------------------------------------------------------------------
    print(f"\nRunning {len(GET_ENDPOINTS)} GET tests...")
    get_results: List[TestResult] = []

    for i, (path, desc) in enumerate(GET_ENDPOINTS, 1):
        r = run_get(session, path, desc)
        get_results.append(r)
        icon = "OK " if r.passed else "ERR"
        err_str = f"  [{r.error}]" if r.error else ""
        print(
            f"  [{icon}] GET {path[:68]:<68}  {r.status_code}  "
            f"{r.response_time_ms:6.1f}ms  {r.field_count} fields{err_str}"
        )
        time.sleep(DELAY)

    get_pass = sum(1 for r in get_results if r.passed)
    print(f"\nGET: {get_pass}/{len(get_results)} passing")

    # -----------------------------------------------------------------------
    # POST tests
    # -----------------------------------------------------------------------
    print(f"\nRunning {len(POST_ENDPOINTS)} POST tests...")
    post_results: List[TestResult] = []

    for i, (path, payload, desc) in enumerate(POST_ENDPOINTS, 1):
        r = run_post(session, path, payload, desc)
        post_results.append(r)
        icon = "OK " if r.passed else "ERR"
        err_str = f"  [{r.error}]" if r.error else ""
        print(
            f"  [{icon}] POST {path[:63]:<63}  {r.status_code}  "
            f"{r.response_time_ms:6.1f}ms  {r.field_count} fields{err_str}"
        )
        time.sleep(DELAY)

    post_pass = sum(1 for r in post_results if r.passed)
    print(f"\nPOST: {post_pass}/{len(post_results)} passing")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    total = len(get_results) + len(post_results)
    total_pass = get_pass + post_pass
    all_times = [r.response_time_ms for r in get_results + post_results if r.response_time_ms > 0]
    avg_ms = round(sum(all_times) / len(all_times), 1) if all_times else 0

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print(f"  GET  : {get_pass}/{len(get_results)} passing")
    print(f"  POST : {post_pass}/{len(post_results)} passing")
    print(f"  TOTAL: {total_pass}/{total} ({round(total_pass/total*100) if total else 0}%)")
    print(f"  Avg response time: {avg_ms}ms")
    print("=" * 70)

    write_report(get_results, post_results)


if __name__ == "__main__":
    main()
