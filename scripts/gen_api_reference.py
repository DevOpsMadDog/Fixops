#!/usr/bin/env python3
"""
gen_api_reference.py — ALDECI API Reference Generator
======================================================
Introspects the live FastAPI app and emits per-sub-app OpenAPI reference docs.

Usage:
    cd /Users/devops.ai/fixops/Fixops
    python scripts/gen_api_reference.py

Output:
    docs/api-reference/aspm.md
    docs/api-reference/cspm.md
    docs/api-reference/ctem.md
    docs/api-reference/grc.md
    docs/api-reference/platform.md
    docs/api-reference/README.md

Strategy:
  - Import create_app(), walk app.routes (FastAPI APIRoute objects).
  - Classify each route into a sub-app bucket using prefix matching against
    the known sub-app router modules extracted from sub_apps/*.py.
  - For each route, emit: method, path, summary, description, auth hint,
    path/query params, request body schema (Pydantic model fields), response
    schema, and all declared status codes.
  - Unclassified routes go into an "other" bucket appended to platform.md.

Re-run at any time after router changes — idempotent, overwrites output files.
"""

from __future__ import annotations

import importlib
import inspect
import os
import re
import sys
import textwrap
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Path bootstrap — mirror sitecustomize.py
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
for _sub in ("suite-api", "suite-core", "suite-attack", "suite-feeds", "suite-evidence-risk", "suite-integrations"):
    _p = REPO_ROOT / _sub
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

os.environ.setdefault("FIXOPS_API_TOKEN", "gen-doc-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "gen-doc-jwt-secret-min-32-chars-ok")
os.environ.setdefault("FIXOPS_DEV_MODE", "false")

# ---------------------------------------------------------------------------
# Sub-app bucket definitions
# Derived from sub_apps/{aspm,cspm,ctem,grc,platform}_app.py import lists.
# Each entry: (sub_app_name, set_of_router_module_names)
# We also classify by URL prefix as a fallback.
# ---------------------------------------------------------------------------

ASPM_ROUTER_MODULES: Set[str] = {
    "triage_router", "wave_c_router", "gate_router", "remediation_router",
    "wave_a_code_intel_router", "validation_router", "api_security_router",
    "container_runtime_router", "application_security_router", "app_security_router",
    "mobile_security_router", "supply_chain_risk_router", "vuln_scanner_router",
    "devsecops_router", "ai_code_scanner_router", "sbom_router",
    "patch_automation_router", "secret_scanner_engine_router", "vuln_workflow_router",
    "api_security_engine_router", "api_security_mgmt_router", "supply_chain_router",
    "secret_scanner_router", "secrets_management_router", "vulnerability_remediation_router",
    "api_gateway_security_router", "asset_lifecycle_router", "supply_chain_monitoring_router",
    "malicious_pkg_router", "container_runtime_security_router", "api_discovery_router",
    "browser_security_router", "firmware_security_router", "mobile_app_security_router",
    "api_abuse_detection_router", "autonomous_remediation_router", "application_risk_router",
    "api_threat_protection_router", "dev_identity_router", "sbom_export_router",
    "sbom_reeval_router", "sast_router", "dast_router", "iac_scanner_router",
    "semgrep_router", "dep_scanner_router", "snyk_router", "snyk_oss_router",
    "trivy_router", "nuclei_router", "code_ownership_router", "arch_graph_router",
    "deep_code_analysis_router", "function_reachability_router", "binary_fingerprint_router",
    "semantic_analyzer_router", "slsa_provenance_router", "provenance_router",
    "pipeline_bom_router", "cicd_router", "pr_gate_router", "pr_generator_router",
    "github_app_router", "github_app_autofix_router", "autofix_router",
    "autofix_verify_router", "fix_engine_router", "vuln_discovery_router",
    "vuln_enricher_router", "vuln_exception_router", "vuln_risk_router",
    "vuln_scan_router", "vuln_lifecycle_router", "vuln_prioritization_router",
    "vuln_prioritizer_router", "vuln_trend_router", "vulnerability_age_router",
    "vulnerability_correlation_router", "vulnerability_prioritization_router",
    "vulnerability_scoring_router", "vulnerability_workflow_router",
    "ml_vuln_prioritizer_router", "epss_router", "cve_enrichment_router",
    "nvd_cve_router", "ghsa_router", "osv_router", "exploitdb_router",
    "patch_management_router", "patch_manager_router", "patch_prioritizer_router",
    "secret_scanner_engine_router", "secrets_manager_router", "secrets_rotation_router",
    "secrets_router", "api_abuse_router", "api_analytics_router", "api_fuzzer_router",
    "api_gateway_router", "api_inventory_router", "api_docs_router",
    "container_scanner_router", "container_registry_security_router",
    "container_security_posture_router", "container_router",
    "software_composition_analysis_router", "software_license_security_router",
    "license_scanner_router", "license_compliance_router",
    "supply_chain_attack_detection_router", "supply_chain_intel_router",
    "code_to_cloud_router", "code_to_runtime_router",
    "asset_criticality_router", "asset_group_router", "asset_inventory_router",
    "asset_tagging_router", "inventory_router",
    "choke_point_router", "blast_radius_router",
    "attack_chain_router", "attack_sim_router", "attack_simulation_router",
    "attack_surface_engine_router", "attack_surface_manager_router",
    "attack_surface_mgmt_router", "attack_surface_monitor_router", "attack_surface_router",
    "wave_b_router", "findings_wave_b_router", "unified_issues_router",
    "stage_matrix_router", "material_change_diff_router", "material_change_router",
    "change_tracker_router", "diff_router",
    "self_scan_router", "github_security_router", "github_issues_router",
}

CSPM_ROUTER_MODULES: Set[str] = {
    "network_security_router", "cloud_discovery_router", "db_security_router",
    "aws_security_hub_router", "azure_defender_router", "agentless_snapshot_router",
    "cert_router", "firewall_rule_router", "pam_router", "posture_score_router",
    "cloud_workload_protection_router", "zero_trust_enforcement_router",
    "zero_trust_policy_router", "cloud_security_engine_router", "network_traffic_router",
    "firewall_management_router", "cloud_cost_security_router", "nac_router",
    "waf_engine_router", "mdm_router", "casb_router", "iam_policy_router",
    "cloud_drift_router", "cloud_native_security_router", "kubernetes_security_router",
    "network_monitoring_router", "bandwidth_analysis_router", "service_account_auditor_router",
    "privilege_escalation_router", "firewall_policy_router", "network_segmentation_router",
    "crypto_key_management_router", "certificate_lifecycle_router", "data_lake_security_router",
    "mobile_device_management_router", "access_control_router", "wireless_security_router",
    "network_access_control_router", "mfa_management_router", "shadow_ai_router",
    "cloud_account_monitoring_router", "cloud_compliance_router", "cloud_connectors_router",
    "cloud_cost_optimization_router", "cloud_governance_router", "cloud_graph_router",
    "cloud_identity_router", "cloud_incident_response_router", "cloud_posture_router",
    "cloud_resource_inventory_router", "cloud_security_analytics_router",
    "cloud_security_findings_router", "cwpp_router", "cnapp_router",
    "cspm_engine_router", "cspm_deep_router", "cspm_connector_router", "cspm_router",
    "k8s_security_router", "multi_csp_router", "gcp_scc_router",
    "cloud_access_security_router", "identity_governance_router", "identity_lifecycle_router",
    "identity_risk_router", "digital_identity_router", "fuzzy_identity_router",
    "itdr_router", "ciem_router", "ciem_ad_router",
    "network_analyzer_router", "network_anomaly_router", "network_forensics_router",
    "network_threat_router", "network_topology_router",
    "waf_router", "rasp_router", "ddos_protection_router",
    "operational_technology_security_router", "ot_security_router",
    "physical_security_router", "iot_security_router",
    "saas_security_posture_router", "digital_twin_security_router",
    "privilege_escalation_detector_router", "privileged_access_governance_router",
    "privileged_identity_router", "privileged_session_recording_router",
    "access_anomaly_router", "access_governance_router", "access_matrix_router",
    "access_request_management_router", "user_access_review_router",
    "posture_router", "posture_advisor_router", "posture_benchmark_router",
    "security_baseline_router", "security_benchmark_router", "security_posture_benchmarking_router",
    "security_posture_history_router", "security_posture_maturity_router",
    "security_posture_pdf_router", "security_posture_reporting_router",
    "security_posture_scoring_router", "security_posture_trend_router",
    "config_benchmark_router", "drift_router", "cloud_drift_router",
    "zero_trust_router", "microsegmentation_policy_router",
    "pki_management_router", "quantum_crypto_router", "quantum_safe_crypto_router",
    "prowler_router", "defender_xdr_connector_router",
}

CTEM_ROUTER_MODULES: Set[str] = {
    "ctem_engine_router", "ctem_router", "ctem_pipeline_router",
    "threat_intel_router", "correlation_router", "soar_router",
    "purple_team_router", "ir_playbook_router", "ir_playbook_runner_router",
    "anomaly_router", "anomaly_ml_router", "threat_hunter_router",
    "bug_bounty_router", "breach_simulation_router", "phishing_router",
    "attack_path_router", "insider_threat_router", "drp_router",
    "deception_router", "composite_alert_router", "endpoint_security_router",
    "email_security_router", "threat_correlation_router", "toxic_combo_router",
    "uba_router", "digital_forensics_router", "threat_feed_aggregator_router",
    "asset_risk_calculator_router", "xdr_router", "edr_router",
    "edr_connector_router", "crowdstrike_falcon_router", "sentinelone_connector_router",
    "pentest_mgmt_router", "threat_intel_sharing_router", "phishing_simulation_router",
    "ioc_enrichment_router", "red_team_mgmt_router", "ai_security_advisor_router",
    "threat_actor_router", "threat_actor_tracking_router", "threat_attribution_router",
    "threat_brief_router", "threat_deception_management_router", "threat_exposure_router",
    "threat_feed_subscription_router", "threat_geolocation_router",
    "threat_hunting_playbook_router", "threat_hunting_router",
    "threat_indicator_router", "threat_intel_connector_router",
    "threat_intel_enrichment_router", "threat_intel_fusion_router",
    "threat_intel_platform_router", "threat_landscape_router",
    "threat_model_generator_router", "threat_model_router",
    "threat_modeling_pipeline_router", "threat_modeling_router",
    "threat_response_router", "threat_score_router", "threat_simulation_router",
    "threat_vector_analysis_router", "zero_day_intelligence_router",
    "threat_intelligence_automation_router", "threat_intelligence_confidence_router",
    "cyber_threat_intelligence_router", "cyber_threat_modeling_router",
    "deception_analytics_router", "hunting_automation_router",
    "incident_response_router", "incident_comms_router", "incident_cost_router",
    "incident_kb_router", "incident_lessons_router", "incident_metrics_router",
    "incident_orchestration_router", "incident_timeline_router", "incident_triage_router",
    "breach_detection_router", "breach_response_router",
    "siem_connector_router", "siem_integration_router", "siem_output_router",
    "ndr_router", "mpte_router", "mpte_orchestrator_router",
    "auto_pentest_router", "dast_pentest_router", "micro_pentest_router",
    "pentest_router", "red_team_router",
    "alert_enrichment_router", "alert_triage_router", "alerting_notification_router",
    "composite_alert_router", "endpoint_threat_hunting_router",
    "malware_router", "malware_analysis_router", "malware_bazaar_router",
    "ransomware_protection_router", "anti_phishing_router", "phishtank_router",
    "abuseipdb_router", "ip_reputation_router", "tor_exit_nodes_router",
    "urlhaus_router", "urlscan_router", "spamhaus_router",
    "dbir_router", "sans_isc_router", "otx_router",
    "attack_surface_engine_router", "sigmahq_router",
    "soar_router", "soc_automation_router", "soc_triage_router", "soc_workflow_router",
    "ai_powered_soc_router", "behavioral_analytics_router",
    "dark_web_monitoring_router", "passive_dns_router",
}

GRC_ROUTER_MODULES: Set[str] = {
    "playbook_routes", "risk_register_router", "policy_generator_router",
    "compliance_reports_router", "evidence_chain_router", "compliance_planner_router",
    "evidence_collector_router", "exception_policy_router", "executive_report_router",
    "exec_security_reports_router", "regulatory_tracker_engine_router",
    "vendor_scorecard_router", "kpi_router", "auto_evidence_router",
    "vendor_risk_router", "audit_analytics_router", "security_kpi_router",
    "playbook_router", "compliance_automation_router", "data_classification_router",
    "compliance_gap_router", "grc_router", "cyber_insurance_router",
    "security_training_router", "risk_quantification_router", "security_roadmap_router",
    "data_governance_router", "compliance_scanner_router", "security_health_router",
    "security_exception_router", "ccm_router", "awareness_score_router",
    "identity_analytics_router", "report_scheduler_router", "iga_router",
    "data_retention_router", "compliance_engine_router", "compliance_evidence_router",
    "compliance_mapping_router", "compliance_router", "compliance_workflow_router",
    "compliance_calendar_router", "compliance_seed_router",
    "risk_router", "risk_acceptance_router", "risk_aggregator_router",
    "risk_quantification_engine_router", "risk_quantifier_router",
    "risk_register_engine_router", "risk_scenario_router", "risk_scoring_router",
    "risk_treatment_router", "composite_risk_router",
    "regulatory_reporting_router", "regulatory_tracker_router",
    "gdpr_compliance_router", "fedramp_router", "fips_router",
    "privacy_gdpr_router", "privacy_impact_assessment_router",
    "data_privacy_router", "data_security_router",
    "audit_management_router", "audit_router", "cmdb_router",
    "evidence_router", "evidence_vault_router",
    "questionnaire_router", "security_questionnaire_router",
    "control_testing_router", "gap_router", "security_gap_analysis_router",
    "kpi_tracking_router", "vendor_compliance_router",
    "third_party_vendor_router", "tprm_exchange_router",
    "commercial_vendor_router",
    "playbook_marketplace_router", "playbook_routes",
    "auto_waiver_router", "auto_evidence_router",
    "awareness_campaign_router", "security_awareness_gamification_router",
    "security_awareness_metrics_router", "security_awareness_program_router",
    "security_champions_router", "security_culture_router",
    "security_training_effectiveness_router", "training_router",
    "fair_per_bu_router", "formula_transparency_router",
    "ciso_report_router", "executive_dashboard_router", "executive_reporting_router",
    "report_builder_router", "reports_router", "scheduled_reports_router",
    "export_coverage_router", "export_router",
    "security_maturity_router", "security_program_maturity_router",
    "security_okr_router",
    "policy_engine_router", "policy_enforcement_router",
    "policy_router", "policies_router", "unified_rules_router",
    "dynamic_rule_dsl_router",
    "risk_quantification_engine_router",
    "data_exfiltration_router", "data_discovery_router",
    "dlp_router",
    "subsidiary_attribution_router",
    "security_budget_router", "security_investment_router", "security_roi_router",
    "cyber_resilience_router",
}

PLATFORM_ROUTER_MODULES: Set[str] = {
    "users_router", "teams_router", "admin_router", "tenant_router",
    "system_router", "metrics_router", "platform_router", "analytics_router",
    "ai_orchestrator_router", "formula_transparency_router",
    "websocket_alerts_router", "ws_events_router",
    "stream_router", "sse_router", "streaming_router",
    "mcp_routes", "mcp_gateway_router", "mcp_router", "mcp_protocol_router",
    "trustgraph_routes", "trustgraph_quality_router", "trustgraph_maintenance_router",
    "trustgraph_integration_router", "trustgraph_backbone_router", "trustgraph_migrator_router",
    "iam_sso_router", "connectors_router", "org_router", "servicenow_sync_router",
    "auth_router", "sso_router", "bulk_router", "collaboration_router",
    "sla_router", "sla_engine_router", "sla_management_router", "sla_escalation_router",
    "workflows_router", "workflow_engine_router", "workflow_router",
    "change_management_router", "wave_d_integrations_router", "hooks_router",
    "notification_router", "webhook_router", "webhook_dlq_router",
    "webhook_events_router", "webhook_notifications_router",
    "webhook_subscriptions_router", "webhook_verifier_router",
    "session_router", "apikey_router", "oauth2_router",
    "rbac_router", "scim_router",
    "onboarding_router", "org_hierarchy_router",
    "admin_wizard_router", "system_health_router",
    "health", "version_router", "versioning_router",
    "backup_router", "backup_validator_router",
    "cache_router", "queue_router", "rate_limit_router", "tenant_rate_limiter_router",
    "integration_health_router", "integration_hub_router", "integration_marketplace_router",
    "marketplace_router", "n8n_router", "n8n_mgmt_router",
    "pagerduty_router", "slack_bot_router", "slack_notifier_router",
    "jira_sync_router", "github_app_router",
    "developer_portal_router", "developer_profiles_router",
    "graph_router", "graph_rag_router", "graphql_router",
    "graphrag_router", "nl_graph_router", "knowledge_graph_router",
    "context_engine_router", "duckdb_analytics_router",
    "analytics_dashboard_router", "analytics_engine_router",
    "user_analytics_router", "security_metrics_router",
    "security_metrics_aggregator_router", "security_metrics_collector_router",
    "security_metrics_dashboard_router", "metrics_aggregator_router",
    "metrics_timeseries_router",
    "observability_router", "log_management_router",
    "event_bus_router", "ingestion", "universal_ingest_router", "scanner_ingest_router",
    "local_file_store_router", "upload_manager",
    "brain_router", "pipeline_router", "pipeline_routes", "predictions_router",
    "feed_manager_router", "feed_registry_router", "feed_correlator_router",
    "feeds_router", "offline_feed_router",
    "llm_router", "llm_loop_metrics_router", "llm_monitor_router",
    "self_learning_router", "copilot_router", "single_agent_router",
    "agents_router", "ai_governance_router",
    "council_enhanced_router", "algorithmic_router",
    "mitre_attack_router", "mitre_attack_coverage_router", "mitre_coverage_router",
    "mitre_mapper_router", "mitre_navigator_router",
    "graph_rag_router", "knowledge_graph_router",
    "tag_router", "deduplication_router", "bulk_operations_router",
    "error_audit_router", "changelog_router",
    "openclaw_router", "ide_router", "ide_backend_router",
    "mindsdb_router", "vllm_router",
    "security_data_pipeline_router", "security_event_correlation_router",
    "security_event_timeline_router", "security_telemetry_router",
    "security_kb_router", "security_query_router",
    "security_registry_router", "security_service_catalog_router",
    "security_tool_inventory_router",
    "deployment_router", "upgrade_path_router", "air_gap_bundle_router", "airgap_router",
    "design_doc_router", "fips_router",
    "cmdb_router", "org_middleware",
    "postfix_verify_router", "verification_router",
    "zero_gravity_router",
    "trust_center_router",
    "security_architecture_review_router",
    "security_automation_router", "security_capacity_planning_router",
    "security_change_management_router", "security_chaos_router",
    "security_dependency_mapping_router", "security_dependency_risk_router",
    "security_exception_workflow_router", "security_findings_router",
    "security_health_scorecard_router", "security_scoreboard_router",
    "security_scorecard_engine_router", "security_scorecard_router",
    "security_tabletop_router",
    "security_operations_metrics_router",
    "privilege_escalation_detector_router",
    "unified_dashboard_router",
    "wave_a_code_intel_router", "wave_c_router", "wave_d_integrations_router",
    "commercial_dast_routers",
    "findings_routes", "findings_lifecycle_router",
    "soc_triage_router",
    "app_config_router",
    "rbac_router", "scim_router",
    "db_security_router",
}

# Ordered list: classification checked in order; first match wins.
SUB_APP_ORDER = ["aspm", "cspm", "ctem", "grc", "platform"]

MODULE_TO_SUBAPP: Dict[str, str] = {}
for _mod in ASPM_ROUTER_MODULES:
    MODULE_TO_SUBAPP[_mod] = "aspm"
# Later entries override — cspm > aspm for shared modules
for _mod in CSPM_ROUTER_MODULES:
    MODULE_TO_SUBAPP[_mod] = "cspm"
for _mod in CTEM_ROUTER_MODULES:
    MODULE_TO_SUBAPP[_mod] = "ctem"
for _mod in GRC_ROUTER_MODULES:
    MODULE_TO_SUBAPP[_mod] = "grc"
for _mod in PLATFORM_ROUTER_MODULES:
    MODULE_TO_SUBAPP[_mod] = "platform"

# URL prefix heuristics for fallback classification
PREFIX_TO_SUBAPP: List[Tuple[str, str]] = [
    ("/api/v1/triage", "aspm"),
    ("/api/v1/sbom", "aspm"),
    ("/api/v1/sast", "aspm"),
    ("/api/v1/dast", "aspm"),
    ("/api/v1/iac", "aspm"),
    ("/api/v1/vuln", "aspm"),
    ("/api/v1/secret", "aspm"),
    ("/api/v1/supply-chain", "aspm"),
    ("/api/v1/supply_chain", "aspm"),
    ("/api/v1/code", "aspm"),
    ("/api/v1/asset", "aspm"),
    ("/api/v1/attack-surface", "aspm"),
    ("/api/v1/attack_surface", "aspm"),
    ("/api/v1/remediation", "aspm"),
    ("/api/v1/findings", "aspm"),
    ("/api/v1/cloud", "cspm"),
    ("/api/v1/cspm", "cspm"),
    ("/api/v1/posture", "cspm"),
    ("/api/v1/network", "cspm"),
    ("/api/v1/k8s", "cspm"),
    ("/api/v1/kubernetes", "cspm"),
    ("/api/v1/iam", "cspm"),
    ("/api/v1/identity", "cspm"),
    ("/api/v1/zero-trust", "cspm"),
    ("/api/v1/zero_trust", "cspm"),
    ("/api/v1/firewall", "cspm"),
    ("/api/v1/threat", "ctem"),
    ("/api/v1/ctem", "ctem"),
    ("/api/v1/attack-path", "ctem"),
    ("/api/v1/attack_path", "ctem"),
    ("/api/v1/incident", "ctem"),
    ("/api/v1/soar", "ctem"),
    ("/api/v1/xdr", "ctem"),
    ("/api/v1/edr", "ctem"),
    ("/api/v1/siem", "ctem"),
    ("/api/v1/malware", "ctem"),
    ("/api/v1/breach", "ctem"),
    ("/api/v1/phish", "ctem"),
    ("/api/v1/red-team", "ctem"),
    ("/api/v1/red_team", "ctem"),
    ("/api/v1/pentest", "ctem"),
    ("/api/v1/compliance", "grc"),
    ("/api/v1/grc", "grc"),
    ("/api/v1/risk", "grc"),
    ("/api/v1/audit", "grc"),
    ("/api/v1/evidence", "grc"),
    ("/api/v1/policy", "grc"),
    ("/api/v1/vendor", "grc"),
    ("/api/v1/regulatory", "grc"),
    ("/api/v1/training", "grc"),
    ("/api/v1/kpi", "grc"),
    ("/api/v1/report", "grc"),
    ("/api/v1/executive", "grc"),
]


# ---------------------------------------------------------------------------
# Sub-app metadata
# ---------------------------------------------------------------------------
SUBAPP_META = {
    "aspm": {
        "title": "ASPM — Application Security Posture Management",
        "description": (
            "Endpoints covering the full application security lifecycle: SAST/DAST/IaC scanning, "
            "SBOM generation and re-evaluation, secret detection, software composition analysis, "
            "supply-chain risk, container security, vulnerability management, CI/CD gating, "
            "code intelligence, asset inventory, and autonomous remediation."
        ),
        "tags": ["ASPM", "Vulnerability Management", "SBOM", "Supply Chain", "Container Security", "Secrets"],
    },
    "cspm": {
        "title": "CSPM — Cloud Security Posture Management",
        "description": (
            "Endpoints covering cloud posture across AWS/Azure/GCP: resource inventory, "
            "misconfiguration detection, CIS benchmark compliance, drift detection, "
            "network security (NDR/WAF/firewall), identity & access management, "
            "zero-trust enforcement, Kubernetes security, and cryptographic key lifecycle."
        ),
        "tags": ["CSPM", "Cloud Security", "Network Security", "Identity", "Zero Trust", "IAM"],
    },
    "ctem": {
        "title": "CTEM — Continuous Threat Exposure Management",
        "description": (
            "Endpoints covering threat intelligence, attack path analysis, incident response, "
            "SOAR playbooks, breach simulation, phishing simulation, EDR/XDR integrations, "
            "SIEM connectors, threat hunting, MPTE orchestration, anomaly detection (ML/UEBA), "
            "and purple/red team management."
        ),
        "tags": ["CTEM", "Threat Intelligence", "Incident Response", "SOAR", "XDR", "Attack Simulation"],
    },
    "grc": {
        "title": "GRC — Governance, Risk & Compliance",
        "description": (
            "Endpoints covering compliance frameworks (SOC2/ISO27001/PCI-DSS/GDPR/FedRAMP), "
            "evidence collection and vault, risk register, policy engine, vendor risk management "
            "(TPRM), audit management, GRC workflows, KPI/OKR tracking, executive reporting, "
            "data classification, privacy, DLP, and security awareness."
        ),
        "tags": ["GRC", "Compliance", "Risk Management", "Audit", "Policy", "Evidence"],
    },
    "platform": {
        "title": "Platform — Auth / Tenancy / Integrations / Infra",
        "description": (
            "Cross-cutting platform endpoints: authentication (JWT/SSO/SAML/OAuth2), user & team "
            "management, multi-tenant org hierarchy, admin controls, MCP gateway (650+ tools), "
            "TrustGraph knowledge store, Brain Pipeline ingestion, streaming/WebSocket events, "
            "webhook management, system health, analytics, DuckDB, and third-party integrations "
            "(Jira, Slack, ServiceNow, PagerDuty, n8n)."
        ),
        "tags": ["Platform", "Auth", "Admin", "MCP", "TrustGraph", "Webhooks", "Integrations"],
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _method_badge(method: str) -> str:
    return f"`{method.upper()}`"


def _safe_schema(field_info: Any) -> str:
    """Return a human-readable type string from a Pydantic FieldInfo."""
    try:
        annotation = field_info.annotation
        if annotation is None:
            return "any"
        name = getattr(annotation, "__name__", None) or str(annotation)
        # Unwrap Optional[X]
        name = re.sub(r"typing\.Optional\[(.+)\]", r"\1 (optional)", name)
        name = re.sub(r"typing\.List\[(.+)\]", r"List[\1]", name)
        name = re.sub(r"typing\.Dict\[(.+)\]", r"Dict[\1]", name)
        return name
    except Exception:
        return "any"


def _model_fields_table(model_class: Any) -> str:
    """Return a markdown table of Pydantic model fields."""
    if model_class is None:
        return ""
    try:
        fields = model_class.model_fields
    except AttributeError:
        try:
            fields = model_class.__fields__
        except AttributeError:
            return ""
    if not fields:
        return ""
    lines = ["| Field | Type | Required | Default | Description |",
             "|-------|------|----------|---------|-------------|"]
    for fname, finfo in fields.items():
        try:
            ftype = _safe_schema(finfo)
            required = "Yes" if finfo.is_required() else "No"
            default = "" if finfo.is_required() else str(finfo.default)
            desc = (finfo.description or "").replace("|", "\\|").replace("\n", " ")
        except Exception:
            ftype = "any"
            required = "?"
            default = ""
            desc = ""
        lines.append(f"| `{fname}` | {ftype} | {required} | {default} | {desc} |")
    return "\n".join(lines)


def _params_table(route: Any) -> str:
    """Return markdown table of path + query parameters."""
    if not hasattr(route, "dependant"):
        return ""
    try:
        path_params = route.dependant.path_params
        query_params = route.dependant.query_params
    except AttributeError:
        return ""
    rows = []
    for p in path_params:
        ptype = getattr(p.field_info, "annotation", None)
        ptype_str = getattr(ptype, "__name__", "string") if ptype else "string"
        rows.append(f"| `{p.name}` | path | {ptype_str} | Yes | — |")
    for p in query_params:
        ptype = getattr(p.field_info, "annotation", None)
        ptype_str = getattr(ptype, "__name__", "string") if ptype else "string"
        required = "Yes" if p.required else "No"
        default = "" if p.required else str(p.default)
        desc = (getattr(p.field_info, "description", "") or "").replace("|", "\\|")
        rows.append(f"| `{p.name}` | query | {ptype_str} | {required} | {desc or default} |")
    if not rows:
        return ""
    header = ["| Name | In | Type | Required | Notes |",
              "|------|----|------|----------|-------|"]
    return "\n".join(header + rows)


def _body_model(route: Any) -> Optional[Any]:
    """Return the Pydantic model for the request body, if any."""
    try:
        body_field = route.dependant.body_params
        if body_field:
            return body_field[0].field_info.annotation
    except Exception:
        pass
    return None


def _auth_hint(route: Any) -> str:
    """Detect auth dependency from route dependencies."""
    try:
        deps = [str(d.dependency) for d in route.dependencies]
        dep_str = " ".join(deps)
        if "_verify_api_key" in dep_str or "api_key_auth" in dep_str:
            if "admin:all" in dep_str:
                return "API Key + scope `admin:all`"
            scope_match = re.search(r'"([a-z]+:[a-zA-Z_]+)"', dep_str)
            if scope_match:
                return f"API Key + scope `{scope_match.group(1)}`"
            return "API Key required"
        if "api_key_auth" in dep_str:
            return "API Key required"
    except Exception:
        pass
    return "See app-level auth (API Key via `X-API-Key` header)"


def _response_schemas(route: Any) -> str:
    """Return a markdown section describing response schemas."""
    lines = []
    try:
        responses = route.responses or {}
    except AttributeError:
        responses = {}
    # Always add 200 from response_model
    try:
        rm = route.response_model
        if rm is not None:
            model_name = getattr(rm, "__name__", str(rm))
            lines.append(f"**200 OK** — `{model_name}`")
            fields_table = _model_fields_table(rm)
            if fields_table:
                lines.append("")
                lines.append(fields_table)
    except Exception:
        lines.append("**200 OK** — See response body")
    # Additional declared status codes
    for code, resp_data in responses.items():
        if code == 200:
            continue
        desc = getattr(resp_data, "description", str(resp_data)) if resp_data else ""
        lines.append(f"\n**{code}** — {desc}")
    # Standard errors always possible
    lines.append("\n**401** — Unauthorized (missing or invalid API key)")
    lines.append("**403** — Forbidden (insufficient scope)")
    lines.append("**422** — Validation Error (request body/params)")
    lines.append("**500** — Internal Server Error")
    return "\n".join(lines)


def _classify_route(route: Any) -> str:
    """Return sub-app bucket name for a route."""
    try:
        # Prefer endpoint module name
        endpoint_mod = getattr(route.endpoint, "__module__", "") or ""
        # e.g. "apps.api.triage_router"
        mod_short = endpoint_mod.split(".")[-1]
        if mod_short in MODULE_TO_SUBAPP:
            return MODULE_TO_SUBAPP[mod_short]
        # Also check second-to-last segment (for nested)
        parts = endpoint_mod.split(".")
        for part in reversed(parts):
            if part in MODULE_TO_SUBAPP:
                return MODULE_TO_SUBAPP[part]
    except Exception:
        pass
    # Fallback: URL prefix
    path = getattr(route, "path", "")
    for prefix, bucket in PREFIX_TO_SUBAPP:
        if path.startswith(prefix):
            return bucket
    return "platform"  # default bucket


def _format_route(route: Any, index: int) -> str:
    """Return a full markdown section for one route."""
    path = getattr(route, "path", "?")
    methods = sorted(getattr(route, "methods", None) or ["GET"])
    method = methods[0]
    summary = getattr(route, "summary", "") or ""
    description = getattr(route, "description", "") or ""
    operation_id = getattr(route, "operation_id", "") or ""
    tags = getattr(route, "tags", []) or []

    # If no summary, derive from operation_id or path
    if not summary:
        if operation_id:
            summary = operation_id.replace("_", " ").title()
        else:
            summary = f"{method} {path}"

    if not description:
        description = "[CITATION NEEDED — needs docstring]"

    # Build section
    anchor = re.sub(r"[^a-z0-9-]", "-", f"{method}-{path}".lower())
    lines = [
        f"### {index}. {_method_badge(method)} `{path}`",
        "",
        f"**Summary:** {summary}",
        "",
    ]

    if tags:
        lines += [f"**Tags:** {', '.join(tags)}", ""]

    lines += [
        f"**Auth:** {_auth_hint(route)}",
        "",
        "**Description:**",
        "",
        textwrap.fill(description, width=100) if description != "[CITATION NEEDED — needs docstring]"
        else description,
        "",
    ]

    params_table = _params_table(route)
    if params_table:
        lines += ["**Parameters:**", "", params_table, ""]

    body_model = _body_model(route)
    if body_model is not None:
        model_name = getattr(body_model, "__name__", str(body_model))
        lines += [f"**Request Body:** `{model_name}`", ""]
        fields_table = _model_fields_table(body_model)
        if fields_table:
            lines += [fields_table, ""]

    lines += ["**Responses:**", "", _response_schemas(route), "", "---", ""]

    return "\n".join(lines)


def _subapp_header(name: str, route_count: int, generated_at: str) -> str:
    meta = SUBAPP_META[name]
    tags_str = ", ".join(f"`{t}`" for t in meta["tags"])
    return f"""# {meta['title']}

> **Generated:** {generated_at}
> **Endpoint count:** {route_count}
> **Tags:** {tags_str}

## Overview

{meta['description']}

## Authentication

All endpoints (unless marked **Public**) require:

```
X-API-Key: <your-api-token>
```

Tokens are managed via **Admin > API Tokens** in the UI or `POST /api/v1/auth/token`.

Some endpoints require additional OAuth2-style scopes (`read:findings`, `write:findings`, `admin:all`).
The required scope is noted in each endpoint's **Auth** field.

## Error Response Format

All error responses follow:

```json
{{
  "detail": "Human-readable error message",
  "error_code": "MACHINE_READABLE_CODE",
  "request_id": "uuid-v4"
}}
```

## Pagination

List endpoints that support pagination accept:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | 1-based page number |
| `page_size` | integer | 50 | Items per page (max 500) |
| `cursor` | string | — | Cursor token for cursor-based pagination |

Paginated responses include:

```json
{{
  "items": [...],
  "total": 1234,
  "page": 1,
  "page_size": 50,
  "next_cursor": "opaque-token"
}}
```

---

## Endpoints

"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out_dir = REPO_ROOT / "docs" / "api-reference"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Loading FastAPI app (this may take 30-60s for 590+ routers)...")
    try:
        from apps.api.app import create_app
        app = create_app()
    except Exception as exc:
        print(f"ERROR: Could not import create_app: {exc}")
        raise

    # Walk all routes
    from fastapi.routing import APIRoute
    all_routes = [r for r in app.routes if isinstance(r, APIRoute)]
    print(f"Total APIRoute objects: {len(all_routes)}")

    # Classify
    buckets: Dict[str, List[Any]] = defaultdict(list)
    for route in all_routes:
        bucket = _classify_route(route)
        buckets[bucket].append(route)

    # Ensure all sub-apps present
    for name in SUB_APP_ORDER:
        if name not in buckets:
            buckets[name] = []

    counts: Dict[str, int] = {}
    commit_notes: List[str] = []

    for name in SUB_APP_ORDER:
        routes = buckets[name]
        counts[name] = len(routes)
        print(f"  {name.upper()}: {len(routes)} routes")

        header = _subapp_header(name, len(routes), generated_at)
        sections: List[str] = [header]

        for i, route in enumerate(routes, start=1):
            try:
                sections.append(_format_route(route, i))
            except Exception as exc:
                path = getattr(route, "path", "?")
                sections.append(f"### {i}. `{path}` — *[generation error: {exc}]*\n\n---\n")

        content = "\n".join(sections)
        out_path = out_dir / f"{name}.md"
        out_path.write_text(content, encoding="utf-8")
        size_kb = out_path.stat().st_size // 1024
        print(f"  Wrote {out_path} ({size_kb} KB)")
        commit_notes.append(f"docs(api): API reference — {name.upper()} sub-app ({len(routes)} endpoints)")

    total = sum(counts.values())

    # Write README
    readme_lines = [
        f"# ALDECI API Reference",
        "",
        f"> **Generated:** {generated_at}  ",
        f"> **Total endpoints documented:** {total}  ",
        f"> **Generator:** `scripts/gen_api_reference.py`",
        "",
        "## Sub-app Endpoint Counts",
        "",
        "| Sub-app | Endpoints | File |",
        "|---------|-----------|------|",
    ]
    for name in SUB_APP_ORDER:
        meta = SUBAPP_META[name]
        readme_lines.append(
            f"| [{meta['title'].split(' — ')[0]}](./{name}.md) | {counts[name]} | `docs/api-reference/{name}.md` |"
        )
    readme_lines += [
        "",
        f"**Total:** {total} endpoints across {len(SUB_APP_ORDER)} sub-apps",
        "",
        "## Quickstart",
        "",
        "```bash",
        "# Obtain an API token (dev mode)",
        "curl -X POST http://localhost:8000/api/v1/auth/token \\",
        '  -H "Content-Type: application/json" \\',
        '  -d \'{"username":"admin","password":"<password>"}\'',
        "",
        "# Use the token",
        "curl http://localhost:8000/api/v1/triage/findings \\",
        '  -H "X-API-Key: <your-token>"',
        "```",
        "",
        "## Authentication Model",
        "",
        "| Method | Header | Notes |",
        "|--------|--------|-------|",
        "| API Key | `X-API-Key: <token>` | Primary method for all API calls |",
        "| JWT Bearer | `Authorization: Bearer <jwt>` | Issued by `/api/v1/auth/token` |",
        "| SSO/SAML | Session cookie | Browser UI flows via `/api/v1/sso/` |",
        "| OAuth2 | `Authorization: Bearer <token>` | `/api/v1/oauth2/` endpoints |",
        "",
        "### Scopes",
        "",
        "| Scope | Access Level |",
        "|-------|-------------|",
        "| `read:findings` | Read security findings, reports, dashboards |",
        "| `write:findings` | Create/update findings, trigger scans |",
        "| `admin:all` | Full admin access — user management, system config |",
        "",
        "## Pagination Convention",
        "",
        "All list endpoints accept `?page=1&page_size=50` query parameters.",
        "Maximum `page_size` is 500. Cursor-based pagination available via `?cursor=<token>`.",
        "",
        "## Error Response Format",
        "",
        "```json",
        "{",
        '  "detail": "Human-readable error message",',
        '  "error_code": "MACHINE_READABLE_CODE",',
        '  "request_id": "550e8400-e29b-41d4-a716-446655440000"',
        "}",
        "```",
        "",
        "## Rate Limiting",
        "",
        "| Tier | Requests/min | Burst |",
        "|------|-------------|-------|",
        "| Starter | 60 | 10 |",
        "| Pro | 300 | 50 |",
        "| Enterprise | 1000 | 200 |",
        "",
        "Rate limit headers returned on every response:",
        "- `X-RateLimit-Limit` — requests allowed per window",
        "- `X-RateLimit-Remaining` — requests remaining",
        "- `X-RateLimit-Reset` — Unix timestamp when window resets",
        "",
        "## Sub-app Reference",
        "",
    ]
    for name in SUB_APP_ORDER:
        meta = SUBAPP_META[name]
        readme_lines += [
            f"### [{meta['title']}](./{name}.md)",
            "",
            meta["description"],
            "",
        ]

    readme_path = out_dir / "README.md"
    readme_path.write_text("\n".join(readme_lines), encoding="utf-8")
    size_kb = readme_path.stat().st_size // 1024
    print(f"  Wrote {readme_path} ({size_kb} KB)")

    print(f"\nDone. {total} endpoints documented across {len(SUB_APP_ORDER)} sub-apps.")
    print("\nSuggested commits:")
    for note in commit_notes:
        print(f"  {note}")
    print("  docs(api): API reference — README + cross-cutting concerns")

    # Write a summary JSON for CI/memory
    summary = {
        "generated_at": generated_at,
        "total_endpoints": total,
        "per_subapp": counts,
        "generator": "scripts/gen_api_reference.py",
    }
    import json
    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"  Wrote {summary_path}")


if __name__ == "__main__":
    main()
