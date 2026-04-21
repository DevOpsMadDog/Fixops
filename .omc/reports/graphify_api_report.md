# ALDECI Backend API Graph Report

**Generated:** 2026-04-21 21:15 UTC
**Tool:** Graphify (AST extraction + knowledge graph)
**Scope:** `suite-api/` — all 568 router files

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total API Endpoints | **5,356** |
| Router Files | **568** |
| Stub Routers (0 endpoints) | **1** |
| Unique Domain Groups | **512** |
| Routes with Path Parameters | **1,746** (32%) |
| Static Routes | **3,610** (67%) |
| suite-api Graph Nodes | **16,395** |
| suite-api Graph Edges | **27,624** |
| suite-api Graph Communities | **282** |
| Global Graph Nodes | **2,258** |
| Global Graph Edges | **2,031** |

---

## HTTP Method Distribution

| Method | Count | % | Bar |
|--------|------:|--:|-----|
| `GET` | 2,962 | 55% | ███████████ |
| `POST` | 1,982 | 37% | ███████ |
| `PUT` | 208 | 3% |  |
| `PATCH` | 104 | 1% |  |
| `DELETE` | 100 | 1% |  |

---

## Top 20 Most-Connected Nodes (suite-api Knowledge Graph)

Highest-degree nodes — symbols and files most referenced across the entire API layer.

| Rank | Degree | Node |
|-----:|-------:|------|
| 1 | 2,458 | `BaseModel` |
| 2 | 2,082 | `str` |
| 3 | 258 | `.to_dict()` |
| 4 | 113 | `.close()` |
| 5 | 100 | `gap_router.py` |
| 6 | 69 | `agents_router.py` |
| 7 | 53 | `micro_pentest_router.py` |
| 8 | 52 | `copilot_router.py` |
| 9 | 50 | `Enum` |
| 10 | 46 | `vendor_risk_router.py` |
| 11 | 46 | `mpte_router.py` |
| 12 | 45 | `airgap_router.py` |
| 13 | 44 | `bulk_router.py` |
| 14 | 44 | `analytics_router.py` |
| 15 | 43 | `remediation_router.py` |
| 16 | 41 | `InputNormalizer` |
| 17 | 41 | `vuln_discovery_router.py` |
| 18 | 41 | `list_findings()` |
| 19 | 40 | `backup_validator_router.py` |
| 20 | 39 | `evidence_router.py` |

---

## Top 30 Routers by Endpoint Count

| Rank | Endpoints | Prefix | File |
|-----:|----------:|--------|------|
| 1 | 33 | `/api/v1/analytics` | `analytics_router.py` |
| 2 | 32 | `/api/v1/copilot/agents` | `agents_router.py` |
| 3 | 28 | `/api/v1/brain` | `brain_router.py` |
| 4 | 27 | `/api/v1/airgap` | `airgap_router.py` |
| 5 | 27 | `/api/v1/remediation` | `remediation_router.py` |
| 6 | 26 | `/api/v1/inventory` | `inventory_router.py` |
| 7 | 24 | `/api/v1/assets` | `asset_inventory_router.py` |
| 8 | 24 | `/api/v1/backup-dr` | `backup_validator_router.py` |
| 9 | 24 | `/api/v1/collaboration` | `collaboration_router.py` |
| 10 | 23 | `/api/v1/mpte` | `mpte_router.py` |
| 11 | 23 | `/api/v1/trust` | `trust_center_router.py` |
| 12 | 21 | `/api/v1/fail` | `fail_router.py` |
| 13 | 21 | `/api/v1/self-learning` | `self_learning_router.py` |
| 14 | 20 | `/api/v1/attack-surface` | `attack_surface_manager_router.py` |
| 15 | 20 | `/api/v1/deduplication` | `deduplication_router.py` |
| 16 | 20 | `/api/v1/threat-intel` | `threat_intel_router.py` |
| 17 | 19 | `/api/v1/audit` | `audit_router.py` |
| 18 | 19 | `/api/v1/changes` | `change_management_router.py` |
| 19 | 19 | `/api/v1/micro-pentest` | `micro_pentest_router.py` |
| 20 | 19 | `/api/v1/network` | `network_security_router.py` |
| 21 | 19 | `/api/v1/risks` | `risk_register_router.py` |
| 22 | 18 | `/api/v1/cloud-cost` | `cloud_cost_security_router.py` |
| 23 | 18 | `/api/v1/evidence-collector` | `evidence_collector_router.py` |
| 24 | 18 | `/evidence` | `evidence_router.py` |
| 25 | 18 | `/api/v1/secrets` | `secrets_router.py` |
| 26 | 17 | `/api/v1/autofix` | `autofix_router.py` |
| 27 | 17 | `/api/v1/code-to-cloud` | `code_to_cloud_router.py` |
| 28 | 17 | `/compliance-engine` | `compliance_engine_router.py` |
| 29 | 17 | `/api/v1/dlp` | `dlp_router.py` |
| 30 | 16 | `/api/v1/copilot` | `copilot_router.py` |

---

## Top 40 Domains by Endpoint Count

| Rank | Domain | Endpoints | Bar |
|-----:|--------|----------:|-----|
| 1 | `analytics` | 42 | ██████████████ |
| 2 | `remediation` | 38 | ████████████ |
| 3 | `brain` | 36 | ████████████ |
| 4 | `integrations` | 36 | ████████████ |
| 5 | `attack-surface` | 33 | ███████████ |
| 6 | `agents` | 32 | ██████████ |
| 7 | `changes` | 32 | ██████████ |
| 8 | `workflows` | 31 | ██████████ |
| 9 | `network` | 30 | ██████████ |
| 10 | `vendors` | 28 | █████████ |
| 11 | `airgap` | 27 | █████████ |
| 12 | `reports` | 27 | █████████ |
| 13 | `secrets` | 27 | █████████ |
| 14 | `inventory` | 26 | ████████ |
| 15 | `compliance` | 25 | ████████ |
| 16 | `assets` | 24 | ████████ |
| 17 | `backup-dr` | 24 | ████████ |
| 18 | `collaboration` | 24 | ████████ |
| 19 | `mitre` | 24 | ████████ |
| 20 | `attack-sim` | 23 | ███████ |
| 21 | `ctem` | 23 | ███████ |
| 22 | `mpte` | 23 | ███████ |
| 23 | `policies` | 23 | ███████ |
| 24 | `trust` | 23 | ███████ |
| 25 | `bulk` | 22 | ███████ |
| 26 | `fail` | 21 | ███████ |
| 27 | `graph` | 21 | ███████ |
| 28 | `metrics` | 21 | ███████ |
| 29 | `self-learning` | 21 | ███████ |
| 30 | `supply-chain` | 21 | ███████ |
| 31 | `api-security-engine` | 20 | ██████ |
| 32 | `cspm` | 20 | ██████ |
| 33 | `deduplication` | 20 | ██████ |
| 34 | `phishing` | 20 | ██████ |
| 35 | `threat-intel` | 20 | ██████ |
| 36 | `audit` | 19 | ██████ |
| 37 | `micro-pentest` | 19 | ██████ |
| 38 | `nac` | 19 | ██████ |
| 39 | `risks` | 19 | ██████ |
| 40 | `vulns` | 19 | ██████ |

---

## Complete Router Registry (568 Routers)

| # | Endpoints | Prefix | File |
|--:|----------:|--------|------|
| 1 | 33 | `/api/v1/analytics` | `analytics_router.py` |
| 2 | 32 | `/api/v1/copilot/agents` | `agents_router.py` |
| 3 | 28 | `/api/v1/brain` | `brain_router.py` |
| 4 | 27 | `/api/v1/airgap` | `airgap_router.py` |
| 5 | 27 | `/api/v1/remediation` | `remediation_router.py` |
| 6 | 26 | `/api/v1/inventory` | `inventory_router.py` |
| 7 | 24 | `/api/v1/assets` | `asset_inventory_router.py` |
| 8 | 24 | `/api/v1/backup-dr` | `backup_validator_router.py` |
| 9 | 24 | `/api/v1/collaboration` | `collaboration_router.py` |
| 10 | 23 | `/api/v1/mpte` | `mpte_router.py` |
| 11 | 23 | `/api/v1/trust` | `trust_center_router.py` |
| 12 | 21 | `/api/v1/fail` | `fail_router.py` |
| 13 | 21 | `/api/v1/self-learning` | `self_learning_router.py` |
| 14 | 20 | `/api/v1/attack-surface` | `attack_surface_manager_router.py` |
| 15 | 20 | `/api/v1/deduplication` | `deduplication_router.py` |
| 16 | 20 | `/api/v1/threat-intel` | `threat_intel_router.py` |
| 17 | 19 | `/api/v1/audit` | `audit_router.py` |
| 18 | 19 | `/api/v1/changes` | `change_management_router.py` |
| 19 | 19 | `/api/v1/micro-pentest` | `micro_pentest_router.py` |
| 20 | 19 | `/api/v1/network` | `network_security_router.py` |
| 21 | 19 | `/api/v1/risks` | `risk_register_router.py` |
| 22 | 18 | `/api/v1/cloud-cost` | `cloud_cost_security_router.py` |
| 23 | 18 | `/api/v1/evidence-collector` | `evidence_collector_router.py` |
| 24 | 18 | `/evidence` | `evidence_router.py` |
| 25 | 18 | `/api/v1/secrets` | `secrets_router.py` |
| 26 | 17 | `/api/v1/autofix` | `autofix_router.py` |
| 27 | 17 | `/api/v1/code-to-cloud` | `code_to_cloud_router.py` |
| 28 | 17 | `/compliance-engine` | `compliance_engine_router.py` |
| 29 | 17 | `/api/v1/dlp` | `dlp_router.py` |
| 30 | 16 | `/api/v1/copilot` | `copilot_router.py` |
| 31 | 16 | `/api/v1/cspm` | `cspm_router.py` |
| 32 | 16 | `/api/v1/firewall-mgmt` | `firewall_management_router.py` |
| 33 | 16 | `/api/v1/training` | `training_router.py` |
| 34 | 16 | `/api/v1/vendors` | `vendor_risk_router.py` |
| 35 | 15 | `/api/v1/ctem` | `ctem_engine_router.py` |
| 36 | 15 | `/api/v1/dashboards` | `dashboard_builder_router.py` |
| 37 | 15 | `/api/v1/integrations` | `integration_hub_router.py` |
| 38 | 15 | `/api/v1/mcp-protocol` | `mcp_protocol_router.py` |
| 39 | 15 | `/api/v1/ml` | `mindsdb_router.py` |
| 40 | 15 | `/api/v1/reports` | `reports_router.py` |
| 41 | 15 | `/api/v1/siem` | `siem_integration_router.py` |
| 42 | 15 | `/api/v1/sla` | `sla_router.py` |
| 43 | 15 | `/api/v1/zero-trust` | `zero_trust_enforcement_router.py` |
| 44 | 14 | `/api/v1/attack-sim` | `attack_sim_router.py` |
| 45 | 14 | `/api/v1/bulk` | `bulk_router.py` |
| 46 | 14 | `` | `marketplace_router.py` |
| 47 | 14 | `/api/v1/observability` | `observability_router.py` |
| 48 | 14 | `/api/v1/openclaw` | `openclaw_router.py` |
| 49 | 14 | `/api/v1/policies` | `policies_router.py` |
| 50 | 14 | `/api/v1/privacy` | `privacy_gdpr_router.py` |
| 51 | 14 | `/api/v1/scheduled-reports` | `scheduled_reports_router.py` |
| 52 | 14 | `/api/v1/tags` | `tag_router.py` |
| 53 | 14 | `/api/v1/hunt` | `threat_hunter_router.py` |
| 54 | 13 | `/api/v1/apps` | `app_config_router.py` |
| 55 | 13 | `/api/v1/attack-surface` | `attack_surface_router.py` |
| 56 | 13 | `/api/v1/auto-evidence` | `auto_evidence_router.py` |
| 57 | 13 | `/api/v1/compliance` | `compliance_automation_router.py` |
| 58 | 13 | `/api/v1/compliance-scanner` | `compliance_scanner_router.py` |
| 59 | 13 | `/api/v1/drift` | `drift_router.py` |
| 60 | 13 | `/api/v1/exec-reporting` | `executive_reporting_router.py` |
| 61 | 13 | `/api/v1/changes` | `material_change_router.py` |
| 62 | 13 | `/api/v1/mitre` | `mitre_navigator_router.py` |
| 63 | 13 | `/api/v1/report-builder` | `report_builder_router.py` |
| 64 | 13 | `/api/v1/metrics` | `security_metrics_router.py` |
| 65 | 13 | `/api/v1/supply-chain` | `supply_chain_router.py` |
| 66 | 13 | `/api/v1/tip` | `threat_intel_platform_router.py` |
| 67 | 13 | `/api/v1/workflows` | `workflows_router.py` |
| 68 | 12 | `/api/v1/algorithms` | `algorithmic_router.py` |
| 69 | 12 | `/api/v1/casb` | `casb_router.py` |
| 70 | 12 | `/api/v1/ownership` | `code_ownership_router.py` |
| 71 | 12 | `/api/v1/compliance` | `compliance_router.py` |
| 72 | 12 | `/api/v1/data-governance` | `data_governance_router.py` |
| 73 | 12 | `/api/v1/feeds` | `feed_manager_router.py` |
| 74 | 12 | `/api/v1/identity-governance` | `identity_governance_router.py` |
| 75 | 12 | `/api/v1/knowledge-graph` | `knowledge_graph_router.py` |
| 76 | 12 | `/api/v1/mdm` | `mdm_router.py` |
| 77 | 12 | `/api/v1/patch-automation` | `patch_automation_router.py` |
| 78 | 12 | `/api/v1/pentest` | `pentest_router.py` |
| 79 | 12 | `/api/v1/policy-engine` | `policy_engine_router.py` |
| 80 | 12 | `/api/v1/ransomware-protection` | `ransomware_protection_router.py` |
| 81 | 12 | `/api/v1/retention` | `retention_router.py` |
| 82 | 12 | `/api/v1/sbom-export` | `sbom_export_router.py` |
| 83 | 12 | `/api/v1/secret-scanner` | `secret_scanner_engine_router.py` |
| 84 | 12 | `/api/v1/kb` | `security_kb_router.py` |
| 85 | 12 | `/api/v1/security-roadmap` | `security_roadmap_router.py` |
| 86 | 12 | `/api/v1/sla-management` | `sla_management_router.py` |
| 87 | 12 | `/api/v1/vendors` | `vendor_scorecard_router.py` |
| 88 | 12 | `/api/v1/vulns` | `vuln_discovery_router.py` |
| 89 | 12 | `/api/v1/vuln-intel` | `vuln_intelligence_router.py` |
| 90 | 12 | `/api/v1/vuln-workflow` | `vuln_workflow_router.py` |
| 91 | 12 | `/api/v1/zero-trust-legacy` | `zero_trust_router.py` |
| 92 | 11 | `/api/v1/alert-enrichment` | `alert_enrichment_router.py` |
| 93 | 11 | `/api/v1/api-security-engine` | `api_security_engine_router.py` |
| 94 | 11 | `/api/v1/appsec` | `application_security_router.py` |
| 95 | 11 | `/api/v1/attack-surface-mgmt` | `attack_surface_engine_router.py` |
| 96 | 11 | `/api/v1/asm` | `attack_surface_mgmt_router.py` |
| 97 | 11 | `/api/v1/auth` | `auth_router.py` |
| 98 | 11 | `/api/v1/cloud-compliance` | `cloud_compliance_router.py` |
| 99 | 11 | `/api/v1/cost-optimization` | `cloud_cost_optimization_router.py` |
| 100 | 11 | `/api/v1/cloud-graph` | `cloud_graph_router.py` |
| 101 | 11 | `/api/v1/cloud-ir` | `cloud_incident_response_router.py` |
| 102 | 11 | `/api/v1/compliance-mapping` | `compliance_mapping_router.py` |
| 103 | 11 | `/api/v1/compliance-planner` | `compliance_planner_router.py` |
| 104 | 11 | `/api/v1/digital-forensics` | `digital_forensics_router.py` |
| 105 | 11 | `/api/v1/endpoint-compliance` | `endpoint_compliance_router.py` |
| 106 | 11 | `/api/v1/endpoint-hunting` | `endpoint_threat_hunting_router.py` |
| 107 | 11 | `/api/v1/evidence-chain` | `evidence_chain_router.py` |
| 108 | 11 | `/api/v1/fedramp` | `fedramp_router.py` |
| 109 | 11 | `/api/v1/remediation` | `fix_engine_router.py` |
| 110 | 11 | `/api/v1/grc` | `grc_router.py` |
| 111 | 11 | `/api/v1/identity-lifecycle` | `identity_lifecycle_router.py` |
| 112 | 11 | `/api/v1/incidents` | `incident_response_router.py` |
| 113 | 11 | `/api/v1/integrations` | `integration_health_router.py` |
| 114 | 11 | `/api/v1/nac` | `nac_router.py` |
| 115 | 11 | `/api/v1/network` | `network_analyzer_router.py` |
| 116 | 11 | `/api/v1/patches` | `patch_manager_router.py` |
| 117 | 11 | `/api/v1/pentest-mgmt` | `pentest_mgmt_router.py` |
| 118 | 11 | `/api/v1/posture-advisor` | `posture_advisor_router.py` |
| 119 | 11 | `/api/v1/privacy-impact` | `privacy_impact_assessment_router.py` |
| 120 | 11 | `/api/v1/red-team` | `red_team_mgmt_router.py` |
| 121 | 11 | `/api/v1/risk-acceptance` | `risk_acceptance_router.py` |
| 122 | 11 | `/api/v1/risk-quantifier` | `risk_quantifier_router.py` |
| 123 | 11 | `/scim/v2` | `scim_router.py` |
| 124 | 11 | `/api/v1/secrets-rotation` | `secrets_rotation_router.py` |
| 125 | 11 | `/api/v1/security-maturity` | `security_maturity_router.py` |
| 126 | 11 | `/api/v1/program-maturity` | `security_program_maturity_router.py` |
| 127 | 11 | `/api/v1/system` | `system_router.py` |
| 128 | 11 | `/api/v1/threat-indicators` | `threat_indicator_router.py` |
| 129 | 11 | `/api/v1/intel-enrichment` | `threat_intel_enrichment_router.py` |
| 130 | 11 | `/api/v1/threat-landscape` | `threat_landscape_router.py` |
| 131 | 11 | `/api/v1/threat-model-gen` | `threat_model_generator_router.py` |
| 132 | 11 | `/api/v1/threat-models` | `threat_model_router.py` |
| 133 | 11 | `/api/v1/threat-response` | `threat_response_router.py` |
| 134 | 11 | `/api/v1/analytics/users` | `user_analytics_router.py` |
| 135 | 11 | `/api/v1/waf-engine` | `waf_engine_router.py` |
| 136 | 11 | `/api/v1/webhook-subscriptions` | `webhook_subscriptions_router.py` |
| 137 | 10 | `/api/v1/access-anomaly` | `access_anomaly_router.py` |
| 138 | 10 | `/api/v1/access-governance` | `access_governance_router.py` |
| 139 | 10 | `/api/v1/admin` | `admin_router.py` |
| 140 | 10 | `/api/v1/ai-governance` | `ai_governance_router.py` |
| 141 | 10 | `/api/v1/ai-soc` | `ai_powered_soc_router.py` |
| 142 | 10 | `/api/v1/ai-advisor` | `ai_security_advisor_router.py` |
| 143 | 10 | `/api/v1/alert-triage` | `alert_triage_router.py` |
| 144 | 10 | `/api/v1/api-discovery` | `api_discovery_router.py` |
| 145 | 10 | `/api/v1/gateway` | `api_gateway_router.py` |
| 146 | 10 | `/api/v1/asset-groups` | `asset_group_router.py` |
| 147 | 10 | `/api/v1/asset-tags` | `asset_tagging_router.py` |
| 148 | 10 | `/api/v1/audit-analytics` | `audit_analytics_router.py` |
| 149 | 10 | `/api/v1/autonomous-remediation` | `autonomous_remediation_router.py` |
| 150 | 10 | `/api/v1/backups` | `backup_router.py` |
| 151 | 10 | `/api/v1/ccm` | `ccm_router.py` |
| 152 | 10 | `/api/v1/change-tracker` | `change_tracker_router.py` |
| 153 | 10 | `/api/v1/cloud-accounts` | `cloud_account_monitoring_router.py` |
| 154 | 10 | `/api/v1/cloud-connectors` | `cloud_connectors_router.py` |
| 155 | 10 | `/api/v1/cloud` | `cloud_discovery_router.py` |
| 156 | 10 | `/api/v1/cloud-security-engine` | `cloud_security_engine_router.py` |
| 157 | 10 | `/api/v1/cwp` | `cloud_workload_protection_router.py` |
| 158 | 10 | `/api/v1/cnapp` | `cnapp_router.py` |
| 159 | 10 | `/api/v1/compliance-calendar` | `compliance_calendar_router.py` |
| 160 | 10 | `/api/v1/compliance-evidence` | `compliance_evidence_router.py` |
| 161 | 10 | `/api/v1/compliance-gaps` | `compliance_gap_router.py` |
| 162 | 10 | `/api/v1/compliance-reports` | `compliance_reports_router.py` |
| 163 | 10 | `/api/v1/compliance-workflows` | `compliance_workflow_router.py` |
| 164 | 10 | `/api/v1/container-registry-security` | `container_registry_security_router.py` |
| 165 | 10 | `/api/v1/container-runtime` | `container_runtime_security_router.py` |
| 166 | 10 | `/api/v1/control-testing` | `control_testing_router.py` |
| 167 | 10 | `/api/v1/cspm-engine` | `cspm_engine_router.py` |
| 168 | 10 | `/api/v1/dark-web` | `dark_web_monitoring_router.py` |
| 169 | 10 | `/api/v1/data-retention` | `data_retention_router.py` |
| 170 | 10 | `/api/v1/data` | `data_security_router.py` |
| 171 | 10 | `/api/v1/deception-analytics` | `deception_analytics_router.py` |
| 172 | 10 | `/api/v1/devsecops` | `devsecops_router.py` |
| 173 | 10 | `/api/v1/digital-identity` | `digital_identity_router.py` |
| 174 | 10 | `/api/v1/edr` | `edr_router.py` |
| 175 | 10 | `/api/v1/email-security` | `email_security_router.py` |
| 176 | 10 | `/api/v1/endpoint-security` | `endpoint_security_router.py` |
| 177 | 10 | `/api/v1/cases` | `exposure_case_router.py` |
| 178 | 10 | `/api/v1/firewall` | `firewall_rule_router.py` |
| 179 | 10 | `/api/v1/identity` | `fuzzy_identity_router.py` |
| 180 | 10 | `/api/v1/ide` | `ide_router.py` |
| 181 | 10 | `/api/v1/identity-analytics` | `identity_analytics_router.py` |
| 182 | 10 | `/api/v1/identity-risk` | `identity_risk_router.py` |
| 183 | 10 | `/api/v1/incident-timeline` | `incident_timeline_router.py` |
| 184 | 10 | `/api/v1/integrations` | `integration_marketplace_router.py` |
| 185 | 10 | `/api/v1/iot-security` | `iot_security_router.py` |
| 186 | 10 | `/api/v1/ir` | `ir_playbook_router.py` |
| 187 | 10 | `/api/v1/itdr` | `itdr_router.py` |
| 188 | 10 | `/api/v1/k8s` | `k8s_security_router.py` |
| 189 | 10 | `/api/v1/licenses` | `license_compliance_router.py` |
| 190 | 10 | `/api/v1/mfa` | `mfa_management_router.py` |
| 191 | 10 | `/api/v1/mobile-app-security` | `mobile_app_security_router.py` |
| 192 | 10 | `/api/v1/ndr` | `ndr_router.py` |
| 193 | 10 | `/api/v1/network-threats` | `network_threat_router.py` |
| 194 | 10 | `/api/v1/network-topology` | `network_topology_router.py` |
| 195 | 10 | `/api/v1/ot-sec` | `operational_technology_security_router.py` |
| 196 | 10 | `/api/v1/phishing` | `phishing_router.py` |
| 197 | 10 | `/api/v1/phishing` | `phishing_simulation_router.py` |
| 198 | 10 | `/playbook-marketplace` | `playbook_marketplace_router.py` |
| 199 | 10 | `/api/v1/posture` | `posture_router.py` |
| 200 | 10 | `/api/v1/predictions` | `predictions_router.py` |
| 201 | 10 | `/api/v1/privileged-identity` | `privileged_identity_router.py` |
| 202 | 10 | `/api/v1/quantum-crypto` | `quantum_safe_crypto_router.py` |
| 203 | 10 | `/api/v1/questionnaires` | `questionnaire_router.py` |
| 204 | 10 | `/api/v1/regulatory-tracker` | `regulatory_tracker_engine_router.py` |
| 205 | 10 | `/api/v1/remediation-board` | `remediation_board_router.py` |
| 206 | 10 | `/api/v1/risk-aggregator` | `risk_aggregator_router.py` |
| 207 | 10 | `/api/v1/risk-scenarios` | `risk_scenario_router.py` |
| 208 | 10 | `/api/v1/runtime` | `runtime_protection_router.py` |
| 209 | 10 | `/api/v1/sast` | `sast_router.py` |
| 210 | 10 | `/api/v1/sbom` | `sbom_router.py` |
| 211 | 10 | `/api/v1/security-chaos` | `security_chaos_router.py` |
| 212 | 10 | `/api/v1/dependency-risk` | `security_dependency_risk_router.py` |
| 213 | 10 | `/api/v1/gap-analysis` | `security_gap_analysis_router.py` |
| 214 | 10 | `/api/v1/security-health` | `security_health_router.py` |
| 215 | 10 | `/api/v1/kpi` | `security_kpi_router.py` |
| 216 | 10 | `/api/v1/posture-trends` | `security_posture_trend_router.py` |
| 217 | 10 | `/api/v1/security-questionnaires` | `security_questionnaire_router.py` |
| 218 | 10 | `/api/v1/security-registry` | `security_registry_router.py` |
| 219 | 10 | `/api/v1/security-roi` | `security_roi_router.py` |
| 220 | 10 | `/api/v1/security-scorecard` | `security_scorecard_engine_router.py` |
| 221 | 10 | `/api/v1/sessions` | `session_router.py` |
| 222 | 10 | `/api/v1/soc-triage` | `soc_triage_router.py` |
| 223 | 10 | `/api/v1/license-security` | `software_license_security_router.py` |
| 224 | 10 | `/api/v1/supply-chain-attacks` | `supply_chain_attack_detection_router.py` |
| 225 | 10 | `/api/v1/supply-chain-intel` | `supply_chain_intel_router.py` |
| 226 | 10 | `/api/v1/threat-actors` | `threat_actor_router.py` |
| 227 | 10 | `/api/v1/actor-tracking` | `threat_actor_tracking_router.py` |
| 228 | 10 | `/api/v1/hunting` | `threat_hunting_router.py` |
| 229 | 10 | `/api/v1/ti-automation` | `threat_intelligence_automation_router.py` |
| 230 | 10 | `/api/v1/threat-modeling-pipeline` | `threat_modeling_pipeline_router.py` |
| 231 | 10 | `/api/v1/threat-modeling` | `threat_modeling_router.py` |
| 232 | 10 | `/api/v1/uba` | `uba_router.py` |
| 233 | 10 | `/api/v1/access-reviews` | `user_access_review_router.py` |
| 234 | 10 | `/api/v1/vuln-scanner` | `vuln_scanner_router.py` |
| 235 | 10 | `/api/v1/vuln-correlation` | `vulnerability_correlation_router.py` |
| 236 | 10 | `/api/v1/webhooks/dlq` | `webhook_dlq_router.py` |
| 237 | 10 | `/api/v1/xdr` | `xdr_router.py` |
| 238 | 10 | `/api/v1/zero-trust-policy` | `zero_trust_policy_router.py` |
| 239 | 9 | `/api/v1/analytics` | `analytics_dashboard_router.py` |
| 240 | 9 | `/api/v1/api-abuse` | `api_abuse_detection_router.py` |
| 241 | 9 | `/api/v1/api-security-engine` | `api_security_mgmt_router.py` |
| 242 | 9 | `/api/v1/app-security` | `app_security_router.py` |
| 243 | 9 | `/api/v1/asset-risk` | `asset_risk_calculator_router.py` |
| 244 | 9 | `/api/v1/attack-chains` | `attack_chain_router.py` |
| 245 | 9 | `/api/v1/attack-sim` | `attack_simulation_router.py` |
| 246 | 9 | `/api/v1/attack-surface/monitor` | `attack_surface_monitor_router.py` |
| 247 | 9 | `/api/v1/breach-response` | `breach_response_router.py` |
| 248 | 9 | `/api/v1/breach-sim` | `breach_simulation_router.py` |
| 249 | 9 | `/api/v1/browser-security` | `browser_security_router.py` |
| 250 | 9 | `/api/v1/certificates` | `cert_router.py` |
| 251 | 9 | `/api/v1/cloud-identity` | `cloud_identity_router.py` |
| 252 | 9 | `/api/v1/cloud-analytics` | `cloud_security_analytics_router.py` |
| 253 | 9 | `/api/v1/cloud-findings` | `cloud_security_findings_router.py` |
| 254 | 9 | `/api/v1/cmdb` | `cmdb_router.py` |
| 255 | 9 | `/api/v1/config-benchmark` | `config_benchmark_router.py` |
| 256 | 9 | `/api/v1/containers` | `container_runtime_router.py` |
| 257 | 9 | `/api/v1/cyber-resilience` | `cyber_resilience_router.py` |
| 258 | 9 | `/api/v1/classification` | `data_classification_router.py` |
| 259 | 9 | `/api/v1/data-exfiltration` | `data_exfiltration_router.py` |
| 260 | 9 | `/api/v1/db-security` | `db_security_router.py` |
| 261 | 9 | `/api/v1/developer` | `developer_portal_router.py` |
| 262 | 9 | `/api/v1/evidence-vault` | `evidence_vault_router.py` |
| 263 | 9 | `/api/v1/exceptions` | `exception_policy_router.py` |
| 264 | 9 | `/api/v1/firmware-security` | `firmware_security_router.py` |
| 265 | 9 | `/api/v1/hunting-automation` | `hunting_automation_router.py` |
| 266 | 9 | `/api/v1/iga` | `iga_router.py` |
| 267 | 9 | `/api/v1/incident-comms` | `incident_comms_router.py` |
| 268 | 9 | `/api/v1/incident-kb` | `incident_kb_router.py` |
| 269 | 9 | `/api/v1/incident-lessons` | `incident_lessons_router.py` |
| 270 | 9 | `/api/v1/incident-metrics` | `incident_metrics_router.py` |
| 271 | 9 | `/api/v1/incident-orchestration` | `incident_orchestration_router.py` |
| 272 | 9 | `/api/v1/insider-threat` | `insider_threat_router.py` |
| 273 | 9 | `/api/v1/ioc-enrichment` | `ioc_enrichment_router.py` |
| 274 | 9 | `/api/v1/mcp` | `mcp_router.py` |
| 275 | 9 | `/api/v1/mitre-attack` | `mitre_attack_router.py` |
| 276 | 9 | `/api/v1/mpte-orchestrator` | `mpte_orchestrator_router.py` |
| 277 | 9 | `/api/v1/network-monitoring` | `network_monitoring_router.py` |
| 278 | 9 | `/api/v1/network-traffic` | `network_traffic_router.py` |
| 279 | 9 | `/api/v1/pam` | `pam_router.py` |
| 280 | 9 | `/api/v1/passive-dns` | `passive_dns_router.py` |
| 281 | 9 | `/api/v1/password-policy` | `password_policy_router.py` |
| 282 | 9 | `/api/v1/pki` | `pki_management_router.py` |
| 283 | 9 | `/api/v1/policies` | `policy_router.py` |
| 284 | 9 | `/api/v1/prioritize` | `prioritizer_router.py` |
| 285 | 9 | `/api/v1/purple-team` | `purple_team_router.py` |
| 286 | 9 | `/api/v1/risk-quantification` | `risk_quantification_router.py` |
| 287 | 9 | `/api/v1/secrets` | `secret_scanner_router.py` |
| 288 | 9 | `/api/v1/secrets-management` | `secrets_management_router.py` |
| 289 | 9 | `/api/v1/secrets-manager` | `secrets_manager_router.py` |
| 290 | 9 | `/api/v1/awareness-program` | `security_awareness_program_router.py` |
| 291 | 9 | `/api/v1/security-baselines` | `security_baseline_router.py` |
| 292 | 9 | `/api/v1/security-budget` | `security_budget_router.py` |
| 293 | 9 | `/api/v1/security-champions` | `security_champions_router.py` |
| 294 | 9 | `/api/v1/security-culture` | `security_culture_router.py` |
| 295 | 9 | `/api/v1/dependency-mapping` | `security_dependency_mapping_router.py` |
| 296 | 9 | `/api/v1/event-timeline` | `security_event_timeline_router.py` |
| 297 | 9 | `/api/v1/security-exceptions` | `security_exception_router.py` |
| 298 | 9 | `/api/v1/exception-workflow` | `security_exception_workflow_router.py` |
| 299 | 9 | `/api/v1/security-findings` | `security_findings_router.py` |
| 300 | 9 | `/api/v1/security-investment` | `security_investment_router.py` |
| 301 | 9 | `/api/v1/metrics-aggregator` | `security_metrics_aggregator_router.py` |
| 302 | 9 | `/api/v1/security-metrics-collector` | `security_metrics_collector_router.py` |
| 303 | 9 | `/api/v1/security-okrs` | `security_okr_router.py` |
| 304 | 9 | `/api/v1/soc-metrics` | `security_operations_metrics_router.py` |
| 305 | 9 | `/api/v1/posture-benchmarking` | `security_posture_benchmarking_router.py` |
| 306 | 9 | `/api/v1/posture-history` | `security_posture_history_router.py` |
| 307 | 9 | `/api/v1/posture-maturity` | `security_posture_maturity_router.py` |
| 308 | 9 | `/api/v1/service-catalog` | `security_service_catalog_router.py` |
| 309 | 9 | `/api/v1/tabletop` | `security_tabletop_router.py` |
| 310 | 9 | `/api/v1/tool-inventory` | `security_tool_inventory_router.py` |
| 311 | 9 | `/api/v1/training-effectiveness` | `security_training_effectiveness_router.py` |
| 312 | 9 | `/api/v1/security-training` | `security_training_router.py` |
| 313 | 9 | `/api/v1/sca` | `software_composition_analysis_router.py` |
| 314 | 9 | `/api/v1/threat-briefs` | `threat_brief_router.py` |
| 315 | 9 | `/api/v1/threat-correlation` | `threat_correlation_router.py` |
| 316 | 9 | `/api/v1/threat-exposure` | `threat_exposure_router.py` |
| 317 | 9 | `/api/v1/feed-subscriptions` | `threat_feed_subscription_router.py` |
| 318 | 9 | `/api/v1/hunting-playbooks` | `threat_hunting_playbook_router.py` |
| 319 | 9 | `/api/v1/tprm-exchange` | `tprm_exchange_router.py` |
| 320 | 9 | `/api/v1/graph` | `trustgraph_backbone_router.py` |
| 321 | 9 | `/api/v1/vuln-trends` | `vuln_trend_router.py` |
| 322 | 9 | `/api/v1/vuln-age` | `vulnerability_age_router.py` |
| 323 | 9 | `/api/v1/vuln-remediation` | `vulnerability_remediation_router.py` |
| 324 | 9 | `/api/v1/vuln-scoring` | `vulnerability_scoring_router.py` |
| 325 | 9 | `/api/v1/workflows` | `workflow_engine_router.py` |
| 326 | 9 | `/api/v1/workflows` | `workflow_router.py` |
| 327 | 9 | `/api/v1/zero-day` | `zero_day_intelligence_router.py` |
| 328 | 8 | `/api/v1/access-control` | `access_control_router.py` |
| 329 | 8 | `/api/v1/access-matrix` | `access_matrix_router.py` |
| 330 | 8 | `/api/v1/ai-orchestrator` | `ai_orchestrator_router.py` |
| 331 | 8 | `/api/v1/alerting` | `alerting_notification_router.py` |
| 332 | 8 | `/api/v1/anomaly-ml` | `anomaly_ml_router.py` |
| 333 | 8 | `/api/v1/anomalies` | `anomaly_router.py` |
| 334 | 8 | `/api/v1/anti-phishing` | `anti_phishing_router.py` |
| 335 | 8 | `/api/v1/api-abuse` | `api_abuse_router.py` |
| 336 | 8 | `/api/v1/api-gateway-security` | `api_gateway_security_router.py` |
| 337 | 8 | `/api/v1/app-risk` | `application_risk_router.py` |
| 338 | 8 | `/api/v1/attack-paths` | `attack_path_router.py` |
| 339 | 8 | `/api/v1/audit-management` | `audit_management_router.py` |
| 340 | 8 | `/api/v1/awareness-score` | `awareness_score_router.py` |
| 341 | 8 | `/api/v1/bandwidth-analysis` | `bandwidth_analysis_router.py` |
| 342 | 8 | `/api/v1/bounty` | `bug_bounty_router.py` |
| 343 | 8 | `/api/v1/bulk` | `bulk_operations_router.py` |
| 344 | 8 | `/api/v1/certificates` | `certificate_lifecycle_router.py` |
| 345 | 8 | `/api/v1/cloud-drift` | `cloud_drift_router.py` |
| 346 | 8 | `/api/v1/connectors` | `connectors_router.py` |
| 347 | 8 | `/api/v1/container` | `container_router.py` |
| 348 | 8 | `/api/v1/crypto-keys` | `crypto_key_management_router.py` |
| 349 | 8 | `/api/v1/ctem` | `ctem_router.py` |
| 350 | 8 | `/api/v1/cve` | `cve_enrichment_router.py` |
| 351 | 8 | `/api/v1/cwpp` | `cwpp_router.py` |
| 352 | 8 | `/api/v1/cyber-insurance` | `cyber_insurance_router.py` |
| 353 | 8 | `/api/v1/cyber-threat-models` | `cyber_threat_modeling_router.py` |
| 354 | 8 | `/api/v1/data-discovery` | `data_discovery_router.py` |
| 355 | 8 | `/api/v1/ddos-protection` | `ddos_protection_router.py` |
| 356 | 8 | `/api/v1/digital-twin` | `digital_twin_security_router.py` |
| 357 | 8 | `/api/v1/firewall-policy` | `firewall_policy_router.py` |
| 358 | 8 | `/api/v1/security/github` | `github_security_router.py` |
| 359 | 8 | `/api/v1/incident-costs` | `incident_cost_router.py` |
| 360 | 8 | `/api/v1/ip-reputation` | `ip_reputation_router.py` |
| 361 | 8 | `/api/v1/jira-sync` | `jira_sync_router.py` |
| 362 | 8 | `/api/v1/kpis` | `kpi_router.py` |
| 363 | 8 | `/api/v1/kubernetes-security` | `kubernetes_security_router.py` |
| 364 | 8 | `/api/v1/log-management` | `log_management_router.py` |
| 365 | 8 | `/api/v1/malware-analysis` | `malware_analysis_router.py` |
| 366 | 8 | `/api/v1/microsegmentation` | `microsegmentation_policy_router.py` |
| 367 | 8 | `/api/v1/mobile-security` | `mobile_security_router.py` |
| 368 | 8 | `/api/v1/nac` | `network_access_control_router.py` |
| 369 | 8 | `/api/v1/network-forensics` | `network_forensics_router.py` |
| 370 | 8 | `/api/v1/network-segmentation` | `network_segmentation_router.py` |
| 371 | 8 | `/api/v1/notifications` | `notification_router.py` |
| 372 | 8 | `/api/v1/onboarding` | `onboarding_router.py` |
| 373 | 8 | `/api/v1/pagerduty` | `pagerduty_router.py` |
| 374 | 8 | `/api/v1/patch-management` | `patch_management_router.py` |
| 375 | 8 | `/api/v1/patch-priority` | `patch_prioritizer_router.py` |
| 376 | 8 | `/api/v1/physical-security` | `physical_security_router.py` |
| 377 | 8 | `/api/v1/brain` | `pipeline_router.py` |
| 378 | 8 | `/api/v1/policy-enforcement` | `policy_enforcement_router.py` |
| 379 | 8 | `/api/v1/policy-generator` | `policy_generator_router.py` |
| 380 | 8 | `/api/v1/verify` | `postfix_verify_router.py` |
| 381 | 8 | `/api/v1/posture-score` | `posture_score_router.py` |
| 382 | 8 | `/api/v1/pag` | `privileged_access_governance_router.py` |
| 383 | 8 | `/api/v1/rbac` | `rbac_router.py` |
| 384 | 8 | `/api/v1/regulatory` | `regulatory_tracker_router.py` |
| 385 | 8 | `/api/v1/risk-quant` | `risk_quantification_engine_router.py` |
| 386 | 8 | `/api/v1/risk-register-engine` | `risk_register_engine_router.py` |
| 387 | 8 | `/risk` | `risk_router.py` |
| 388 | 8 | `/api/v1/sspm` | `saas_security_posture_router.py` |
| 389 | 8 | `/api/v1/scanner-ingest` | `scanner_ingest_router.py` |
| 390 | 8 | `/api/v1/arch-review` | `security_architecture_review_router.py` |
| 391 | 8 | `/api/v1/security-automation` | `security_automation_router.py` |
| 392 | 8 | `/api/v1/capacity-planning` | `security_capacity_planning_router.py` |
| 393 | 8 | `/api/v1/event-correlation` | `security_event_correlation_router.py` |
| 394 | 8 | `/api/v1/health-scorecard` | `security_health_scorecard_router.py` |
| 395 | 8 | `/api/v1/metrics-dashboard` | `security_metrics_dashboard_router.py` |
| 396 | 8 | `/api/v1/posture-reports` | `security_posture_reporting_router.py` |
| 397 | 8 | `/api/v1/posture-scoring` | `security_posture_scoring_router.py` |
| 398 | 8 | `/api/v1/security-scoreboard` | `security_scoreboard_router.py` |
| 399 | 8 | `/api/v1/security-telemetry` | `security_telemetry_router.py` |
| 400 | 8 | `/api/v1/service-account-auditor` | `service_account_auditor_router.py` |
| 401 | 8 | `/api/v1/servicenow-sync` | `servicenow_sync_router.py` |
| 402 | 8 | `/api/v1/sla-engine` | `sla_engine_router.py` |
| 403 | 8 | `/api/v1/soar` | `soar_router.py` |
| 404 | 8 | `/api/v1/soc-automation` | `soc_automation_router.py` |
| 405 | 8 | `/api/v1/soc-workflow` | `soc_workflow_router.py` |
| 406 | 8 | `/api/v1/supply-chain-monitoring` | `supply_chain_monitoring_router.py` |
| 407 | 8 | `/api/v1/supply-chain` | `supply_chain_risk_router.py` |
| 408 | 8 | `/api/v1/teams` | `teams_router.py` |
| 409 | 8 | `/api/v1/rate-limits` | `tenant_rate_limiter_router.py` |
| 410 | 8 | `/api/v1/third-party-vendor` | `third_party_vendor_router.py` |
| 411 | 8 | `/api/v1/threat-attribution` | `threat_attribution_router.py` |
| 412 | 8 | `/api/v1/threat-deception` | `threat_deception_management_router.py` |
| 413 | 8 | `/api/v1/threat-geolocation` | `threat_geolocation_router.py` |
| 414 | 8 | `/api/v1/threat-intel-fusion` | `threat_intel_fusion_router.py` |
| 415 | 8 | `/api/v1/threat-sharing` | `threat_intel_sharing_router.py` |
| 416 | 8 | `/api/v1/ti-confidence` | `threat_intelligence_confidence_router.py` |
| 417 | 8 | `/api/v1/threat-simulation` | `threat_simulation_router.py` |
| 418 | 8 | `/api/v1/threat-vectors` | `threat_vector_analysis_router.py` |
| 419 | 8 | `/api/v1/vendor-compliance` | `vendor_compliance_router.py` |
| 420 | 8 | `/api/v1/vuln-lifecycle` | `vuln_lifecycle_router.py` |
| 421 | 8 | `/api/v1/vuln-prioritization` | `vuln_prioritization_router.py` |
| 422 | 8 | `/api/v1/vuln-scans` | `vuln_scan_router.py` |
| 423 | 8 | `/api/v1/vuln-prioritization` | `vulnerability_prioritization_router.py` |
| 424 | 8 | `/api/v1/waf` | `waf_router.py` |
| 425 | 7 | `/api/v1/access-requests` | `access_request_management_router.py` |
| 426 | 7 | `/api/v1/analytics-engine` | `analytics_engine_router.py` |
| 427 | 7 | `/api/v1/api-inventory` | `api_inventory_router.py` |
| 428 | 7 | `/api/v1/api-security` | `api_security_router.py` |
| 429 | 7 | `/api/v1/api-threat-protection` | `api_threat_protection_router.py` |
| 430 | 7 | `/api/v1/auth/keys` | `apikey_router.py` |
| 431 | 7 | `/api/v1/asset-criticality` | `asset_criticality_router.py` |
| 432 | 7 | `/api/v1/asset-lifecycle` | `asset_lifecycle_router.py` |
| 433 | 7 | `/api/v1/awareness-campaigns` | `awareness_campaign_router.py` |
| 434 | 7 | `/api/v1/behavioral-analytics` | `behavioral_analytics_router.py` |
| 435 | 7 | `/api/v1/breach-detection` | `breach_detection_router.py` |
| 436 | 7 | `/api/v1/ciem` | `ciem_router.py` |
| 437 | 7 | `/api/v1/cloud-access-security` | `cloud_access_security_router.py` |
| 438 | 7 | `/api/v1/cloud-governance` | `cloud_governance_router.py` |
| 439 | 7 | `/api/v1/cloud-native` | `cloud_native_security_router.py` |
| 440 | 7 | `/api/v1/cloud-posture` | `cloud_posture_router.py` |
| 441 | 7 | `/api/v1/cloud-inventory` | `cloud_resource_inventory_router.py` |
| 442 | 7 | `/api/v1/container-posture` | `container_security_posture_router.py` |
| 443 | 7 | `/api/v1/cyber-threat-intel` | `cyber_threat_intelligence_router.py` |
| 444 | 7 | `/api/v1/dast` | `dast_router.py` |
| 445 | 7 | `/api/v1/data-lake-security` | `data_lake_security_router.py` |
| 446 | 7 | `/api/v1/data-privacy` | `data_privacy_router.py` |
| 447 | 7 | `/api/v1/deception` | `deception_router.py` |
| 448 | 7 | `/api/v1/deployment` | `deployment_router.py` |
| 449 | 7 | `/api/v1/executive` | `executive_dashboard_router.py` |
| 450 | 7 | `/api/v1/reports/executive` | `executive_report_router.py` |
| 451 | 7 | `/api/v1/forensics-readiness` | `forensics_readiness_router.py` |
| 452 | 7 | `/api/v1/github/issues` | `github_issues_router.py` |
| 453 | 7 | `/graph` | `graph_router.py` |
| 454 | 7 | `/api/v1/iac` | `iac_scanner_router.py` |
| 455 | 7 | `/api/v1/iam-policy` | `iam_policy_router.py` |
| 456 | 7 | `/api/v1/incident-triage` | `incident_triage_router.py` |
| 457 | 7 | `/api/v1/kpi-tracking` | `kpi_tracking_router.py` |
| 458 | 7 | `/api/v1/mitre` | `mitre_mapper_router.py` |
| 459 | 7 | `/api/v1/n8n` | `n8n_router.py` |
| 460 | 7 | `/api/v1/network-anomaly` | `network_anomaly_router.py` |
| 461 | 7 | `/api/v1/ot-security` | `ot_security_router.py` |
| 462 | 7 | `/api/v1/playbooks` | `playbook_router.py` |
| 463 | 7 | `/api/v1/pr-gate` | `pr_gate_router.py` |
| 464 | 7 | `/api/v1/privilege-escalation` | `privilege_escalation_router.py` |
| 465 | 7 | `/api/v1/session-recording` | `privileged_session_recording_router.py` |
| 466 | 7 | `/api/v1/rasp` | `rasp_router.py` |
| 467 | 7 | `/api/v1/regulatory-reporting` | `regulatory_reporting_router.py` |
| 468 | 7 | `/api/v1/reports` | `report_scheduler_router.py` |
| 469 | 7 | `/api/v1/risk-treatment` | `risk_treatment_router.py` |
| 470 | 7 | `/api/v1/awareness-gamification` | `security_awareness_gamification_router.py` |
| 471 | 7 | `/api/v1/awareness-metrics` | `security_awareness_metrics_router.py` |
| 472 | 7 | `/api/v1/security-benchmarks` | `security_benchmark_router.py` |
| 473 | 7 | `/api/v1/change-management` | `security_change_management_router.py` |
| 474 | 7 | `/api/v1/data-pipeline` | `security_data_pipeline_router.py` |
| 475 | 7 | `/api/v1/security-playbooks` | `security_playbook_router.py` |
| 476 | 7 | `/api/v1/scorecard` | `security_scorecard_router.py` |
| 477 | 7 | `/api/v1/ai-agent` | `single_agent_router.py` |
| 478 | 7 | `/api/v1/auth/sso` | `sso_router.py` |
| 479 | 7 | `/api/v1/system` | `system_health_router.py` |
| 480 | 7 | `/api/v1/threat-scores` | `threat_score_router.py` |
| 481 | 7 | `/api/v1/vuln-exceptions` | `vuln_exception_router.py` |
| 482 | 7 | `/api/v1/vuln-intel-fusion` | `vuln_intel_fusion_router.py` |
| 483 | 7 | `/api/v1/vulns` | `vuln_prioritizer_router.py` |
| 484 | 7 | `/api/v1/vuln-workflow` | `vulnerability_workflow_router.py` |
| 485 | 7 | `/api/v1/wireless-security` | `wireless_security_router.py` |
| 486 | 7 | `/api/v1/zero-gravity` | `zero_gravity_router.py` |
| 487 | 6 | `/api/v1/api-analytics` | `api_analytics_router.py` |
| 488 | 6 | `/api/v1/docs` | `api_docs_router.py` |
| 489 | 6 | `/api/v1/scan/aws-security-hub` | `aws_security_hub_router.py` |
| 490 | 6 | `/api/v1/scan/azure-defender` | `azure_defender_router.py` |
| 491 | 6 | `/api/v1/cicd` | `cicd_router.py` |
| 492 | 6 | `/api/v1/ciso-report` | `ciso_report_router.py` |
| 493 | 6 | `/api/v1/containers` | `container_scanner_router.py` |
| 494 | 6 | `/api/v1/dep-scanner` | `dep_scanner_router.py` |
| 495 | 6 | `/api/v1/drp` | `drp_router.py` |
| 496 | 6 | `/api/v1/email-filtering` | `email_filtering_router.py` |
| 497 | 6 | `/api/v1/gate` | `gate_router.py` |
| 498 | 6 | `/api/v1/scan/gcp-scc` | `gcp_scc_router.py` |
| 499 | 6 | `/api/v1/gdpr` | `gdpr_compliance_router.py` |
| 500 | 6 | `/api/v1/license-scanner` | `license_scanner_router.py` |
| 501 | 6 | `/api/v1/llm` | `llm_router.py` |
| 502 | 6 | `/api/v1/metrics` | `metrics_aggregator_router.py` |
| 503 | 6 | `/api/v1/mdm` | `mobile_device_management_router.py` |
| 504 | 6 | `/api/v1/posture-benchmark` | `posture_benchmark_router.py` |
| 505 | 6 | `/api/v1/quantum-crypto` | `quantum_crypto_router.py` |
| 506 | 6 | `/api/v1/red-team` | `red_team_router.py` |
| 507 | 6 | `/api/v1/scan/semgrep` | `semgrep_router.py` |
| 508 | 6 | `/api/v1/integrations/slack` | `slack_notifier_router.py` |
| 509 | 6 | `/api/v1/scan/snyk` | `snyk_router.py` |
| 510 | 6 | `/api/v1/threat-feeds` | `threat_feed_aggregator_router.py` |
| 511 | 6 | `/api/v1/triage` | `triage_router.py` |
| 512 | 6 | `/api/v1/trustgraph/migrate` | `trustgraph_migrator_router.py` |
| 513 | 6 | `/api/v1/unified-dashboard` | `unified_dashboard_router.py` |
| 514 | 6 | `/api/versions` | `versioning_router.py` |
| 515 | 6 | `/api/v1/vllm` | `vllm_router.py` |
| 516 | 6 | `/api/v1/webhooks/notifications` | `webhook_notifications_router.py` |
| 517 | 5 | `/api/v1/changelog` | `changelog_router.py` |
| 518 | 5 | `/api/v1/risk` | `composite_risk_router.py` |
| 519 | 5 | `/api/v1/correlations` | `correlation_router.py` |
| 520 | 5 | `/api/v1/reports` | `exec_security_reports_router.py` |
| 521 | 5 | `/api/v1/feeds` | `feeds_router.py` |
| 522 | 5 | `/api/v1/playbooks` | `ir_playbook_runner_router.py` |
| 523 | 5 | `/api/v1/llm-monitor` | `llm_monitor_router.py` |
| 524 | 5 | `/api/v1/malware` | `malware_router.py` |
| 525 | 5 | `/provenance` | `provenance_router.py` |
| 526 | 5 | `/api/v1/rate-limits` | `rate_limit_router.py` |
| 527 | 5 | `/api/v1/risk` | `risk_scoring_router.py` |
| 528 | 5 | `/api/v1/sla-escalation` | `sla_escalation_router.py` |
| 529 | 5 | `/api/v1/scan/trivy` | `trivy_router.py` |
| 530 | 5 | `/api/v1/graph` | `trustgraph_integration_router.py` |
| 531 | 5 | `/api/v1/trustgraph/quality` | `trustgraph_quality_router.py` |
| 532 | 5 | `/api/v1/users` | `users_router.py` |
| 533 | 5 | `/api/v1/validate` | `validation_router.py` |
| 534 | 5 | `/api/v1/vuln-risk` | `vuln_risk_router.py` |
| 535 | 5 | `/api/v1/events` | `webhook_events_router.py` |
| 536 | 4 | `/api/v1/api-fuzzer` | `api_fuzzer_router.py` |
| 537 | 4 | `/api/v1/auto-pentest` | `auto_pentest_router.py` |
| 538 | 4 | `/api/v1/cspm` | `cspm_deep_router.py` |
| 539 | 4 | `/api/v1/event-bus` | `event_bus_router.py` |
| 540 | 4 | `/api/v1/export` | `export_router.py` |
| 541 | 4 | `/api/v1/graphrag` | `graph_rag_router.py` |
| 542 | 4 | `/api/v1/mcp-gateway` | `mcp_gateway_router.py` |
| 543 | 4 | `/api/v1/mitre` | `mitre_coverage_router.py` |
| 544 | 4 | `/api/v1/n8n` | `n8n_mgmt_router.py` |
| 545 | 4 | `/api/v1/remediation/prs` | `pr_generator_router.py` |
| 546 | 4 | `/api/v1/queue` | `queue_router.py` |
| 547 | 4 | `/api/v1/self-scan` | `self_scan_router.py` |
| 548 | 4 | `/api/v1/stream` | `stream_router.py` |
| 549 | 4 | `/api/v1/stream` | `streaming_router.py` |
| 550 | 4 | `/api/v1/tenants` | `tenant_router.py` |
| 551 | 4 | `/api/v1/trustgraph/maintenance` | `trustgraph_maintenance_router.py` |
| 552 | 4 | `/api/v1/webhooks` | `webhook_router.py` |
| 553 | 4 | `/api/v1/webhooks/verify` | `webhook_verifier_router.py` |
| 554 | 3 | `/api/v1/autofix/verify` | `autofix_verify_router.py` |
| 555 | 3 | `/api/v1/cache` | `cache_router.py` |
| 556 | 3 | `/api/v1/council` | `council_enhanced_router.py` |
| 557 | 3 | `/api/v1/error-audit` | `error_audit_router.py` |
| 558 | 3 | `/api/v1/orgs` | `org_router.py` |
| 559 | 3 | `/api/v1/slack` | `slack_bot_router.py` |
| 560 | 3 | `/api/v1/vuln` | `vuln_enricher_router.py` |
| 561 | 2 | `/api/v1/graphql` | `graphql_router.py` |
| 562 | 2 | `/api/v1/metrics` | `metrics_router.py` |
| 563 | 1 | `/api/v1/platform` | `platform_router.py` |
| 564 | 1 | `/api/v1/security-posture-pdf` | `security_posture_pdf_router.py` |
| 565 | 1 | `/api/v1` | `version_router.py` |
| 566 | 1 | `` | `websocket_alerts_router.py` |
| 567 | 1 | `` | `ws_events_router.py` |
| 568 | 0 | `/api/v1/audit` | `gap_router.py` |

---

## Stub Routers (0 Endpoints — Need Wiring)

| File | Prefix |
|------|--------|
| `gap_router.py` | `/api/v1/audit` |

---

## Graph Topology Analysis

### Key Observations

- **BaseModel (2,458 edges)** and **str (2,082 edges)** are the most-referenced symbols —
  consistent with a Pydantic v2 FastAPI codebase where every request/response schema inherits
  from BaseModel.
- **gap_router.py (100 edges)** is the most-connected router file in the graph despite having
  0 declared route endpoints — it is a structural hub with imports/helpers used by many other routers.
- **agents_router.py (69 edges)** and **micro_pentest_router.py (53 edges)** are the densest
  functional routers, reflecting complex multi-step agent orchestration logic.
- **282 graph communities** in suite-api — each community represents a cohesive functional cluster
  (auth, threat-intel, compliance, network-security, etc.).
- **33% of routes (1,746)** use path parameters — indicating a well-structured REST resource hierarchy.

### suite-api Graph vs Global Graph

| Graph | Nodes | Edges | Scope |
|-------|------:|------:|-------|
| suite-api (fresh) | 16,395 | 27,624 | API layer only (596 files) |
| Global (full repo) | 2,258 | 2,031 | Entire codebase |

---

## Graphify Commands Reference

```bash
# Refresh graph after new router files are added
cd /Users/devops.ai/fixops/Fixops
graphify update suite-api/

# Query the graph for a domain
graphify query "which routers handle vulnerability management" \
  --graph suite-api/graphify-out/graph.json

# Find shortest path between two routers
graphify path "analytics_router.py" "brain_router.py" \
  --graph suite-api/graphify-out/graph.json

# Explain a specific router file
graphify explain "agents_router.py" \
  --graph suite-api/graphify-out/graph.json

# Re-run clustering only (fast, no re-extraction)
graphify cluster-only suite-api/ --graph suite-api/graphify-out/graph.json
```
