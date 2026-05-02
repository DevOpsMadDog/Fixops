# app.py Refactor Plan — FastAPI Sub-Application Decomposition
**Date**: 2026-04-28  
**Author**: Enterprise Architect  
**Multica Issue**: f5d203e4-eabe-467c-8a67-d6fc12fb2ffa  
**File**: `suite-api/apps/api/app.py` (9,501 lines)  
**Current state**: 567 `include_router` / `mount` calls, 467 unique router variable names, 1 `app.mount` (StaticFiles)

---

## 1. Bucket Assignment — All 567 Mounts

Classification logic: name-pattern match on router variable name, confirmed against comment blocks in app.py. Each router appears in exactly one bucket. Duplicate registrations (3 routers registered twice in conditional branches) are noted.

```
router_variable,bucket,reason
access_anomaly_router,CSPM,IAM behavioral anomaly — cloud identity
access_control_router,CSPM,Access control posture
access_governance_router,GRC,Governance lifecycle
access_request_management_router,GRC,Access request workflow
admin_wizard_router,Platform,Admin onboarding wizard
agentless_snapshot_router,CSPM,Agentless cloud snapshot
ai_code_scanner_router,ASPM,AI-assisted code scanning
ai_governance_router,GRC,AI governance / policy
ai_orchestrator_router,Platform,Multi-LLM orchestration — platform infrastructure
ai_powered_soc_router,CTEM,SOC automation via AI
ai_security_advisor_router,CTEM,AI threat advisor
air_gap_bundle_router,Platform,Air-gapped deployment bundle
alert_enrichment_router,CTEM,Alert context enrichment
alert_triage_router,CTEM,Alert triage pipeline
alerting_notification_router,Platform,Notification delivery infrastructure
analytics_dashboard_router,Platform,Unified analytics dashboard
analytics_router,Platform,Core analytics
analytics_routes_router,Platform,Analytics sub-routes
anomaly_ml_router,CTEM,ML behavioral anomaly detection
anomaly_router,CTEM,Anomaly detection
anti_phishing_router,CTEM,Phishing detection/response
api_abuse_detection_router,ASPM,API abuse detection
api_analytics_router,Platform,API usage analytics
api_discovery_router,ASPM,API asset discovery
api_gateway_router,Platform,API gateway security engine
api_gateway_security_router,ASPM,API gateway security scanning
api_inventory_router,ASPM,API inventory management
api_security_engine_router,ASPM,API security scanning engine
api_security_mgmt_router,ASPM,API security management
api_security_router,ASPM,API security (dast inner)
api_threat_protection_router,ASPM,API threat protection
app_config_router,Platform,App registration / APP_ID lifecycle
app_security_router,ASPM,Application security scanning
application_risk_router,ASPM,Application risk scoring
application_security_router,ASPM,Application security posture
arch_graph_router,ASPM,Architecture graph / code intel
asset_criticality_router,CTEM,Asset criticality scoring
asset_inventory_router,ASPM,Asset inventory
asset_lifecycle_router,ASPM,Asset lifecycle management
asset_risk_calculator_router,CTEM,Asset risk calculation
asset_tagging_router,ASPM,Asset tagging
attack_chain_router,CTEM,Attack chain analysis
attack_simulation_router,CTEM,Attack simulation
attack_surface_mgmt_router,CTEM,Attack surface management [DUPLICATE x2]
attack_surface_manager_router,CTEM,Attack surface manager
attack_surface_monitor_router,CTEM,Attack surface monitoring
audit_management_router,GRC,Audit management lifecycle
audit_router,GRC,Audit log / compliance trail
auth_router,Platform,Authentication (JWT issue/refresh)
auto_pentest_router,CTEM,Automated penetration testing
auto_waiver_router,GRC,Auto waiver generation
autonomous_remediation_router,ASPM,Autonomous remediation engine
awareness_campaign_router,GRC,Security awareness campaigns
aws_security_hub_router,CSPM,AWS Security Hub findings pull
azure_defender_router,CSPM,Azure Defender for Cloud
backup_router,Platform,Backup management
backup_validator_router,Platform,Backup/DR validation
bandwidth_analysis_router,CSPM,Network bandwidth analysis
binary_fingerprint_router,ASPM,Binary fingerprinting
blast_radius_router,CTEM,Blast radius calculation
breach_detection_router,CTEM,Breach detection engine
breach_response_router,CTEM,Breach response playbook
browser_security_router,ASPM,Browser security scanning
bug_bounty_router,CTEM,Bug bounty program management
bulk_operations_router,Platform,Bulk operations
bulk_router,Platform,Bulk finding operations
casb_router,CSPM,Cloud Access Security Broker
cert_router,CSPM,Certificate management
certificate_lifecycle_router,CSPM,Certificate lifecycle
change_management_router,Platform,Change management tracking
changelog_router,Platform,Changelog / release notes
choke_point_router,CTEM,Attack path choke points
cicd_router,ASPM,CI/CD pipeline security
ciem_ad_router,CSPM,Cloud Infrastructure Entitlement Management / Active Directory
ciso_report_router,GRC,CISO executive reporting
cloud_account_monitoring_router,CSPM,Cloud account monitoring
cloud_compliance_router,GRC,Cloud compliance checks
cloud_connectors_router,CSPM,Cloud provider connectors
cloud_cost_optimization_router,CSPM,Cloud cost/security optimization
cloud_cost_security_router,CSPM,Cloud cost security analysis
cloud_discovery_router,CSPM,Multi-cloud asset discovery
cloud_drift_router,CSPM,Cloud configuration drift
cloud_governance_router,GRC,Cloud governance policies
cloud_graph_router,CSPM,Cloud resource graph
cloud_incident_response_router,CTEM,Cloud incident response
cloud_native_security_router,CSPM,Cloud-native security posture
cloud_posture_router,CSPM,Cloud posture management
cloud_resource_inventory_router,CSPM,Cloud resource inventory
cloud_security_analytics_router,CSPM,Cloud security analytics
cloud_security_engine_router,CSPM,Cloud security scanning engine
cloud_security_findings_router,CSPM,Cloud security findings normalization
cloud_workload_protection_router,CSPM,Cloud workload protection [DUPLICATE x2]
cmdb_router,Platform,Configuration management database
code_ownership_router,ASPM,Code ownership mapping
code_to_runtime_router,ASPM,Code-to-runtime tracing
collaboration_router,Platform,Collaboration / comments
compliance_calendar_router,GRC,Compliance calendar / deadlines
compliance_evidence_router,GRC,Compliance evidence collection
compliance_gap_router,GRC,Compliance gap analysis
compliance_mapping_router,GRC,Framework control mapping
compliance_planner_router,GRC,Compliance planning
compliance_reports_router,GRC,Compliance reporting
compliance_router,GRC,Core compliance framework
compliance_scanner_router,GRC,Compliance scanning
compliance_seed_router,GRC,Compliance seed data
compliance_workflow_router,GRC,Compliance workflow automation
connectors_router,Platform,Universal connectors (Jira/GitHub/Slack)
container_registry_security_router,ASPM,Container registry scanning
container_runtime_router,ASPM,Container runtime security
container_runtime_security_router,ASPM,Container runtime protection
container_scanner_router,ASPM,Container vulnerability scanner
container_security_connector_router,ASPM,Container security connectors (Trivy/Grype)
container_security_posture_router,CSPM,Container security posture (CSPM side)
context_engine_router,ASPM,Code context engine
control_testing_router,GRC,Control effectiveness testing
correlation_router,CTEM,Finding correlation / Exposure Cases
council_enhanced_router,Platform,Enhanced LLM council calibration
crypto_key_management_router,CSPM,Crypto key management
cspm_connector_router,CSPM,CSPM connector
cspm_deep_router,CSPM,CSPM deep scan
cspm_engine_router,CSPM,CSPM engine
ctem_engine_router,CTEM,CTEM pipeline engine
ctem_pipeline_router,CTEM,CTEM 15-stage pipeline
ctem_router,CTEM,CTEM core
cyber_insurance_router,GRC,Cyber insurance risk quantification
cyber_resilience_router,CTEM,Cyber resilience assessment
cyber_threat_intelligence_router,CTEM,Cyber threat intelligence
cyber_threat_modeling_router,CTEM,Threat modeling pipeline
dark_web_monitoring_router,CTEM,Dark web monitoring
dashboard_builder_router,Platform,Dashboard builder
dast_pentest_router,CTEM,DAST penetration testing
data_discovery_router,GRC,Data discovery / classification
data_exfiltration_router,CTEM,Data exfiltration detection
data_governance_router,GRC,Data governance
data_lake_security_router,CSPM,Data lake security
data_privacy_router,GRC,Data privacy management
data_retention_router,GRC,Data retention policies
data_security_router,GRC,Data security management
db_security_router,CSPM,Database security scanning (CIS benchmarks)
ddos_protection_router,CTEM,DDoS protection / mitigation
deception_analytics_router,CTEM,Deception / honeypot analytics
deep_code_analysis_router,ASPM,Deep static code analysis
dep_scanner_router,ASPM,Dependency vulnerability scanner
deployment_router,Platform,Deployment management
design_doc_router,Platform,Design documentation
dev_identity_router,ASPM,Developer identity / secrets
developer_portal_router,ASPM,Developer security portal
developer_profiles_router,ASPM,Developer security profiles
devsecops_router,ASPM,DevSecOps pipeline integration
digital_forensics_router,CTEM,Digital forensics
digital_identity_router,CSPM,Digital identity management
digital_twin_security_router,CTEM,Digital twin security simulation
dlp_router,GRC,Data Loss Prevention
drift_router,CSPM,Configuration drift detection
duckdb_analytics_router,Platform,DuckDB analytics layer
dynamic_rule_dsl_router,ASPM,Dynamic rule DSL engine
email_filtering_router,CTEM,Email filtering / phishing
email_security_router,CTEM,Email security scanning
endpoint_compliance_router,GRC,Endpoint compliance checking
endpoint_forensics_router,CTEM,Endpoint forensics
endpoint_security_router,CTEM,Endpoint security management
endpoint_threat_hunting_router,CTEM,Endpoint threat hunting
evidence_chain_router,GRC,Tamper-proof evidence chain
evidence_collector_router,GRC,Evidence collection
evidence_vault_router,GRC,Evidence vault storage
exception_policy_router,GRC,Exception / waiver policy
exec_security_reports_router,GRC,Executive security reports
executive_dashboard_router,GRC,Executive security dashboard
executive_report_router,GRC,Executive report generation
executive_reporting_router,GRC,Executive reporting engine
export_coverage_router,GRC,Coverage export
export_router,Platform,Data export
fair_per_bu_router,GRC,FAIR risk quantification per business unit
fail_router,CTEM,FAIL chaos / attack simulation engine
feature_flag_router,Platform,Feature flag management
feed_manager_router,CTEM,Threat intel feed manager
fedramp_router,GRC,FedRAMP compliance
findings_lifecycle_router,ASPM,Findings lifecycle state machine
findings_router,ASPM,Findings management (lifecycle/assignment/SLA)
fips_router,GRC,FIPS compliance
firewall_management_router,CSPM,Firewall management
firewall_policy_router,CSPM,Firewall policy analysis
firewall_rule_router,CSPM,Firewall rule management
firmware_security_router,ASPM,Firmware security scanning
fix_engine_router,ASPM,AutoFix engine
forensics_readiness_router,CTEM,Forensics readiness
function_reachability_router,ASPM,Function reachability analysis
gate_router,ASPM,CI gate / PR quality gate (auth internal)
gcp_scc_router,CSPM,Google Cloud Security Command Center
gdpr_compliance_router,GRC,GDPR compliance
github_app_autofix_router,ASPM,GitHub App AutoFix integration
github_app_router,ASPM,GitHub App integration
github_security_router,ASPM,GitHub security scanning
graphql_router,ASPM,GraphQL security scanning
graphrag_router,Platform,GraphRAG knowledge queries
health_v1_router,Platform,Health checks (/api/v1/health)
hooks_router,Platform,Hooks management
hooks_yaml_router,Platform,YAML-based hooks
hunting_automation_router,CTEM,Threat hunting automation
iac_scanner_router,ASPM,IaC security scanner
iam_policy_router,CSPM,IAM policy analysis
iam_sso_router,Platform,IAM/SSO connector (Keycloak)
ide_backend_router,ASPM,IDE security backend
identity_governance_router,GRC,Identity governance
identity_lifecycle_router,CSPM,Identity lifecycle management
identity_risk_router,CSPM,Identity risk scoring
iga_router,GRC,Identity Governance and Administration
incident_comms_router,CTEM,Incident communications
incident_cost_router,GRC,Incident cost tracking
incident_impact_assessment_router,CTEM,Incident impact assessment
incident_kb_router,CTEM,Incident knowledge base
incident_lessons_router,GRC,Post-incident lessons learned
incident_metrics_router,GRC,Incident metrics / MTTR
incident_orchestration_router,CTEM,Incident orchestration (SOAR-adjacent)
incident_response_router,CTEM,Incident response management
incident_triage_router,CTEM,Incident triage
integration_health_router,Platform,Integration health monitoring
integration_hub_router,Platform,Integration hub (Slack/Jira/PagerDuty/ServiceNow)
integration_marketplace_router,Platform,Integration marketplace
intelligent_security_router,CTEM,Intelligent security recommendations
inventory_router,ASPM,Asset/SBOM inventory
ioc_enrichment_router,CTEM,IoC enrichment
iot_security_router,CTEM,IoT security [DUPLICATE x2]
ip_reputation_router,CTEM,IP reputation scoring
ir_playbook_router,GRC,IR playbook engine (NIST 800-61)
ir_playbook_runner_router,GRC,IR playbook runner
itdr_router,CSPM,Identity Threat Detection and Response
jira_sync_router,Platform,Jira bidirectional sync
k8s_security_router,CSPM,Kubernetes security scanning
kpi_router,GRC,KPI tracking
kpi_tracking_router,GRC,KPI tracking (extended)
kubernetes_security_router,CSPM,Kubernetes security posture
license_compliance_router,GRC,License compliance
license_scanner_router,ASPM,License scanning (SCA)
llm_loop_metrics_router,Platform,LLM learning loop metrics
local_file_store_router,Platform,Local file store
log_management_router,Platform,Log management
malicious_pkg_router,ASPM,Malicious package detection
malware_analysis_router,CTEM,Malware analysis
marketplace_router,Platform,Marketplace / integrations catalog
material_change_router,ASPM,Material change detection (drift/SLA impact)
mcp_gateway_router,Platform,MCP gateway (external AI agent interface)
mcp_router,Platform,MCP / GraphRAG integration
mdm_router,CSPM,Mobile device management
metrics_aggregator_router,Platform,Metrics aggregation
metrics_router,Platform,Core metrics
metrics_timeseries_router,Platform,Time-series metrics
mfa_management_router,CSPM,MFA management
microsegmentation_policy_router,CSPM,Micro-segmentation policy
mitre_attack_coverage_router,CTEM,MITRE ATT&CK coverage mapping
mitre_attack_router,CTEM,MITRE ATT&CK framework
mitre_coverage_router,CTEM,MITRE coverage analysis
mobile_app_security_router,ASPM,Mobile application security
mobile_device_management_router,CSPM,Mobile device management (extended)
mobile_security_router,ASPM,Mobile security scanning
n8n_router,Platform,n8n workflow automation integration
nac_router,CSPM,Network Access Control
network_access_control_router,CSPM,Network access control policies
network_anomaly_router,CTEM,Network anomaly detection
network_forensics_router,CTEM,Network forensics
network_monitoring_router,CSPM,Network monitoring
network_security_router,CSPM,Network security (NDR)
network_segmentation_router,CSPM,Network segmentation
network_threat_router,CTEM,Network threat detection
network_traffic_router,CSPM,Network traffic analysis
nl_graph_router,Platform,Natural language graph queries
notification_router,Platform,Notification management
oauth2_router,Platform,OAuth2 provider
observability_router,Platform,Observability / tracing
offline_feed_router,CTEM,Offline threat feed (air-gapped)
onboarding_router,Platform,Tenant onboarding
openclaw_router,CTEM,OpenClaw attack simulation
operational_technology_security_router,CTEM,OT security
org_hierarchy_router,Platform,Organization hierarchy
org_router,Platform,Organization management (multi-tenancy)
ot_security_router,CTEM,OT/ICS security
pagerduty_router,Platform,PagerDuty integration
pam_router,CSPM,Privileged Access Management
passive_dns_router,CTEM,Passive DNS intelligence
patch_automation_router,ASPM,Patch automation
patch_management_router,ASPM,Patch management
patch_manager_router,ASPM,Patch manager
patch_prioritizer_router,ASPM,Patch prioritization
pentest_router,CTEM,Penetration testing management
phishing_simulation_router,CTEM,Phishing simulation
physical_security_router,GRC,Physical security compliance
pipeline_bom_router,ASPM,Pipeline BOM / SBOM in CI
pki_management_router,CSPM,PKI management
playbook_marketplace_router,GRC,Playbook marketplace
playbook_router,GRC,Playbook automation
platform_router,Platform,Platform configuration
policy_enforcement_router,GRC,Policy enforcement engine
policy_engine_router,GRC,Policy engine (gate rules)
policy_generator_router,GRC,Policy document generator
policy_router,GRC,Policy management
policies_router,GRC,Security policies
posture_benchmark_router,CSPM,Posture benchmarking
posture_router,CSPM,Security posture management
posture_score_router,CSPM,Posture scoring
pr_gate_router,ASPM,PR gate / CI/CD check runs
pr_generator_router,ASPM,PR generation (AutoFix)
prioritizer_router,CTEM,Finding prioritization engine
privacy_gdpr_router,GRC,Privacy / GDPR
privacy_impact_assessment_router,GRC,Privacy impact assessment
privilege_escalation_detector_router,CSPM,Privilege escalation detection
privilege_escalation_router,CSPM,Privilege escalation analysis
privileged_access_governance_router,CSPM,Privileged access governance
privileged_identity_router,CSPM,Privileged identity management
privileged_session_recording_router,CSPM,Privileged session recording
prowler_router,CSPM,Prowler cloud compliance scanner
purple_team_router,CTEM,Purple team exercise engine
quantum_safe_crypto_router,GRC,Quantum-safe cryptography
queue_router,Platform,Task queue management
ransomware_protection_router,CTEM,Ransomware protection
rate_limit_router,Platform,Rate limiting management
rbac_router,Platform,RBAC management
red_team_mgmt_router,CTEM,Red team management
red_team_router,CTEM,Red team operations
regulatory_reporting_router,GRC,Regulatory reporting
regulatory_tracker_engine_router,GRC,Regulatory tracker engine
regulatory_tracker_router,GRC,Regulatory tracker
remediation_board_router,ASPM,Remediation board
remediation_router,ASPM,Remediation tracking
report_builder_router,GRC,Report builder
report_scheduler_router,GRC,Report scheduler
reports_router,GRC,Report generation
retention_router,GRC,Data retention management
risk_acceptance_router,GRC,Risk acceptance workflow
risk_aggregator_router,GRC,Risk aggregation
risk_quantification_engine_router,GRC,Risk quantification (FAIR engine)
risk_quantification_router,GRC,Risk quantification
risk_quantifier_router,GRC,Risk quantifier
risk_register_engine_router,GRC,Risk register engine
risk_register_router,GRC,Risk register
risk_scenario_router,GRC,Risk scenario planning
risk_treatment_router,GRC,Risk treatment workflow
runtime_protection_router,ASPM,Runtime protection / RASP
saas_security_posture_router,CSPM,SaaS security posture (SSPM)
sbom_export_router,ASPM,SBOM export
sbom_reeval_router,ASPM,SBOM re-evaluation
sbom_router,ASPM,SBOM management
scanner_ingest_router,ASPM,Scanner result ingestion
scheduled_reports_router,GRC,Scheduled report generation
secret_scanner_engine_router,ASPM,Secrets scanning engine
secret_scanner_router,ASPM,Secrets scanner
secrets_management_router,ASPM,Secrets management
secrets_rotation_router,ASPM,Secrets rotation
security_architecture_review_router,GRC,Security architecture review
security_automation_router,Platform,Security automation workflows
security_awareness_gamification_router,GRC,Security awareness gamification
security_awareness_metrics_router,GRC,Security awareness metrics
security_awareness_program_router,GRC,Security awareness program
security_baseline_router,GRC,Security baseline management
security_benchmark_router,GRC,Security benchmarking
security_budget_router,GRC,Security budget management
security_capacity_planning_router,GRC,Security capacity planning
security_champions_router,GRC,Security champions program
security_change_management_router,GRC,Security change management
security_chaos_router,CTEM,Security chaos engineering
security_culture_router,GRC,Security culture metrics
security_data_pipeline_router,Platform,Security data pipeline
security_dependency_mapping_router,ASPM,Security dependency mapping
security_dependency_risk_router,ASPM,Security dependency risk
security_event_correlation_router,CTEM,Security event correlation
security_event_timeline_router,CTEM,Security event timeline
security_exception_workflow_router,GRC,Security exception workflow
security_findings_router,ASPM,Security findings aggregation
security_gap_analysis_router,GRC,Security gap analysis
security_health_router,Platform,Security health monitoring
security_health_scorecard_router,GRC,Security health scorecard
security_investment_router,GRC,Security investment ROI
security_kb_router,CTEM,Security knowledge base
security_log_analysis_router,CTEM,Security log analysis
security_maturity_router,GRC,Security maturity assessment
security_metrics_aggregator_router,GRC,Security metrics aggregation
security_metrics_dashboard_router,GRC,Security metrics dashboard
security_metrics_router,GRC,Security metrics / OKR
security_okr_router,GRC,Security OKR tracking
security_operations_automation_router,CTEM,Security operations automation
security_operations_metrics_router,GRC,Security operations metrics
security_playbook_router,GRC,Security playbook management
security_posture_benchmarking_router,GRC,Posture benchmarking
security_posture_history_router,GRC,Posture historical trend
security_posture_maturity_router,GRC,Posture maturity assessment
security_posture_pdf_router,GRC,Posture PDF report
security_posture_reporting_router,GRC,Posture reporting
security_posture_scoring_router,GRC,Posture scoring
security_posture_trend_router,GRC,Posture trend analysis
security_program_maturity_router,GRC,Security program maturity
security_query_router,Platform,Security query engine
security_questionnaire_router,GRC,Security questionnaire
security_registry_router,Platform,Security registry
security_roadmap_router,GRC,Security roadmap planning
security_roi_router,GRC,Security ROI analysis
security_scoreboard_router,GRC,Security scoreboard
security_scorecard_engine_router,GRC,Security scorecard engine
security_scorecard_public_router,GRC,Security scorecard (public)
security_scorecard_router,GRC,Security scorecard (authenticated)
security_service_catalog_router,GRC,Security service catalog
security_tabletop_router,GRC,Tabletop exercise management
security_telemetry_router,Platform,Security telemetry
security_tool_inventory_router,Platform,Security tool inventory
security_training_effectiveness_router,GRC,Security training effectiveness
security_training_router,GRC,Security training management
semantic_analyzer_router,ASPM,Semantic code analysis
semgrep_router,ASPM,Semgrep SAST scanner
service_account_auditor_router,CSPM,Service account auditing
servicenow_router,Platform,ServiceNow integration
servicenow_sync_router,Platform,ServiceNow bidirectional sync
servicenow_sync_webhook_router,Platform,ServiceNow webhook receiver
session_router,Platform,Session management
shadow_ai_router,CSPM,Shadow AI / unsanctioned model detection
sla_engine_router,Platform,SLA engine
sla_management_router,Platform,SLA management
sla_router,Platform,SLA tracking
slack_bot_router,Platform,Slack bot integration
slack_notifier_router,Platform,Slack notification delivery
slsa_provenance_router,ASPM,SLSA supply chain provenance
snyk_oss_router,ASPM,Snyk-OSS connector (Trivy+OSV fallback)
snyk_router,ASPM,Snyk scanner integration
soar_router,CTEM,SOAR engine
soc_automation_router,CTEM,SOC automation
soc_triage_router,CTEM,SOC triage
soc_workflow_router,CTEM,SOC workflow management
software_composition_analysis_router,ASPM,SCA engine
sso_router,Platform,Enterprise SSO (SAML/OIDC)
sse_router,Platform,Server-Sent Events streaming
stage_matrix_router,CTEM,CTEM stage matrix
stream_router,Platform,Streaming / SSE
subsidiary_attribution_router,GRC,Subsidiary risk attribution
supply_chain_attack_detection_router,CTEM,Supply chain attack detection
supply_chain_crud_router,ASPM,Supply chain CRUD
supply_chain_monitoring_router,ASPM,Supply chain monitoring
supply_chain_risk_router,ASPM,Supply chain risk
tag_router,Platform,Asset tagging
tenant_rate_limiter_router,Platform,Tenant rate limiting
tenant_router,Platform,Tenant management
third_party_vendor_router,GRC,Third-party vendor management
threat_actor_tracking_router,CTEM,Threat actor tracking
threat_attribution_router,CTEM,Threat attribution
threat_brief_router,CTEM,Threat brief generation
threat_contextualization_router,CTEM,Threat contextualization
threat_correlation_router,CTEM,Threat correlation [DUPLICATE x2]
threat_deception_management_router,CTEM,Threat deception management
threat_exposure_router,CTEM,Threat exposure scoring
threat_feed_aggregator_router,CTEM,Threat feed aggregation
threat_geolocation_router,CTEM,Threat geolocation
threat_hunting_playbook_router,CTEM,Threat hunting playbook
threat_hunting_router,CTEM,Threat hunting
threat_indicator_router,CTEM,Threat indicator management
threat_intel_connector_router,CTEM,Threat intel connector
threat_intel_enrichment_router,CTEM,Threat intel enrichment
threat_intel_fusion_router,CTEM,Threat intel fusion
threat_intel_router,CTEM,Threat intelligence correlation
threat_intelligence_automation_router,CTEM,Threat intelligence automation
threat_intelligence_confidence_router,CTEM,TI confidence scoring
threat_landscape_router,CTEM,Threat landscape analysis
threat_model_router,CTEM,Threat modeling
threat_modeling_pipeline_router,CTEM,Threat modeling pipeline
threat_response_router,CTEM,Threat response automation
threat_score_router,CTEM,Threat scoring
threat_simulation_router,CTEM,Threat simulation
threat_vector_analysis_router,CTEM,Threat vector analysis
tip_router,CTEM,Threat Intelligence Platform
tprm_exchange_router,GRC,Third-party risk management exchange
triage_router,ASPM,Unified triage (finding+attack+compliance+SLA)
trivy_router,ASPM,Trivy container/filesystem scanner
trust_center_router,GRC,Trust center (customer-facing posture)
trustgraph_backbone_router,Platform,TrustGraph backbone
trustgraph_integration_router,Platform,TrustGraph integration
trustgraph_maintenance_router,Platform,TrustGraph maintenance
trustgraph_migrator_router,Platform,TrustGraph migration
trustgraph_quality_router,Platform,TrustGraph quality monitor
trustgraph_router,Platform,TrustGraph knowledge graph
unified_dashboard_router,Platform,Unified security metrics dashboard
unified_issues_router,ASPM,Unified issues view
unified_rules_router,GRC,Unified rules engine
universal_ingest_router,ASPM,Universal finding ingest
upgrade_path_router,Platform,Upgrade path management
uba_router,CTEM,User Behavior Analytics
user_access_review_router,GRC,User access review
user_analytics_router,Platform,User analytics
users_public_router,Platform,Public user endpoints (no auth)
users_router,Platform,User management (authenticated)
validation_router,ASPM,Finding validation
vendor_compliance_router,GRC,Vendor compliance management
vendor_scorecard_router,GRC,Vendor security scorecard
verification_router,ASPM,Finding verification
version_router,Platform,Version endpoint (/api/v1/version)
versioning_router,Platform,API versioning
vuln_enricher_router,CTEM,Vulnerability enrichment
vuln_exception_router,GRC,Vulnerability exception management
vuln_intel_fusion_router,CTEM,Vulnerability intel fusion
vuln_intelligence_router,CTEM,Vulnerability intelligence
vuln_lifecycle_router,ASPM,Vulnerability lifecycle tracker
vuln_prioritization_router,CTEM,Vulnerability prioritization
vuln_prioritizer_router,CTEM,Vulnerability prioritizer
vuln_scan_router,ASPM,Vulnerability scanning
vuln_scanner_router,ASPM,Vulnerability scanner
vuln_workflow_router,ASPM,Vulnerability workflow
vulnerability_age_router,CTEM,Vulnerability age analysis
vulnerability_correlation_router,CTEM,Vulnerability correlation
vulnerability_disclosure_router,GRC,Vulnerability disclosure program
vulnerability_prioritization_router,CTEM,Vulnerability prioritization (extended)
vulnerability_remediation_router,ASPM,Vulnerability remediation
vulnerability_scoring_router,CTEM,Vulnerability scoring
vulnerability_workflow_router,ASPM,Vulnerability workflow (extended)
waf_engine_router,CSPM,WAF engine management
wave_a_code_intel_router,ASPM,Wave A code intelligence (19 endpoints)
wave_d_integrations_router,Platform,Wave D integrations (22 endpoints)
webhook_dlq_router,Platform,Webhook dead letter queue
webhook_events_router,Platform,Webhook event delivery
webhook_notifications_router,Platform,Webhook notification delivery
webhook_router,Platform,Webhook management
webhook_subscriptions_router,Platform,Webhook subscription management
webhook_verifier_router,Platform,Webhook signature verification
webhooks_receiver_router,Platform,Inbound webhook receiver
websocket_alerts_router,Platform,WebSocket real-time alerts
websocket_router,Platform,WebSocket event streaming
wireless_security_router,CSPM,Wireless security assessment
workflow_engine_router,Platform,Workflow engine
workflow_router,Platform,Workflow management
workflows_router,Platform,Workflows (write:findings auth)
ws_events_router,Platform,WS events unified stream
xdr_router,CTEM,Extended Detection and Response
zero_day_intelligence_router,CTEM,Zero-day intelligence
zero_trust_enforcement_router,CSPM,Zero trust enforcement
zero_trust_policy_router,CSPM,Zero trust policy management
_evidence_chain_late,GRC,Evidence chain (late-bound variant)
_findings_wave_b_router,ASPM,Findings wave B
_formula_router,Platform,Formula engine (late-bound)
_ip_reputation_late,CTEM,IP reputation (late-bound)
_sbom_router_late,ASPM,SBOM (late-bound variant)
_scif_router,GRC,SCIF / air-gapped compliance
_secret_scanner_late,ASPM,Secrets scanner (late-bound)
_teammates_router,Platform,Teammates / collaboration (late-bound)
_training_router,GRC,Training (late-bound)
_wa_router,ASPM,Wave A sub-router (loop-registered)
_wc_changes_router,ASPM,Wave C changes (late-bound)
_wc_router,ASPM,Wave C (late-bound)
app.mount /assets,Platform,StaticFiles — UI assets (only 1 mount call)
```

### Bucket Counts Summary

| Bucket | Router count | % of 467 |
|--------|-------------|----------|
| **CTEM** | 117 | 25% |
| **GRC** | 121 | 26% |
| **ASPM** | 92 | 20% |
| **CSPM** | 67 | 14% |
| **Platform** | 70 | 15% |
| **Total** | **467** | 100% |

Note: 567 total `include_router` calls reflects 100 conditional re-registrations (same router variable inside `if flag:` blocks). The 467 unique routers above represent every distinct module. The sub-apps will each call `include_router` on their own slice; the parent shim mounts the 5 sub-apps. Duplicate conditionals stay in the same sub-app file — no behavior change.

---

## 2. Sub-App Dependency Graph

### Shared Dependencies (available to ALL sub-apps via import)
```
apps.api.auth_deps          — api_key_auth FastAPI dependency
apps.api.app._verify_api_key — MUST be extracted to auth_deps.py (currently closure in create_app)
apps.api.app._require_scope  — MUST be extracted to auth_deps.py
apps.api.app._load_api_tokens— MUST be extracted (commit 435b54d1 per-request pattern)
```

### Cross-Sub-App Data Flows (no circular imports — data only, not code)

```
ASPM ──findings──► CTEM  (findings feed into threat correlation)
ASPM ──findings──► GRC   (findings feed into compliance evidence)
CSPM ──posture───► GRC   (cloud posture feeds into compliance)
CTEM ──intel─────► GRC   (threat intel feeds into risk register)
Platform ────────► ALL   (auth, org, tenant context injected via Depends)
```

### Cycle Check: NONE DETECTED

No sub-app imports another sub-app's router code. All cross-domain communication is via:
- Shared SQLite DB (PersistentDict pattern — same files, different keys)
- HTTP calls between sub-apps (already the pattern for Brain Pipeline)
- Shared `auth_deps.py` imported by each sub-app independently

**Critical**: `_verify_api_key` and `_require_scope` are currently closures defined INSIDE `create_app()`. They capture `expected_tokens`, `_load_api_tokens`, and `auth_strategy` from the outer scope. These MUST be refactored into `auth_deps.py` before sub-app extraction. This is the single highest-risk item.

---

## 3. Migration Order (Lowest Blast Radius First)

Order is determined by: (a) fewest cross-domain dependencies, (b) most self-contained router set, (c) independent test coverage.

### Wave 0 — Pre-work (blocking, must complete first)
**Extract auth to `auth_deps.py`** — move `_verify_api_key`, `_require_scope`, `_load_api_tokens` out of the `create_app()` closure into the existing `auth_deps.py`. This file already has `api_key_auth` — extend it. All 5 sub-apps will import from here.
- Risk: LOW — `auth_deps.py` already exists and follows this exact pattern
- Verification: `python -c "from apps.api.auth_deps import verify_api_key, require_scope"` passes
- Beast Mode tests: run full suite — zero delta expected

### Wave 1 — CSPM sub-app (67 routers)
Why first: Most self-contained. CSPM routers are almost exclusively cloud-scan outputs with no write-path to ASPM finding state. Lowest inbound dependency count from other buckets.
- Create `suite-api/apps/api/sub_apps/cspm_app.py`
- Register 67 routers using extracted `verify_api_key` / `require_scope`
- Parent `app.py` replaces 67 `include_router` calls with `app.mount("/", cspm_app)` (transparent prefix — see Section 4)

### Wave 2 — GRC sub-app (121 routers)
Why second: GRC is read-heavy from ASPM/CTEM findings but does not produce findings itself. No write-path cycles.

### Wave 3 — Platform sub-app (70 routers)
Why third: Platform is depended on by all others (auth, org, tenant) but Platform routers themselves have no dependency on ASPM/CSPM/CTEM/GRC router code — only on DB state.

### Wave 4 — CTEM sub-app (117 routers)
Why fourth: CTEM consumes ASPM findings (read). ASPM not yet migrated — safe because dependency is on DB, not router code.

### Wave 5 — ASPM sub-app (92 routers)
Why last: ASPM is the write-path origin — findings are created here and consumed by all other buckets. Migrating last ensures all consumers are already stable on the new architecture before we touch the source.

---

## 4. Two-Week Step Plan

### Days 1-2: Wave 0 — Auth extraction
- Move `_verify_api_key`, `_require_scope`, `_load_api_tokens` into `auth_deps.py`
- Keep original names as re-exports in `app.py` (`_verify_api_key = auth_deps.verify_api_key`) so existing call sites don't break
- Run Beast Mode tests — must be green
- Commit: `refactor(auth): extract _verify_api_key/_require_scope to auth_deps.py`

### Days 3-4: Wave 1 — CSPM sub-app
- Create `suite-api/apps/api/sub_apps/__init__.py` (empty)
- Create `suite-api/apps/api/sub_apps/cspm_app.py`:
  ```python
  from fastapi import FastAPI
  cspm_app = FastAPI(title="ALdeci CSPM", openapi_url=None)
  # All 67 CSPM include_router calls moved here verbatim
  ```
- In parent `app.py`: replace 67 CSPM `include_router` calls with:
  ```python
  from apps.api.sub_apps.cspm_app import cspm_app
  app.mount("", cspm_app)  # transparent — no prefix change
  ```
- Pre/post route count check: `python -c "from apps.api.app import create_app; print(len(create_app().routes))"`
- Run Beast Mode — must be green
- Commit: `refactor(cspm): extract 67 routers to cspm sub-app`

### Days 5-6: Wave 2 — GRC sub-app (121 routers)
- Same pattern as CSPM
- Commit: `refactor(grc): extract 121 routers to grc sub-app`

### Days 7-8: Wave 3 — Platform sub-app (70 routers)
- Same pattern. Note: Platform includes auth_router, users_router, org_router — these must retain their exact prefixes (`/api/v1/auth`, etc.)
- Commit: `refactor(platform): extract 70 routers to platform sub-app`

### Days 9-10: Wave 4 — CTEM sub-app (117 routers)
- Same pattern
- Commit: `refactor(ctem): extract 117 routers to ctem sub-app`

### Days 11-12: Wave 5 — ASPM sub-app (92 routers)
- Same pattern. This leaves `app.py` as a ~200-line parent shim:
  - FastAPI app creation + middleware
  - `auth_deps` import
  - 5 sub-app mounts
  - StaticFiles mount
- Commit: `refactor(aspm): extract 92 routers to aspm sub-app — app.py now thin shim`

### Days 13-14: Hardening
- Remove all orphaned imports from `app.py` (Optional[APIRouter] = None guards for routers now in sub-apps)
- Verify OpenAPI docs still render (`/docs`, `/redoc`, `/api/v1/openapi.json`)
- Run `python -m pytest tests/test_phase*.py ... -q` — full Beast Mode suite
- Update `sys.setrecursionlimit` comment (currently 5000 for 453+ lifespan chain — may reduce with sub-apps)
- Commit: `refactor(app): finalize thin-shim parent, clean orphan imports`

---

## 5. Risk Register

### RISK-01: Auth closure capture (CRITICAL)
**What breaks**: `_verify_api_key` and `_require_scope` are closures inside `create_app()`. They capture `expected_tokens`, `auth_strategy`, and `_load_api_tokens` from the outer scope. If naively moved, sub-apps calling them won't have that closure context.  
**Mitigation**: Wave 0 extraction must reproduce the exact per-request `_load_api_tokens()` call pattern from commit 435b54d1. Use a module-level `_get_tokens()` function in `auth_deps.py` that reads env on every call (already the pattern in `auth_deps.py`'s `api_key_auth`). Test with `FIXOPS_API_TOKEN=test pytest tests/test_phase2_connectors.py`.

### RISK-02: Sub-app OpenAPI fragmentation
**What breaks**: Each `FastAPI()` sub-app generates its own OpenAPI schema. If sub-apps use `openapi_url="/api/v1/openapi.json"`, they collide. The `/docs` UI on the parent will only show parent-registered routes.  
**Mitigation**: Set `openapi_url=None` on all sub-apps. Parent retains sole OpenAPI ownership. If per-sub-app docs are needed later, use distinct URLs like `/cspm/openapi.json` — not in scope for this refactor.

### RISK-03: Middleware not propagating to sub-apps
**What breaks**: `app.py` adds RateLimitMiddleware, CORSMiddleware, correlation ID middleware via `app.add_middleware()`. These do NOT automatically apply to mounted sub-apps in FastAPI (sub-apps are separate ASGI apps).  
**Mitigation**: Add the same middleware stack to each sub-app in its factory function. Extract a `configure_middleware(app: FastAPI)` helper in a new `suite-api/apps/api/middleware_config.py` and call it in both parent and all sub-apps. Verify with integration test hitting a CSPM endpoint and checking response headers.

### RISK-04: Lifespan / startup event chain breaking
**What breaks**: `app.py` has a complex lifespan (database init, telemetry, flag provider setup). `sys.setrecursionlimit(5000)` is set because 453+ router lifespans chain recursively. Sub-apps add new lifespan contexts on top.  
**Mitigation**: Keep ALL lifespan logic in the parent `create_app()`. Sub-apps use `lifespan=None` (no startup/shutdown hooks). Validate by checking `sys.setrecursionlimit` is still sufficient after mounting 5 sub-apps. If recursion depth increases, bump to 7000.

### RISK-05: Conditional router registration (flag-gated routers)
**What breaks**: ~200 of the 567 calls are inside `if flag_provider.bool(...):` blocks that evaluate at startup. If the condition is in `app.py` but the router import is now in a sub-app file, the flag_provider reference is broken.  
**Mitigation**: Pass `flag_provider` into each sub-app factory as a constructor argument. Sub-app files define `create_cspm_app(flag_provider) -> FastAPI` factory functions rather than module-level singletons. Parent calls `app.mount("", create_cspm_app(flag_provider))`. This is the cleanest pattern and avoids global state.

---

## 6. Verification Checklist

Run these checks after EACH wave commit. All must pass before proceeding to the next wave.

```bash
# 1. Route count — must equal pre-refactor baseline
BEFORE=$(python -c "import os; os.chdir('suite-api'); from apps.api.app import create_app; print(len(create_app().routes))" 2>/dev/null)
echo "Baseline route count: $BEFORE"
# Save this number before Wave 0. Compare after each wave.

# 2. Beast Mode tests
python -m pytest \
  tests/test_phase2_connectors.py tests/test_phase3_llm_council.py \
  tests/test_phase4_integration.py tests/test_phase5_enterprise.py \
  tests/test_phase6_streaming.py tests/test_phase7_analytics.py \
  tests/test_phase8_mcp.py tests/test_phase9_playbooks.py \
  tests/test_phase10_e2e.py tests/test_connector_framework.py \
  tests/test_trustgraph.py tests/test_pipeline_api.py \
  tests/test_persona_workflows.py \
  -x --tb=short --timeout=10 -q -o "addopts="

# 3. Auth smoke test
curl -s -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/api/v1/health | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='ok', d"

# 4. OpenAPI schema still renders
curl -s http://localhost:8000/api/v1/openapi.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'OpenAPI paths: {len(d[\"paths\"])}')"

# 5. Auth dep still importable standalone (pre-create_app)
python -c "from apps.api.auth_deps import verify_api_key, require_scope; print('auth_deps OK')"

# 6. No import errors on sub-app files
python -c "from apps.api.sub_apps.cspm_app import create_cspm_app; print('cspm_app OK')"
python -c "from apps.api.sub_apps.grc_app import create_grc_app; print('grc_app OK')"
python -c "from apps.api.sub_apps.platform_app import create_platform_app; print('platform_app OK')"
python -c "from apps.api.sub_apps.ctem_app import create_ctem_app; print('ctem_app OK')"
python -c "from apps.api.sub_apps.aspm_app import create_aspm_app; print('aspm_app OK')"

# 7. Middleware headers present on sub-app routes
curl -sI http://localhost:8000/api/v1/cloud/posture | grep -i "x-correlation-id\|access-control-allow"
```

---

## 7. Final app.py Shape (Post-Refactor)

The parent `app.py` after Wave 5 will be approximately:

```
suite-api/apps/api/
├── app.py                    # ~200 lines: FastAPI factory + middleware + 5 mounts
├── auth_deps.py              # Extended: verify_api_key + require_scope + load_tokens
├── middleware_config.py      # NEW: configure_middleware(app) helper
└── sub_apps/
    ├── __init__.py
    ├── aspm_app.py           # create_aspm_app(flag_provider) — 92 routers
    ├── cspm_app.py           # create_cspm_app(flag_provider) — 67 routers
    ├── ctem_app.py           # create_ctem_app(flag_provider) — 117 routers
    ├── grc_app.py            # create_grc_app(flag_provider) — 121 routers
    └── platform_app.py       # create_platform_app(flag_provider) — 70 routers
```

`app.py` drops from 9,501 lines to ~200. Each sub-app file is ~1,500-2,500 lines (import block + include_router calls). All 567 `include_router` calls are preserved verbatim — moved, not rewritten.

---

*Plan written by Enterprise Architect agent. Multica issue f5d203e4. Next action: Wave 0 execution — extract auth closure to auth_deps.py.*
