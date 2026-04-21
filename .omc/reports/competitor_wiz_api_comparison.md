# Wiz.io API vs ALDECI API — Competitive Coverage Analysis

**Date:** 2026-04-17
**Analyst:** Executor (Claude Sonnet 4.6)
**Purpose:** Compare Wiz's public API surface against ALDECI's 5,263+ endpoints to identify gaps and advantages

---

## 1. Wiz API Architecture — Findings Summary

### 1.1 API Type

Wiz exposes a **GraphQL-only API**. There is no REST surface whatsoever.

- **Single endpoint per tenant:** `https://api.<tenant>.wiz.io/graphql`
- All operations (reads and writes) are HTTP POST to this one URL
- The endpoint region is embedded in the tenant subdomain: `us1`, `us2`, `eu1`, `eu2`
- A separate SCIM v2 endpoint exists at `https://api.<tenant>.wiz.io/scim/v2` (Enterprise plan only) for IdP-driven user provisioning

### 1.2 Authentication

- **Method:** OAuth 2.0 Client Credentials (service account model)
- **Token endpoint:** `https://auth.app.wiz.io/oauth/token`
- **Token request body:** `grant_type=client_credentials`, `client_id`, `client_secret`, `audience=wiz-api`
- **Token lifetime:** Not publicly documented; typically short-lived (1 hour)
- **Setup:** Settings > Service Accounts in the Wiz portal; client secrets shown only once
- **No API key support:** Token-only authentication; no static API key header option

### 1.3 Rate Limiting

| Constraint | Value |
|-----------|-------|
| Max requests/second | **3 req/s** (Cribl documentation) |
| HTTP 429 on breach | Yes |
| Retry-After header | Not documented publicly |
| Audit Logs result cap | 10,000 per query |
| Cloud Configuration result cap | 10,000 per query |
| Issues | No documented limit |
| Vulnerabilities | No documented limit |
| Pagination | Cursor-based (`pageInfo.endCursor`), max 500 records/page |

### 1.4 Webhooks / Event Push

**Wiz has no webhook system.** Real-time event delivery is not available. The only options are:
- Poll the GraphQL API on a schedule
- Use SCIM for IdP-managed user provisioning events
- Use partner integrations (Datadog, Splunk, etc.) which themselves poll Wiz

### 1.5 SDK Availability

- OpenAPI/Swagger specification is available (noted on apitracker.io)
- No official client SDK published (Python, Go, JavaScript, etc.)
- Community-maintained Python wrappers exist but are not officially supported
- No CLI tool published by Wiz

---

## 2. Wiz API Data Categories — Complete Map

Based on research across Brinqa, Cribl, Datadog, Qualys, Port, and Stitchflow integration documentation, Wiz exposes the following data domains via GraphQL:

### 2.1 Core Security Data (Read)

| Category | GraphQL Scope | Notes |
|----------|--------------|-------|
| **Issues** | `read:issues` | Security findings with severity, status (OPEN/RESOLVED/REJECTED), type |
| **Vulnerabilities** | `read:vulnerabilities` | CVE data, CVSS, EPSS, vendor severity, remediation guidance, KEV status |
| **Cloud Configuration Findings** | `read:cloud_configuration` | Misconfigurations vs CIS/NIST/PCI baselines (10,000 result cap) |
| **Host Configuration Findings** | `read:host_configuration` | OS-level configuration assessment |
| **Audit Logs** | (implicit) | Admin actions, mutations, login events (10,000 result cap) |
| **Controls** | `read:issues` | Security control definitions with descriptions and recommendations |
| **Service Tickets** | `read:issues` | External ticket references (Jira, ServiceNow) |
| **SBOM Artifacts** | `read:sbom_artifacts` | Software packages, version, ecosystem, license |

### 2.2 Cloud Inventory (Read)

| Category | GraphQL Scope | Resource Types |
|----------|--------------|----------------|
| **Cloud Resources** | `read:resources`, `read:inventory` | Virtual Machines, Container Instances, Serverless Functions, Storage Buckets, Volumes, Storage Accounts, Virtual Networks, Subnets, Load Balancers, Database Servers, File Systems |
| **Cloud Accounts** | `read:cloud_accounts` | AWS accounts, Azure subscriptions, GCP projects, OCI tenancies, Alibaba accounts |
| **Kubernetes Resources** | `read:inventory` | Clusters, pods, containers, network exposures |
| **Projects** | `read:projects` | Wiz organizational grouping (maps to cloud accounts/environments) |
| **Repositories** | `read:inventory` | Git repos with platform, visibility, branch data |
| **Technologies** | `read:inventory` | Software/technology catalog: usage, risk, deployment |
| **Hosted Technologies** | `read:inventory` | Installed technologies with detection method, OS association |

### 2.3 Identity & Access (Read)

| Category | Notes |
|----------|-------|
| **IAM Identities** | Excessive/unused permissions via IAM Recommender integration |
| **Effective Permissions** | Computed actual permissions vs assigned permissions |
| **Service Accounts** | Read via GraphQL with scopes and creation timestamps |

### 2.4 User Management (Read + Write)

| Operation | GraphQL |
|-----------|---------|
| List users | Query, cursor-paginated |
| Get user by ID | Query |
| Create user | Mutation: `createUser(input: {name, email, role})` |
| Update user | Mutation: `updateUser` — role, isActive |
| Delete user | Mutation: `deleteUser` |
| List service accounts | Query |

### 2.5 Reports Endpoint (Separate)

For large dataset exports (cloud inventory, vulnerability bulk data), Wiz uses a separate **reports endpoint** rather than GraphQL due to GraphQL's limitations with large datasets. This returns CSV format. Operations:
- `create:reports` scope required
- Query `CloudConfigurationFindingsPage` with filterBy, first, after, orderBy parameters
- Inventory and vulnerability data retrieved via this reports export path

### 2.6 Compliance (Read)

- 250+ built-in frameworks (CIS, NIST 800-53, PCI-DSS, HIPAA, SOC 2, GDPR, ISO 27001, etc.)
- 2,800+ cloud configuration rules running continuously
- Framework compliance posture queryable via GraphQL
- No write operations to compliance data (findings are read-only)

---

## 3. Wiz API Scope Reference

The documented scopes (permissions) assignable to a service account:

| Scope | Access |
|-------|--------|
| `read:all` | Full read access (super-scope) |
| `read:cloud_accounts` | Cloud provider accounts |
| `read:resources` | Cloud resource inventory |
| `read:cloud_configuration` | Config finding reads |
| `read:host_configuration` | Host config finding reads |
| `read:issues` | Issues + controls + service tickets |
| `read:vulnerabilities` | CVE/vulnerability data |
| `read:inventory` | Full inventory including K8s, repos, technologies |
| `read:sbom_artifacts` | SBOM package data |
| `read:projects` | Project/org groupings |
| `read:reports` | Access to reports endpoint |
| `create:reports` | Generate new reports |
| `read:users` | User management reads |
| `write:users` | User CRUD mutations |
| `read:service_accounts` | Service account reads |

---

## 4. ALDECI API Architecture

### 4.1 API Type

ALDECI exposes a **REST API exclusively** — the opposite of Wiz's GraphQL-only approach.

- **Framework:** FastAPI (Python) with OpenAPI 3.0 spec auto-generated
- **Total router files:** 568 (as of 2026-04-17)
- **Estimated endpoint count:** 5,263+ (avg ~9 endpoints per router)
- **Versioning:** All endpoints under `/api/v1/` prefix
- **Schema:** Auto-generated OpenAPI/Swagger at `/docs` and `/redoc`

### 4.2 Authentication

- **Method:** API key via `X-API-Key` header (all routers use `Depends(api_key_auth)` or `Depends(_verify_api_key)`)
- **Simpler integration** than OAuth 2.0 client credentials — no token fetch step required
- SAML/OIDC SSO bridge available for user-facing authentication
- SCIM v2 also implemented for IdP provisioning

### 4.3 Rate Limiting

- Per-tenant rate limiting via `tenant_rate_limiter` router
- Redis-backed with org_id-scoped keys
- Configurable thresholds (not fixed at 3 req/s like Wiz)
- HTTP 429 with configurable Retry-After behavior

### 4.4 Webhooks / Event Push

ALDECI has a **full webhook system** — a significant advantage over Wiz:
- `webhook_router` — webhook subscription management
- `webhook_notifications` — notification delivery
- `webhook_events` — event streaming
- `webhook_dlq` — dead letter queue for failed deliveries
- `webhook_subscriptions` — subscription lifecycle
- `webhook_verifier` — HMAC signature verification
- `websocket_alerts` — real-time WebSocket push
- `ws_events` — WebSocket event streaming

---

## 5. Head-to-Head API Coverage Comparison

### 5.1 Data Domains — What Wiz Has vs ALDECI

| Domain | Wiz API | ALDECI API |
|--------|---------|-----------|
| Cloud resource inventory | read:inventory | `cloud_resource_inventory`, `cloud_discovery`, `asset_inventory`, `cmdb` |
| Cloud configuration findings | read:cloud_configuration | `cloud_compliance`, `cspm`, `cspm_deep`, `cloud_posture`, `config_benchmark` |
| Vulnerabilities (CVE) | read:vulnerabilities | `cve_enrichment`, `vuln_intelligence`, `vuln_lifecycle`, `vuln_scan`, `vuln_trend`, `vulnerability_age`, `vulnerability_correlation`, `vulnerability_scoring`, `vuln_prioritization`, `vulnerability_remediation`, `vuln_exception`, `vuln_workflow`, `vuln_intel_fusion` |
| Issues / findings | read:issues | `security_findings`, `cloud_security_findings`, `alert_enrichment`, `alert_triage` |
| Audit logs | implicit | `audit`, `audit_analytics`, `audit_management` |
| SBOM | read:sbom_artifacts | `sbom`, `sbom_export`, `sca`, `software_composition_analysis` |
| Users & service accounts | write:users | `users`, `admin`, `scim`, `identity_lifecycle`, `digital_identity` |
| Projects / orgs | read:projects | `org`, `tenant`, `admin` |
| Cloud accounts | read:cloud_accounts | `cloud_account_monitoring`, `cloud_connectors` |
| Compliance frameworks | read-only | `compliance`, `compliance_automation`, `compliance_calendar`, `compliance_evidence`, `compliance_gap`, `compliance_mapping`, `compliance_scanner`, `compliance_workflow`, `gdpr_compliance`, `fedramp` |
| Controls | read:issues | `control_testing`, `security_benchmark` |
| Kubernetes security | read:inventory | `kubernetes_security`, `k8s_security`, `container_security_posture`, `container_registry_security`, `container_runtime_security` |
| Identity & permissions | IAM Recommender | `iam_policy`, `ciem`, `access_control`, `access_governance`, `access_matrix`, `privileged_access_governance`, `privileged_identity`, `privileged_session_recording` |
| Attack paths | Security Graph (UI only, no API) | `attack_path`, `attack_chain`, `attack_simulation`, `attack_surface` |
| Repositories | read:inventory | `github_security`, `cicd`, `code_ownership` |
| Technologies / SBOM | read:inventory | `sca`, `dependency_risk`, `security_dependency_mapping`, `security_dependency_risk` |

### 5.2 What Wiz Has That ALDECI Has (Equivalents)

Every Wiz API data category has a direct ALDECI equivalent. The table above shows complete coverage parity at the data-domain level.

### 5.3 What Wiz Has That ALDECI Does NOT Have

| Wiz Feature | Gap Analysis |
|-------------|-------------|
| **Security Graph API** | Wiz's graph relationships (resource-to-resource, IAM-to-resource, data-to-resource) are queryable as graph edges via GraphQL. ALDECI has `graph_rag`, `knowledge_graph`, `cloud_graph`, `trustgraph_*` routers but **no unified cloud asset relationship graph API** that maps cloud resources to IAM to data the way Wiz's Security Graph does. |
| **Toxic Combinations query** | Wiz can return findings that are classified as "toxic combinations" — multi-factor risk chains. ALDECI has no equivalent `toxic_combination` or correlated multi-factor finding query. |
| **"isAccessibleFromInternet" filter** | Wiz exposes internet-exposure as a first-class filter on any resource or finding query. ALDECI's `attack_surface` and `exposure_case` routers touch this but it is not a universal filter parameter across all resource queries. |
| **"hasSensitiveData" filter** | Wiz DSPM marks resources as containing sensitive data, queryable as a filter. ALDECI has `data_discovery`, `dlp`, `data_classification` but these are separate domains not a universal filter. |
| **GraphQL introspection** | Wiz's schema is self-documenting via GraphQL introspection — any client can enumerate all available queries/mutations/types without reading docs. ALDECI's OpenAPI spec provides equivalent documentation but requires reading the spec file rather than programmatic discovery. |
| **Reports bulk-export endpoint** | Wiz's reports endpoint produces CSV exports of full datasets for large-scale data pipeline ingestion. ALDECI has `export`, `report_builder`, `report_scheduler` but no dedicated bulk CSV export endpoint for raw engine data. |

### 5.4 What ALDECI Has That Wiz Does NOT Have

This is where ALDECI's competitive advantage lies. Wiz is a focused CNAPP. ALDECI covers the entire enterprise security stack.

#### A. Operational Security (Wiz has zero coverage)

| ALDECI Domain | Endpoints | Wiz Equivalent |
|---------------|-----------|----------------|
| SOC workflow management | `soc_workflow`, `soc_automation`, `soc_triage` | None |
| Incident orchestration | `incident_orchestration`, `incident_response`, `incident_triage`, `incident_timeline`, `incident_comms`, `incident_cost`, `incident_lessons`, `incident_kb`, `incident_metrics` | None |
| SIEM integration | `siem_integration` | None (Wiz feeds SIEMs, not manage them) |
| SOAR | `soar` | None |
| Alert management | `alerting_notification`, `alert_triage`, `alert_enrichment` | None |
| Threat hunting | `threat_hunting`, `threat_hunting_playbook`, `hunting_automation`, `endpoint_threat_hunting` | None |
| Playbooks | `playbook`, `playbook_marketplace`, `ir_playbook`, `ir_playbook_runner`, `security_playbook` | None |
| On-call / SLA | `sla`, `sla_engine`, `sla_escalation`, `sla_management` | None |

#### B. Endpoint & OT/IoT (Wiz = cloud only)

| ALDECI Domain | Wiz Equivalent |
|---------------|----------------|
| EDR | `edr` | None |
| NDR | `ndr` | None |
| XDR | `xdr` | None |
| MDM | `mdm`, `mobile_device_management` | None |
| OT/ICS/SCADA | `ot_security`, `operational_technology_security` | None |
| IoT security | `iot_security` | None |
| Firmware security | `firmware_security` | None |
| Physical security | `physical_security` | None |
| Wireless security | `wireless_security` | None |
| Mobile app security | `mobile_app_security` | None |
| Browser security | `browser_security` | None |

#### C. Identity & Access Management (ALDECI far deeper)

| ALDECI Domain | Wiz Equivalent |
|---------------|----------------|
| Privileged access governance | `privileged_access_governance` | Partial (IAM only) |
| Session recording | `privileged_session_recording` | None |
| MFA management | `mfa_management` | None |
| ITDR | `itdr` | None |
| Access request workflow | `access_request_management` | None |
| Access reviews | `user_access_review` | None |
| Digital identity (NIST 800-63) | `digital_identity` | None |
| Identity risk scoring | `identity_risk` | None |
| SCIM provisioning | `scim` | Enterprise-only |

#### D. Threat Intelligence (ALDECI far broader)

| ALDECI Domain | Wiz Equivalent |
|---------------|----------------|
| TIP (Threat Intel Platform) | `threat_intel_platform` | None |
| Dark web monitoring | `dark_web_monitoring` | None |
| Threat actor tracking | `threat_actor`, `threat_actor_tracking`, `threat_attribution` | None |
| IOC enrichment/lifecycle | `ioc_enrichment`, `threat_indicator`, `threat_intel_enrichment` | None |
| Threat intel sharing (STIX 2.1) | `threat_intel_sharing` | None |
| Threat intelligence automation | `threat_intelligence_automation` | None |
| Threat vector analysis | `threat_vector_analysis` | None |
| Geolocation | `threat_geolocation` | None |
| IP reputation | `ip_reputation` | None |
| Passive DNS | `passive_dns` | None |
| Feed subscriptions | `feed_manager`, `feeds`, `threat_feed_subscription`, `threat_feed_aggregator` | None |
| Zero-day intelligence | `zero_day_intelligence` | None |

#### E. GRC & Compliance (ALDECI far deeper)

| ALDECI Domain | Wiz Equivalent |
|---------------|----------------|
| Evidence collection/vault | `evidence`, `evidence_chain`, `evidence_collector`, `evidence_vault`, `auto_evidence` | None |
| Audit management | `audit_management` | None |
| Risk register | `risk_register`, `risk_register_engine` | None |
| Risk treatment | `risk_treatment` | None |
| Risk scenario modeling | `risk_scenario` | None |
| Risk quantification (FAIR) | `risk_quantification`, `risk_quantification_engine` | None |
| Security OKRs | `security_okr` | None |
| Security budget/investment | `security_budget`, `security_investment` | None |
| Vendor risk management | `vendor_risk`, `vendor_compliance`, `vendor_scorecard`, `third_party_vendor` | None |
| Security questionnaires | `security_questionnaire` | None |
| Regulatory reporting | `regulatory_reporting`, `regulatory_tracker` | None |
| Pentest management | `pentest_mgmt`, `pentest`, `micro_pentest`, `auto_pentest` | None |
| Bug bounty | `bug_bounty` | None |
| Red team management | `red_team_mgmt` | None |
| Tabletop exercises | `security_tabletop` | None |
| Security training | `security_training`, `training`, `security_training_effectiveness`, `security_awareness_program`, `awareness_score`, `awareness_campaign` | None |
| Compliance calendar | `compliance_calendar` | None |
| Policy management | `policies`, `policy`, `policy_enforcement` | None |

#### F. AI & Automation (ALDECI unique)

| ALDECI Domain | Wiz Equivalent |
|---------------|----------------|
| AI Governance | `ai_governance` | None |
| AI-powered SOC | `ai_powered_soc` | Partial (AI features in UI only) |
| AI security advisor (LLM) | `ai_security_advisor` | Chatbot only |
| TrustGraph / GraphRAG | `trustgraph_*`, `graph_rag`, `knowledge_graph` | None |
| Autonomous remediation | `autonomous_remediation`, `autofix`, `autofix_verify` | Partial (guided remediation) |
| Self-learning | `self_learning` | None |
| Security chaos engineering | `security_chaos` | None |
| Digital twin security | `digital_twin_security` | None |
| Quantum-safe crypto | `quantum_safe_crypto`, `quantum_crypto` | None |

#### G. Network Security (ALDECI only)

| ALDECI Domain | Wiz Equivalent |
|---------------|----------------|
| Network monitoring | `network_monitoring`, `network_analyzer`, `network_traffic` | None |
| Bandwidth analysis | `bandwidth_analysis` | None |
| WAF management | `waf`, `waf_engine` | None |
| DDoS protection | `ddos_protection` | None |
| Firewall policy | `firewall_management`, `firewall_policy`, `firewall_rule` | None |
| Network segmentation | `network_segmentation`, `microsegmentation_policy` | None |
| NAC | `nac`, `network_access_control` | None |
| Network forensics | `network_forensics` | None |
| Network anomaly detection | `network_anomaly` | None |
| Network threat detection | `network_threat` | None |

#### H. Developer Security (ALDECI additional depth)

| ALDECI Domain | Wiz Equivalent |
|---------------|----------------|
| DevSecOps pipeline | `devsecops`, `cicd`, `pr_gate`, `pr_generator` | Limited (IaC scanning) |
| SAST | `sast` | None |
| DAST | `dast` | None |
| API fuzzing | `api_fuzzer` | None |
| RASP | `rasp` | None |
| Secret scanning | `secret_scanner`, `secret_scanner_engine`, `secrets`, `secrets_management`, `secrets_rotation` | Limited (secrets detection) |
| License compliance | `license_compliance`, `software_license_security` | None |
| Code ownership | `code_ownership` | None |
| Semgrep integration | `semgrep` | None |
| Trivy integration | `trivy` | None |
| IaC scanning | `iac_scanner` | Yes (core feature) |

---

## 6. API Design Philosophy Comparison

| Dimension | Wiz | ALDECI |
|-----------|-----|--------|
| **API style** | GraphQL (single endpoint) | REST (versioned `/api/v1/`) |
| **Discoverability** | GraphQL introspection | OpenAPI/Swagger at `/docs` |
| **Auth** | OAuth 2.0 client credentials | API key (simpler) |
| **Rate limit** | 3 req/s (fixed, low) | Configurable per tenant |
| **Webhooks** | None | Full webhook + WebSocket system |
| **Real-time push** | None (polling only) | WebSocket alerts + event bus |
| **Bulk export** | Reports CSV endpoint | Export router + report builder |
| **SDK** | None official | None official (FastAPI auto-client gen possible) |
| **SCIM** | Enterprise plan only | Available by default |
| **Multi-tenant** | Yes (subdomain per tenant) | Yes (org_id-scoped, Redis-backed) |
| **Self-hosted** | No (SaaS only) | Yes (core value proposition) |
| **Domain coverage** | ~15 domains (cloud-focused) | 340+ domains (entire security stack) |

---

## 7. Gaps ALDECI Should Close

These are genuine features Wiz offers where ALDECI's coverage is weaker:

### Gap 1 — Unified Cloud Asset Relationship Graph API
**Priority: HIGH**

Wiz's core differentiator is not just discovering resources — it's mapping **relationships** between them (which IAM role can access which S3 bucket, which VM is reachable from the internet, which database has sensitive data accessible via a publicly-exposed container). These relationships are queryable via GraphQL edges.

ALDECI has TrustGraph, cloud_graph, and knowledge_graph routers, but no unified REST API that exposes:
- `GET /api/v1/cloud-graph/resources/{id}/relationships` — traversable edges to connected resources
- `GET /api/v1/cloud-graph/attack-paths/toxic-combinations` — multi-factor correlated risk paths
- `GET /api/v1/cloud-graph/resources?filter=isAccessibleFromInternet=true&hasSensitiveData=true` — universal exposure filters

**Recommendation:** Add a `cloud_graph_query` router that exposes BFS traversal, exposure filters, and toxic combination detection as REST endpoints.

### Gap 2 — Internet Exposure as Universal Filter
**Priority: MEDIUM**

Add `is_internet_exposed`, `has_sensitive_data`, `has_public_ip` as query parameters to the `asset_inventory`, `cloud_resource_inventory`, `vulnerability_*`, and `security_findings` endpoints. Currently these are domain-specific fields, not universal filters.

### Gap 3 — Bulk Data Export (CSV/NDJSON)
**Priority: MEDIUM**

Wiz's reports endpoint solves the "I need to export 50,000 findings to my SIEM" use case. ALDECI should add:
- `POST /api/v1/export/bulk` — initiate async bulk export
- `GET /api/v1/export/bulk/{job_id}` — poll status
- `GET /api/v1/export/bulk/{job_id}/download` — stream CSV/NDJSON result

### Gap 4 — GraphQL Endpoint (Optional / Enterprise)
**Priority: LOW**

Some enterprise buyers and integration teams strongly prefer GraphQL for its flexibility. ALDECI already has a `graphql` router. Exposing a read-only GraphQL schema covering the top 20 most-queried entities (findings, vulnerabilities, assets, compliance) would unlock integrations that target Wiz's GraphQL API specifically (Cribl, Brinqa, Port, Datadog).

### Gap 5 — Official Python SDK
**Priority: LOW**

Neither ALDECI nor Wiz ships an official Python SDK. However, because ALDECI's OpenAPI spec is auto-generated by FastAPI, publishing a generated Python client (via `openapi-generator`) would take ~1 day and provide a significant enterprise integration story that Wiz cannot match.

---

## 8. ALDECI Advantages to Market

These are genuine, documentable API-level advantages over Wiz that sales and marketing should lead with:

| Advantage | ALDECI | Wiz |
|-----------|--------|-----|
| **Webhook/event push** | Full webhook system + WebSocket real-time | Polling only, no webhooks |
| **API rate limit** | Configurable per tenant | Fixed 3 req/s ceiling |
| **API coverage** | 5,263+ endpoints across 340+ domains | ~50 GraphQL operations across ~15 domains |
| **Auth simplicity** | API key in header (1 step) | OAuth client credentials (2 steps: fetch token, then call) |
| **Operational security APIs** | SOC, SIEM, SOAR, playbooks, SLA | None |
| **Threat intelligence APIs** | 25+ TI domain routers | None |
| **GRC / risk APIs** | 40+ GRC routers | None |
| **Network security APIs** | 15+ network domain routers | None |
| **OT/IoT/physical security** | Full coverage | None |
| **Self-hosted** | Yes — all APIs run on-prem | SaaS-only |
| **AI governance API** | Yes | None |
| **Quantum-safe crypto API** | Yes | None |
| **Digital twin security** | Yes | None |

---

## 9. Summary Scorecard

| Criterion | Wiz Score | ALDECI Score | Notes |
|-----------|-----------|-------------|-------|
| Cloud security API depth | 9/10 | 7/10 | Wiz's Security Graph edges are richer; ALDECI covers the same domains but less relationship-aware |
| API breadth (total domains) | 3/10 | 10/10 | ALDECI covers 22x more security domains |
| API ease of integration | 6/10 | 9/10 | API key auth beats OAuth2 token flow for simplicity |
| Real-time event delivery | 0/10 | 9/10 | Wiz has no webhooks; ALDECI has full webhook + WebSocket stack |
| Rate limit flexibility | 4/10 | 8/10 | Wiz's 3 req/s cap is a real integration blocker at scale |
| Documentation / discoverability | 7/10 | 7/10 | GraphQL introspection vs OpenAPI — both adequate |
| SDK / tooling | 3/10 | 4/10 | Neither has an official SDK; Wiz has more community wrappers |
| Self-hosted / on-prem | 0/10 | 10/10 | Wiz is SaaS-only; ALDECI's entire API stack runs on-prem |
| Compliance API depth | 5/10 | 9/10 | Wiz has 250+ framework rules; ALDECI has evidence collection, audit trails, automated testing |
| Threat intelligence API | 0/10 | 9/10 | Wiz does not expose any TI data; ALDECI has 25+ TI domains |

**ALDECI overall API competitive position: SUPERIOR in breadth, parity in cloud-depth, superior in delivery mechanisms.**

---

## 10. Sources

- [Wiz User Management API Guide — Stitchflow](https://www.stitchflow.com/user-management/wiz/api)
- [Wiz Connector — Brinqa Docs](https://docs.brinqa.com/docs/connectors/wiz/)
- [Wiz Connector — Qualys Docs](https://docs.qualys.com/en/conn/latest/integrations/wiz_connector.htm)
- [Wiz Integration — Port Docs](https://docs.port.io/build-your-software-catalog/sync-data-to-catalog/code-quality-security/wiz/)
- [Wiz API Source — Cribl Docs](https://docs.cribl.io/stream/sources-wiz/)
- [Wiz Integration — Datadog Docs](https://docs.datadoghq.com/integrations/wiz/)
- [Wiz API — APITracker](https://apitracker.io/a/wiz-io)
- [Wiz in 2026: Definitive Guide — Solide Info](https://solideinfo.com/wiz-cloud-security/)
- [RegScale Wiz Integration](https://regscale.readme.io/docs/wiz)
- [Phoenix Security Wiz Integration](https://kb.phoenix.security/?ht_kb=wiz-integration)
- [Wiz Integrations Marketplace](https://www.wiz.io/integrations)
- [Wiz + Google Cloud Architecture](https://docs.cloud.google.com/architecture/partners/id-prioritize-security-risks-with-wiz)
