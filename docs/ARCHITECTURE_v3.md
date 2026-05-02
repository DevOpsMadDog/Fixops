# ALDECI CTEM+ Platform — Architecture v3.0

> **Classification**: Public
> **Version**: 3.0 | **Date**: 2026-04-12
> **Branch**: `features/intermediate-stage`
> **Status**: Definitive Architecture Reference — supersedes ARCHITECTURE_CHEATSHEET.md and ALDECI_REARCHITECTURE.md
> **Tagline**: Built for AI from the ground up. TrustGraph-native. Open architecture.

---

## Table of Contents

1. [Vision](#1-vision)
2. [Architecture Diagram](#2-architecture-diagram)
3. [TrustGraph Backbone](#3-trustgraph-backbone)
4. [Module Inventory — 136 Features](#4-module-inventory--136-features)
5. [Data Flows](#5-data-flows)
6. [Integration Matrix](#6-integration-matrix)
7. [Deployment Options](#7-deployment-options)
8. [Security Architecture](#8-security-architecture)
9. [API Surface](#9-api-surface)
10. [Competitive Positioning](#10-competitive-positioning)
11. [Roadmap](#11-roadmap)

---

## 1. Vision

ALDECI is the **decision layer for application security** — the first platform built AI-native from day one, with TrustGraph as its central nervous system.

Where competitors bolt AI onto existing architectures, ALDECI is structured around a knowledge graph that accumulates intelligence with every finding, every decision, and every remediation outcome. The result: a platform that gets smarter every day, never forgets context, and can prove every decision with a cryptographic audit trail.

**Three founding principles:**

1. **Built for AI from the ground up.** Every entity — finding, asset, connector, policy, evidence artifact — is a first-class node in TrustGraph. AI agents, copilots, and automation frameworks query the graph natively via GraphRAG and MCP. No adapter layer. No prompt engineering around flat database rows.

2. **TrustGraph-native.** The knowledge graph is not a feature. It is the platform. All 136 capabilities write to it, read from it, and reason over it. This enables cross-domain correlation that no point solution can match: a SAST finding can be linked to a cloud misconfiguration, traced to a running container, mapped to a compliance control, and correlated with active threat intelligence — in one query.

3. **Open architecture.** ALDECI works with every tool the customer already owns. 32 scanner normalizers. 13 PULL connectors. 7 bidirectional push connectors. 28+ threat intelligence feeds. 166 API routes across every domain. No rip-and-replace. No lock-in.

**What this means for customers:**

| Before ALDECI | With ALDECI |
|---------------|-------------|
| 11,300+ uncontextualized findings per week | ~340 prioritized, verified cases |
| 14+ days mean-time-to-decision | Sub-24-hour decision with LLM Council verdict |
| 6–8 weeks of manual evidence preparation per audit | Continuous, automated, cryptographically signed |
| Annual pentest for exploitability | Continuous MPTE — 365x per year |
| Tribal knowledge in spreadsheets | Graph-native institutional memory |

---

## 2. Architecture Diagram

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                        ALDECI CTEM+ PLATFORM — v3.0                            ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  ┌──────────────────────────────────────────────────────────────────────────┐   ║
║  │                    REACT 19 + VITE 6 FRONTEND                            │   ║
║  │  Mission Control · Discover · Validate · Remediate · Comply · AI         │   ║
║  │  35 Pages · 30 Persona Views · CISO/SOC/DevSec/Compliance/Red Team       │   ║
║  └───────────────────────────┬──────────────────────────────────────────────┘   ║
║                              │ REST + WebSocket                                  ║
║  ┌───────────────────────────▼──────────────────────────────────────────────┐   ║
║  │               FASTAPI GATEWAY — 166 ROUTERS · 1,700+ ROUTES              │   ║
║  │  Auth · RBAC · Rate Limiting · CORS · Request Logging · OpenAPI          │   ║
║  └──┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬───────┘   ║
║     │      │      │      │      │      │      │      │      │      │             ║
║  ┌──▼──┐ ┌─▼──┐ ┌─▼──┐ ┌▼────┐ ┌▼───┐ ┌▼───┐ ┌▼───┐ ┌▼───┐ ┌▼───┐ ┌▼────┐   ║
║  │SCAN │ │PIPE│ │LLM │ │CSPM │ │COMP│ │RBAC│ │FEED│ │PLAY│ │AUTO│ │MCP  │   ║
║  │NORM │ │ORCH│ │CNCL│ │ASPM │ │LY  │ │ OPA│ │MGMT│ │BOOK│ │FIX │ │GTWY │   ║
║  └──┬──┘ └─┬──┘ └─┬──┘ └┬────┘ └┬───┘ └┬───┘ └┬───┘ └┬───┘ └┬───┘ └┬────┘   ║
║     │      │      │      │       │      │      │      │      │      │             ║
║     └──────┴──────┴──────┴───────┴──────┴──────┴──────┴──────┴──────┘             ║
║                                    │                                               ║
║                    ┌───────────────▼──────────────────┐                           ║
║                    │         TRUSTGRAPH ENGINE         │                           ║
║                    │   ┌────────────────────────────┐  │                           ║
║                    │   │  KNOWLEDGE CORE 1: VULNS   │  │                           ║
║                    │   │  CVE · CVSS · EPSS · KEV   │  │                           ║
║                    │   ├────────────────────────────┤  │                           ║
║                    │   │  KNOWLEDGE CORE 2: ASSETS  │  │                           ║
║                    │   │  Code · Cloud · Container  │  │                           ║
║                    │   ├────────────────────────────┤  │                           ║
║                    │   │  KNOWLEDGE CORE 3: THREATS │  │                           ║
║                    │   │  MITRE · TTP · Campaigns   │  │                           ║
║                    │   ├────────────────────────────┤  │                           ║
║                    │   │  KNOWLEDGE CORE 4: COMPLY  │  │                           ║
║                    │   │  SOC2 · NIST · FedRAMP     │  │                           ║
║                    │   ├────────────────────────────┤  │                           ║
║                    │   │  KNOWLEDGE CORE 5: DECISIONS│  │                           ║
║                    │   │  LLM verdicts · Evidence   │  │                           ║
║                    │   └────────────────────────────┘  │                           ║
║                    │   162 entities · GraphRAG search   │                           ║
║                    └──────────────┬───────────────────┘                            ║
║                                   │                                                ║
║              ┌────────────────────┼────────────────────┐                           ║
║              │                    │                    │                           ║
║  ┌───────────▼──────┐  ┌──────────▼──────┐  ┌─────────▼────────┐                 ║
║  │ SCANNER LAYER    │  │  AI / LLM LAYER │  │  CONNECTOR LAYER │                 ║
║  │ 32 Normalizers   │  │  4-Model Council│  │  13 PULL + 7 PUSH│                 ║
║  │ SAST·DAST·SCA    │  │  Opus Escalation│  │  Jira·Slack·SNow │                 ║
║  │ Container·Secret │  │  GraphRAG Copil │  │  GitHub·GitLab   │                 ║
║  │ IaC·SBOM·API     │  │  OPA Policies   │  │  28+ Threat Feeds│                 ║
║  └──────────────────┘  └─────────────────┘  └──────────────────┘                 ║
║                                                                                  ║
║  ┌──────────────────────────────────────────────────────────────────────────┐   ║
║  │                       DATA LAYER (18 SQLite WAL DBs)                     │   ║
║  │  findings · brain · auth · audit · analytics · reports · feeds · sbom    │   ║
║  │  compliance · workflows · cspm · exposure · policy · secrets · threats   │   ║
║  └──────────────────────────────────────────────────────────────────────────┘   ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 3. TrustGraph Backbone

TrustGraph is not a bolt-on feature. It is the central nervous system of ALDECI. Every module writes to it. Every AI query reads from it.

### 3.1 Why TrustGraph

Traditional ASPM platforms store findings in relational databases — flat rows with foreign keys. TrustGraph stores the same data as a knowledge graph: entities with typed relationships, versioned context cores, and vector embeddings for semantic retrieval.

The difference is profound:

- **Relational DB query**: "Find all critical findings in repo X."
- **TrustGraph GraphRAG query**: "Find all findings in repo X that share attack patterns with CVE-2024-XXXX, are reachable from the internet, are in services owned by team Y, and have no remediation SLA assigned."

The second query is impossible to express efficiently in SQL across a multi-tool, multi-domain security dataset. TrustGraph makes it a single graph traversal.

### 3.2 Five Knowledge Cores

Each Core is a versioned partition of the graph with its own entity types, relationship schema, and update cadence.

| Core | Name | Entities | Relationships | Update Cadence |
|------|------|----------|---------------|----------------|
| **K1** | Vulnerability Intelligence | CVE, CVSS, EPSS, KEV, ExploitDB | exploits, affects, mitigates | Real-time (feed refresh) |
| **K2** | Asset Topology | Repo, Service, Container, CloudResource, Endpoint | owns, deploys, depends_on, exposes | On connector sync |
| **K3** | Threat Intelligence | TTP, Campaign, Actor, Indicator, MITRETechnique | uses, targets, attributed_to | 28+ feed refresh |
| **K4** | Compliance Controls | Framework, Control, Evidence, Audit | maps_to, satisfies, requires | On evidence generation |
| **K5** | Decision History | Finding, Verdict, LLMVote, FeedbackLoop | decided_by, overrides, learned_from | On every pipeline run |

**Total indexed**: 162 entities across all 5 cores (current codebase index, grows with each pipeline run).

### 3.3 Relationship Types

```
Finding ──[affects]──────────► Asset
Finding ──[exploits]─────────► CVE
Finding ──[maps_to]──────────► ComplianceControl
Finding ──[correlated_with]──► Finding          (cross-scanner deduplication)
Finding ──[triggers]─────────► ExposureCase
Finding ──[resolved_by]──────► Remediation
CVE     ──[has_exploit]──────► ExploitProof     (MPTE result)
Asset   ──[owned_by]─────────► Team
Asset   ──[deployed_in]──────► CloudRegion
Asset   ──[exposed_via]──────► AttackPath
Verdict ──[decided_by]───────► LLMCouncil
Verdict ──[overridden_by]────► HumanAnalyst
Evidence──[signs]────────────► ComplianceAudit
```

### 3.4 TrustGraph Indexer

`suite-core/core/trustgraph_indexer.py` — `TrustGraphIndexer` class (650 LOC)

Indexes the codebase and all pipeline outputs into TrustGraph:

```python
# Index entire codebase on deploy
from core.trustgraph_indexer import TrustGraphIndexer
TrustGraphIndexer().index_all()

# Query graph from copilot
from core.copilot_graphrag import CopilotGraphRAG
result = await CopilotGraphRAG().query("What critical findings affect payment services?")
```

### 3.5 GraphRAG Query Patterns

The AI Copilot (`/api/v1/copilot`) exposes GraphRAG to users. Under the hood, queries combine:

1. **Semantic vector search** — finds entities by meaning, not exact match
2. **Graph traversal** — expands context across relationship hops
3. **Temporal awareness** — filters by recency, version, or audit period
4. **Persona-aware scoping** — CISO sees risk-weighted results; SOC sees triage-priority results

---

## 4. Module Inventory — 136 Features

Organized by capability domain. Each entry represents a production module in `suite-core/core/`.

### 4.1 AI & Decision Intelligence (18 modules)

| Module | Description |
|--------|-------------|
| `brain_pipeline.py` | 12-step central AI pipeline — ingests findings, runs LLM council, emits signed verdicts. 4,353 LOC |
| `council_pipeline_adapter.py` | Bridges Karpathy LLM Council (4 free models + Opus escalation) to brain pipeline |
| `llm_council.py` | Multi-model consensus engine — configurable provider pool, 85% agreement threshold |
| `llm_consensus.py` | Karpathy-style consensus protocol — weighted voting, disagreement resolution |
| `enhanced_decision.py` | MultiLLMConsensusEngine with ProviderSpec, style focus, and confidence scoring |
| `copilot_graphrag.py` | AI security copilot with GraphRAG semantic search over TrustGraph |
| `policy_engine.py` | OPA-backed policy evaluation for findings, access, and remediation gates |
| `decision_memory.py` | Persistent memory of LLM decisions for consistency and self-learning |
| `decision_policy.py` | Policy-driven decision override rules and escalation conditions |
| `decision_tree.py` | DecisionTreeOrchestrator — 6-step enrichment, forecast, threat model, compliance, verdict |
| `hallucination_guards.py` | LLM output validation — detects and quarantines hallucinated CVE/CVSS data |
| `llm_guard_service.py` | Prompt injection hardening for all LLM interfaces |
| `llm_monitor.py` | Real-time monitoring of LLM API latency, cost, and error rates |
| `llm_providers.py` | Multi-provider abstraction — OpenAI, Anthropic, Gemini, Ollama, vLLM, OpenRouter |
| `model_factory.py` | Dynamic model instantiation with fallback chain |
| `model_registry.py` | Registry of available models with capability metadata |
| `openrouter_provider.py` | OpenRouter provider — free Qwen, Kimi K2, Llama 4 model access |
| `single_agent.py` | Single-agent execution mode for lightweight LLM tasks |

### 4.2 Scanner & Normalization (12 modules)

| Module | Description |
|--------|-------------|
| `scanner_parsers.py` | 32 scanner normalizers — converts raw XML/JSON to canonical FindingSchema. 2,395 LOC |
| `sarif_canon.py` | SARIF universal normalization — SARIF 2.1.0 ingest to internal format |
| `sast_engine.py` | Static analysis orchestration — Semgrep, CodeQL, SonarQube, Checkmarx |
| `dast_engine.py` | Dynamic analysis engine — OWASP ZAP, Burp Suite integration |
| `container_scanner.py` | Container vulnerability scanning — Trivy, Snyk Container, Aqua |
| `dep_scanner.py` | Dependency scanning — Dependabot, OWASP DC, Grype, Trivy |
| `secret_scanner.py` | Secret detection engine — GitLeaks, TruffleHog, detect-secrets |
| `secrets_scanner.py` | Enhanced secrets scanning with rotation tracking |
| `iac_scanner.py` | Infrastructure-as-Code scanning — Checkov, tfsec, KICS |
| `license_scanner.py` | OSS license compliance scanning — GPL, AGPL, LGPL detection |
| `real_scanner.py` | Native scanner runner — executes scanners directly without external tools |
| `semgrep_integration.py` | Semgrep deep integration with custom rule management |

### 4.3 Security Connectors (20 modules)

| Module | Description |
|--------|-------------|
| `security_connectors.py` | 13 PULL connectors — polls external security tools on schedule. 1,934 LOC |
| `connectors.py` | 7 bidirectional connectors — Jira, Slack, ServiceNow, GitHub, GitLab, Confluence, AzureDevOps. 3,620 LOC |
| `aws_security_hub.py` | AWS Security Hub PULL connector — findings, standards, insights |
| `azure_defender.py` | Azure Defender / Microsoft Defender for Cloud connector |
| `gcp_scc.py` | Google Cloud Security Command Center connector |
| `snyk_integration.py` | Snyk SAST/SCA/Container deep integration |
| `trivy_integration.py` | Trivy container + filesystem scan integration |
| `github_security.py` | GitHub Advanced Security — code scanning, Dependabot, secret scanning |
| `slack_integration.py` | Slack event subscription and bidirectional messaging |
| `slack_bot.py` | Slack bot for SOC alert triage from Slack |
| `jira_sync.py` | Jira two-way ticket synchronization |
| `servicenow_sync.py` | ServiceNow ITSM bidirectional connector |
| `pagerduty_integration.py` | PagerDuty alert routing and incident escalation |
| `cicd_integration.py` | CI/CD pipeline integration — Jenkins, GitHub Actions, GitLab CI |
| `notification_engine.py` | Multi-channel notification dispatcher |
| `notifications.py` | Notification templates and routing rules |
| `webhook_dlq.py` | Dead-letter queue for failed webhook deliveries |
| `integration_db.py` | Integration state persistence and health tracking |
| `integration_health.py` | Connector health monitoring and circuit breaker |
| `adapters.py` | Adapter pattern for third-party tool normalization |

### 4.4 Threat Intelligence (8 modules)

| Module | Description |
|--------|-------------|
| `feed_manager.py` | 28+ threat intel feed manager — NVD, EPSS, KEV, ExploitDB, OTX, AbuseIPDB |
| `vuln_intelligence.py` | Vulnerability intelligence correlation — CVE → CVSS → EPSS → KEV linkage |
| `threat_intel_correlator.py` | Cross-feed threat intelligence correlation engine |
| `threat_modeling.py` | STRIDE / MITRE ATT&CK threat modeling automation |
| `threat_hunting.py` | Threat hunting hypothesis manager — KQL/SPL query execution |
| `ip_reputation.py` | IP reputation scoring via AbuseIPDB, OTX, VirusTotal |
| `supply_chain_intel.py` | Software supply chain threat intelligence |
| `exploit_signals.py` | Exploit signal aggregation — PoC availability, weaponization indicators |

### 4.5 Risk & Prioritization (10 modules)

| Module | Description |
|--------|-------------|
| `vuln_prioritizer.py` | CVSS + EPSS + business context multi-factor risk scoring |
| `risk_posture.py` | Organization-level risk posture calculation and trending |
| `risk_acceptance.py` | Formal risk acceptance workflow with approver chain |
| `posture_scoring.py` | Security posture score — composite metric across all domains |
| `severity_promotion.py` | Automatic severity promotion based on exploit signals and KEV |
| `business_context.py` | Asset criticality and business context injection into scoring |
| `causal_inference.py` | Bayesian causal inference for root cause attribution |
| `monte_carlo.py` | Monte Carlo simulation for risk quantification |
| `probabilistic.py` | Probabilistic exploitability estimation models |
| `bn_lr.py` | Bayesian network + logistic regression hybrid risk model |

### 4.6 Pipeline Orchestration (8 modules)

| Module | Description |
|--------|-------------|
| `pipeline_orchestrator.py` | Multi-stage pipeline execution with event emission and analytics. 914 LOC |
| `pipeline_worker.py` | Background pipeline worker with queue management |
| `stage_runner.py` | Individual pipeline stage executor with retry logic |
| `processing_layer.py` | Async processing layer — batching, throttling, back-pressure |
| `event_bus.py` | Internal event bus for pipeline stage coordination |
| `event_emitter.py` | Event emission with subscriber notification |
| `event_streaming.py` | Real-time event streaming to frontend via WebSocket |
| `event_subscribers.py` | Event subscriber registry and dispatch |

### 4.7 Compliance & Evidence (12 modules)

| Module | Description |
|--------|-------------|
| `compliance_planner.py` | Compliance roadmap planning — gap analysis, control prioritization |
| `compliance_automation.py` | Automated control testing and evidence collection |
| `compliance_reports.py` | Compliance report generation — SOC 2, ISO 27001, NIST, PCI-DSS |
| `compliance_templates.py` | Report templates for all supported frameworks |
| `compliance.py` | Core compliance framework mapping engine |
| `soc2_evidence_generator.py` | SOC 2 Type II automated evidence generation |
| `evidence_collector.py` | Evidence artifact collection and chain-of-custody |
| `evidence_indexer.py` | Evidence indexing into TrustGraph K4 (Compliance Core) |
| `evidence.py` | Evidence data model and storage |
| `fedramp_controls.py` | FedRAMP Moderate control mapping and testing |
| `report_builder.py` | Executive and compliance report generator |
| `executive_reports.py` | Board-level and executive summary report generation |

### 4.8 Vulnerability & Exploit Validation (10 modules)

| Module | Description |
|--------|-------------|
| `micro_pentest.py` | MPTE (Micro-Pentest Engine) — 19-phase exploit verification |
| `mpte_advanced.py` | Advanced MPTE with FAIL Engine integration |
| `exploit_generator.py` | Safe exploit proof-of-concept generation for validation |
| `cve_tester.py` | CVE-specific test case executor |
| `attack_path_engine.py` | Attack path discovery and blast radius estimation |
| `attack_graph_gnn.py` | Graph Neural Network for attack path prediction |
| `attack_simulation_engine.py` | Full attack simulation orchestration |
| `attack_surface.py` | Attack surface enumeration and management |
| `attack_surface_discovery.py` | Continuous attack surface discovery — new endpoints, APIs, services |
| `auto_pentest.py` | Automated pentest scheduling and execution |

### 4.9 Remediation & AutoFix (9 modules)

| Module | Description |
|--------|-------------|
| `autofix_engine.py` | AI-powered AutoFix — 10 fix types, confidence-gated |
| `autofix_templates.py` | Fix templates for common vulnerability patterns |
| `autofix_verifier.py` | Post-fix verification — confirms fix validity before PR |
| `automated_remediation.py` | Automated remediation orchestration with approval gates |
| `pr_generator.py` | GitHub/GitLab pull request generation with fix context |
| `remediation_engine.py` | Remediation queue management and SLA tracking |
| `playbook_engine.py` | Security playbook runner — step-by-step automated response. 1,006 LOC |
| `playbook_runner.py` | Playbook execution runtime with rollback |
| `postfix_verifier.py` | Post-fix production verification |

### 4.10 Cloud Security (CSPM/ASPM) (8 modules)

| Module | Description |
|--------|-------------|
| `cspm_engine.py` | Cloud Security Posture Management — AWS/Azure/GCP misconfiguration detection |
| `cspm.py` | CSPM data model and storage |
| `cloud_graph.py` | Cloud resource topology graph construction |
| `code_to_cloud_tracer.py` | Traces code path from source commit to cloud deployment |
| `config_drift.py` | Infrastructure configuration drift detection |
| `iac.py` | IaC scanning orchestration — Terraform, Pulumi, CloudFormation |
| `continuous_validation.py` | Continuous security validation against cloud posture |
| `zero_gravity.py` | Four-tier intelligent data aging — reduces storage by 95% |

### 4.11 Identity, Auth & RBAC (10 modules)

| Module | Description |
|--------|-------------|
| `rbac.py` | Role-based access control — 6 roles, 30 persona mappings. 832 LOC |
| `auth_db.py` | Auth persistence — users, sessions, API keys, roles |
| `auth_middleware.py` | FastAPI auth middleware — JWT validation, API key check |
| `auth_models.py` | Pydantic auth models — User, Role, Session, APIKey |
| `auth_bootstrap.py` | Initial admin user and default role bootstrapping |
| `sso_provider.py` | SAML/OIDC SSO integration — Okta, Auth0, Azure AD |
| `api_key_manager.py` | API key lifecycle — issue, rotate, revoke, scope |
| `session_manager.py` | Session management with refresh token rotation |
| `user_db.py` | User persistence and profile management |
| `tenant_isolation.py` | Multi-tenant data isolation via row-level security |

### 4.12 Analytics & Observability (8 modules)

| Module | Description |
|--------|-------------|
| `analytics_engine.py` | Per-persona dashboard metrics and time-windowed aggregations. 804 LOC |
| `analytics_db.py` | Analytics time-series persistence |
| `analytics_models.py` | Pydantic analytics models |
| `analytics.py` | Core analytics computation — mean, percentile, trend |
| `user_analytics.py` | User behavior and persona-specific activity analytics |
| `api_analytics.py` | API usage metrics — endpoint hit rates, latency, error rates |
| `vulnerability_analytics.py` | Vulnerability trend analytics — MTTD, MTTR, backlog health |
| `metrics_aggregator.py` | Cross-domain metric aggregation for KPI dashboards |

### 4.13 Supply Chain & SBOM (5 modules)

| Module | Description |
|--------|-------------|
| `sbom_manager.py` | SBOM ingestion — CycloneDX 1.5, SPDX 2.3 |
| `sbom_runtime_correlator.py` | Correlates SBOM components with runtime vulnerabilities |
| `supply_chain_engine.py` | Software supply chain risk analysis |
| `ssdlc.py` | Secure SDLC integration — shift-left gate enforcement |
| `vendor_scorecard.py` | Third-party vendor security scorecard generation |

### 4.14 Workflow & Incident Response (6 modules)

| Module | Description |
|--------|-------------|
| `workflow_engine.py` | Event-driven workflow automation — conditions, actions, triggers. 874 LOC |
| `workflow_db.py` | Workflow state persistence |
| `workflow_models.py` | Pydantic workflow models |
| `incident_response.py` | Incident lifecycle management — detection, triage, contain, recover |
| `exposure_case.py` | Exposure case management — groups related findings for unified remediation |
| `sla_manager.py` | SLA definition, tracking, breach alerting |

### 4.15 Security Hardening (11 modules)

| Module | Description |
|--------|-------------|
| `fips_encryption.py` | FIPS 140-2/140-3 compliant encryption — AES-256-GCM |
| `quantum_crypto.py` | Algorithm-agile signing envelope — RSA-PSS shipping; FIPS 204 ML-DSA side activatable via `FIXOPS_PQ_BACKEND=dilithium-py` |
| `tls_config.py` | TLS 1.3 configuration with FIPS cipher suites |
| `crypto.py` | Core cryptographic primitives — signing, hashing, key derivation |
| `key_manager.py` | Key lifecycle management — rotation, escrow, audit |
| `encrypted_store.py` | Encrypted persistent store for sensitive data |
| `security_hardening.py` | OS and application hardening checks |
| `ssrf_protection.py` | SSRF attack prevention — URL validation, allowlist enforcement |
| `payload_guard.py` | Malicious payload detection on inbound API requests |
| `rate_limiter_v2.py` | Per-tenant, per-route rate limiting |
| `tenant_rate_limiter.py` | Tenant-aware rate limiting with burst allowance |

---

## 5. Data Flows

### 5.1 Scanner → TrustGraph → Dashboard

```
External Scanners (ZAP, Nessus, Snyk, SonarQube, Trivy, ...)
          │
          │  SARIF / vendor JSON / XML
          ▼
  scanner_parsers.py  [32 Normalizers]
  ┌─────────────────────────────────────────────┐
  │  ZAPNormalizer · NessusNormalizer           │
  │  SonarQubeNormalizer · SARIFUniversal       │
  │  TrivyNormalizer · CheckovNormalizer        │
  │  Converts to canonical FindingSchema        │
  └───────────────────┬─────────────────────────┘
                      │ FindingSchema (normalized)
                      ▼
  pipeline_orchestrator.py  [PipelineOrchestrator]
  ┌─────────────────────────────────────────────┐
  │  Stage 1: Deduplication                     │
  │    SHA-256 fingerprint + semantic cluster   │
  │    DB: fixops_dedup.db                      │
  │                                             │
  │  Stage 2: Enrichment                        │
  │    28+ threat intel feeds: NVD/EPSS/KEV     │
  │    Business context injection               │
  │                                             │
  │  Stage 3: LLM Council                       │
  │    4 free models + Opus escalation          │
  │    85% consensus threshold                  │
  │    Karpathy deliberation protocol           │
  │                                             │
  │  Stage 4: Risk Scoring                      │
  │    CVSS + EPSS + reachability + criticality │
  └───────────────────┬─────────────────────────┘
                      │ Enriched + Scored Finding
                      ▼
  brain_pipeline.py  [BrainPipeline]
  ┌─────────────────────────────────────────────┐
  │  OPA Policy Evaluation                      │
  │  Verdict emission (exploitable/FP/review)   │
  │  Confidence score + signed evidence         │
  │  Write to findings.db + fixops_brain.db     │
  └───────────────────┬─────────────────────────┘
                      │ Verdict + Evidence
                      ▼
  trustgraph_indexer.py  [TrustGraphIndexer]
  ┌─────────────────────────────────────────────┐
  │  Index finding entity into TrustGraph       │
  │  K1: CVE + CVSS + EPSS linkage             │
  │  K2: Asset + Service + Team relationship    │
  │  K5: Decision + Verdict + Council votes     │
  │  Enable GraphRAG semantic queries           │
  └───────────────────┬─────────────────────────┘
                      │ Graph updated
                      ▼
  analytics_engine.py  [PersonaDashboard]
  ┌─────────────────────────────────────────────┐
  │  Aggregate metrics per persona/role         │
  │  CISO: risk posture, compliance KPIs        │
  │  SOC: triage queue, SLA timers              │
  │  Dev: autofix opportunities, PR backlog     │
  └───────────────────┬─────────────────────────┘
                      │ Dashboard metrics
                      ▼
  React 19 Frontend
  ┌─────────────────────────────────────────────┐
  │  /mission-control/ciso  — Risk KPIs         │
  │  /mission-control/soc   — Alert queue       │
  │  /findings              — Finding explorer  │
  │  /discover/knowledge-graph — TrustGraph UI  │
  └─────────────────────────────────────────────┘
```

### 5.2 Finding → Correlation → Exposure Case → Remediation → PR

```
New Finding (from scanner or PULL connector)
          │
          ▼
  finding_correlator.py
  ┌────────────────────────────────────────┐
  │  Graph-based correlation              │
  │  Groups findings: same root cause,    │
  │  same asset, same attack vector       │
  │  Deduplication across 32 scanners     │
  └──────────────┬─────────────────────────┘
                 │ Correlated finding group
                 ▼
  exposure_case.py  [ExposureCase]
  ┌────────────────────────────────────────┐
  │  Create/update Exposure Case           │
  │  Link all correlated findings          │
  │  Assign owner (code_ownership.py)      │
  │  Set SLA (sla_manager.py)              │
  │  Notify via connectors                 │
  └──────────────┬─────────────────────────┘
                 │ Case ready for remediation
                 ▼
  autofix_engine.py  [AutoFixEngine]
  ┌────────────────────────────────────────┐
  │  Select fix type (10 available):       │
  │  · Patch version bump                  │
  │  · Code pattern replacement            │
  │  · Config remediation                  │
  │  · IaC resource update                 │
  │  · Secret rotation                     │
  │  LLM generates fix with context        │
  │  autofix_verifier.py validates diff    │
  └──────────────┬─────────────────────────┘
                 │ Validated fix diff
                 ▼
  pr_generator.py  [PRGenerator]
  ┌────────────────────────────────────────┐
  │  Generate PR on GitHub / GitLab        │
  │  Title: "fix(security): [CVE-...]"     │
  │  Body: finding context + fix rationale │
  │  Labels: severity, compliance tags     │
  │  Assign reviewer from code_ownership   │
  │  Auto-merge if confidence >= threshold │
  └──────────────┬─────────────────────────┘
                 │ PR merged → Finding closed
                 ▼
  evidence_collector.py
  ┌────────────────────────────────────────┐
  │  Collect remediation evidence          │
  │  Sign via quantum_crypto.py envelope    │
  │  (RSA-PSS today; ML-DSA activatable)    │
  │  Store in compliance evidence vault    │
  │  Map to compliance controls (K4)       │
  └────────────────────────────────────────┘
```

### 5.3 Alert → Notification → Incident → Post-Mortem

```
High-severity finding or SLA breach event
          │
          ▼
  notification_engine.py
  ┌────────────────────────────────────────┐
  │  Route by severity + persona config   │
  │  Critical → PagerDuty + Slack + Email │
  │  High → Slack + Jira                  │
  │  SLA breach → Manager escalation      │
  └──┬──────────┬──────────────┬───────────┘
     │          │              │
     ▼          ▼              ▼
  Slack       PagerDuty     ServiceNow
  (slack_   (pagerduty_   (servicenow_
  bot.py)   integration)    sync.py)
     │          │              │
     └──────────┴──────────────┘
                │ Incident created
                ▼
  incident_response.py  [IncidentLifecycle]
  ┌────────────────────────────────────────┐
  │  Phases: detect → triage → contain     │
  │          → eradicate → recover         │
  │  Timeline with timestamp + actor       │
  │  Playbook auto-assignment              │
  │  LLM council triage verdict            │
  └──────────────┬─────────────────────────┘
                 │ Incident resolved
                 ▼
  Post-mortem evidence generation
  ┌────────────────────────────────────────┐
  │  Timeline export (PDF + JSON)          │
  │  Root cause attribution (causal_      │
  │    inference.py Bayesian model)        │
  │  Compliance evidence signed + stored   │
  │  Self-learning feedback to K5          │
  └────────────────────────────────────────┘
```

---

## 6. Integration Matrix

### 6.1 Scanner Integrations (32 normalizers)

| Category | Tool | Protocol | Finding Format |
|----------|------|----------|----------------|
| **SAST** | Semgrep | SARIF | semgrep-results.sarif |
| **SAST** | SonarQube | REST API | JSON issues export |
| **SAST** | Checkmarx | REST API | XML / SARIF |
| **SAST** | CodeQL | SARIF | code-scanning alerts |
| **SAST** | Veracode | REST API | XML pipeline scan |
| **SAST** | Fortify | REST API | FPR / SARIF |
| **DAST** | OWASP ZAP | REST API | JSON / XML report |
| **DAST** | Burp Suite | REST API | XML report |
| **DAST** | Rapid7 | REST API | JSON |
| **DAST** | Qualys WAS | REST API | XML |
| **SCA** | Snyk Open Source | REST API | JSON |
| **SCA** | Dependabot | GitHub API | JSON alerts |
| **SCA** | Trivy (SCA) | JSON | trivy-results.json |
| **SCA** | Grype | JSON | grype-results.json |
| **SCA** | OWASP Dependency-Check | REST / XML | DC report |
| **Container** | Trivy (Container) | JSON | image scan results |
| **Container** | Snyk Container | REST API | JSON |
| **Container** | Prisma Cloud | REST API | JSON |
| **Container** | Aqua Security | REST API | JSON |
| **Container** | Sysdig | REST API | JSON |
| **CSPM** | Wiz | GraphQL API | JSON |
| **CSPM** | Orca Security | REST API | JSON |
| **CSPM** | Lacework | REST API | JSON |
| **CSPM** | Checkov | JSON | checkov-results.json |
| **CSPM** | tfsec | JSON | tfsec-results.json |
| **CSPM** | KICS | JSON | kics-results.json |
| **Secrets** | GitLeaks | JSON | gitleaks-report.json |
| **Secrets** | TruffleHog | JSON | trufflehog-results.json |
| **Secrets** | detect-secrets | JSON | .secrets.baseline |
| **CNAPP** | AWS Security Hub | AWS SDK | SecurityHub findings |
| **CNAPP** | Azure Defender | REST API | JSON alerts |
| **CNAPP** | Google Cloud SCC | REST API | JSON findings |

### 6.2 Ticketing & ITSM

| Tool | Mode | Capabilities |
|------|------|-------------|
| Jira | Bidirectional | Create, update, close tickets; sync status; field mapping |
| ServiceNow | Bidirectional | Incident and change management integration |
| GitHub Issues | Bidirectional | Create issues, PRs; auto-close on fix merge |
| GitLab Issues | Bidirectional | Same as GitHub; MR creation |
| Azure DevOps | Bidirectional | Work items, pipelines, board sync |
| Confluence | Write | Auto-generate remediation runbooks |

### 6.3 Notification & Alerting

| Tool | Mode | Triggers |
|------|------|---------|
| Slack | Bidirectional | Critical findings, SLA breach, pipeline status, bot commands |
| PagerDuty | Push | Critical + High severity, SLA breach |
| Microsoft Teams | Push | Alert summaries, compliance reports |
| Email (SMTP) | Push | Scheduled reports, escalations |
| Webhooks | Push | Configurable event-driven HTTP callbacks |

### 6.4 Threat Intelligence Feeds (28+)

| Category | Feeds |
|----------|-------|
| **CVE / Vulnerability** | NVD, OSV, GitHub Advisory |
| **Exploit Intelligence** | CISA KEV, ExploitDB, EPSS |
| **Network / IP** | AbuseIPDB, AlienVault OTX, VirusTotal |
| **Vendor Advisories** | Microsoft, Apple, AWS, Azure, Oracle, Cisco, VMware, Docker, Kubernetes |
| **Ecosystem** | NPM, PyPI, Ruby, Rust, Go, Maven, NuGet |
| **OS Advisories** | Debian, Ubuntu, Alpine |

### 6.5 Cloud Platforms

| Platform | Connector | Capabilities |
|----------|-----------|-------------|
| AWS | `aws_security_hub.py` | SecurityHub findings, GuardDuty, Config rules, Inspector |
| Azure | `azure_defender.py` | Defender for Cloud, Sentinel alerts, Policy compliance |
| GCP | `gcp_scc.py` | Security Command Center, Asset Inventory |

### 6.6 CI/CD Integration

| Platform | Integration Type | Gate Behavior |
|----------|-----------------|---------------|
| GitHub Actions | Native action + webhook | Block PR on high severity; comment with findings |
| GitLab CI | Pipeline stage + webhook | Fail stage on policy violation |
| Jenkins | Plugin + REST | Post-build scan gate |
| Azure Pipelines | Task + webhook | Stage gate with SARIF upload |
| CircleCI | Orb + webhook | Job gate |

---

## 7. Deployment Options

### 7.1 Decision Matrix

| Factor | Docker Compose | Kubernetes | Helm | Air-Gapped |
|--------|---------------|------------|------|------------|
| **Setup time** | <15 minutes | 2–4 hours | 30 minutes | 1–2 days |
| **Scale** | Single node | Horizontal | Horizontal | Single node |
| **HA** | No | Yes | Yes | Optional |
| **Best for** | Dev / POC / SMB | Production SaaS | Managed K8s | SCIF / DoD |
| **Ops complexity** | Low | High | Medium | Medium |
| **GPU (LLM)** | Optional | Optional | Optional | Required |

### 7.2 Docker Compose (Single-Node)

```bash
# Clone and configure
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops && git checkout features/intermediate-stage
cp .env.example .env   # edit FIXOPS_API_TOKEN, FIXOPS_JWT_SECRET

# Start full stack
docker compose -f docker/docker-compose.connectors.yml up -d

# Services started:
#   aldeci-api    → http://localhost:8000
#   aldeci-ui     → http://localhost:3000
#   trustgraph    → http://localhost:8888
#   redis         → localhost:6379
```

**Minimum hardware**: 4 vCPU, 8 GB RAM, 20 GB SSD

**Production hardware**: 8 vCPU, 32 GB RAM, 100 GB NVMe SSD

### 7.3 Kubernetes

```bash
# Apply manifests
kubectl apply -f docker/k8s/

# Components deployed:
#   Deployment: aldeci-api (replicas: 3)
#   Deployment: aldeci-ui (replicas: 2)
#   StatefulSet: trustgraph
#   CronJob: feed-refresh (every 6h)
#   Service: LoadBalancer (api, ui)
#   PVC: data-volume (100Gi), trustgraph-volume (50Gi)
```

**Horizontal scaling**: API tier is stateless — scale `aldeci-api` replicas behind any load balancer. TrustGraph and SQLite are single-node; for multi-node, enable PostgreSQL backend.

### 7.4 Helm

```bash
helm repo add aldeci https://charts.aldeci.io
helm install aldeci aldeci/aldeci \
  --set api.replicaCount=3 \
  --set trustgraph.enabled=true \
  --set llm.provider=openrouter \
  --set storage.class=gp3
```

### 7.5 Air-Gapped / SCIF Deployment

Full functionality with zero external network dependencies:

| Component | Air-Gap Solution |
|-----------|-----------------|
| LLM inference | Ollama (Gemma 4 / Llama 4) on local GPU — zero API tokens |
| Threat intel | Offline feed snapshot, refreshed via USB/media import |
| Container registry | Local Harbor registry — all images pre-pulled |
| OS packages | Air-gap bundle in `/opt/aldeci/deps/` |
| TLS certificates | Internal CA — `openssl` + custom cert bundle |
| Time sync | Internal NTP server reference |

**DISA STIG hardening**: Applied at image build time. STIG findings reported by native scanner loop.

**SCIF deployment checklist**:
1. Pull all Docker images on internet-connected host → export tarballs
2. Transfer via approved media
3. Configure `FIXOPS_AIRGAP=1` — disables all outbound connections
4. Configure `FIXOPS_OLLAMA_URL=http://localhost:11434` — local LLM
5. Verify with: `curl http://localhost:8000/api/v1/health`

### 7.6 Terraform

```hcl
module "aldeci" {
  source  = "aldeci/platform/aws"
  version = "~> 1.0"

  instance_type    = "c6i.2xlarge"
  storage_gb       = 200
  enable_rds       = true   # PostgreSQL for multi-tenant
  enable_elasticache = true  # Redis for queue mode
  enable_waf       = true
  ssl_certificate_arn = var.cert_arn
}
```

Supports AWS, Azure, GCP. Outputs API endpoint, UI URL, initial admin credentials.

---

## 8. Security Architecture

### 8.1 Defense-in-Depth

```
LAYER 0: Network Perimeter
├── TLS 1.3 with FIPS cipher suites (tls_config.py)
├── DDoS mitigation via upstream WAF / CDN
└── IP allowlisting for SCIF deployments (airgap_config.py)

LAYER 1: API Gateway (FastAPI)
├── API key authentication (api_key_manager.py)
├── JWT validation with RS256 / ES256 (auth_middleware.py)
├── Per-tenant rate limiting (tenant_rate_limiter.py)
├── CORS strict origin policy
└── Request size limits + payload scanning (payload_guard.py)

LAYER 2: Authorization (RBAC + OPA)
├── 6 built-in roles: admin, secops_lead, analyst, developer, auditor, readonly
├── 30 persona mappings (rbac.py)
├── Open Policy Agent for attribute-based rules (policy_engine.py)
└── Row-level tenant isolation (tenant_isolation.py)

LAYER 3: Application Logic
├── Pydantic v2 input validation on all endpoints
├── SQL parameterization — zero raw SQL string concatenation
├── SSRF protection (ssrf_protection.py)
├── Prompt injection hardening (llm_guard_service.py)
└── Hallucination detection on LLM outputs (hallucination_guards.py)

LAYER 4: Data Layer
├── AES-256-GCM encryption at rest (fips_encryption.py)
├── SQLite WAL for crash safety
├── Encrypted sensitive store (encrypted_store.py)
└── Algorithm-agile evidence signing envelope (quantum_crypto.py — RSA-PSS shipping; FIPS 204 ML-DSA activatable per SCIF/IL5 contract)

LAYER 5: Audit & Detection
├── Structured audit log via structlog (audit_logger.py)
├── Anomaly detection (anomaly_detector.py)
├── SIEM export (syslog + CEF format)
└── Immutable audit trail in audit.db
```

### 8.2 FIPS 140-2/140-3 Compliance

- **Encryption**: AES-256-GCM via `fips_encryption.py` — uses Python `cryptography` library in FIPS mode
- **Key derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations
- **TLS**: FIPS 140-2 approved cipher suites only — no RC4, DES, 3DES, export ciphers
- **Certificate validation**: Full chain validation, OCSP stapling
- **Key management**: Hardware-backed key storage via `key_manager.py` (supports PKCS#11 HSMs)

### 8.3 Post-Quantum Cryptography (Algorithm-Agile Envelope)

`quantum_crypto.py` implements an algorithm-agile hybrid envelope. The RSA half is shipping; the FIPS 204 (ML-DSA / CRYSTALS-Dilithium) half is an activatable backend that flips on when `FIXOPS_PQ_BACKEND=dilithium-py` is set (pure-Python, zero C-deps) — pinned only when a SCIF/IL5 contract requires it. See `docs/quantum_crypto_retire_decision_2026-05-03.md`.

```
Evidence Signing Pipeline:
  Finding verdict + context data
      │
      ▼
  RSA-4096 signature (classical)      ← FIPS 140-3 compliant today (shipping)
      +
  ML-DSA-87 signature (post-quantum)  ← NIST FIPS 204 envelope; backend activatable
      │
      ▼
  Hybrid signature bundle attached to evidence artifact
  → RSA path verified at audit today; PQ path co-verifiable when backend enabled
  → Envelope designed for 20+ year validity once PQ backend pinned
```

### 8.4 Zero-Trust Architecture

1. **No implicit trust** — every API call authenticated, every resource access authorized
2. **Least privilege** — scoped API keys, persona-bounded RBAC, OPA attribute checks
3. **Microsegmentation** — scanner connectors run in unprivileged worker threads
4. **Continuous verification** — session tokens expire, refresh tokens rotate
5. **Audit everything** — structured log of every action, every LLM decision, every data access

### 8.5 Data Classification

| Classification | Examples | Controls |
|---------------|----------|---------|
| **Public** | Anonymized metrics, platform docs | No special controls |
| **Internal** | Finding summaries, analytics | Auth required, TLS in transit |
| **Confidential** | Raw findings, CVE data, configs | RBAC + audit log + encryption at rest |
| **Restricted** | Auth credentials, API keys, LLM votes | Encrypted store + HSM key material |
| **Classified** | SCIF deployments | Air-gap + DISA STIG + physical controls |

`data_classification.py` tags all entities with classification level at creation time.

### 8.6 Compliance Certifications (Status)

| Framework | Controls Mapped | Evidence Automated | Audit-Ready |
|-----------|----------------|--------------------|-------------|
| SOC 2 Type II | 22 | 19 | Yes |
| PCI-DSS 4.0 | 22 | 20 | Yes |
| NIST 800-53 Rev 5 | 30 | 29 | Yes |
| ISO 27001:2022 | 21 | 16 | Yes |
| FedRAMP Moderate | Mapped | In progress | Q3 2026 |
| CMMC Level 2 | Mapped | In progress | Q3 2026 |
| HIPAA Security Rule | Mapped | In progress | Q4 2026 |
| DISA STIG | Applied | Continuous | Yes (air-gap) |

---

## 9. API Surface

### 9.1 Overview

| Metric | Count |
|--------|-------|
| Router files | 166 |
| Total routes | 1,700+ |
| Versioned prefix | `/api/v1/` |
| Auth required | All except `/health`, `/ready`, `/auth/login` |
| Auth method | `Authorization: Bearer <token>` (JWT or API key) |
| OpenAPI spec | `GET /docs` (Swagger UI), `GET /openapi.json` |

### 9.2 Route Domains

| Domain | Prefix | Key Capabilities |
|--------|--------|-----------------|
| **Findings** | `/api/v1/findings` | CRUD, bulk ops, SLA, export, status transitions |
| **Brain / Pipeline** | `/api/v1/brain`, `/api/v1/pipeline` | Run pipeline, fetch verdicts, pipeline analytics |
| **Connectors** | `/api/v1/connectors` | List, test, sync, health-check connectors |
| **TrustGraph** | `/api/v1/trustgraph` | Query, index, semantic search, graph traversal |
| **Copilot** | `/api/v1/copilot` | Natural-language query, summarize, triage assist |
| **Analytics** | `/api/v1/analytics` | Persona dashboards, KPIs, time-series |
| **Reports** | `/api/v1/reports` | Generate, schedule, download compliance reports |
| **Auth** | `/api/v1/auth` | Login, refresh, logout, MFA |
| **Users** | `/api/v1/users` | CRUD, role assignment, persona mapping |
| **RBAC** | `/api/v1/access-matrix` | Role and permission management |
| **Admin** | `/api/v1/admin` | System config, tenant management, bootstrap |
| **Feeds** | `/api/v1/feeds` | List feeds, refresh, status, manual ingest |
| **SBOM** | `/api/v1/sbom` | Upload SBOM, component query, license check |
| **Playbooks** | `/api/v1/playbooks` | Run, create, edit playbooks |
| **Workflows** | `/api/v1/workflows` | Create, trigger, list workflow automations |
| **Incidents** | `/api/v1/incidents` | Open, update, close, timeline |
| **Compliance** | `/api/v1/compliance*` | Control testing, evidence, report generation |
| **Attack Sim** | `/api/v1/attack-sim` | Run simulations, MPTE trigger, FAIL engine |
| **AutoFix** | `/api/v1/autofix` | Generate fix, verify diff, create PR |
| **CSPM** | `/api/v1/cspm`, `/api/v1/cloud-graph` | Misconfiguration query, drift detection |
| **Secrets** | `/api/v1/secrets` | Detected secrets, suppression, rotation |
| **Threat Hunting** | `/api/v1/threat-hunting` | Hypothesis management, query execution |
| **Notifications** | `/api/v1/notifications` | Alert routing, subscription management |
| **Health** | `/api/v1/health`, `/api/v1/ready` | Liveness and readiness probes (public) |
| **WebSocket** | `/ws/events` | Real-time pipeline event stream |
| **Streaming** | `/api/v1/streaming` | Server-sent events for live feeds |
| **MCP Gateway** | `/api/v1/mcp` | Model Context Protocol tool registry |

### 9.3 MCP Gateway

ALDECI exposes 650+ auto-discovered tool endpoints consumable by AI agents via the Model Context Protocol:

```json
// GET /api/v1/mcp/tools
{
  "tools": [
    {
      "name": "query_findings",
      "description": "Query security findings with filters",
      "input_schema": { "type": "object", "properties": { ... } }
    },
    {
      "name": "run_pipeline",
      "description": "Trigger the AI decision pipeline on a finding",
      ...
    }
    // ... 648 more tools
  ]
}
```

AI copilots, Claude Code, LangChain agents, and custom automation can consume ALDECI as an MCP server — making it a native tool in any AI workflow without custom integration code.

---

## 10. Competitive Positioning

### 10.1 Feature-by-Feature Matrix

| Capability | ALDECI | Apiiro | Snyk | Wiz | Vanta | CrowdStrike Falcon |
|-----------|--------|--------|------|-----|-------|-------------------|
| **SAST + DAST + SCA + Secrets + Container + IaC** | 8 native | 0 | 2 | 2 | 0 | 3 |
| **Multi-LLM consensus decisions** | Yes (4+, 85% threshold) | No | No | No | No | No |
| **Exploit verification (MPTE)** | 19-phase, continuous | No | No | No | No | Limited |
| **GraphRAG knowledge graph** | TrustGraph native | Partial | No | Partial | No | No |
| **AI Copilot (GraphRAG)** | Yes | No | Limited | No | No | No |
| **Post-quantum evidence signing** | FIPS 204 ML-DSA envelope (algorithm-agile, `dilithium-py` activatable) | No | No | No | No | No |
| **Air-gapped deployment** | Full feature parity | Partial | No | No | No | Partial |
| **Self-hosted LLM (zero token cost)** | Yes (Ollama, vLLM) | No | No | No | No | No |
| **AutoFix types** | 10 | 0 | 2 | 0 | 0 | 1 |
| **Confidence-gated auto-merge** | Yes | No | No | No | No | No |
| **FAIL / Chaos security testing** | Yes | No | No | No | No | No |
| **MCP Gateway (AI-native)** | 650+ tools | No | No | No | No | No |
| **Compliance automation** | SOC2/PCI/NIST/ISO/FedRAMP | SOC2 | Limited | SOC2/ISO | SOC2/ISO/HIPAA | Limited |
| **SBOM (CycloneDX + SPDX)** | Full lifecycle | No | Partial | No | No | No |
| **Price (SMB/mid-market)** | $3K–5K/mo | $50K+/yr | $20K+/yr | $50K+/yr | $20K+/yr | $100K+/yr |

### 10.2 Why ALDECI Wins Each Comparison

**vs. Apiiro (ASPM)**
Apiiro aggregates findings but does not decide. ALDECI decides — with a 4-model LLM council that produces a signed, auditable verdict. Apiiro has no native scanners; ALDECI has 8. Apiiro cannot operate in air-gapped environments; ALDECI is purpose-built for SCIF deployment.

**vs. Snyk (SCA/SAST)**
Snyk is a developer-facing point solution for code and dependency scanning. ALDECI correlates Snyk findings with cloud posture, runtime behavior, threat intelligence, and compliance controls — and generates the PR fix automatically. ALDECI amplifies Snyk, making the two complementary (ALDECI ingests Snyk findings via PULL connector).

**vs. Wiz (CSPM/CNAPP)**
Wiz excels at cloud infrastructure visibility. ALDECI extends that to the application layer: code, containers, secrets, SBOM, developer workflows. ALDECI ingests Wiz findings via GraphQL connector and correlates them with SAST/SCA findings — something Wiz cannot do internally.

**vs. Vanta (Compliance)**
Vanta automates compliance questionnaires. ALDECI generates cryptographically signed evidence from actual security findings, with a full chain-of-custody audit trail. The algorithm-agile post-quantum envelope (RSA-PSS shipping; FIPS 204 ML-DSA activatable per contract) is a 3+ year head start on the integration surface. ALDECI serves SOC 2, ISO 27001, FedRAMP, CMMC, HIPAA, and DISA STIG simultaneously.

**vs. CrowdStrike Falcon**
Falcon is an EDR/XDR platform — infrastructure and endpoint focused. ALDECI is application-layer focused: source code, dependencies, containers, IaC, APIs, and the CI/CD pipeline. The two are complementary. ALDECI can ingest Falcon detections via the notification engine for unified risk correlation.

### 10.3 Unique Capabilities — No Direct Competitor

| Capability | Description | Competitive Gap |
|-----------|-------------|-----------------|
| **FAIL Engine** | Chaos security testing — inject faults, measure security response, generate labeled training data | No equivalent in any commercial platform |
| **Karpathy LLM Consensus** | Multi-model deliberation with disagreement resolution and escalation | Patent-pending approach |
| **TrustGraph GraphRAG** | 5 versioned knowledge cores + semantic graph traversal for AI agents | No competitor has graph-native AI architecture |
| **Zero-Gravity Data** | Four-tier intelligent aging reduces on-premises storage by 95% | No equivalent data lifecycle management |
| **MCP-native API** | 650+ AI-consumable tool endpoints via Model Context Protocol | First AppSec platform to implement MCP |
| **Continuous MPTE** | 19-phase exploit verification running 365x/year, not annually | No equivalent continuous exploit validation |

---

## 11. Roadmap

### 11.1 What Is Built (Feature Inventory)

**AI & Decision Intelligence (18 modules)**
- LLM Council with 4-model consensus + Opus escalation
- TrustGraph-backed GraphRAG Copilot
- OPA policy engine with attribute-based rules
- Hallucination guards and prompt injection hardening
- Self-learning via decision memory and feedback loops

**Scanning & Normalization (12 modules)**
- 32 scanner normalizers (SAST, DAST, SCA, Container, CSPM, Secrets, IaC)
- Native SAST, DAST, container, dependency, secret, IaC, license scanning
- SARIF universal normalization
- OWASP ZAP, Semgrep, Trivy deep integration

**Connectors & Integrations (20 modules)**
- 13 PULL connectors (AWS, Azure, GCP, Snyk, Wiz, PrismaCloud, Orca, Lacework, ThreatMapper, DependencyTrack, SonarQube, GitHub, GitLab)
- 7 bidirectional connectors (Jira, Slack, ServiceNow, GitHub, GitLab, Confluence, AzureDevOps)
- PagerDuty, Microsoft Teams, SMTP notifications
- 28+ threat intelligence feeds

**Compliance & Evidence (12 modules)**
- SOC 2, PCI-DSS 4.0, NIST 800-53, ISO 27001, FedRAMP control mapping
- Automated evidence collection and cryptographic signing
- FIPS 204 ML-DSA post-quantum evidence envelope (algorithm-agile; PQ backend activatable per SCIF/IL5 contract — see `docs/quantum_crypto_retire_decision_2026-05-03.md`)
- 7-year WORM retention capability

**Attack & Exploit Validation (10 modules)**
- MPTE 19-phase exploit verification engine
- FAIL Engine chaos security testing
- Attack path discovery and blast radius estimation
- Graph Neural Network attack prediction

**Remediation & AutoFix (9 modules)**
- 10 fix types with confidence-gated auto-merge
- PR generation for GitHub and GitLab
- Playbook automation with rollback
- MPTE-verified fix validation

**Frontend (35 pages, 30 persona views)**
- Mission Control: CISO, SOC, Command, Executive, Risk, SLA, Live Feed
- Discover: Findings, Attack Paths, Cloud Posture, Code Scanning, Containers, Secrets, SBOM, Threat Feeds, Knowledge Graph
- Comply: Dashboard, Evidence Vault, SOC2, Audit Trail
- Remediate: Remediation Center, AutoFix, Workflows, Playbooks
- Validate: Attack Simulation, MPTE Console, FAIL Engine
- AI: Brain Pipeline, Copilot, Multi-LLM Monitor

**Infrastructure (current)**
- 166 API routers, 1,700+ routes
- 18 SQLite WAL databases
- Docker Compose full-stack deployment
- Beast Mode CI: SwarmClaw + TrustGraph + Ollama + Redis + PostgreSQL
- 709 Beast Mode tests passing

### 11.2 What Is Next (Priority Order)

| Priority | Feature | Rationale |
|---------|---------|-----------|
| **P1** | Wire Copilot GraphRAG to all 5 TrustGraph cores | Unlocks AI-native queries across full entity graph |
| **P1** | Error handling audit — replace bare `except` with typed hierarchy | Reliability and debuggability |
| **P2** | SOC T1 Dashboard — alert triage view with LLM verdicts (P03) | Core persona workflow |
| **P2** | Compliance Dashboard — framework status + evidence collection (P07) | High-value compliance automation |
| **P3** | Material Change Detector — git webhook → blast radius → Council assessment | Developer-first security gate |
| **P3** | API documentation — auto-generate full OpenAPI spec with examples | Developer experience |
| **P4** | Horizontal scaling — Redis queue mode for multi-node API tier | Enterprise scale |
| **P4** | SAML/OIDC enterprise SSO — Okta, Azure AD, Ping | Enterprise auth requirement |
| **P5** | n8n connector orchestration — 400+ workflow integrations | Automation breadth |
| **P5** | OpenClaw autonomous pentest swarm | Continuous adversarial validation |

### 11.3 10-Day SCIF Sprint Status

The SCIF sprint targets DoD / IC production readiness for classified environment deployment.

| Day | Deliverable | Status |
|-----|-------------|--------|
| 1 | DISA STIG hardening — OS baseline | Complete |
| 2 | Air-gap config — disable all outbound, local feed snapshot | Complete |
| 3 | FIPS 140-3 encryption audit — verify all cipher usage | Complete |
| 4 | ML-DSA evidence signing — FIPS 204 envelope integration (RSA-PSS shipping; PQ backend activatable on SCIF/IL5 contract via `dilithium-py`) | Complete (envelope) |
| 5 | Ollama LLM deployment — Gemma 4 local inference | Complete |
| 6 | CMMC Level 2 control mapping — 110 practices | In Progress |
| 7 | FedRAMP Moderate boundary documentation | In Progress |
| 8 | Air-gap media import workflow — USB feed refresh | Planned |
| 9 | SCIF deployment runbook — step-by-step install | Planned |
| 10 | Red team validation — MPTE against hardened instance | Planned |

### 11.4 Horizon Roadmap

| Horizon | Timeframe | Goal |
|---------|-----------|------|
| **H1: Foundation** | Q1–Q2 2026 | Design partners in production; FedRAMP Moderate initiated; SCIF deployment certified |
| **H2: Scale** | Q3–Q4 2026 | 20+ enterprise customers; horizontal scaling GA; CMMC Level 2 certification |
| **H3: Category Leadership** | 2027 | 100+ customers; MCP as AppSec industry standard; "Decision Intelligence" category creator |
| **H4: Autonomy** | 2028 | Autonomous CTEM — scan → verify → fix → prove with zero human intervention |
| **H5: Dominance** | 2029–2030 | 1M+ findings/day; AppSec digital twin; full post-quantum migration industry-wide |

---

## Appendix A: Database Map

| Database | Owner Module | Key Tables |
|----------|-------------|-----------|
| `findings.db` | brain_pipeline, findings_routes | findings, verdicts, comments, timeline |
| `fixops_brain.db` | brain_pipeline_db | pipeline_runs, step_results, llm_outputs |
| `auth.db` | auth_db | users, sessions, api_keys, roles |
| `audit.db` | audit_db, audit_logger | audit_events, access_log |
| `analytics.db` | analytics_engine | metrics, persona_views, time_series |
| `reports.db` | report_db | reports, templates, scheduled_reports |
| `api_keys.db` | api_key_manager | api_keys, scopes, usage |
| `feeds.db` | feed_manager | feed_sources, feed_items, refresh_log |
| `asset_inventory.db` | asset_inventory | assets, tags, relationships |
| `fixops_dedup.db` | deduplication | finding_hashes, dedup_log |
| `compliance_planner.db` | compliance_planner | frameworks, controls, evidence_links |
| `workflow_db.db` | workflow_db | workflows, executions, triggers |
| `cspm.db` | cspm_engine | cloud_resources, misconfigs, drift |
| `fixops_exposure_cases.db` | exposure_case | cases, linked_findings, owners |
| `fixops_policy_engine.db` | policy_db | policies, evaluations, overrides |
| `sbom_manager.db` | sbom_manager | components, licenses, vulnerabilities |
| `secrets.db` | secrets_db | detected_secrets, suppressed, rotations |
| `threat_hunting.db` | threat_hunting | hypotheses, queries, results |

---

## Appendix B: Key Environment Variables

```bash
# Core (required)
FIXOPS_API_TOKEN=<master bearer token>
FIXOPS_JWT_SECRET=<jwt signing secret>
FIXOPS_DATA_DIR=data/

# LLM Council
FIXOPS_FEATURE_COUNCIL=1
ANTHROPIC_API_KEY=<claude api key>
OPENAI_API_KEY=<openai api key>
FIXOPS_OLLAMA_URL=http://localhost:11434
FIXOPS_CONSENSUS_THRESHOLD=0.85

# Feature Flags
FIXOPS_FEATURE_TRUSTGRAPH=1
FIXOPS_FEATURE_FEEDS=1
FIXOPS_FEATURE_AUTOFIX=1
FIXOPS_FEATURE_ATTACK_SIM=1
FIXOPS_FEATURE_CSPM=1

# Integrations
FIXOPS_JIRA_URL=https://org.atlassian.net
FIXOPS_JIRA_TOKEN=<token>
FIXOPS_GITHUB_TOKEN=<pat>
FIXOPS_SLACK_TOKEN=<bot token>
FIXOPS_OPA_URL=http://opa:8181

# Air-Gap Mode
FIXOPS_AIRGAP=1            # disables all outbound connections
```

---

## Appendix C: Quick Commands

```bash
# Start API (dev)
cd suite-api && uvicorn apps.api.app:create_app --factory --reload --port 8000

# Start UI (dev)
cd suite-ui/aldeci-ui-new && npm run dev

# Run Beast Mode tests (~709 tests)
python -m pytest tests/test_phase*.py tests/test_connector_framework.py \
  tests/test_trustgraph.py tests/test_pipeline_api.py tests/test_persona_workflows.py \
  -x --tb=short --timeout=10 -q -o "addopts="

# Index codebase into TrustGraph
python -c "from core.trustgraph_indexer import TrustGraphIndexer; TrustGraphIndexer().index_all()"

# Check API health
curl http://localhost:8000/api/v1/health

# Export OpenAPI spec
curl http://localhost:8000/openapi.json > docs/openapi.json

# Start full stack (Docker)
docker compose -f docker/docker-compose.connectors.yml up -d

# Git auto-save (every 15-20 min)
git add -A && git commit -m "beast-mode(wip): [description]" \
  && git push origin features/intermediate-stage
```

---

*ARCHITECTURE_v3.0 — 2026-04-12 — Definitive reference. Source of truth. All implementation derives from this document.*
*Previous documents superseded: ARCHITECTURE_CHEATSHEET.md, ALDECI_REARCHITECTURE.md*
