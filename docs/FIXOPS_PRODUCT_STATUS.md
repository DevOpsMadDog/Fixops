# FixOps Product Status & Technical Reference

**Document Version:** 3.0  
**Date:** January 2026  
**Purpose:** Consolidated product status with technical deep-dive for architects, product owners, and engineers

---

## Capability Map

```mermaid
flowchart LR
  F[FixOps<br/>Security Decision Engine]:::root

  subgraph TODAY[Available Today]
    direction TB
    T1[T1: Intake & Normalize]:::done
    T2[T2: Prioritize & Triage]:::done
    T3[T3: Automated Decisions]:::done
    T4[T4: Remediation Workflow]:::done
    T5[T5: Compliance & Evidence]:::done
    T6[T6: Notifications]:::done
    T7[T7: Security Scanning]:::done
    T8[T8: Jira Integration]:::done
  end

  subgraph NEXT[Coming Next]
    direction TB
    N1[N1: Reliable Ticket Delivery]:::planned
    N2[N2: Broader Integrations]:::planned
    N3[N3: Enterprise Login SSO]:::planned
    N4[N4: Scale & HA]:::planned
    N5[N5: Multi-Tenant Support]:::planned
  end

  subgraph LATER[Future Enhancements]
    direction TB
    L1[L1: Executive Dashboards]:::later
    L2[L2: SOC Integration]:::later
    L3[L3: Developer Experience]:::later
    L4[L4: Advanced Analytics]:::later
  end

  F --> TODAY
  F --> NEXT
  F --> LATER

  classDef root fill:#1e293b,stroke:#1e293b,color:#ffffff,font-weight:bold;
  classDef done fill:#d1fae5,stroke:#10b981,color:#065f46;
  classDef planned fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a;
  classDef later fill:#f3f4f6,stroke:#9ca3af,color:#374151;
```

---

## Implementation Index (Quick Reference)

| ID | Capability | API Endpoints | CLI Commands | Core Modules | Status |
|----|------------|---------------|--------------|--------------|--------|
| T1 | Intake & Normalize | `POST /inputs/*` (7 endpoints) | `ingest`, `stage-run` | `apps/api/normalizers.py`, `apps/api/ingestion_router.py` | Production |
| T2 | Prioritize & Triage | `GET /api/v1/triage`, `POST /api/v1/risk/*` | `analyze` | `core/services/risk.py`, `core/severity_promotion.py` | Production |
| T3 | Automated Decisions | `POST /api/v1/enhanced/*` | `make-decision`, `run` | `core/enhanced_decision.py`, `core/pentagi_advanced.py` | Production |
| T4 | Remediation Workflow | `/api/v1/remediation/*` (13 endpoints) | `remediation` | `core/services/remediation.py`, `apps/api/remediation_router.py` | Production |
| T5 | Compliance & Evidence | `/api/v1/evidence/*`, `/api/v1/compliance/*` | `get-evidence`, `compliance` | `core/evidence.py`, `services/provenance/attestation.py` | Production |
| T6 | Notifications | `/api/v1/collaboration/notifications/*` | `notifications` | `core/services/collaboration.py`, `core/connectors.py` | Production |
| T7 | Security Scanning | `POST /api/v1/iac/scan/*`, `POST /api/v1/secrets/scan/*` | - | `core/iac_scanner.py`, `core/secrets_scanner.py` | Production |
| T8 | Jira Integration | `POST /api/v1/webhooks/jira/*` | `integrations` | `core/connectors.py:49-124`, `apps/api/webhooks_router.py:233-350` | Production |
| N1 | Reliable Ticket Delivery | - | - | `apps/api/webhooks_router.py:744-1012` (outbox exists) | **Needs Worker** |
| N2 | Broader Integrations | Webhook receivers only | - | `apps/api/webhooks_router.py` | **Inbound Only** |
| N3 | Enterprise Login (SSO) | `/api/v1/auth/sso/*` | - | `core/auth_db.py` | **Config Only** |
| N4 | Scale & HA | - | - | 12+ SQLite DBs in `core/*_db.py` | **Needs PostgreSQL** |
| N5 | Multi-Tenant Support | - | - | Partial `org_id` in some services | **Needs Enforcement** |

---

## What FixOps Does (Business Capabilities)

### Available Today

| Capability | What It Does | Business Value |
|------------|--------------|----------------|
| **Intake & Normalize** | Aggregates outputs from any scanner (SAST, DAST, SCA, IaC, secrets) | Single pane of glass for all security findings |
| **Prioritize & Triage** | Scores vulnerabilities using threat intelligence (EPSS, KEV, CVSS) | Focus on what matters most, reduce noise by 35% |
| **Automated Decisions** | AI consensus from multiple models decides allow/block/review | Consistent, explainable security decisions at scale |
| **Remediation Workflow** | Assigns tasks, tracks SLAs, verifies fixes | Clear accountability, measurable MTTR |
| **Compliance & Evidence** | Generates signed, tamper-proof audit bundles | Audit-ready evidence for any framework |
| **Notifications** | Sends alerts via Slack and email | Keep teams informed in real-time |
| **Security Scanning** | Scans infrastructure-as-code and detects hardcoded secrets | Shift-left security before deployment |
| **Jira Integration** | Creates and syncs tickets bidirectionally | Seamless developer workflow |

### Coming Next (Enterprise Plug-and-Play)

| Capability | What It Does | Business Value |
|------------|--------------|----------------|
| **Reliable Ticket Delivery** | Automatically creates/updates tickets with guaranteed delivery | No more manual ticket creation |
| **Broader Integrations** | Connect to ServiceNow, GitLab, Azure DevOps, GitHub | Works with your existing tools |
| **Enterprise Login (SSO)** | OIDC/SAML integration with your identity provider | Single sign-on, role-based access |
| **Scale & High Availability** | Production-grade database with failover | Enterprise reliability |
| **Multi-Tenant Support** | Isolated data per organization | Secure multi-team deployment |

### Future Enhancements (Optional)

| Capability | What It Does | Business Value |
|------------|--------------|----------------|
| **Executive Dashboards** | Board-ready visualizations and trends | Strategic visibility for leadership |
| **SOC Integration** | SIEM connectors (Splunk, Sentinel) | Correlate vulnerabilities with incidents |
| **Developer Experience** | PR annotations, self-service portal | Developer-friendly security |
| **Advanced Analytics** | Risk quantification ($), industry benchmarks | Data-driven security investment |

---

## Executive Summary

FixOps is an Enterprise DevSecOps Decision & Verification Engine with substantial production-ready functionality. This document provides a single source of truth for implementation status, enterprise readiness, and roadmap.

**What's Working (Production-Ready):**
- Multi-LLM consensus decisioning (GPT-5, Claude-3, Gemini-2, Sentinel)
- Deduplication with 7 correlation strategies (35% noise reduction)
- Risk scoring (EPSS + KEV + CVSS + Bayesian + Markov probabilistic forecasting)
- Evidence bundles with RSA-SHA256 signing, Fernet encryption, SLSA v1 provenance
- Real connectors: Jira, Confluence, Slack (actual HTTP calls)
- Webhook receivers: Jira, ServiceNow, GitLab, Azure DevOps (with signature verification)
- IaC scanning (checkov/tfsec) and Secrets scanning (gitleaks/trufflehog)
- Storage backends: Local, S3 Object Lock, Azure Immutable Blob

**Enterprise Blockers (Must Fix):**
- 12+ separate SQLite databases with hardcoded paths (blocks HA/scaling)
- No background worker (outbox queues items but never processes them)
- Missing outbound connectors for ServiceNow, GitLab, Azure DevOps, GitHub
- Integration sync endpoint is a no-op (stamps "success" without syncing)

---

## Enterprise Connector Checklist

For true enterprise plug-and-play, each connector needs: Inbound (webhook receiver), Outbound (create/update), Background Worker, and Bidirectional Sync.

| Connector | Inbound | Outbound | Worker | Bidir Sync | Status | What's Missing |
|-----------|---------|----------|--------|------------|--------|----------------|
| **Jira** | Webhook receiver | `create_issue()` | Outbox queues | Drift detection | **PARTIAL** | Worker to process outbox |
| **Confluence** | - | `create_page()` | - | - | **OUTBOUND ONLY** | No inbound, no sync |
| **Slack** | - | `post_message()` | - | - | **OUTBOUND ONLY** | No inbound, no sync |
| **ServiceNow** | Webhook receiver | **MISSING** | - | - | **INBOUND ONLY** | Need `create_incident()` |
| **GitLab** | Webhook receiver | **MISSING** | - | - | **INBOUND ONLY** | Need `create_issue()` |
| **Azure DevOps** | Webhook receiver | **MISSING** | - | - | **INBOUND ONLY** | Need `create_work_item()` |
| **GitHub** | - | **MISSING** | - | - | **NOT IMPLEMENTED** | Need full connector |

**Critical Gap:** Outbox pattern exists (`apps/api/webhooks_router.py:744-1012`) but NO background worker polls and processes it. Items are queued forever.

---

## Implementation Status by Category

### Core Platform (All Production-Ready)

| Component | Status | Evidence |
|-----------|--------|----------|
| **Multi-LLM Consensus** | REAL | 4 providers, 85% threshold, `core/pentagi_advanced.py` |
| **Deduplication** | REAL | 7 strategies, SQLite-backed, `core/services/deduplication.py` |
| **Risk Scoring** | REAL | EPSS+KEV+CVSS+Bayesian+Markov, `core/services/risk.py` |
| **Evidence Bundles** | REAL | RSA-SHA256, Fernet encryption, SLSA v1, `core/services/evidence.py` |
| **Policy Evaluation** | REAL | OPA-based rules, configurable guardrails |
| **Tri-State Decisions** | REAL | ALLOW/BLOCK/NEEDS REVIEW with confidence scores |
| **Remediation Lifecycle** | REAL | Full state machine with SLA tracking |
| **Notification Delivery** | REAL | Slack webhooks with SSRF protection, SMTP with TLS |

### Scanning (Production-Ready)

| Scanner | Status | Tools | Code Reference |
|---------|--------|-------|----------------|
| **IaC Scanning** | REAL | checkov, tfsec | `core/iac_scanner.py` |
| **Secrets Scanning** | REAL | gitleaks, trufflehog | `core/secrets_scanner.py` |
| **SARIF Ingestion** | REAL | Any SARIF-compliant scanner | `apps/api/ingestion_router.py` |
| **SBOM Analysis** | REAL | CycloneDX, SPDX | `apps/api/ingestion_router.py` |

### Storage Backends (Production-Ready)

| Backend | Status | Features |
|---------|--------|----------|
| **Local Filesystem** | REAL | Default for demo/dev |
| **S3 Object Lock** | REAL | WORM compliance, retention policies |
| **Azure Immutable Blob** | REAL | Immutability policies |

### API Coverage

| Category | Endpoints | Status |
|----------|-----------|--------|
| Ingestion | 15 | Complete |
| Pipeline | 4 | Complete |
| Enhanced Decision | 4 | Complete |
| Analytics | 16 | Complete |
| Audit | 10 | Complete |
| Reports | 9 | Complete |
| Teams/Users | 14 | Complete |
| Policies | 8 | Complete |
| Integrations | 8 | Complete |
| Workflows | 7 | Complete |
| Inventory | 15 | Complete |
| PentAGI | 33 | Complete |
| IaC/Secrets | 10 | Complete |
| Evidence | 17 | Complete |
| Deduplication | 17 | Complete |
| Remediation | 13 | Complete |
| Webhooks | 20 | Complete |
| Feeds | 20 | Complete |

---

## Enterprise Blockers (Must Fix Before Deployment)

### 1. SQLite Everywhere - CRITICAL

**Problem:** 12+ separate SQLite databases with hardcoded relative paths.

| Database | Default Path | Impact |
|----------|--------------|--------|
| users.db | `data/users.db` | No HA/failover |
| integrations.db | `data/integrations.db` | No concurrent writes |
| policies.db | `data/policies.db` | Breaks in containers |
| reports.db | `data/reports.db` | No horizontal scaling |
| audit.db | `data/audit.db` | No proper backup story |
| + 7 more | `data/*.db` | Same issues |

**Solution:** Database abstraction layer + PostgreSQL backend + Alembic migrations

### 2. No Background Workers - CRITICAL

**Problem:** Outbox pattern exists but no worker processes the queue.

The outbox table stores items with status, retry_count, max_retries, next_retry_at, last_error - but there is NO CODE that:
1. Polls the outbox for pending items
2. Routes items to appropriate connectors
3. Makes actual HTTP calls to external systems
4. Updates status based on delivery result

**Solution:** Create worker entrypoint (`python -m core.worker`) with outbox processor

### 3. Missing Outbound Connectors - HIGH

**Problem:** Webhook receivers exist for ServiceNow/GitLab/Azure DevOps but no outbound capability.

| System | Inbound | Outbound |
|--------|---------|----------|
| Jira | Yes | Yes |
| ServiceNow | Yes | **NO** |
| GitLab | Yes | **NO** |
| Azure DevOps | Yes | **NO** |
| GitHub | No | **NO** |

**Solution:** Implement `ServiceNowConnector`, `GitLabConnector`, `AzureDevOpsConnector`, `GitHubConnector`

### 4. Integration Sync No-Op - MEDIUM

**Problem:** `apps/api/integrations_router.py:trigger_sync()` stamps "success" without actually syncing.

**Solution:** Implement real sync logic per integration type

---

## Roadmap

### Phase 0: Enterprise Infrastructure (Weeks 1-4) - MUST

| Task | Effort | Priority |
|------|--------|----------|
| **Database Abstraction + PostgreSQL** | 2 weeks | MUST |
| **Centralize Path Configuration** | 3 days | MUST |
| **Implement Outbox Worker** | 1 week | MUST |
| **Fix Integration Sync Endpoint** | 2 days | MUST |

### Phase 1: Connector Expansion (Weeks 5-8) - SHOULD

| Task | Effort | Priority |
|------|--------|----------|
| **ServiceNow Outbound Connector** | 3-5 days | SHOULD |
| **GitLab Outbound Connector** | 3-5 days | SHOULD |
| **Azure DevOps Outbound Connector** | 3-5 days | SHOULD |
| **GitHub Connector (Full)** | 1 week | SHOULD |
| **Wire Outbox to Connectors** | 1 week | SHOULD |

### Phase 2: Enterprise Security (Weeks 9-12) - SHOULD

| Task | Effort | Priority |
|------|--------|----------|
| **Multi-Tenancy Enforcement** | 2 weeks | SHOULD |
| **OIDC/SAML Integration** | 1 week | SHOULD |
| **RBAC Middleware Enforcement** | 1 week | SHOULD |

### Medium Priority (Enterprise Enablement)

| Task | Effort | Priority |
|------|--------|----------|
| **OSS Fallback Wiring** | 3-5 days | MEDIUM |
| **Cross-Stage Correlation** | 1-2 weeks | MEDIUM |
| **Runtime Event Ingestion** | 1 week | MEDIUM |
| **Application Components from SBOM** | 3-5 days | MEDIUM |

### Items That Can Be Deferred (Optional/Not Required)

| Feature | Why Deferrable |
|---------|----------------|
| Risk Quantification ($) | Budget justification, not operational |
| Industry Benchmarking | No customer data yet |
| ROI Calculator | Nice-to-have for execs |
| Board-ready Dashboards | API data exists, UI is enhancement |
| SIEM (Splunk/Sentinel) | Build when customer demands |
| CMDB Sync | Customer-specific integration |
| Developer Portal | Self-service is nice-to-have |
| Scanner Health Dashboard | Operational monitoring, not core |

**Key Principle:** If it doesn't block (1) deploying safely, (2) making decisions, (3) tracking remediation, or (4) generating audit evidence, it can be deferred.

---

## Stakeholder Coverage Summary

| Stakeholder | Coverage | Key Gaps |
|-------------|----------|----------|
| **Vulnerability Management Analyst** | High | Workload balancing (optional) |
| **Vulnerability Assessment Analyst** | High | Manual pentest workflow (optional) |
| **TVM Engineer** | High | Custom connector SDK (optional) |
| **SOC/Security Analyst** | Medium | SIEM integration (build when demanded) |
| **VM Manager** | High | Executive dashboard (optional) |
| **Security Engineer/DevSecOps** | High | PR annotations (should build) |
| **DevOps/Platform Engineer** | Medium | Patch management integration (optional) |
| **Application Engineering Lead** | High | Sprint velocity impact (optional) |
| **Compliance/GRC Officer** | High | Risk acceptance workflow (should build) |
| **CISO/Head of Security** | Medium | Risk quantification (optional) |

---

## Quick Reference

### What IS Working (Code References)

| Component | Code Location | Status |
|-----------|---------------|--------|
| Jira Connector | `core/connectors.py:49-124` | REAL HTTP calls |
| Confluence Connector | `core/connectors.py:127-210` | REAL HTTP calls |
| Slack Connector | `core/connectors.py:213-248` | REAL HTTP calls |
| Jira Webhook | `apps/api/webhooks_router.py:233-350` | HMAC verification |
| ServiceNow Webhook | `apps/api/webhooks_router.py:353-433` | State mapping |
| GitLab Webhook | `apps/api/webhooks_router.py:1110-1227` | Label mapping |
| Azure DevOps Webhook | `apps/api/webhooks_router.py:1261-1357` | State mapping |
| Deduplication | `core/services/deduplication.py` | 7 strategies |
| Remediation | `core/services/remediation.py` | Full state machine |
| Evidence | `core/services/evidence.py` | RSA-SHA256 + SLSA v1 |
| IaC Scanner | `core/iac_scanner.py` | checkov/tfsec |
| Secrets Scanner | `core/secrets_scanner.py` | gitleaks/trufflehog |

### What Needs Building (Priority Order)

1. **Outbox Worker** - `core/worker.py` (1 week)
2. **PostgreSQL Backend** - `core/db/postgres.py` (2 weeks)
3. **ServiceNow Outbound** - `core/connectors/servicenow.py` (3-5 days)
4. **GitLab Outbound** - `core/connectors/gitlab.py` (3-5 days)
5. **Azure DevOps Outbound** - `core/connectors/azure_devops.py` (3-5 days)
6. **GitHub Connector** - `core/connectors/github.py` (1 week)

---

## Deployment Artifacts

| Artifact | Location | Status |
|----------|----------|--------|
| Dockerfile | `/Dockerfile` | Multi-stage build, Python 3.11-slim |
| Dockerfile.enterprise | `/Dockerfile.enterprise` | Enterprise variant |
| docker-compose.yml | `/docker-compose.yml` | Local development |
| docker-compose.enterprise.yml | `/docker-compose.enterprise.yml` | Enterprise stack |
| Helm Chart | `/deployment/kubernetes/helm/fixops-enterprise/` | Kubernetes deployment |

---

---

## Technical Deep Dive by Capability

### T1: Intake & Normalize

**What it does:** Aggregates outputs from any scanner (SAST, DAST, SCA, IaC, secrets) into a unified schema.

**API Endpoints:**
- `POST /inputs/design` - Upload design CSV
- `POST /inputs/sbom` - Upload SBOM (CycloneDX/SPDX)
- `POST /inputs/sarif` - Upload SARIF scan results
- `POST /inputs/cve` - Upload CVE feed
- `POST /inputs/vex` - Upload VEX document
- `POST /inputs/cnapp` - Upload CNAPP findings
- `POST /inputs/context` - Upload business context

**CLI Commands:**
```bash
python -m core.cli ingest --sarif file.sarif --sbom file.json --cve cve.json
python -m core.cli stage-run --stage sarif --input file.sarif
```

**Program Flow:**
```
Scanner Output (SARIF/SBOM/CVE/VEX)
    |
    v
[apps/api/ingestion_router.py] - HTTP endpoint receives file
    |
    v
[apps/api/normalizers.py:InputNormalizer] - Parse and normalize
    |-- load_sarif() -> NormalizedSARIF
    |-- load_sbom() -> NormalizedSBOM
    |-- load_cve_feed() -> NormalizedCVEFeed
    |-- load_vex() -> NormalizedVEX
    |
    v
[core/storage.py:ArtefactArchive] - Persist normalized data
    |
    v
Unified Schema in data/archive/
```

**Key Modules:**
| File | Class/Function | Purpose |
|------|----------------|---------|
| `apps/api/normalizers.py` | `InputNormalizer` | Parse SARIF/SBOM/CVE/VEX/CNAPP |
| `apps/api/ingestion_router.py` | Router endpoints | HTTP handlers for `/inputs/*` |
| `core/cli.py:403-417` | `_handle_ingest()` | CLI ingest command |
| `core/cli.py:622-678` | `_handle_stage_run()` | CLI stage-run command |
| `core/storage.py` | `ArtefactArchive` | Persist artifacts to disk |

---

### T2: Prioritize & Triage

**What it does:** Scores vulnerabilities using threat intelligence (EPSS, KEV, CVSS) with Bayesian/Markov probabilistic forecasting.

**API Endpoints:**
- `GET /api/v1/triage` - Get prioritized findings
- `POST /api/v1/risk/score` - Calculate risk score
- `POST /api/v1/risk/profile` - Get risk profile

**CLI Commands:**
```bash
python -m core.cli analyze --sarif file.sarif
python -m core.cli train-forecast --history incidents.json
python -m core.cli predict-bn-lr --finding finding.json
```

**Program Flow:**
```
Normalized Findings
    |
    v
[core/services/risk.py:RiskScorer] - Calculate composite risk
    |-- EPSS score lookup
    |-- KEV status check
    |-- CVSS base score
    |-- Business context multiplier
    |
    v
[core/severity_promotion.py] - Promote severity based on KEV/EPSS
    |-- promote_if_kev()
    |-- promote_if_high_epss()
    |
    v
[core/probabilistic.py:ProbabilisticForecastEngine] - Bayesian/Markov
    |-- bayesian_posterior()
    |-- markov_transition()
    |
    v
Prioritized Findings with Risk Scores
```

**Key Modules:**
| File | Class/Function | Purpose |
|------|----------------|---------|
| `core/services/risk.py` | `RiskScorer` | Composite risk calculation |
| `core/severity_promotion.py` | `SeverityPromoter` | KEV/EPSS-based promotion |
| `core/probabilistic.py` | `ProbabilisticForecastEngine` | Bayesian/Markov forecasting |
| `core/cli.py:477-549` | `_handle_analyze()` | CLI analyze command |
| `core/cli.py:933-964` | `_handle_train_forecast()` | CLI train-forecast command |

---

### T3: Automated Decisions

**What it does:** AI consensus from multiple LLM providers (GPT-5, Claude-3, Gemini-2, Sentinel) decides allow/block/review.

**API Endpoints:**
- `POST /api/v1/enhanced/analyze` - Multi-LLM consensus analysis
- `GET /api/v1/enhanced/capabilities` - Check LLM provider status
- `POST /api/v1/enhanced/compare-llms` - Side-by-side comparison

**CLI Commands:**
```bash
python -m core.cli make-decision --sarif file.sarif --sbom sbom.json
python -m core.cli run --overlay config/fixops.overlay.yml
python -m core.cli demo --mode enterprise
```

**Program Flow:**
```
Security Findings + Business Context
    |
    v
[core/enhanced_decision.py:MultiLLMConsensusEngine]
    |-- query_providers() - Call all LLM providers
    |   |-- OpenAI GPT-5
    |   |-- Anthropic Claude-3
    |   |-- Google Gemini-2
    |   |-- SentinelCyber
    |
    v
[core/pentagi_advanced.py:PentAGIAdvanced]
    |-- _call_llm() - Real provider calls with fallback
    |-- consensus_vote() - Weighted voting (85% threshold)
    |
    v
[core/decision_policy.py:DecisionPolicyEngine]
    |-- evaluate_guardrails() - Policy overrides
    |-- apply_critical_override() - Force BLOCK for critical
    |
    v
Tri-State Decision: ALLOW | BLOCK | NEEDS_REVIEW
    + Confidence Score + Explanation
```

**Key Modules:**
| File | Class/Function | Purpose |
|------|----------------|---------|
| `core/enhanced_decision.py` | `MultiLLMConsensusEngine` | Orchestrate multi-LLM consensus |
| `core/pentagi_advanced.py:354-460` | `_call_llm()` | Real LLM provider calls |
| `core/llm_providers.py` | `LLMProviderManager` | Provider abstraction |
| `core/decision_policy.py` | `DecisionPolicyEngine` | Policy evaluation |
| `core/cli.py:455-474` | `_handle_make_decision()` | CLI make-decision command |

**Environment Variables:**
- `OPENAI_API_KEY` - OpenAI GPT-5
- `ANTHROPIC_API_KEY` - Claude-3
- `GOOGLE_API_KEY` - Gemini-2
- `SENTINEL_API_KEY` - SentinelCyber

---

### T4: Remediation Workflow

**What it does:** Assigns tasks, tracks SLAs, verifies fixes with full state machine.

**API Endpoints:**
- `POST /api/v1/remediation/tasks` - Create remediation task
- `GET /api/v1/remediation/tasks/{id}` - Get task details
- `PUT /api/v1/remediation/tasks/{id}/status` - Update task status
- `GET /api/v1/remediation/sla` - Check SLA compliance
- `GET /api/v1/remediation/metrics` - Get MTTR metrics

**CLI Commands:**
```bash
python -m core.cli remediation list
python -m core.cli remediation create --finding-id X --assignee user@example.com
python -m core.cli remediation update --task-id Y --status IN_PROGRESS
```

**Program Flow:**
```
Finding Identified
    |
    v
[apps/api/remediation_router.py] - Create task endpoint
    |
    v
[core/services/remediation.py:RemediationService]
    |-- create_task()
    |-- State Machine:
    |   OPEN -> ASSIGNED -> IN_PROGRESS -> VERIFICATION -> RESOLVED
    |
    v
[core/services/remediation.py:SLATracker]
    |-- calculate_sla_deadline()
    |-- check_breach()
    |
    v
[core/services/remediation.py:MTTRCalculator]
    |-- calculate_mttr()
    |
    v
Task Persisted to data/remediation.db
```

**Key Modules:**
| File | Class/Function | Purpose |
|------|----------------|---------|
| `core/services/remediation.py` | `RemediationService` | Full state machine |
| `apps/api/remediation_router.py` | Router (13 endpoints) | HTTP handlers |
| `core/cli.py:3443-3594` | `_handle_remediation_cli()` | CLI remediation commands |

---

### T5: Compliance & Evidence

**What it does:** Generates signed, tamper-proof audit bundles with SLSA v1 provenance.

**API Endpoints:**
- `POST /api/v1/evidence/generate` - Generate evidence bundle
- `POST /api/v1/evidence/verify` - Verify signature
- `GET /api/v1/evidence/{id}` - Retrieve bundle
- `GET /api/v1/compliance/frameworks` - List frameworks
- `GET /api/v1/compliance/status` - Compliance status

**CLI Commands:**
```bash
python -m core.cli get-evidence --run result.json --target ./out
python -m core.cli compliance status
python -m core.cli compliance frameworks
```

**Program Flow:**
```
Pipeline Result
    |
    v
[core/evidence.py:EvidenceHub]
    |-- persist()
    |   |-- compress (gzip)
    |   |-- encrypt (Fernet)
    |   |-- checksum (SHA256)
    |   |-- sign (RSA-SHA256)
    |
    v
[services/provenance/attestation.py]
    |-- generate_slsa_provenance()
    |-- create_intoto_envelope()
    |
    v
[core/storage_backends.py]
    |-- LocalBackend (default)
    |-- S3ObjectLockBackend (WORM compliance)
    |-- AzureImmutableBlobBackend
    |
    v
Evidence Bundle (signed .tar.gz + manifest.json + provenance.json)
```

**Key Modules:**
| File | Class/Function | Purpose |
|------|----------------|---------|
| `core/evidence.py` | `EvidenceHub` | Bundle generation + signing |
| `services/provenance/attestation.py` | SLSA v1 provenance | In-toto attestation |
| `core/storage_backends.py` | Storage backends | Local/S3/Azure |
| `backend/api/evidence/router.py:162-303` | Verify endpoint | Signature verification |
| `core/cli.py:586-619` | `_handle_get_evidence()` | CLI get-evidence command |

---

### T6: Notifications

**What it does:** Sends alerts via Slack webhooks and SMTP email with SSRF protection.

**API Endpoints:**
- `POST /api/v1/collaboration/notifications` - Create notification
- `POST /api/v1/collaboration/notifications/{id}/deliver` - Deliver notification
- `GET /api/v1/collaboration/notifications/pending` - List pending

**CLI Commands:**
```bash
python -m core.cli notifications list
python -m core.cli notifications process
```

**Program Flow:**
```
Event Trigger (finding, SLA breach, etc.)
    |
    v
[core/services/collaboration.py:NotificationService]
    |-- create_notification()
    |-- queue_for_delivery()
    |
    v
[core/services/collaboration.py:DeliveryEngine]
    |-- _deliver_slack()
    |   |-- SSRF protection: validate hooks.slack.com domain
    |   |-- requests.post(webhook_url, json=payload)
    |
    |-- _deliver_email()
    |   |-- smtplib.SMTP with TLS
    |   |-- Configurable SMTP settings
    |
    v
Notification Delivered + Status Updated
```

**Key Modules:**
| File | Class/Function | Purpose |
|------|----------------|---------|
| `core/services/collaboration.py` | `NotificationService` | Queue + delivery |
| `core/connectors.py:213-248` | `SlackConnector` | Slack webhook calls |
| `core/cli.py:3597-3664` | `_handle_notifications()` | CLI notifications commands |

**Environment Variables:**
- `SLACK_WEBHOOK_URL` - Slack incoming webhook
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` - Email config

---

### T7: Security Scanning

**What it does:** Scans infrastructure-as-code (checkov/tfsec) and detects hardcoded secrets (gitleaks/trufflehog).

**API Endpoints:**
- `GET /api/v1/iac/scanners/status` - Check available scanners
- `POST /api/v1/iac/scan/content` - Scan IaC content
- `GET /api/v1/secrets/scanners/status` - Check secrets scanners
- `POST /api/v1/secrets/scan/content` - Scan for secrets

**Program Flow:**
```
IaC Content (Terraform/CloudFormation/K8s)
    |
    v
[core/iac_scanner.py:IaCScanner]
    |-- scan_content()
    |-- _run_checkov() - subprocess call
    |-- _run_tfsec() - subprocess call
    |-- _parse_checkov_output()
    |
    v
[core/secrets_scanner.py:SecretsScanner]
    |-- scan_content()
    |-- _run_gitleaks()
    |-- _run_trufflehog()
    |
    v
Findings Persisted to data/iac.db, data/secrets.db
```

**Key Modules:**
| File | Class/Function | Purpose |
|------|----------------|---------|
| `core/iac_scanner.py` | `IaCScanner` | checkov/tfsec integration |
| `core/secrets_scanner.py` | `SecretsScanner` | gitleaks/trufflehog integration |
| `apps/api/iac_router.py` | Scan endpoints | HTTP handlers |
| `apps/api/secrets_router.py` | Scan endpoints | HTTP handlers |

**External Tools Required:**
- `checkov` - IaC scanning
- `tfsec` - Terraform security
- `gitleaks` - Secrets detection
- `trufflehog` - Secrets detection

---

### T8: Jira Integration

**What it does:** Creates and syncs tickets bidirectionally with HMAC signature verification.

**API Endpoints:**
- `POST /api/v1/webhooks/jira/receive` - Receive Jira webhook
- `POST /api/v1/integrations/jira/create-issue` - Create Jira issue

**CLI Commands:**
```bash
python -m core.cli integrations list
python -m core.cli integrations test jira
python -m core.cli integrations sync jira
```

**Program Flow:**
```
FixOps Finding -> Jira Issue (Outbound)
    |
    v
[core/connectors.py:JiraConnector]
    |-- create_issue()
    |   |-- self._request("POST", "/rest/api/3/issue", json=payload)
    |   |-- Real HTTP call with auth
    |
    v
[apps/api/webhooks_router.py:744-1012] - Outbox Pattern
    |-- Queue item in outbox table
    |-- **NO WORKER PROCESSES IT** (Enterprise Blocker)

Jira Webhook -> FixOps (Inbound)
    |
    v
[apps/api/webhooks_router.py:233-350]
    |-- verify_hmac_signature()
    |-- map_jira_status_to_fixops()
    |-- update_remediation_task()
    |
    v
Bidirectional Sync with Drift Detection
```

**Key Modules:**
| File | Class/Function | Purpose |
|------|----------------|---------|
| `core/connectors.py:49-124` | `JiraConnector` | Real HTTP calls |
| `apps/api/webhooks_router.py:233-350` | Jira webhook handler | Inbound sync |
| `apps/api/webhooks_router.py:744-1012` | Outbox pattern | Queue for delivery |
| `core/cli.py:2284-2437` | `_handle_integrations()` | CLI integrations commands |

**Environment Variables:**
- `JIRA_URL` - Jira instance URL
- `JIRA_TOKEN` - API token
- `JIRA_WEBHOOK_SECRET` - HMAC secret

---

## CLI Command Reference

| Command | Subcommands | Purpose |
|---------|-------------|---------|
| `run` | - | Execute full pipeline |
| `ingest` | - | Normalize artifacts |
| `make-decision` | - | Get decision (exit code 0=allow, 1=block, 2=defer) |
| `analyze` | - | Analyze findings |
| `demo` | `--mode demo\|enterprise` | Run with bundled fixtures |
| `stage-run` | `--stage sarif\|sbom\|cve` | Process single stage |
| `get-evidence` | `--run result.json` | Copy evidence bundle |
| `show-overlay` | - | Print overlay config |
| `health` | - | Check integration readiness |
| `teams` | `list`, `create`, `delete` | Manage teams |
| `users` | `list`, `create`, `delete` | Manage users |
| `pentagi` | `analyze`, `status` | Pentagi pen testing |
| `compliance` | `status`, `frameworks` | Compliance management |
| `reports` | `list`, `generate` | Report management |
| `inventory` | `list`, `create` | Application inventory |
| `policies` | `list`, `create`, `test` | Policy management |
| `integrations` | `list`, `test`, `sync` | Integration management |
| `analytics` | `dashboard`, `trends` | View analytics |
| `audit` | `list`, `export` | Audit logs |
| `workflows` | `list`, `create`, `run` | Workflow automation |
| `remediation` | `list`, `create`, `update` | Remediation tasks |
| `notifications` | `list`, `process` | Notification queue |
| `correlation` | `list`, `create` | Finding correlation |
| `groups` | `list`, `create` | Finding clusters |
| `reachability` | `analyze` | Attack path analysis |
| `advanced-pentest` | `run` | AI-powered pentest |
| `train-forecast` | - | Train probabilistic model |
| `train-bn-lr` | - | Train Bayesian-LR model |
| `predict-bn-lr` | - | Predict exploitation risk |

---

*This document is the single source of truth for FixOps product status. Previous documents (STAKEHOLDER_ANALYSIS.md, ENTERPRISE_READINESS_ANALYSIS.md, FIXOPS_IMPLEMENTATION_STATUS.md, next_features.md) have been consolidated here and can be deleted.*
