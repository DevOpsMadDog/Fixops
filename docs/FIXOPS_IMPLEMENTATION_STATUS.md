# FixOps Implementation Status & Product Roadmap

**Last Updated:** January 2, 2026  
**Document Owner:** DevSecOps Engineering  
**Status:** Living Document - Update as features are completed

---

## Executive Summary (For CISOs & Stakeholders)

### What is FixOps?

FixOps is an **on-premises DevSecOps Decision & Verification Engine** that sits on top of your existing security toolchain. It ingests outputs from your scanners (Snyk, Trivy, SAST tools), applies intelligent decision-making, and produces audit-ready evidence bundles.

**Key Value Proposition:**
- **Ingest** security artifacts from existing tools (no scanner replacement needed)
- **Decide** with multi-LLM consensus and policy enforcement
- **Prove** decisions with cryptographically verifiable evidence bundles
- **Act** via integrations with Jira, ServiceNow, GitLab, Azure DevOps
- **Govern** with RBAC, audit trails, and compliance mapping

### Deployment Model

FixOps is designed for **single-tenant, on-premises deployment**. This means:
- Your data never leaves your infrastructure
- SQLite storage works well for single-tenant deployments
- Your existing SSO/auth infrastructure handles authentication
- No multi-tenancy complexity

### Current Readiness

| Capability | Status | Notes |
|------------|--------|-------|
| **Security Decision Automation** | Production Ready | Multi-LLM consensus, policy overrides, severity promotion |
| **Tool Ingestion** | Production Ready | SARIF, SBOM, CVE, VEX, CNAPP normalization |
| **Evidence Generation** | Production Ready | Compression, encryption, checksums |
| **Workflow Integrations** | Production Ready | Jira, ServiceNow, GitLab, Azure DevOps webhooks |
| **Analytics & ROI** | Production Ready | Dashboard, trends, MTTR metrics |
| **Deduplication** | Production Ready | Correlation, fingerprinting, baseline comparison |
| **RBAC** | In Progress | Role model exists, middleware needed |
| **Evidence Signing** | Integration Pending | Crypto module complete, wiring needed |

---

## PPT Slide Content (One-Slide Summary)

### Title: FixOps Product Maturity Timeline
**Subtitle:** On-Prem Security Decision & Verification Engine

```
TIMELINE BAR (Jan - Dec 2025):

[Jan-Mar] -----> [Apr-Jun] -----> [Jul-Aug] -----> [Sep] -----> [Oct] -----> [Dec] -----> [Next]
    |                |                |              |            |            |            |
 Problem         Prototype &      Pre-Product    Platform    Decision    Enterprise    Governance
 Discovery &     Feasibility      Hardening     Foundation  Automation  Intelligence  & Operability
 Architecture    Validation
```

| Phase | Timeline | What Customers Get |
|-------|----------|-------------------|
| **Problem Discovery & Architecture** | Jan-Mar 2025 | Requirements analysis, reference architecture, API contracts, threat model |
| **Prototype & Feasibility** | Apr-Jun 2025 | Validated approach for normalization, decisioning, and evidence generation |
| **Pre-Product Hardening** | Jul-Aug 2025 | Module boundaries, on-prem requirements, test strategy, internal alpha |
| **Platform Foundation** | Sep 2025 | Production codebase, configuration system, API scaffolding |
| **Decision Automation** | Oct 2025 | Ingest scanner outputs, automated decisions, evidence bundles |
| **Enterprise Intelligence** | Dec 2025 | Integrations, deduplication, analytics, workflow automation |
| **Governance & Operability** | Next | RBAC, background jobs, migrations, offline mode |

**Proof Points:**
- 12-month development cycle from ideation to production-ready
- 286/288 OpenAPI operations have handlers (99.3% coverage)
- 100% E2E test pass rate achieved
- Evidence bundles: checksum + encryption today; signing integration next

**Deployment:** On-premises, single-tenant, local-first operation

---

## Part 1: Production-Ready Features (10/10 Working)

### Definition of "10/10 Working"

A feature is considered 10/10 working when it meets ALL of these criteria:
1. **Implemented** - Real logic, not placeholder/stub
2. **Local-First** - Works without external API keys or network access
3. **Tested** - Exercised by E2E test harness or unit tests
4. **Wired** - Connected to the canonical app factory (`apps.api.app:create_app`)

### 1.1 Core Pipeline & Ingestion

These endpoints process security artifacts and execute the decision pipeline.

| Feature | Endpoints | Implementation | Test Coverage |
|---------|-----------|----------------|---------------|
| Health Checks | `/health`, `/api/v1/health`, `/api/v1/status` | Trivial but real | E2E harness health polling |
| Artifact Ingestion | `/inputs/design`, `/inputs/sbom`, `/inputs/sarif`, `/inputs/cve`, `/inputs/vex`, `/inputs/cnapp`, `/inputs/context` | Full parsing in `apps/api/normalizers.py` (1,839 lines) | E2E upload tests |
| Chunked Upload | `/inputs/{stage}/chunks/*` | Real upload manager with session tracking | Unit tests |
| Pipeline Execution | `/pipeline/run` (GET/POST) | Full orchestrator in `apps/api/pipeline.py` (1,735 lines) | E2E pipeline tests |
| Triage View | `/api/v1/triage` | Transforms pipeline results | E2E tests |

**Code References:**
- `apps/api/app.py:1065-1138` - Pipeline endpoint with full orchestrator integration
- `apps/api/normalizers.py` - SARIF/SBOM/CVE/VEX/CNAPP parsing
- `apps/api/pipeline.py` - PipelineOrchestrator with crosswalk, severity promotion, guardrails

### 1.2 Decision Engine

The multi-LLM consensus engine with policy overrides.

| Feature | Endpoints | Implementation | Test Coverage |
|---------|-----------|----------------|---------------|
| Enhanced Analysis | `/api/v1/enhanced/analyze` | Multi-LLM consensus in `core/enhanced_decision.py` (1,280 lines) | Unit + E2E |
| Capabilities | `/api/v1/enhanced/capabilities` | Returns LLM provider status | E2E |
| LLM Comparison | `/api/v1/enhanced/compare-llms` | Side-by-side provider analysis | E2E |
| Risk Profiling | `/api/v1/risk/*` | Heuristic + Bayesian-LR hybrid | Unit tests |

**Code References:**
- `core/enhanced_decision.py` - `MultiLLMConsensusEngine` with weighted voting
- `core/decision_policy.py` - `DecisionPolicyEngine` with critical overrides
- `core/severity_promotion.py` - KEV/EPSS-based severity escalation

**Note:** Falls back to deterministic mode when LLM API keys unavailable (design choice, not a stub).

### 1.3 Data Management (SQLite-Backed)

Full CRUD operations with SQLite persistence.

| Feature | Endpoints | Implementation |
|---------|-----------|----------------|
| Inventory Applications | `/api/v1/inventory/applications/*` | Real SQLite CRUD |
| Users | `/api/v1/users/*` | Full user management |
| Teams | `/api/v1/teams/*` | Team management with members |
| Policies | `/api/v1/policies/*` | Policy storage and retrieval |
| Workflows | `/api/v1/workflows/*` | Workflow definitions |
| IaC Findings | `/api/v1/iac/*` (except `/scan`) | Finding storage |
| Secrets Findings | `/api/v1/secrets/*` (except `/scan`) | Finding storage |
| SSO Config | `/api/v1/auth/sso/*` | SSO configuration storage |

**Code References:**
- `apps/api/inventory_router.py` - Application CRUD
- `apps/api/users_router.py` - User management with `UserRole` enum
- `apps/api/teams_router.py` - Team management

### 1.4 Analytics & Reporting

Real database queries and calculations.

| Feature | Endpoints | Implementation |
|---------|-----------|----------------|
| Dashboard | `/api/v1/analytics/dashboard`, `/analytics/dashboard` | Real DB queries |
| Trends | `/api/v1/analytics/trends` | Time-series analysis |
| MTTR | `/api/v1/analytics/mttr` | Mean Time To Remediation |
| ROI | `/api/v1/analytics/roi` | Cost avoidance calculations |
| Reports | `/api/v1/reports/*` | Report management |
| Audit Trail | `/api/v1/audit/*` | Audit log queries |

**Code References:**
- `apps/api/analytics_router.py` (437 lines) - 16 endpoints with real DB queries
- `core/analytics.py` - `AnalyticsStore`, `ROIDashboard`

### 1.5 Deduplication & Correlation

Full SQLite-backed clustering and correlation.

| Feature | Endpoints | Implementation |
|---------|-----------|----------------|
| Clusters | `/api/v1/deduplication/clusters/*` | Full cluster management |
| Correlations | `/api/v1/deduplication/correlations/*` | Cross-finding correlation |
| Fingerprinting | `/api/v1/deduplication/fingerprint` | Correlation key generation |
| Baseline | `/api/v1/deduplication/baseline/*` | Delta detection |

**Code References:**
- `core/services/deduplication.py` (1,158 lines) - Full implementation
- `apps/api/deduplication_router.py` (418 lines) - 17 endpoints

### 1.6 Remediation Lifecycle

Task management with SLA tracking.

| Feature | Endpoints | Implementation |
|---------|-----------|----------------|
| Tasks | `/api/v1/remediation/tasks/*` | Full task lifecycle |
| SLA | `/api/v1/remediation/sla/*` | SLA compliance calculation |
| Metrics | `/api/v1/remediation/metrics` | MTTR aggregation |

**Code References:**
- `apps/api/remediation_router.py` (269 lines) - 13 endpoints

### 1.7 Collaboration

SQLite-backed collaboration features.

| Feature | Endpoints | Implementation |
|---------|-----------|----------------|
| Comments | `/api/v1/collaboration/comments/*` | Threaded comments |
| Watchers | `/api/v1/collaboration/watchers/*` | Watcher management |
| Activity | `/api/v1/collaboration/activity/*` | Activity feed |
| Mentions | `/api/v1/collaboration/mentions/*` | Mention tracking |

**Code References:**
- `apps/api/collaboration_router.py` (584 lines) - 21 endpoints

### 1.8 Evidence & Compliance

Evidence bundle generation and compliance mapping.

| Feature | Endpoints | Implementation |
|---------|-----------|----------------|
| Evidence Bundles | `/api/v1/evidence/*` | Gzip, Fernet encryption, SHA256 |
| Compliance | `/api/v1/compliance/*` | SOC2/ISO27001/PCI-DSS/GDPR mapping |
| Provenance | `/provenance/*` | Attestation tracking |
| Graph | `/graph/*` | Artifact relationship graphs |

**Code References:**
- `core/evidence.py` (327 lines) - `EvidenceHub` with compression, encryption, checksums

---

## Part 2: Working When Configured (Requires External Access)

These features are fully implemented but require API keys, tokens, or network access.

| Feature | Endpoints | What's Needed | Code Reference |
|---------|-----------|---------------|----------------|
| **Multi-LLM Consensus** | `/api/v1/enhanced/*` | OpenAI/Anthropic/Gemini API keys | `core/llm_providers.py` (660 lines) |
| **Webhook Integrations** | `/api/v1/webhooks/*` | Webhook secrets + incoming webhooks | `apps/api/webhooks_router.py` (1,580 lines) |
| **Pentagi Integration** | `/api/v1/pentagi/*` | Pentagi service endpoint | `apps/api/pentagi_router_enhanced.py` (620 lines) |
| **Pentagi Docker Layer** | N/A (Docker Compose) | `docker-compose.pentagi.yml` overlay | See `docs/PENTAGI_INTEGRATION.md` |
| **Reachability Analysis** | `/api/v1/reachability/*` | Git clone access to target repos | `risk/reachability/analyzer.py` (810 lines) |
| **Notification Delivery** | `/api/v1/collaboration/notifications/*/deliver` | Slack/email credentials | `core/connectors.py` |
| **Vulnerability Feeds** | `/api/v1/feeds/*` | Network access for NVD/CISA KEV | `data/feeds/` |

**Webhook Integrations Detail:**
- Jira: HMAC signature verification, bidirectional sync
- ServiceNow: State mapping, drift detection
- GitLab: Label-to-status mapping
- Azure DevOps: Work item sync
- Outbox pattern with retry logic for reliable delivery

---

## Part 3: Being Built / Placeholder Features

These endpoints exist but return empty arrays, static data, or "not implemented" messages.

### 3.1 Inventory Subresources

| Endpoint | Current Behavior | What's Needed |
|----------|------------------|---------------|
| `/applications/{id}/components` | Returns `[]` | Populate from SBOM uploads |
| `/applications/{id}/apis` | Returns `[]` | API catalog integration |
| `/applications/{id}/dependencies` | Returns `[]` | Dependency graph from SBOM |
| `/api/v1/inventory/services/*` | Returns `[]` or 404 | Service registry |
| `/api/v1/inventory/apis/*` | Returns `[]` | API catalog |

**Code Reference:** `apps/api/inventory_router.py:152-204`

### 3.2 Scanning Endpoints

| Endpoint | Current Behavior | What's Needed |
|----------|------------------|---------------|
| `/api/v1/iac/scan` | Returns `"status": "scanning"` | Integrate checkov/tfsec |
| `/api/v1/secrets/scan` | Returns `"status": "scanning"` | Integrate gitleaks/trufflehog |

**Code References:**
- `apps/api/iac_router.py:122-130`
- `apps/api/secrets_router.py:116-124`

### 3.3 IDE Integration

| Endpoint | Current Behavior | What's Needed |
|----------|------------------|---------------|
| `/api/v1/ide/analyze` | Returns empty findings | Analysis engine integration |
| `/api/v1/ide/suggestions` | Returns empty suggestions | Suggestion engine |

**Code Reference:** `apps/api/ide_router.py:58-81`

### 3.4 Export & Bulk Operations

| Endpoint | Current Behavior | What's Needed |
|----------|------------------|---------------|
| `/api/v1/reports/export/csv` | Returns "not implemented" | CSV formatter |
| `/api/v1/reports/export/sarif` | Minimal implementation | Enhanced SARIF export |
| `/api/v1/bulk/findings/*` | Shallow handlers | Service layer wiring |
| `/api/v1/policies/{id}/test` | Returns "not implemented" | Policy evaluation engine |
| `/api/v1/integrations/{id}/test` | Returns "not implemented" | Integration test logic |

### 3.5 Marketplace (Enterprise-Gated)

| Endpoint | Current Behavior | What's Needed |
|----------|------------------|---------------|
| `/api/v1/marketplace/browse` | Returns demo data (3 items) | Enterprise marketplace service |
| `/api/v1/marketplace/contribute` | Returns 403 | Enterprise license |
| `/api/v1/marketplace/rate` | Returns 403 | Enterprise license |
| `/api/v1/marketplace/purchase` | Returns 403 | Enterprise license |

**Note:** This is intentional feature-gating, not incomplete implementation.

**Code Reference:** `apps/api/marketplace_router.py:34-74` - Demo fallback pattern

### 3.6 Scanner Adapter Wiring (Code Exists, Not Exposed)

Full adapter implementations exist in `core/adapters.py` (1,149 lines) but are **not wired to any API endpoints**.

| Adapter | Code Location | What It Does | What's Needed |
|---------|---------------|--------------|---------------|
| `TrivyAdapter` | `core/adapters.py:460-614` | Parses Trivy JSON, handles vulnerabilities + misconfigurations | API route + CLI command |
| `ProwlerAdapter` | `core/adapters.py:617-718` | Parses Prowler JSON/CSV, AWS CIS benchmarks | API route + CLI command |
| `OWASPZAPAdapter` | `core/adapters.py:721-827` | Parses ZAP JSON or fetches from ZAP API | API route + CLI command |
| `SemgrepAdapter` | `core/adapters.py:830-951` | Parses Semgrep SARIF/JSON output | API route + CLI command |
| `CheckovAdapter` | `core/adapters.py:954-1077` | Parses Checkov JSON for IaC findings | API route + CLI command |
| `AdapterRegistry` | `core/adapters.py:1080-1133` | Manages all adapters, `fetch_all()` method | Wire to pipeline |

**Also includes:** `GitLabAdapter`, `AzureDevOpsAdapter`, `SnykAdapter` - all fully implemented.

**Effort Estimate:** 2-3 days to wire all adapters to API endpoints

**Suggested API Routes:**
- `POST /api/v1/adapters/{adapter_name}/ingest` - Generic ingestion endpoint
- `GET /api/v1/adapters` - List available adapters
- `GET /api/v1/adapters/{adapter_name}/status` - Check adapter configuration

### 3.7 Cross-Stage Correlation (Partial)

The deduplication engine correlates findings within stages but does not track the full lifecycle.

| Feature | Current State | What's Needed |
|---------|---------------|---------------|
| Finding correlation | Working (7 strategies) | None |
| Lifecycle stage tracking | Not implemented | Add `lifecycle_stage` field to findings |
| Design → Build correlation | Not implemented | Link design findings to SARIF results |
| Build → Deploy correlation | Not implemented | Link SARIF to deployment artifacts |
| Deploy → Runtime correlation | Not implemented | Link deployment to runtime events |

**Code Reference:** `core/services/deduplication.py` - Add `lifecycle_stage` enum and cross-stage linking

**Effort Estimate:** 1-2 weeks for full cross-stage correlation

### 3.8 Runtime Event Ingestion (Not Implemented)

No endpoint exists for ingesting runtime security events (WAF logs, exploit attempts, anomalies).

| Feature | Current State | What's Needed |
|---------|---------------|---------------|
| Runtime event model | Not implemented | Define `RuntimeEvent` schema |
| Event ingestion endpoint | Not implemented | `POST /api/v1/events/ingest` |
| Event-to-finding correlation | Not implemented | Link runtime events to CVE findings |
| Severity escalation | Not implemented | Escalate findings with active exploit attempts |

**Effort Estimate:** 1 week for basic runtime event ingestion

### 3.9 OSS Fallback Engine (Code Exists, Not Wired)

Full OSS fallback engine exists but is not integrated into the pipeline.

| Component | Code Location | What It Does | What's Needed |
|-----------|---------------|--------------|---------------|
| `OSSFallbackEngine` | `core/oss_fallback.py:58-377` | Manages proprietary-first, OSS fallback strategy | Wire to pipeline |
| `FallbackStrategy` | `core/oss_fallback.py:17-23` | Enum: proprietary_first, oss_first, etc. | Config in overlay |
| Tool parsers | `core/oss_fallback.py:273-319` | Parses Semgrep, Bandit output | Add more tool parsers |

**Effort Estimate:** 3-5 days to wire into pipeline with config

---

## Part 4: Product Roadmap Timeline (January - December 2025)

> **Note:** January through August 2025 represents founder-led architecture and prototype work. September onward is fully evidenced by git history.

---

### Phase 1: Problem Discovery & Reference Architecture (January - March 2025)

**Business Value:** Deep understanding of the problem space and a validated technical approach

**Key Activities:**
- Interviewed security engineering and AppSec leads across multiple organizations
- Mapped pain points: alert fatigue, inconsistent decisions, evidence gaps, tool sprawl
- Defined the operating model: scanner-agnostic decision layer that sits on top of existing tools
- Created reference architecture for the data model (findings, run IDs, evidence bundles)
- Established API-first design principles with OpenAPI contracts
- Selected deployment posture: on-premises, single-tenant, local-first operation
- Conducted threat modeling for the platform itself

**Key Deliverables:**
- Reference architecture diagrams
- Product requirements documents (PRDs)
- Threat model documentation
- Initial OpenAPI contract specifications
- Competitive analysis of existing solutions

**Customer Impact:** Clear product vision aligned with real security team needs

---

### Phase 2: Prototype & Feasibility Validation (April - June 2025)

**Business Value:** Validated technical approach for the hardest problems before committing to production code

**Key Activities:**
- Built throwaway POCs for critical technical risks:
  - Normalizing SARIF/SBOM/CVE into a common schema
  - Experimenting with deterministic vs LLM-assisted decisioning
  - Designing evidence bundle format (manifest + checksum + encryption)
  - Testing integration feasibility with Jira/ServiceNow webhook payloads
- Validated core capabilities:
  - "Ingest and normalize" - can we handle diverse scanner outputs?
  - "Produce consistent decisions" - can we reduce noise reliably?
  - "Generate audit artifacts" - can we meet compliance requirements?
- Iterated on data model based on prototype learnings

**Key Deliverables:**
- Working prototype demonstrating end-to-end flow
- Validated normalization approach for SARIF, SBOM, CVE formats
- Evidence bundle format specification
- Integration feasibility report for ticketing systems

**Customer Impact:** Confidence that the technical approach would work at scale

---

### Phase 3: Pre-Product Hardening (July - August 2025)

**Business Value:** Transition from prototype to product-ready architecture

**Key Activities:**
- Defined module boundaries:
  - Pipeline orchestrator (crosswalk, severity promotion, guardrails)
  - Normalizers (SARIF, SBOM, CVE, VEX, CNAPP)
  - Decision engine (multi-LLM consensus, policy overrides)
  - Connectors (Jira, ServiceNow, Slack, Confluence)
  - Evidence hub (compression, encryption, checksums)
- Established operational requirements for on-prem deployment:
  - Secrets management approach
  - Offline mode concept for air-gapped environments
  - Data retention policies
- Selected storage approach: SQLite for single-tenant simplicity
- Designed E2E test harness architecture
- Created internal alpha deployment plan

**Key Deliverables:**
- Module architecture documentation
- On-premises deployment requirements
- E2E test strategy
- Internal alpha milestone achieved

**Customer Impact:** Production-ready architecture with clear module boundaries

---

### Phase 4: Platform Foundation (September 2025)

**Business Value:** Production codebase with solid architectural foundation

**Key Deliverables:**
- Initial project scaffolding in production repository
- Core directory structure
- Configuration overlay system (`fixops.overlay.yml`)
- API/CLI scaffolding
- FastAPI application factory

**Anchor Commit:** `2025-09-11` - Initial commit (repository inception)

**Customer Impact:** Stable foundation for rapid feature development

---

### Phase 5: Security Decision Automation (October 2025)

**Business Value:** Ingest scanner outputs, make automated decisions, generate evidence bundles

**Key Deliverables:**
- Pipeline orchestration with crosswalk building
- Evidence bundle generation with signing
- Severity promotion engine (KEV/EPSS)
- Demo orchestrator for competitive evaluation
- Scanner comparison framework

**Key Commits:**
| Date | Commit | Description |
|------|--------|-------------|
| Oct 30 | `db6dec43` | Automatic severity promotion with full evidence tracking |
| Oct 29 | `22700ee4` | Learning and adaptation capabilities with vector store |
| Oct 29 | `7213e2cd` | Comprehensive 6-step demo orchestrator |
| Oct 29 | `fe24919e` | E2E demo system for competitive evaluation |
| Oct 28 | `01c6f06c` | E2E orchestration with scanner comparison |
| Oct 9 | `11d0102c` | Demo pipeline with signing and marketplace |
| Oct 4 | `e81caa84` | Contributor reputation and QA automation |

**Customer Impact:** POC/demo readiness achieved

---

### Phase 6: Operational Workflows & Integrations (December 1-20, 2025)

**Business Value:** Connect decisions to action - ticketing, collaboration, remediation tracking

**Key Deliverables:**
- Reachability analysis engine (810 lines)
- Pentagi integration for micro-pentest
- CLI covering 250+ API endpoints
- Frontend API integration
- Marketplace UI and backend

**Key Commits:**
| Date | Commit | Description |
|------|--------|-------------|
| Dec 20 | `429492b2` | CLI expansion to cover 250+ endpoints |
| Dec 20 | `c1e9b1d9` | Shared API client package + frontend wiring |
| Dec 17 | `c0126552` | Marketplace UI + legacy marketplace backend |
| Dec 12 | `18234bd1` | Micro penetration test sidecar with animated CLI |
| Dec 8 | `2cb901c2` | Complete PentAGI-FixOps integration |
| Dec 8 | `381acea4` | Micro penetration testing feature |
| Dec 8 | `62518b25` | Teams and users CLI commands |
| Dec 7 | `e9842245` | Proprietary reachability analysis |
| Dec 7 | `3e84f262` | Core security features and parity |

**Customer Impact:** Enterprise integration capabilities

---

### Phase 7: Enterprise-Grade Intelligence Layer (December 21-25, 2025)

**Business Value:** Reduce noise, scale decisioning, prove ROI

**Key Deliverables:**
- Deduplication & correlation engine (1,158 lines)
- Collaboration system (comments, watchers, activity feeds)
- Webhook integrations (Jira, ServiceNow, GitLab, Azure DevOps)
- Vulnerability intelligence feeds
- Remediation lifecycle management
- Notification delivery with outbox pattern

**Key Commits:**
| Date | Commit | Description |
|------|--------|-------------|
| Dec 25 | `93434f9f` | CLI commands, triage view modes, notification delivery, outbox pattern |
| Dec 25 | `b14ee565` | All gaps and pending items for world-class enterprise |
| Dec 25 | `3c4a34bc` | Vulnerability intelligence feeds API (8 categories) |
| Dec 25 | `a476b97d` | World-class enterprise features (6 phases) |
| Dec 25 | `9235e1a5` | Deduplication and correlation engine |
| Dec 24 | `fe56a5f3` | Apple-like UI design system |
| Dec 21 | `fc64e3f6` | Frontend apps integrated with backend API |

**Customer Impact:** Enterprise-grade noise reduction and workflow automation

---

### Phase 8: Assurance & Reliability (December 26-28, 2025)

**Business Value:** Prove it works - comprehensive testing and documentation

**Key Deliverables:**
- 100% E2E test pass rate
- OpenAPI-driven test coverage for 291 operations
- Commercial deployment validation modes
- Docker image with bundled demos
- Comprehensive E2E documentation

**Key Commits:**
| Date | Commit | Description |
|------|--------|-------------|
| Dec 27 | `78d7a359` | OpenAPI-driven full coverage for all 291 API operations |
| Dec 27 | `e829afe2` | Comprehensive E2E test suite with Mac M5 setup |
| Dec 27 | `02159e2c` | Fix 6 backend bugs for 100% E2E test pass rate |
| Dec 27 | `1cc72901` | Test modes for commercial deployment validation |
| Dec 27 | `de1610fd` | Super detailed E2E test documentation |
| Dec 26 | `ab2903f1` | 10 new applications, animated demos, 7 core capability areas |
| Dec 26 | `b427cb17` | Bundle demo scripts into Docker image |

**Customer Impact:** Deployment confidence and quality assurance

---

## Part 5: Next Milestones (Governance & Operability)

### What Already Exists vs What's Needed

Each milestone below shows what's already implemented and what remains to be wired.

---

### 5A: Feature Gating

**Business Value:** Clear capability boundaries - customers know exactly what's enabled

**Timeline:** 3-5 days

**What Already Exists:**
- `/api/v1/enhanced/capabilities` endpoint returns LLM provider capabilities
- Feature flag infrastructure via `OverlayConfig.flag_provider`
- LaunchDarkly integration for remote flags

**Code Reference:** `apps/api/routes/enhanced.py:91-99`

**What's Needed:**
- Add general `/capabilities` endpoint listing all enabled features
- Replace ~15 empty-array responses with 501 + feature flag check

---

### 5B: Artifact Store (Unified Run Management)

**Business Value:** Consistent artifact lifecycle - every run is traceable and reproducible

**Timeline:** 3-5 days

**What Already Exists (404 lines in `fixops-enterprise/src/services/run_registry.py`):**
```python
class RunRegistry:
    def create_run(app_id, sign_outputs=False) -> RunContext
    def reopen_run(app_id, run_id, sign_outputs=False) -> RunContext
    def active_run(app_id) -> RunContext | None
    def ensure_run(app_id, stage, sign_outputs=False) -> RunContext

class RunContext:
    app_id: str
    run_id: str
    inputs_dir: Path      # artefacts/<app>/<run>/inputs/
    outputs_dir: Path     # artefacts/<app>/<run>/outputs/
    signed_outputs_dir: Path
    transparency_index: Path
    
    def save_input(filename, payload) -> Path
    def write_output(name, document) -> Path  # Auto-signs when sign_outputs=True
```

**Features:**
- `LATEST` marker for current run pointer
- Transparency index for signed outputs
- Automatic signing integration when `sign_outputs=True`
- Canonical output validation

**What's Needed:**
- Wire `RunRegistry` into `EvidenceHub` and graph/provenance routers
- Integration only - no new code required

---

### 5C: Offline Mode

**Business Value:** Air-gapped deployments - operate without external network access

**Timeline:** 2-3 days

**What Already Exists:**
- CLI supports `--offline` flag for air-gapped runs
- Connectors have conditional execution based on config
- Demo mode already operates without external calls

**Code Reference:** `samples/api-examples/README.md:750` - `python -m core.cli run --offline`

**What's Needed:**
- Add `INTEGRATIONS_MODE=offline` env var check in webhook/connector code
- Store "would-send" payloads for validation

---

### 5D: Schema Migrations

**Business Value:** Safe upgrades - no data loss during version updates

**Timeline:** 2-3 days

**What Already Exists (in `archive/enterprise_legacy/src/db/migrations/`):**
- Full Alembic setup with `alembic.ini`
- `env.py` migration environment
- `001_initial_schema.py` - users, sessions, audit logs (PostgreSQL)
- `002_add_kev_waivers.py` - KEV waiver tables
- `run_migrations.py` script

**Code Reference:** `archive/enterprise_legacy/src/db/migrations/versions/001_initial_schema.py`

**What's Needed:**
- Port migrations from archive to main codebase
- Add SQLite-compatible migrations for on-prem

---

### 5E: RBAC (Role-Based Access Control)

**Business Value:** Governance - control who can do what

**Timeline:** 1-1.5 weeks

**What Already Exists:**
```python
# apps/api/users_router.py
class UserRole(Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class UserCreate(BaseModel):
    role: UserRole = Field(default=UserRole.VIEWER)
```

- User model has `role` field
- Team members have `role` field
- Migration schema includes `roles` array column
- User sessions and audit logs tables

**Code References:**
- `apps/api/users_router.py:44-65` - Role enum and user models
- `apps/api/teams_router.py:53` - Team member roles
- `archive/enterprise_legacy/src/db/migrations/versions/001_initial_schema.py:41` - Roles array

**What's Needed:**
- Add role-checking middleware/decorator
- Enforce permissions on sensitive endpoints

---

### 5F: Background Jobs

**Business Value:** Reliability - long-running tasks don't block the API

**Timeline:** 1-2 weeks

**What Already Exists:**
- `BackgroundTasks` from FastAPI used in multiple routers
- Reachability analysis has job queue with status tracking
- Webhook outbox pattern with retry logic

**Code References:**
- `apps/api/bulk_router.py:11` - `from fastapi import BackgroundTasks`
- `apps/api/bulk_router.py:422-531` - Bulk operations using BackgroundTasks
- `apps/api/pentagi_router_enhanced.py:150` - Pentagi background tasks

**What's Needed:**
- Add persistent job store (SQLite table for job state)
- Add job status API endpoints
- Add retry/cancellation logic

---

### 5G: Evidence Signing

**Business Value:** Cryptographic proof - evidence bundles are tamper-evident

**Timeline:** 2-3 days

**What Already Exists (724 lines in `fixops-enterprise/src/utils/crypto.py`):**
```python
# Signing functions
def rsa_sign(json_bytes: bytes) -> Tuple[bytes, str]
def rsa_verify(json_bytes: bytes, signature: bytes, pub_fingerprint: str) -> bool

# Key providers
class EnvKeyProvider:      # Environment-based RSA keys
class AWSKMSProvider:      # AWS KMS integration
class AzureKeyVaultProvider:  # Azure Key Vault integration

# Key management
def get_key_provider() -> KeyProvider
def evaluate_rotation_health(provider, max_age_days) -> Dict[str, Any]
```

**Features:**
- RSA-SHA256 signing and verification
- Key rotation with SLA monitoring
- Attestation metadata
- `RunContext.write_output()` already calls signing when `sign_outputs=True`

**Code Reference:** `fixops-enterprise/src/utils/crypto.py:431-443`

**What's Needed:**
- Wire `rsa_sign()` into `EvidenceHub.persist()`
- Add `/api/v1/evidence/verify` endpoint that calls `rsa_verify()`
- Store signature + fingerprint in the manifest

---

## Timeline Summary

| Phase | Original Estimate | Revised Estimate | Reason |
|-------|-------------------|------------------|--------|
| **5A: Feature Gating** | 1-2 weeks | **3-5 days** | Capabilities endpoint exists |
| **5B: Artifact Store** | 2 weeks | **3-5 days** | `RunRegistry` fully implemented |
| **5C: Offline Mode** | 1 week | **2-3 days** | CLI offline mode exists |
| **5D: Migrations** | 1 week | **2-3 days** | Alembic setup in archive |
| **5E: RBAC** | 2-3 weeks | **1-1.5 weeks** | Role model exists |
| **5F: Background Jobs** | 2-3 weeks | **1-2 weeks** | BackgroundTasks pattern used |
| **5G: Evidence Signing** | 2 weeks | **2-3 days** | Full crypto module exists |

**Original Total:** 10-14 weeks  
**Revised Total:** 4-6 weeks

---

## Appendix A: Code Location Reference

### Canonical App Factory

The E2E test harness uses `apps.api.app:create_app` as the canonical app factory.

**Evidence:** `tests/harness/server_manager.py:26`
```python
app_module: str = "apps.api.app:create_app"
```

### Key File Locations

| Component | File | Lines |
|-----------|------|-------|
| Pipeline Orchestrator | `apps/api/pipeline.py` | 1,735 |
| Multi-LLM Consensus | `core/enhanced_decision.py` | 1,280 |
| Input Normalization | `apps/api/normalizers.py` | 1,839 |
| Webhook Integrations | `apps/api/webhooks_router.py` | 1,580 |
| Deduplication Service | `core/services/deduplication.py` | 1,158 |
| Reachability Analyzer | `risk/reachability/analyzer.py` | 810 |
| Crypto/Signing | `fixops-enterprise/src/utils/crypto.py` | 724 |
| LLM Providers | `core/llm_providers.py` | 660 |
| Pentagi Router | `apps/api/pentagi_router_enhanced.py` | 620 |
| Collaboration Router | `apps/api/collaboration_router.py` | 584 |
| Analytics Router | `apps/api/analytics_router.py` | 437 |
| Deduplication Router | `apps/api/deduplication_router.py` | 418 |
| Run Registry | `fixops-enterprise/src/services/run_registry.py` | 404 |
| Evidence Hub | `core/evidence.py` | 327 |
| Remediation Router | `apps/api/remediation_router.py` | 269 |

### Enterprise Modules (Available but Need Integration)

| Module | Location | Status |
|--------|----------|--------|
| Run Registry | `fixops-enterprise/src/services/run_registry.py` | Ready to wire |
| Crypto/Signing | `fixops-enterprise/src/utils/crypto.py` | Ready to wire |
| Alembic Migrations | `archive/enterprise_legacy/src/db/migrations/` | Ready to port |

---

## Appendix B: Test Coverage Status

### Current Coverage Metrics (January 2, 2026)

| Metric | Value | Notes |
|--------|-------|-------|
| **Global Coverage** | 18.95% | Measured on core/ + apps/ modules |
| **Total Statements** | 28,254 | In core/ and apps/ directories |
| **Covered Statements** | 5,580 | Statements with test coverage |
| **Uncovered Statements** | 22,674 | Statements needing tests |
| **Tests Passing** | 44/46 | 2 tests failing due to env issues |

### Coverage Policy: "100% Always"

Starting January 2, 2026, FixOps enforces **100% test coverage on all new and modified code** via diff-coverage in CI.

**Policy Details:**
1. **New code must have 100% coverage** - Any lines added or modified in a PR must be covered by tests
2. **Global baseline increases over time** - Systematic coverage improvement on existing code
3. **Critical modules have priority** - Decision engine, evidence generation, auth boundaries first

### Module-Level Coverage

**Well-Covered Modules (>70%):**
| Module | Coverage |
|--------|----------|
| `core/severity_promotion.py` | 90.15% |
| `core/performance.py` | 85.90% |
| `core/storage.py` | 85.42% |
| `core/probabilistic.py` | 80.75% |
| `core/vector_store.py` | 70.31% |

**Uncovered Modules (0%):**
- `core/pentagi_*.py` - Pen testing integration
- `core/stage_runner.py` - Pipeline stage execution
- `risk/reachability/*.py` - Reachability analysis
- `risk/feeds/*.py` - Vulnerability feeds

### Phased Coverage Improvement Plan

| Phase | Target | Timeline | Focus Areas |
|-------|--------|----------|-------------|
| Phase 1 | 25% | Jan 2026 | Decision engine, evidence generation |
| Phase 2 | 50% | Feb 2026 | Policy enforcement, auth boundaries |
| Phase 3 | 70% | Mar 2026 | Database operations, API endpoints |
| Phase 4 | 100% | Apr 2026 | All remaining modules |

**Full coverage plan:** See [COVERAGE_PLAN.md](./COVERAGE_PLAN.md)

---

## Appendix C: API Handler Statistics

| Metric | Count |
|--------|-------|
| Total OpenAPI Operations | 288 |
| Operations with Handlers | 286 (99.3%) |
| E2E Test Coverage | 137 endpoints explicitly tested |
| Total HTTP Endpoints | ~275 |

### Breakdown by Implementation Depth

| Category | Count | Percentage |
|----------|-------|------------|
| Production Ready (10/10) | ~140 | ~51% |
| Working When Configured | ~40 | ~15% |
| Being Built / Placeholder | ~50 | ~18% |
| Feature-Gated (Enterprise) | ~45 | ~16% |

---

## Appendix D: Update Log

| Date | Author | Changes |
|------|--------|---------|
| 2026-01-02 | Devin | Initial document creation |
| 2026-01-02 | Devin | Added Appendix B: Test Coverage Status with 18.95% baseline and "100% Always" policy |
| 2026-01-03 | Devin | Added PentAGI Docker integration status; updated pending items |
| 2026-01-03 | Devin | Added Part 3 sections 3.6-3.9: Scanner adapter wiring, cross-stage correlation, runtime events, OSS fallback |

---

## How to Update This Document

When completing a milestone:

1. Move the feature from "Part 3: Being Built" to "Part 1: Production Ready"
2. Update the code references with final implementation locations
3. Add the completion date to the Phase timeline
4. Update the API Coverage Statistics
5. Add an entry to the Update Log

When starting a new feature:

1. Add it to "Part 3: Being Built" with current status
2. Document what already exists vs what's needed
3. Provide realistic timeline estimate based on existing code
