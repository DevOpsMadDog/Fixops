# FixOps Platform Architecture

The FixOps Blended Enterprise platform delivers an agentic DevSecOps control plane that spans planning, build, verification, and ongoing operations. This document captures the current implementation, the tooling in place, and how the recently defined enhancement initiatives map into the architecture.

---

## 1. Platform Scope & Outcomes
- **Mission:** Provide a policy-driven, evidence-backed decision engine that accelerates secure releases while keeping compliance artefacts continuously updated.
- **Coverage:** Ingests scanner results, SBOM/IaC context, business-criticality profiles, and threat intelligence. Outputs automated ALLOW / DEFER / BLOCK verdicts, remediation playbooks, audit trails, and marketplace content.
- **Key Characteristics:**
  - Low-latency hot path (`/health`, `/ready`, decision endpoints) built on FastAPI with uvloop.
  - Deterministic evidence hashing via `EvidenceLake.store_evidence()` for tamper detection.
  - Dual-mode operation (demo vs. production) with feature flagging for integrations such as Redis, ChromaDB, and external feeds.

---

## 2. Layered Architecture Overview
```
┌────────────────────────────────────────────────────────────────────────────┐
│ Experience Layer                                                           │
│  • React/Vite dashboard • Typer CLI • FastAPI REST API                     │
├────────────────────────────────────────────────────────────────────────────┤
│ Integration & Workflow Layer                                               │
│  • CI/CD adapters • GitHub/GitLab webhooks • Feeds scheduler                │
├────────────────────────────────────────────────────────────────────────────┤
│ Intelligence & Decision Layer                                              │
│  • Processing Layer Orchestrator • Bayesian Prior Mapping • Markov Chain   │
│  • SSVC Fusion • SARIF handler • Knowledge Graph • LLM Explanation Engine  │
├────────────────────────────────────────────────────────────────────────────┤
│ Data & Evidence Layer                                                      │
│  • PostgreSQL/SQLite via SQLAlchemy • Redis cache • Evidence Lake          │
│  • Vector Store (Demo/ChromaDB) • Object storage & compliance artefacts    │
└────────────────────────────────────────────────────────────────────────────┘
```

Each layer is modularized under `src/` with services and utilities that can be deployed together via Docker Compose, Kubernetes, or standalone scripts.

---

## 3. SSDLC Process Mapping
| SSDLC Stage | FixOps Entry Points | Inputs Consumed | Outputs Produced | Enhancement Hooks |
| --- | --- | --- | --- | --- |
| **Plan & Requirements** | `business_context` APIs, Backstage plugin | Service metadata, historical verdicts, compliance frameworks | Criticality tags, guardrail checklist, policy defaults | Context learning engine retrains Bayesian priors; compliance automation seeds evidence templates |
| **Threat Modeling** | `knowledge_graph` service, ATT&CK feeds | Live intel feeds, asset graph, MITRE mappings | Ranked attack paths, threat narratives | Threat-path intelligence enriches knowledge graph and influences priors |
| **Design** | IaC upload endpoints, dependency advisory ingestion | Terraform/Kubernetes manifests, SBOM diffs | Annotated design review packages, dependency risk badges | Business-aware dependency governance merges SBOM with mission impact |
| **Build & Integrate** | CI/CD CLI (`fixops make-decision`), webhook callbacks | Normalized SARIF, pipeline metadata, cache lookups | Cached decisions, policy checks, queue events | Asynchronous orchestrator + Redis fingerprinting accelerate re-evaluation |
| **Verify** | Decision API, marketplace recommendations | Consolidated analytics, remediation patterns | ALLOW/DEFER/BLOCK verdict with evidence bundle | SSVC fusion with Markov/Bayesian scores; automated remediation drafting |
| **Release & Operate** | Dashboard, compliance export APIs | Deployment telemetry, marketplace submissions | Signed evidence packs, runbooks, contributor scoring | Compliance automation executes controls, content automation refreshes marketplace |

### 3.1 Stage Data Contracts & Artefacts

| Stage | Primary Interface | Core Input Models | Persisted / Returned Artefacts | Implementation Notes |
| --- | --- | --- | --- | --- |
| Plan | `api/v1/business_context.py` (`/jira-context`, `/confluence-context`, `/enrich-context`) | Free-form JSON enriched into `enriched_context` dictionaries | Cached context metadata in `business_context_processor` and policy defaults | Demo stubs ship in repo; production deployments replace simulated payloads with live Jira/Confluence connectors. |
| Threat Modeling | `services/knowledge_graph.py`, ATT&CK feed tasks in `feeds_service.py` | Threat intelligence payloads, asset nodes, MITRE technique identifiers | NetworkX graph snapshots, ATT&CK technique scores | Graph output is stored with evidence attachments so threat-path scores influence downstream priors. |
| Design | SBOM/IaC ingestion via `services/sbom_parser.py` and CLI | CycloneDX SBOM JSON, Terraform/Kubernetes manifests | Dependency risk badges, IaC posture assessments stored with decision cache keys | SBOM parser normalizes package metadata that `business_context_processor` cross-references against mission impact. |
| Build & Integrate | CI/CD hook (`api/v1/cicd.py`) and Typer CLI `DecisionRequest` | `DecisionContext` (service name, findings, SBOM, threat model) | Queue entries plus cached fingerprints in `cache_service.py` | Decision cache maps request fingerprints to prior verdicts to short-circuit repeated builds. |
| Verify | `/decisions/make-decision` FastAPI route | Same `DecisionContext` with normalized findings (`security_findings` list) | `DecisionOutcome` (decision, confidence, consensus details) and `evidence_id` | Outcome is persisted via `EvidenceLake.store_evidence()` which computes the SHA-256 `immutable_hash` signature and links compliance controls. |
| Release & Operate | `marketplace` API, compliance export CLI, monitoring endpoints | Remediation submissions, audit export filters, telemetry | Marketplace content bundles, signed compliance packets (`audit_export` output) | Marketplace tokens signed via `SecureTokenManager`; compliance bundles packaged from evidence digests for auditors. |

---

## 4. Component Breakdown

### 4.1 Experience & Access Channels
- **FastAPI Application (`src/main.py`)** exposes REST endpoints for scans, decisions, marketplace, policy administration, and system health. Startup wires in `DatabaseManager`, `CacheService`, the decision engines, marketplace service, and feed scheduler.
- **CLI (`src/cli`)** built with Typer mirrors API functionality for pipeline use (`fixops make-decision`, data uploads, dry runs).
- **Web Dashboard (`frontend/`)** built with React + Vite, consuming the public API for analysts to review decisions, evidence, and marketplace content.

### 4.2 Integration & Workflow Services
- **CI/CD Adapters (`src/api/v1/cicd.py`)** accept artifacts from GitHub Actions, GitLab CI, Jenkins, etc., and normalize them for processing.
- **Feeds Service (`src/services/feeds_service.py`)** schedules EPSS/KEV updates, storing results in the database and pushing deltas to the processing layer.
- **Policy Engine (`src/services/policy_engine.py`)** loads organization policies, ensures consistent evaluation, and drives ALLOW/DEFER/BLOCK logic.
- **Cache Service (`src/services/cache_service.py`)** provides Redis-backed caching (with in-memory fallback) for decision fingerprints, hot-path configuration, and telemetry.

### 4.3 Intelligence & Decision Layer
- **Processing Layer Orchestrator (`src/services/processing_layer.py`)** coordinates data normalization, Bayesian priors, Markov transitions, SSVC evaluation, and knowledge graph queries before emitting unified risk objects.
- **Bayesian Prior Mapping (`src/services/processing_layer.py`, `BayesianPriorMapping` class)** leverages `pgmpy` (when available) to initialize context-based probabilities; falls back to heuristic scoring if the library is absent.
- **Markov Transition Matrix Builder (`src/services/processing_layer.py`)** uses `mchmm` or deterministic matrices to simulate lifecycle transitions across `secure`, `vulnerable`, `exploited`, and `patched` states.
- **SSVC Probabilistic Fusion (`src/services/processing_layer.py`)** synthesizes deterministic SSVC vectors with Bayesian/Markov outputs, applying non-linear boosts for critical findings.
- **SARIF Handler (`src/services/processing_layer.py` & `services/sbom_parser.py`)** unifies scanner output, clusters similar findings, and infers risk for non-CVE issues.
- **Knowledge Graph Builder (`src/services/knowledge_graph.py`)** uses CTI Nexus style extraction to populate a NetworkX graph, computing centrality metrics for dependency and threat propagation.
- **LLM Engines (`src/services/llm_explanation_engine.py`, `advanced_llm_engine.py`)** convert analytics into tailored narratives and remediation playbooks using the Awesome-LLM4Cybersecurity prompt library with deterministic fallbacks.
- **Enhanced Decision Engine (`src/services/enhanced_decision_engine.py`)** wraps multi-LLM ensembles, integrates context-learning feedback, and manages asynchronous decision caching queues.

### 4.4 Data & Evidence Management
- **Database Layer (`src/db`)** abstracts PostgreSQL/SQLite via SQLAlchemy async sessions, connection pooling, and health checks.
- **Evidence Lake (`src/services/evidence_lake.py`)** stores decision artefacts, computes SHA-256 `immutable_hash` signatures, and associates evidence with compliance controls.
- **Vector Store (`src/services/vector_store.py`)** offers demo in-memory embeddings and production ChromaDB support for semantic search across security patterns.
- **Metrics & Monitoring (`src/services/metrics.py`, Prometheus middleware in `main.py`)** export counters/histograms consumed by Grafana or cloud monitoring.

### 4.5 Marketplace & Knowledge Sharing
- **Marketplace Service (`src/services/marketplace.py`)** curates remediation content, manages contributor incentives via signed tokens, and exposes APIs for download with HMAC protection.
- **Fix Engine (`src/services/fix_engine.py`)** merges scanner evidence, knowledge graph insights, and marketplace recommendations into actionable remediation plans.
- **Missing OSS Integrations Tracker (`src/services/missing_oss_integrations.py`)** highlights absent tool connectors, guiding roadmap prioritization.

---

## 5. Technology Stack & Tooling
| Domain | Tooling in Production Mode | Demo / Fallbacks | Notes |
| --- | --- | --- | --- |
| Runtime | FastAPI + uvicorn/uvloop | Same | Hot-path optimized middleware stack |
| Data Storage | PostgreSQL (async SQLAlchemy) | SQLite | Managed via `DatabaseManager` |
| Caching | Redis with connection pooling | In-memory dict | Fingerprints decisions, warms hot paths |
| Message & Async | `asyncio` tasks, background queues | Same | Future-ready for Celery/Kafka plug-in |
| Vector Search | ChromaDB + OpenAI embeddings | Deterministic hash embeddings | Aligns with content automation |
| Threat Feeds | CISA KEV, EPSS, ATT&CK | Mock feeds | `FeedsService` orchestrates updates |
| Compliance | Policy engine + evidence lake | YAML policies + local storage | Integrates with audit export CLI |
| Frontend | React + Tailwind + Vite | Same | Served via `frontend/` bundle |
| Infrastructure | Docker Compose, Kubernetes manifests, Terraform modules | Local docker | Scripts under `deploy-*.sh`, `kubernetes/`, `terraform/` |

---

## 6. Enhancement Implementation Matrix
| Initiative | Architectural Touchpoints | Current State |
| --- | --- | --- |
| Decision caching & async orchestration | `CacheService`, enhanced decision engine, pipeline webhooks | Redis-backed caching implemented; async hooks in place with TODOs for full queue workers |
| Business context learning | Bayesian prior mapper, business-context processor | Historical verdict ingestion implemented; model retraining hooks prepared |
| Threat-path intelligence | Knowledge graph, feeds service, ATT&CK mapping | Graph builder operational with MITRE technique tagging; live feed enrichment configurable |
| Dependency & IaC enrichment | SBOM parser, IaC processors, design review APIs | SBOM ingestion active; IaC context mapping integrated with design endpoints |
| Marketplace automation | Marketplace service, fix engine, LLM engines | Auto-generated remediation drafts shipping via LLM engine; contributor incentives issued with signed tokens |
| Compliance automation | Evidence lake, policy engine, audit export CLI | Evidence hashing live; compliance export endpoints producing signed packets, framework mapping underway |

---

## 7. Deployment & Operations
- **Local / Demo:** `docker-compose.yml` orchestrates API, frontend, Redis, and database. `run_enterprise.py` bootstraps demo datasets and enables mock integrations.
- **Enterprise:** Kubernetes manifests define API deployment, Redis, Postgres, and Prometheus scraping. Terraform modules provision cloud infrastructure for production rollouts.
- **Observability:** Prometheus metrics endpoints (`/metrics`), structured logging via `structlog`, and optional OpenTelemetry exporters give runtime visibility. Supervisord configuration keeps workers healthy in VM deployments.

---

## 8. Security, Compliance & Governance
- **Authentication & Authorization:** `SecurityManager` enforces token validation, signed download URLs, and request rate limiting.
- **Evidence Integrity:** All decision artefacts hashed on write; tokens for marketplace downloads use shared-secret HMAC to prevent tampering.
- **Policy Governance:** YAML-driven policies versioned in Git, validated through the policy engine, and surfaced via API/UI for transparency.
- **Compliance Readiness:** Export endpoints compile control evidence bundles, while the evidence lake retains artefacts for audit replay.

---

## 9. Next Steps
1. **Scale async orchestration** by introducing a dedicated task runner (Celery/Kafka) for long-running enrichment workloads.
2. **Productionize vector embeddings** with managed providers (OpenAI/Azure) and fallback open-source models for air-gapped deployments.
3. **Expand compliance mappings** by codifying additional frameworks (SOC2, ISO 27001) into the policy engine’s control catalog.
4. **Tighten closed-loop learning** through automated retraining of Bayesian priors and Markov matrices using post-deployment outcomes.
5. **Deepen marketplace analytics** with contributor reputation scoring and automated quality gates for submitted remediation content.

This architecture brings together the tooling, processes, and modules already built in the repository while positioning the platform to deliver the “super implementation” of the FixOps enhancement roadmap.

---

## 10. End-to-End Flow (User Perspective)
1. **Code pushed → CI trigger:** Git-based workflows invoke the Typer CLI or `/cicd/pipeline-callback`, uploading scanner SARIF, SBOM fragments, and service context assembled through the business-context APIs.
2. **Context & enrichment:** `business_context_processor.py` and `knowledge_graph.py` merge business metadata, dependency relationships, and ATT&CK paths into the shared decision payload. Cached lookups in `cache_service.py` trim repetitive enrichments across pipelines.
3. **Decision synthesis:** `processing_layer.py` orchestrates Bayesian priors, Markov transitions, SSVC fusion, and SARIF clustering before `decision_engine.py` applies policy gating and latency instrumentation.
4. **Evidence signing & persistence:** `EvidenceLake.store_evidence()` persists the generated `DecisionOutcome`, computing the `immutable_hash` signature and attaching artefacts for compliance export. Marketplace tokens and download links are wrapped via `SecureTokenManager` for downstream consumption.
5. **Feedback & operations:** The React dashboard and `/decisions/*` endpoints expose verdicts, confidence, evidence IDs, and remediation artefacts. Compliance exports bundle signed evidence, while the marketplace service surfaces LLM-authored remediation guidance for on-call and platform teams.
