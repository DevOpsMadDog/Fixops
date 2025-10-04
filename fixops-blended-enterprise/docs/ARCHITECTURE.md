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
