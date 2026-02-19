# ALdeci Suite Architecture

> **Last updated**: 2026-02-19
> **See also**: [DEVIN_CONTEXT.md](../DEVIN_CONTEXT.md) · [API_REFERENCE.md](API_REFERENCE.md) · [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [suite-api — REST Gateway](#2-suite-api--rest-gateway)
3. [suite-core — Business Logic Engine](#3-suite-core--business-logic-engine)
4. [suite-attack — Offensive Security](#4-suite-attack--offensive-security)
5. [suite-feeds — Vulnerability Intelligence](#5-suite-feeds--vulnerability-intelligence)
6. [suite-evidence-risk — Evidence & Risk](#6-suite-evidence-risk--evidence--risk)
7. [suite-integrations — External Connectors](#7-suite-integrations--external-connectors)
8. [suite-ui — React Frontend](#8-suite-ui--react-frontend)
9. [Inter-Suite Dependencies](#9-inter-suite-dependencies)
10. [Data Flow Diagrams](#10-data-flow-diagrams)
11. [Namespace Package Rules](#11-namespace-package-rules)

---

## 1. Architecture Overview

ALdeci uses a **6-suite microservice architecture** running in **monolithic mode**. All suites are loaded into a single FastAPI process via `suite-api/apps/api/app.py`.

```
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Process (port 8000)                │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ suite-api │  │suite-core│  │suite-atk │  │suite-feed│    │
│  │ (gateway) │──│ (engine) │──│ (pentest)│  │ (ingest) │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│  ┌────────────────┐  ┌──────────────────┐                    │
│  │suite-evidence   │  │suite-integrations│                    │
│  │(risk+compliance)│  │ (webhooks+tools) │                    │
│  └────────────────┘  └──────────────────┘                    │
└─────────────────────────────────────────────────────────────┘
         ↕ API calls                    ↕ feeds refresh
┌──────────────┐              ┌──────────────────────┐
│  suite-ui    │              │ NVD, CISA, EPSS,     │
│  (React SPA) │              │ GitHub, OSV, ExploitDB│
│  port 3001   │              └──────────────────────┘
└──────────────┘
```

**PYTHONPATH requirement** (all 6 suite dirs):
```bash
PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations"
```

---

## 2. suite-api — REST Gateway

**Role**: FastAPI application entry point. Hosts all REST endpoints by importing routers from all suites.
**Files**: 41 `.py` files
**Entry point**: `suite-api/apps/api/app.py` (2,466 lines)

### Directory Structure

```
suite-api/
├── apps/
│   ├── api/
│   │   ├── app.py                    # FastAPI entry point (create_app + inline endpoints)
│   │   ├── analytics_router.py       # /api/v1/analytics (22 endpoints)
│   │   ├── audit_router.py           # /api/v1/audit (14 endpoints)
│   │   ├── auth_router.py            # /api/v1/auth (4 endpoints)
│   │   ├── bulk_router.py            # /api/v1/bulk (12 endpoints)
│   │   ├── collaboration_router.py   # /api/v1/collaboration (20 endpoints)
│   │   ├── demo_data.py              # Demo/seed data generators
│   │   ├── dependencies.py           # Shared FastAPI dependencies
│   │   ├── detailed_logging.py       # /api/v1/logs (7 endpoints) + middleware
│   │   ├── health.py                 # /api/v1 health/ready/version (6 endpoints)
│   │   ├── iac_router.py             # /api/v1/iac (duplicate, see note)
│   │   ├── ide_router.py             # /api/v1/ide (duplicate, see note)
│   │   ├── ingestion.py              # InputNormalizer helper
│   │   ├── integrations.py           # Integration utilities
│   │   ├── integrations_router.py    # /api/v1/integrations (duplicate)
│   │   ├── inventory_router.py       # /api/v1/inventory (19 endpoints)
│   │   ├── marketplace_router.py     # /api/v1/marketplace (14 endpoints)
│   │   ├── mcp_router.py             # /api/v1/mcp (duplicate)
│   │   ├── middleware.py             # CorrelationId, RequestLogging middleware
│   │   ├── normalizers.py            # Data normalizers
│   │   ├── pipeline.py               # PipelineOrchestrator
│   │   ├── policies_router.py        # /api/v1/policies (11 endpoints)
│   │   ├── rate_limiter.py           # Rate limiting middleware
│   │   ├── remediation_router.py     # /api/v1/remediation (15 endpoints)
│   │   ├── reports_router.py         # /api/v1/reports (14 endpoints)
│   │   ├── routes/
│   │   │   └── enhanced.py           # /api/v1/enhanced (6 endpoints)
│   │   ├── teams_router.py           # /api/v1/teams (8 endpoints)
│   │   ├── upload_manager.py         # Chunked upload management
│   │   ├── users_router.py           # /api/v1/users (6 endpoints)
│   │   ├── validation_router.py      # /api/v1/validation (5 endpoints)
│   │   ├── webhooks_router.py        # /api/v1/webhooks (duplicate)
│   │   └── workflows_router.py       # /api/v1/workflows (13 endpoints)
│   ├── fixops_cli/                   # Legacy CLI integration
│   └── mpte_integration.py           # MPTE integration helper
└── backend/
    ├── app.py                        # Alternative backend entry (unused)
    └── normalizers.py                # Backend normalizers
```

> **Note**: Some routers exist both in `suite-api/apps/api/` and in other suites (e.g., `iac_router.py`, `ide_router.py`, `integrations_router.py`). The `app.py` loading logic tries the suite-specific version first via namespace package imports. If not found, it falls back to the local `apps.api.*` version.

### Middleware Stack (applied in order, outer → inner)

1. `CORSMiddleware` — CORS headers
2. `add_product_header` — X-Product-Name header
3. `LearningMiddleware` — ML API traffic capture (optional)
4. `DetailedLoggingMiddleware` — Full payload capture (optional)
5. `RequestLoggingMiddleware` — Request/response logging
6. `CorrelationIdMiddleware` — Correlation ID propagation
7. `FastAPIInstrumentor` — OpenTelemetry instrumentation

---

## 3. suite-core — Business Logic Engine

**Role**: Core business logic, Knowledge Graph, Brain Pipeline, AI agents, LLM providers, configuration.
**Files**: 322 `.py` files (largest suite)
**Key import**: `from core.configuration import OverlayConfig, load_overlay`

### Directory Structure (key modules)

```
suite-core/
├── core/                            # Main business logic
│   ├── knowledge_brain.py           # Knowledge Graph (SQLite + NetworkX)
│   ├── brain_pipeline.py            # 12-step Brain Pipeline orchestrator
│   ├── configuration.py             # Overlay config (YAML/JSON/env vars)
│   ├── enhanced_decision.py         # Multi-signal decision engine
│   ├── llm_providers.py             # OpenAI, Claude, Gemini abstraction
│   ├── event_bus.py                 # In-process event bus
│   ├── storage.py                   # ArtefactArchive (file-based storage)
│   ├── exposure_case.py             # Exposure Case lifecycle
│   ├── micro_pentest.py             # Micro-pentest engine
│   ├── mpte_advanced.py             # Advanced MPTE with multi-stage verification
│   ├── attack_simulation_engine.py  # Attack simulation + MITRE mapping
│   ├── autofix_engine.py            # Automated fix generation
│   ├── playbook_runner.py           # YAML playbook execution
│   ├── monte_carlo.py               # Monte Carlo risk simulation
│   ├── causal_inference.py          # Causal inference engine
│   ├── attack_graph_gnn.py          # GNN-based attack graph analysis
│   ├── sast_engine.py               # Static analysis engine
│   ├── dast_engine.py               # Dynamic analysis engine
│   ├── secrets_scanner.py           # Secrets detection
│   ├── container_scanner.py         # Container scanning
│   ├── cspm_engine.py               # Cloud security posture
│   ├── api_fuzzer.py                # API fuzzing engine
│   ├── malware_detector.py          # Malware detection
│   ├── analytics.py / analytics_db.py  # Analytics storage
│   ├── feedback.py                  # User feedback recorder
│   ├── paths.py / safe_path_ops.py  # Secure path operations
│   ├── flags/                       # Feature flags (local, LaunchDarkly, combined)
│   ├── models/                      # Data models (Bayesian, Markov, enterprise, legacy)
│   ├── services/                    # Service layer
│   │   ├── enterprise/              # Enterprise services (KG, decisions, feeds, marketplace)
│   │   ├── legacy/                  # Legacy services (for backward compatibility)
│   │   ├── collaboration.py         # Team collaboration
│   │   ├── deduplication.py         # Finding deduplication
│   │   ├── fuzzy_identity.py        # Fuzzy CVE/asset matching
│   │   └── remediation.py           # Remediation management
│   ├── db/                          # Database sessions + migrations
│   └── utils/                       # Crypto, logging utilities
├── agents/                          # AI Agent framework
│   ├── core/                        # agent_framework.py, agent_orchestrator.py
│   ├── language/                    # python, java, javascript, go agents
│   ├── design_time/                 # code_repo_agent.py
│   └── runtime/                     # container_agent.py
├── api/                             # 18 REST routers (brain, copilot, agents, etc.)
├── cli/                             # CLI tools (aldeci, fixops-ci, fixops-provenance, etc.)
│   ├── enterprise/                  # Enterprise CLI extensions
│   └── legacy_fixops/               # Legacy CLI compatibility
├── config/                          # YAML configs, playbooks, deployment packs
│   ├── playbooks/                   # Remediation playbook templates
│   ├── normalizers/                 # Input normalization configs
│   ├── deployment-packs/            # Docker, K8s, AWS, Azure, GCP deployment
│   └── enterprise/                  # Enterprise config overlays
├── configs/overlays/                # Config overlay YAML files
├── simulations/                     # Demo data, e2e validation, SSDLC scenarios
├── telemetry/                       # Telemetry configuration
└── telemetry_bridge/                # Edge collectors for AWS/Azure/GCP
```

---

## 4. suite-attack — Offensive Security

**Role**: MPTE engine, micro-pentesting, attack simulation, scanning engines.
**Files**: 13 `.py` files
**Key import**: `from api.mpte_router import router as mpte_router`

### Directory Structure

```
suite-attack/
├── api/
│   ├── app.py                       # Suite sub-app (unused in monolith mode)
│   ├── mpte_router.py               # /api/v1/mpte (19 endpoints)
│   ├── micro_pentest_router.py      # /api/v1/micro-pentest (18 endpoints)
│   ├── pentagi_router.py            # /api/v1/pentagi (8 endpoints)
│   ├── vuln_discovery_router.py     # /api/v1/vuln-discovery (12 endpoints)
│   ├── attack_sim_router.py         # /api/v1/attack-simulation (14 endpoints)
│   ├── secrets_router.py            # /api/v1/secrets (8 endpoints)
│   ├── sast_router.py               # /api/v1/sast (4 endpoints)
│   ├── dast_router.py               # /api/v1/dast (2 endpoints)
│   ├── container_router.py          # /api/v1/container (3 endpoints)
│   ├── cspm_router.py               # /api/v1/cspm (4 endpoints)
│   ├── api_fuzzer_router.py         # /api/v1/api-fuzzer (3 endpoints)
│   └── malware_router.py            # /api/v1/malware (4 endpoints)
```

---

## 5. suite-feeds — Vulnerability Intelligence

**Role**: Real-time vulnerability feed ingestion from 6 external sources.
**Files**: 3 `.py` files
**Key import**: `from api.feeds_router import router as feeds_router`

### Directory Structure

```
suite-feeds/
└── api/
    ├── app.py                       # Suite sub-app
    └── feeds_router.py              # /api/v1/feeds (30 endpoints)
```

### Feed Sources

| Source | Endpoints | Data |
|--------|-----------|------|
| **EPSS** (FIRST.org) | `GET /epss`, `POST /epss/refresh` | Exploit Prediction Scoring System |
| **CISA KEV** | `GET /kev`, `POST /kev/refresh` | Known Exploited Vulnerabilities |
| **NVD** (NIST) | `POST /nvd/refresh`, `GET /nvd/recent`, `GET /nvd/{cve_id}` | National Vulnerability Database |
| **ExploitDB** | `POST /exploitdb/refresh` | Public exploit database |
| **OSV** (Google) | `POST /osv/refresh` | Open Source Vulnerabilities |
| **GitHub Advisories** | `POST /github/refresh` | GitHub Security Advisories |

---

## 6. suite-evidence-risk — Evidence & Risk

**Role**: Evidence bundling, compliance mapping, risk scoring, reachability analysis, SBOM risk, dependency graph.
**Key import**: `from api.evidence_router import router as evidence_router`

### Directory Structure

```
suite-evidence-risk/
├── api/
│   ├── app.py                       # Suite sub-app
│   ├── evidence_router.py           # /api/v1/evidence (6 endpoints)
│   ├── risk_router.py               # /api/v1/risk (3 endpoints)
│   ├── graph_router.py              # /api/v1/graph (4 endpoints)
│   ├── provenance_router.py         # /api/v1/provenance (2 endpoints)
│   ├── business_context.py          # /api/v1/business-context (3 endpoints)
│   ├── business_context_enhanced.py # /api/v1/business-context-enhanced (4 endpoints)
│   ├── evidence_init.py             # Evidence init helpers
│   ├── graph_init.py                # Graph init helpers
│   ├── provenance_init.py           # Provenance init helpers
│   └── risk_init.py                 # Risk init helpers
├── compliance/
│   ├── __init__.py
│   ├── mapping.py                   # SOC2/ISO27001/PCI compliance mapping
│   └── templates/                   # Compliance report templates
├── evidence/
│   ├── __init__.py
│   └── packager.py                  # Evidence bundle packaging (collision detection)
├── policy/                          # OPA/Rego policy bundles per app
│   ├── APP1-APP4/                   # Per-application policy sets
│   ├── enterprise/                  # Enterprise policy overlays
│   └── psl_shim.py                  # Policy Scripting Language shim
├── reports/
│   ├── coverage/                    # Code coverage reports
│   └── deep_review/                 # Deep audit review reports
└── risk/
    ├── scoring.py                   # Composite risk scoring
    ├── enrichment.py                # Feed-based enrichment
    ├── forecasting.py               # Risk trend forecasting
    ├── threat_model.py              # STRIDE/DREAD threat modeling
    ├── dependency_graph.py          # Dependency graph construction
    ├── dependency_health.py         # Dependency health scoring
    ├── dependency_realtime.py       # Real-time dependency monitoring
    ├── license_compliance.py        # OSS license compliance checks
    ├── secrets_detection.py         # Secrets-in-code detection
    ├── reachability/api.py          # /api/v1/reachability (7 endpoints)
    ├── feeds/                       # Feed integration for risk
    ├── iac/                         # IaC security risk
    ├── runtime/                     # Runtime risk assessment
    └── sbom/                        # SBOM risk analysis
```



## 7. suite-integrations — External Connectors

**Role**: Third-party integrations, webhook management, IaC scanning, IDE plugins, MCP protocol, OSS tools.
**Key import**: `from api.integrations_router import router as integrations_router_ext`

### Directory Structure

```
suite-integrations/
├── api/
│   ├── app.py                       # Suite sub-app
│   ├── integrations_router.py       # /api/v1/integrations (8 endpoints)
│   ├── webhooks_router.py           # /api/v1/webhooks (19 ep) + receiver_router (4 ep)
│   ├── iac_router.py                # /api/v1/iac (7 endpoints)
│   ├── ide_router.py                # /api/v1/ide (5 endpoints)
│   ├── mcp_router.py                # /api/v1/mcp (10 endpoints)
│   └── oss_tools.py                 # /api/v1/oss (8 endpoints)
├── integrations/
│   ├── github/                      # GitHub integration connector
│   ├── jenkins/                     # Jenkins integration connector
│   ├── sonarqube/                   # SonarQube integration connector
│   ├── mpte_client.py               # MPTE client integration
│   ├── mpte_decision_integration.py # MPTE ↔ decision engine bridge
│   └── mpte_service.py              # MPTE service wrapper
├── lib4sbom/
│   ├── normalizer.py                # SBOM normalization (metadata guard)
│   └── parser.py                    # SBOM parser (CycloneDX, SPDX)
├── backstage/enterprise/            # Backstage catalog templates
├── mpte-aldeci/                     # Standalone MPTE UI build
├── postman/                         # Postman collection exports
└── ssvc/plugins/                    # SSVC categorization plugins
```

---

## 8. suite-ui — React Frontend

**Role**: Single-page application (SPA). React 18 + Vite 5 + TypeScript 5.3 + Tailwind CSS.
**Port**: 3001 (dev server) → proxies API calls to :8000
**Entry**: `suite-ui/aldeci/src/main.tsx`

### Directory Structure

```
suite-ui/aldeci/
├── src/
│   ├── App.tsx                      # Router + QueryClient + AnimatePresence
│   ├── main.tsx                     # Entry point
│   ├── layouts/MainLayout.tsx       # Sidebar + top bar + content area
│   ├── pages/                       # 56 page components
│   │   ├── Dashboard.tsx            # Main dashboard
│   │   ├── NerveCenter.tsx          # Brain nerve center
│   │   ├── DataFabric.tsx           # Data ingestion
│   │   ├── IntelligenceHub.tsx      # Intelligence overview
│   │   ├── DecisionEngine.tsx       # Decision engine
│   │   ├── AttackLab.tsx            # Attack simulation lab
│   │   ├── RemediationCenter.tsx    # Remediation management
│   │   ├── EvidenceVault.tsx        # Evidence bundles
│   │   ├── Copilot.tsx / Settings.tsx
│   │   ├── ai-engine/              # Multi-LLM, Algorithmic Lab, Predictions, Policies, ML
│   │   ├── attack/                 # MPTE Chat, PentAGI, Vuln Discovery, SecOps
│   │   ├── cloud/                  # Container Security, Runtime, CSPM, Attack Path
│   │   ├── code/                   # SAST, Secrets, SBOM, API Security
│   │   ├── core/                   # Knowledge Graph, Brain Pipeline, Exposure Cases
│   │   ├── evidence/               # Compliance, Bundles, Audit, Reports, SOC2, SLSA
│   │   ├── feeds/                  # Live Feed Dashboard
│   │   ├── protect/                # AutoFix Dashboard
│   │   └── settings/               # Teams, Users, Integrations, Marketplace
│   ├── components/
│   │   ├── AICopilot.tsx            # Persistent copilot panel
│   │   ├── ApiActivityPanel.tsx     # API activity monitor
│   │   ├── ErrorBoundary.tsx        # Error boundary wrapper
│   │   ├── GlobalStatusBar.tsx      # Status bar
│   │   ├── attack/MPTEChat.tsx      # MPTE chat component
│   │   ├── dashboard/              # CTEMProgressRing, MultiLLMConsensusPanel
│   │   └── ui/                     # shadcn/ui: badge, button, card, input, etc.
│   ├── lib/
│   │   ├── api.ts                   # Axios API client (1200+ lines, all endpoints)
│   │   └── utils.ts                 # Utility functions (cn helper)
│   ├── stores/index.ts              # Zustand stores (UI, Auth, Chat)
│   └── hooks/useSSE.ts              # Server-Sent Events hook
├── tests/                           # Playwright E2E tests
├── vite.config.ts                   # Vite config (proxy → :8000)
├── tailwind.config.js               # Tailwind CSS config
├── tsconfig.json                    # TypeScript config
└── package.json                     # Dependencies
```

### Key Libraries

| Library | Purpose |
|---------|---------|
| React 18.2 + Vite 5.0 | UI framework + build tool |
| TypeScript 5.3 | Type system |
| Tailwind CSS + shadcn/ui | Styling + component primitives |
| Zustand | Client state management |
| @tanstack/react-query | Server state / caching |
| framer-motion | Page transitions + animations |
| axios | HTTP client to backend |
| lucide-react | Icon library |
| sonner | Toast notifications |
| recharts | Charts and data visualizations |

---

## 9. Inter-Suite Dependencies

### Dependency Graph

```
suite-ui ──(HTTP)──► suite-api ──(Python import)──► suite-core
                         │                              │
                         ├──(namespace import)──► suite-attack
                         ├──(namespace import)──► suite-feeds
                         ├──(namespace import)──► suite-evidence-risk
                         ├──(namespace import)──► suite-integrations
                         │                              │
                         └──(direct import)─────► risk.reachability.api
                                                  (suite-evidence-risk)
```

### Import Relationships in `suite-api/apps/api/app.py`

**From `core.*` (suite-core) — direct imports (11 total):**

| Import | Module | Purpose |
|--------|--------|---------|
| `core.analytics.AnalyticsStore` | Analytics DB | Finding/metric storage |
| `core.configuration.OverlayConfig, load_overlay` | Configuration | YAML overlay loading |
| `core.enhanced_decision.EnhancedDecisionEngine` | AI Engine | Multi-LLM consensus |
| `core.feedback.FeedbackRecorder` | Feedback | User feedback recording |
| `core.flags.provider_factory.create_flag_provider` | Feature Flags | Flag evaluation |
| `core.paths.ensure_secure_directory, verify_allowlisted_path` | Path Security | Safe file I/O |
| `core.storage.ArtefactArchive` | Storage | Artefact persistence |
| `core.learning_middleware.LearningMiddleware` | ML | Learning from API calls |
| `core.event_subscribers.register_all_subscribers` | Event Bus | Event-driven hooks |
| `core.services.deduplication.DeduplicationService` | Dedup | Finding deduplication |

**From `api.*` (namespace packages — 44 router imports):**

| Source Suite | Routers Imported | Count |
|---|---|---|
| **suite-attack** | mpte, micro_pentest, vuln_discovery, pentagi, secrets, attack_sim, sast, container, dast, cspm, api_fuzzer, malware | 12 |
| **suite-core** | nerve_center, decisions, deduplication, mindsdb, autofix, fuzzy_identity, exposure_case, pipeline, copilot, agents, predictions, llm, algorithmic, intelligent_engine, llm_monitor, code_to_cloud, streaming, brain | 18 |
| **suite-feeds** | feeds | 1 |
| **suite-evidence-risk** | evidence, risk, graph, provenance, business_context, business_context_enhanced | 6 |
| **suite-integrations** | integrations, webhooks (+ receiver_router), iac, ide, mcp, oss_tools | 7 |
| **Total** | | **44** |

**From `risk.*` (direct import from suite-evidence-risk):**
- `risk.reachability.api.router` — mounted at `/api/v1/reachability`

**From `apps.api.*` (local suite-api routers — 6):**
- validation_router, marketplace_router, health, enhanced, detailed_logging + all 12 direct imports (analytics, audit, auth, bulk, collaboration, inventory, policies, remediation, reports, teams, users, workflows)

### How Mounting Works

`app.py` loads routers in 5 groups, each with try/except for graceful degradation:

1. **Direct local imports** (lines 34-45): `from apps.api.analytics_router import ...`
2. **Namespace try/except** (lines 48-429): `from api.mpte_router import ...`
3. **Core direct imports** (lines 431-437): `from core.configuration import ...`
4. **`create_app()` mounts** (lines 767-980): `app.include_router(router, dependencies=[Depends(_verify_api_key)])`
5. **Inline endpoints** (lines 1368-2466): `@app.get("/api/v1/...")` for 23 endpoints

---

## 10. Data Flow Diagrams

### 10a. Brain Pipeline (12-Step E2E Flow)

Source: `suite-core/core/brain_pipeline.py`

```
┌─────────────────────────────────────────────────────────────────┐
│                    BrainPipeline.run(input)                      │
│                                                                  │
│  Step 1: Connect         ─► Tally ingested findings + assets     │
│  Step 2: Normalize       ─► Canonical shape (title, severity,    │
│                              cve_id, asset_name)                 │
│  Step 3: Resolve Identity─► Fuzzy asset matching (Levenshtein)   │
│  Step 4: Deduplicate     ─► Cluster findings → Exposure Cases    │
│  Step 5: Build Graph     ─► Knowledge Graph (NetworkX/SQLite)    │
│                              Nodes: CVE, CWE, Asset, Finding     │
│                              Edges: affects, mitigates, maps_to  │
│  Step 6: Enrich Threats  ─► EPSS + KEV + CVSS from feeds cache   │
│  Step 7: Score Risk      ─► Composite: CVSS×0.4 + EPSS×0.3      │
│                              × KEV boost × asset criticality     │
│  Step 8: Apply Policy    ─► Rule evaluation → block/review/      │
│                              escalate/accept                      │
│  Step 9: LLM Consensus   ─► EnhancedDecisionEngine               │
│                              (GPT-4 + Claude + Gemini)            │
│  Step 10: Micro Pentest  ─► MPTE validation (optional)            │
│  Step 11: Run Playbooks  ─► Remediation playbooks (optional)      │
│  Step 12: Gen Evidence   ─► SOC2 Type II packs (optional)         │
│                                                                  │
│  Output: PipelineResult { run_id, steps[], status, summary }     │
└─────────────────────────────────────────────────────────────────┘
```

Steps 10-12 are **optional** — controlled by `PipelineInput.run_pentest`, `.run_playbooks`, `.generate_evidence`.

### 10b. Ingestion Flow

```
External Tool (SARIF/SBOM/VEX)
        │
        ▼
  POST /api/v1/ingest
  POST /api/v1/ingest/sarif
  POST /api/v1/ingest/sbom
        │
        ▼
  ┌─── Normalization ───┐
  │  SARIF → UnifiedFinding │
  │  SBOM → CycloneDX/SPDX  │
  │  VEX → Advisory records  │
  └─────────┬────────────┘
            │
            ▼
  ┌─── Storage Layer ──────┐
  │  ArtefactArchive (disk) │
  │  AnalyticsStore (SQLite) │
  │  Knowledge Brain (Graph) │
  └─────────┬───────────────┘
            │
            ▼
  ┌─── Event Bus ──────────┐
  │  finding.created event  │
  │  → enrich from feeds    │
  │  → trigger pipeline     │
  └─────────────────────────┘
```

### 10c. Feed Refresh Flow

```
  Scheduler / Manual trigger
        │
        ▼
  POST /api/v1/feeds/{source}/refresh
        │
        ├──► NVD API (nist.gov)
        ├──► CISA KEV (cisa.gov)
        ├──► EPSS API (first.org)
        ├──► GitHub Advisory DB (api.github.com)
        ├──► OSV (osv.dev)
        └──► ExploitDB (gitlab.com/exploit-database)
                │
                ▼
        ┌─── Cache Layer ──────┐
        │  In-memory + disk    │
        │  TTL-based freshness │
        └────────┬─────────────┘
                 │
                 ▼
        ┌─── Enrichment ──────┐
        │  Match CVE IDs       │
        │  Update EPSS scores  │
        │  Flag KEV entries    │
        │  Link exploits       │
        └──────────────────────┘
```

### 10d. MPTE (Micro-Pentest Testing Engine) Flow

```
  User request (UI or Pipeline Step 10)
        │
        ▼
  POST /api/v1/mpte/test  or  POST /api/v1/micro-pentest/run
        │
        ▼
  ┌─── MPTE Router ────────────┐
  │  Validate target + scope    │
  │  Create test session        │
  └──────────┬─────────────────┘
             │
             ▼
  ┌─── PentAGI Engine ─────────┐
  │  Stage 1: Reconnaissance    │
  │  Stage 2: Vulnerability     │
  │           Confirmation      │
  │  Stage 3: Exploitation      │
  │           Attempt           │
  │  Stage 4: Impact Analysis   │
  └──────────┬─────────────────┘
             │
             ▼
  ┌─── 4-State Verdict ────────┐
  │  CONFIRMED / LIKELY /       │
  │  UNLIKELY / NOT_VULNERABLE  │
  └──────────┬─────────────────┘
             │
             ▼
  ┌─── Multi-LLM Consensus ───┐
  │  GPT-4 + Claude + Gemini   │
  │  validate verdict           │
  └────────────────────────────┘
```

---

## 11. Namespace Package Rules (⚠️ Critical)

### The Problem

All 6 suites have an `api/` directory with router files. Python needs to import them all under a single `api` namespace (e.g., `from api.mpte_router import router`). Standard Python packages would conflict because each suite has its own `api/`.

### The Solution: PEP 420 Namespace Packages

**Rule 1: NEVER add `__init__.py` to any `api/` directory.**

```
suite-attack/api/           ← NO __init__.py
suite-core/api/             ← NO __init__.py
suite-feeds/api/            ← NO __init__.py
suite-evidence-risk/api/    ← NO __init__.py
suite-integrations/api/     ← NO __init__.py
```

If you add `__init__.py` to any `api/` dir, Python will treat it as a regular package and **block** discovery of routers from other suites.

**Rule 2: PYTHONPATH must include all 6 suite directories.**

```bash
export PYTHONPATH=.:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations
```

This is set in:
- `docker/Dockerfile` (line 88): `ENV PYTHONPATH=...`
- Local dev: run command or `.env` file

**Rule 3: Import pattern for routers.**

```python
# ✅ CORRECT — namespace import (works because all api/ dirs merge)
from api.mpte_router import router as mpte_router       # from suite-attack
from api.feeds_router import router as feeds_router      # from suite-feeds
from api.brain_router import router as brain_router      # from suite-core

# ✅ CORRECT — local import within same suite
from apps.api.analytics_router import router             # from suite-api (local)

# ✅ CORRECT — direct module import
from core.configuration import load_overlay              # from suite-core
from risk.reachability.api import router                 # from suite-evidence-risk

# ❌ WRONG — never use suite prefix in imports
from suite_attack.api.mpte_router import router          # WILL NOT WORK
from suite_core.core.configuration import load_overlay   # WILL NOT WORK
```

**Rule 4: Always use try/except for cross-suite imports.**

```python
mpte_router: Optional[APIRouter] = None
try:
    from api.mpte_router import router as mpte_router
    logger.info("Loaded MPTE router from suite-attack")
except ImportError as e:
    logger.warning("MPTE router not available: %s", e)
```

This ensures the app starts even if a suite is missing (graceful degradation).

**Rule 5: `core/` and `risk/` also use namespace packages.**

```
suite-core/core/           ← has __init__.py (standard package)
suite-evidence-risk/risk/  ← has __init__.py (standard package)
```

These work as standard packages because only one suite defines each namespace (`core` → suite-core, `risk` → suite-evidence-risk).

### Quick Diagnostic

If router imports fail at startup, check:

1. `PYTHONPATH` includes all suite dirs
2. No `__init__.py` in any `api/` directory: `find . -path "*/api/__init__.py" | grep suite`
3. Router file exists and has `router = APIRouter(...)` at module level
4. No circular imports (use lazy imports inside function bodies)

---

*See also: [API_REFERENCE.md](API_REFERENCE.md) for all 617 endpoints | [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for setup instructions | [DEVIN_CONTEXT.md](../DEVIN_CONTEXT.md) for master context*