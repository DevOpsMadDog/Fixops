# ALdeci — Comprehensive Application Context

> **Last updated**: 2026-02-21
> **Branch**: `features/intermediate-stage`
> **Formerly known as**: FixOps
> **Related docs**: [API_REFERENCE.md](docs/API_REFERENCE.md) · [SUITE_ARCHITECTURE.md](docs/SUITE_ARCHITECTURE.md) · [DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) · [CLIENT_DEMO_GUIDE.md](docs/CLIENT_DEMO_GUIDE.md)

---

## Table of Contents

1. [What is ALdeci?](#1-what-is-aldeci)
2. [Architecture — 6 Suites](#2-architecture--6-suites-monolithic-mode)
3. [Entry Point & Router Loading](#3-entry-point--router-loading)
4. [Complete Router Inventory](#4-complete-router-inventory)
5. [Key Business Logic Modules (suite-core)](#5-key-business-logic-modules-suite-core)
6. [Frontend (suite-ui)](#6-frontend-suite-ui)
7. [Brain Pipeline — 12-Step Data Flow](#7-brain-pipeline--12-step-data-flow)
8. [How to Run Locally](#8-how-to-run-locally)
9. [Environment Variables](#9-environment-variables)
10. [Docker](#10-docker)
11. [CI/CD Workflows](#11-cicd-workflows)
12. [Testing](#12-testing)
13. [Repository Structure](#13-repository-structure)
14. [Inter-Suite Dependency Map](#14-inter-suite-dependency-map)
15. [Database Files & Storage](#15-database-files--storage)
16. [Cleanup History](#16-cleanup-history)
17. [Enterprise Mode & Authentication](#17-enterprise-mode--authentication)
18. [CTEM Loop — 5-Stage Flow](#18-ctem-loop--5-stage-flow)
19. [Testing & Validation Scripts](#19-testing--validation-scripts)
20. [Guidelines for AI Agents & Developers](#20-guidelines-for-ai-agents--developers)

---

## 1. What is ALdeci?

ALdeci is a **security vulnerability management and risk assessment platform**. It ingests vulnerabilities from multiple feeds (NVD, CISA KEV, EPSS, GitHub Advisories, OSV, ExploitDB), runs AI-powered analysis, simulates attacks, scores risk, and provides a unified dashboard for security teams.

**Key capabilities:**
- Real-time vulnerability feed ingestion and correlation
- Knowledge Graph Brain for CVE/CWE/CPE relationship mapping
- AI-powered micro-pentesting (MPTE engine + PentAGI)
- Attack simulation, DAST, SAST, container scanning, API fuzzing
- Evidence bundling and compliance reporting (SOC2, ISO27001)
- SBOM normalization (CycloneDX, SPDX) and dependency analysis
- Multi-LLM consensus (OpenAI GPT-4, Anthropic Claude, Google Gemini)
- Brain Pipeline — 12-step automated vulnerability triage
- Exposure Case lifecycle management
- Playbook-driven automated remediation

---

## 2. Architecture — 6 Suites (Monolithic Mode)

The app uses a **6-suite microservice architecture** that currently runs in **monolithic mode** — all suites loaded into a single FastAPI process on port 8000.

| Suite | Directory | Port (future) | .py files | Purpose |
|-------|-----------|---------------|-----------|---------|
| **API** | `suite-api/` | 8000 | 41 | FastAPI app, REST endpoints, 17 routers + 23 inline endpoints |
| **Core** | `suite-core/` | 8001 | 322 | Business logic, CLI, Knowledge Graph, Brain Pipeline, agents |
| **Attack** | `suite-attack/` | 8002 | 13 | MPTE engine, micro-pentest, attack simulation, DAST/SAST |
| **Feeds** | `suite-feeds/` | 8003 | 3 | NVD, CISA KEV, EPSS, GitHub Advisories, OSV, ExploitDB |
| **Evidence-Risk** | `suite-evidence-risk/` | 8004 | 69 | Evidence packager, risk scoring, compliance, provenance |
| **Integrations** | `suite-integrations/` | 8005 | 23 | Webhooks, IaC, IDE, MCP, OSS tools, SBOM normalization |

### Critical: PYTHONPATH

Every suite directory must be on `PYTHONPATH` for imports to resolve:

```bash
export PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations"
```

**Why?** Code uses `from apps.api.app import ...`, `from core.engine import ...`, `from api.feeds_router import ...`.
With the suite layout, `suite-api/apps/api/app.py` needs `suite-api/` on the path so Python finds `apps.api.app`.

### Critical: No `__init__.py` in `api/` directories

All suites use **implicit namespace packages**. Do NOT add `__init__.py` to any `api/` directory or Python will treat the first one found as a regular package and break imports from other suites.

---

## 3. Entry Point & Router Loading

**File**: `suite-api/apps/api/app.py` (2,466 lines)
**Function**: `create_app()` → returns `FastAPI` instance
**Variable**: `app = create_app()` (module-level, used by uvicorn)

### How Router Loading Works

1. **Lines 34–45**: Direct imports from `apps.api.*` (suite-api's own routers)
2. **Lines 48–429**: Try/except imports from `api.*` (namespace package — resolves to suite-core, suite-attack, suite-feeds, suite-evidence-risk, or suite-integrations based on PYTHONPATH)
3. **Lines 431–463**: Direct imports from `core.*` (suite-core business logic)
4. **Lines 534–766**: `create_app()` — app creation, middleware, CORS, state init
5. **Lines 767–980**: Router mounting (all routers registered with `app.include_router()`)
6. **Lines 1368–1488**: Inline ingestion endpoints (`/inputs/design`, `/inputs/sbom`, etc.)
7. **Lines 1490–1810**: Multipart ingestion, chunk upload, asset inventory
8. **Lines 1811–2200**: Triage endpoints
9. **Lines 2201–2466**: Graph, analytics, feedback endpoints

### Import Pattern

```python
# suite-api's own routers (direct import, always available)
from apps.api.analytics_router import router as analytics_router

# Other suite routers (try/except, may not be available)
mpte_router: Optional[APIRouter] = None
try:
    from api.mpte_router import router as mpte_router      # → suite-attack/api/mpte_router.py
except ImportError as e:
    _logger.warning("MPTE router not available: %s", e)

# Business logic (direct import from suite-core)
from core.analytics import AnalyticsStore                   # → suite-core/core/analytics.py
from core.configuration import OverlayConfig, load_overlay  # → suite-core/core/configuration.py
```

---

## 4. Complete Router Inventory

> For full endpoint details with schemas, see [docs/API_REFERENCE.md](docs/API_REFERENCE.md)

### suite-api Routers (17 routers + 23 inline endpoints)

| Router File | Prefix | Endpoints | Domain |
|-------------|--------|-----------|--------|
| `analytics_router.py` | `/api/v1/analytics` | 22 | Dashboard stats, findings, decisions, MTTR, ROI |
| `audit_router.py` | `/api/v1/audit` | 16 | Audit logs, compliance frameworks, chain verification |
| `auth_router.py` | `/api/v1/auth` | 6 | SSO configuration CRUD |
| `bulk_router.py` | `/api/v1/bulk` | 14 | Bulk cluster operations, jobs |
| `collaboration_router.py` | `/api/v1/collaboration` | 23 | Comments, watchers, mentions, notifications |
| `inventory_router.py` | `/api/v1/inventory` | 21 | Assets, applications, services, dependencies, SBOM gen |
| `policies_router.py` | `/api/v1/policies` | 13 | Policy CRUD, validation, testing, enforcement |
| `remediation_router.py` | `/api/v1/remediation` | 17 | Tasks CRUD, SLA checks, metrics, autofix |
| `reports_router.py` | `/api/v1/reports` | 16 | Reports CRUD, generation, SARIF/CSV/JSON export |
| `teams_router.py` | `/api/v1/teams` | 10 | Teams CRUD, members |
| `users_router.py` | `/api/v1/users` | 8 | Login, users CRUD |
| `workflows_router.py` | `/api/v1/workflows` | 15 | Workflows CRUD, execution, SLA, rules |
| `validation_router.py` | `/api/v1/validation` | 5 | Input validation, batch validation |
| `marketplace_router.py` | `/api/v1/marketplace` | 14 | Packs, browse, recommendations, purchase |
| `health.py` | `/api/v1` | 6 | Health, ready, version, metrics |
| `routes/enhanced.py` | `/api/v1/enhanced` | 6 | Enhanced analysis, compare LLMs |
| `detailed_logging.py` | `/api/v1/logs` | 7 | Log query, stats, recent, clear, stream |

**Inline endpoints in `app.py`** (23 total):
- `/health` (legacy healthcheck), `/api/v1/status`, `/api/v1/search`
- `/inputs/{design,sbom,cve,vex,cnapp,sarif,context}` (7 ingestion endpoints)
- `/api/v1/ingest/{multipart,assets,formats}` (3 ingest utilities)
- `/inputs/{stage}/chunks/{start,upload,complete,status}` (4 chunked upload)
- `/api/v1/triage`, `/api/v1/triage/export` (2 triage endpoints)
- `/api/v1/graph` (knowledge graph visualization)
- `/analytics/dashboard`, `/analytics/runs/{run_id}` (2 analytics)
- `/feedback` (user feedback)

### suite-core Routers (18 routers)

| Router File | Prefix | Endpoints | Domain |
|-------------|--------|-----------|--------|
| `agents_router.py` | `/api/v1/agents` | 30 | Analyst, pentest, compliance, remediation agents |
| `algorithmic_router.py` | `/api/v1/algorithmic` | 11 | Monte Carlo, causal analysis, GNN |
| `autofix_router.py` | `/api/v1/autofix` | 13 | Generate, apply, validate, rollback fixes |
| `brain_router.py` | `/api/v1/brain` | 21 | Knowledge Graph nodes/edges CRUD, paths, risk |
| `code_to_cloud_router.py` | `/api/v1/code-to-cloud` | 2 | Code-to-cloud tracing |
| `copilot_router.py` | `/api/v1/copilot` | 14 | Chat sessions, messages, quick-analyze |
| `decisions.py` | `/api/v1/decisions` | 7 | Decision engine, SSDLC stages, evidence |
| `deduplication_router.py` | `/api/v1/dedup` | 18 | Finding deduplication, clusters, correlation |
| `exposure_case_router.py` | `/api/v1/exposure-cases` | 8 | Exposure case lifecycle management |
| `fuzzy_identity_router.py` | `/api/v1/identity` | 7 | Canonical identity, alias resolution |
| `intelligent_engine_routes.py` | `/api/v1/intelligent-engine` | 11 | Multi-LLM consensus, MindsDB |
| `llm_monitor_router.py` | `/api/v1/llm-monitor` | 4 | LLM prompt monitoring, patterns |
| `llm_router.py` | `/api/v1/llm` | 6 | LLM provider status, settings |
| `mindsdb_router.py` | `/api/v1/ml` | 14 | MindsDB models, train, predict |
| `nerve_center.py` | `/api/v1/nerve-center` | 8 | Real-time pulse, intelligence map |
| `pipeline_router.py` | `/api/v1/pipeline` | 6 | Brain Pipeline execution, evidence packs |
| `predictions_router.py` | `/api/v1/predictions` | 8 | Attack chain, risk trajectory, Bayesian |
| `streaming_router.py` | `/api/v1/streaming` | 2 | SSE pipeline events |

### suite-attack Routers (13 routers)

| Router File | Prefix | Endpoints | Domain |
|-------------|--------|-----------|--------|
| `mpte_router.py` | `/api/v1/mpte` | 20 | MPTE requests, configs, verify, monitoring |
| `micro_pentest_router.py` | `/api/v1/micro-pentest` | 18 | Pentest start/status/verify, reports |
| `pentagi_router.py` | `/api/v1/pentagi` | 8 | PentAGI threat-intel, simulate, remediation |
| `vuln_discovery_router.py` | `/api/v1/vuln-discovery` | 12 | Discovered vulns, contribute, train |
| `attack_sim_router.py` | `/api/v1/attack-simulation` | 14 | Scenarios, campaigns, MITRE heatmap |
| `secrets_router.py` | `/api/v1/secrets` | 8 | Secrets scanning, resolve |
| `sast_router.py` | `/api/v1/sast` | 4 | Static analysis scanning |
| `dast_router.py` | `/api/v1/dast` | 2 | Dynamic analysis scanning |
| `container_router.py` | `/api/v1/container` | 3 | Dockerfile/image scanning |
| `cspm_router.py` | `/api/v1/cspm` | 4 | Cloud security posture |
| `api_fuzzer_router.py` | `/api/v1/api-fuzzer` | 3 | API endpoint fuzzing |
| `malware_router.py` | `/api/v1/malware` | 4 | Malware content scanning |

### suite-feeds Router (1 router)

| Router File | Prefix | Endpoints | Domain |
|-------------|--------|-----------|--------|
| `feeds_router.py` | `/api/v1/feeds` | 30 | EPSS, KEV, NVD, ExploitDB, OSV, GitHub, enrichment, scheduler |

### suite-evidence-risk Routers (6 routers)

| Router File | Prefix | Endpoints | Domain |
|-------------|--------|-----------|--------|
| `evidence_router.py` | `/api/v1/evidence` | 5 | Evidence stats, list, bundles, verify |
| `risk_router.py` | `/api/v1/risk` | 3 | Risk by component, by CVE |
| `graph_router.py` | `/api/v1/graph` | 4 | Lineage, KEV components, anomalies |
| `provenance_router.py` | `/api/v1/provenance` | 2 | Provenance list, by artifact |
| `business_context.py` | `/api/v1/business-context` | 3 | Jira/Confluence context enrichment |
| `business_context_enhanced.py` | `/api/v1/business-context-enhanced` | 4 | Upload, validate business context |

### suite-integrations Routers (6 routers)

| Router File | Prefix | Endpoints | Domain |
|-------------|--------|-----------|--------|
| `integrations_router.py` | `/api/v1/integrations` | 8 | Integration CRUD, test, sync |
| `webhooks_router.py` | `/api/v1/webhooks` | 18 | Webhooks, drift, outbox, ALM work-items |
| `iac_router.py` | `/api/v1/iac` | 8 | IaC findings, remediate, scanners |
| `ide_router.py` | `/api/v1/ide` | 5 | IDE plugin status, analyze, SARIF |
| `mcp_router.py` | `/api/v1/mcp` | 11 | MCP clients, tools, resources, prompts |
| `oss_tools.py` | `/api/v1/oss` | 9 | Trivy/Grype scan, Sigstore verify, OPA |

---

## 5. Key Business Logic Modules (suite-core)

### Core Engine (`suite-core/core/`)

| Module | Purpose |
|--------|---------|
| `knowledge_brain.py` | Central Knowledge Graph (SQLite + NetworkX). All entities: CVE, CWE, CPE, Asset, Finding |
| `brain_pipeline.py` | 12-step Brain Pipeline orchestrator (see §7) |
| `configuration.py` | Overlay config loading (YAML/JSON), env var resolution, data directory setup |
| `enhanced_decision.py` | Multi-signal decision engine (EPSS + KEV + CVSS + exploit signals) |
| `llm_providers.py` | OpenAI, Anthropic Claude, Google Gemini provider abstraction |
| `event_bus.py` | In-process event bus for cross-module communication |
| `storage.py` | ArtefactArchive — stores pipeline outputs, SBOM, evidence bundles |
| `exposure_case.py` | Exposure Case lifecycle (open → triaging → decided → remediated → closed) |
| `micro_pentest.py` | Micro-penetration testing engine |
| `mpte_advanced.py` | Advanced MPTE (Micro-Pentest Testing Engine) with multi-stage verification |
| `attack_simulation_engine.py` | Attack campaign simulation, MITRE ATT&CK mapping |
| `autofix_engine.py` | Automated fix generation and application |
| `playbook_runner.py` | YAML playbook execution engine |
| `policy.py` / `decision_policy.py` | Policy evaluation and enforcement |
| `analytics.py` / `analytics_db.py` | Analytics storage, dashboard metrics |
| `feedback.py` | User feedback recording |
| `sast_engine.py` / `dast_engine.py` | Static/dynamic analysis engines |
| `secrets_scanner.py` | Secrets detection in code |
| `container_scanner.py` | Container image scanning |
| `cspm_engine.py` | Cloud Security Posture Management |
| `api_fuzzer.py` | API endpoint fuzzing engine |
| `malware_detector.py` | Malware content analysis |
| `monte_carlo.py` / `causal_inference.py` | Probabilistic risk analysis |
| `attack_graph_gnn.py` | Graph Neural Network for attack path analysis |

### Services (`suite-core/core/services/`)

| Service | Purpose |
|---------|---------|
| `enterprise/knowledge_graph.py` | Enterprise Knowledge Graph service |
| `enterprise/decision_engine.py` | Enterprise decision engine |
| `enterprise/feeds_service.py` | Feed integration service |
| `enterprise/marketplace.py` | Content marketplace |
| `enterprise/compliance_engine.py` | Compliance checking |
| `enterprise/evidence_lake.py` | Evidence data lake |
| `enterprise/risk_scorer.py` | Risk scoring engine |
| `enterprise/sbom_parser.py` | SBOM parsing and normalization |
| `enterprise/vex_ingestion.py` | VEX document ingestion |
| `collaboration.py` | Comments, watchers, team collaboration |
| `deduplication.py` | Finding deduplication and clustering |
| `fuzzy_identity.py` | Fuzzy matching for CVE/asset identity resolution |
| `remediation.py` | Remediation task management |

### Agents (`suite-core/agents/`)

| Agent | Purpose |
|-------|---------|
| `core/agent_framework.py` | Base agent framework |
| `core/agent_orchestrator.py` | Multi-agent orchestration |
| `language/{python,java,javascript,go}_agent.py` | Language-specific vulnerability agents |
| `design_time/code_repo_agent.py` | Design-time code analysis agent |
| `runtime/container_agent.py` | Runtime container security agent |
| `mindsdb_agents.py` | MindsDB ML model agents |

### CLI (`suite-core/cli/`)

| CLI Tool | Command | Purpose |
|----------|---------|---------|
| `aldeci.py` | `aldeci` | Main CLI entry point |
| `fixops_ci.py` | `fixops-ci` | CI/CD pipeline integration |
| `fixops_provenance.py` | `fixops-provenance` | Provenance attestation |
| `fixops_repro.py` | `fixops-repro` | Reproducibility verification |
| `fixops_risk.py` | `fixops-risk` | Risk assessment CLI |
| `fixops_sbom.py` | `fixops-sbom` | SBOM generation CLI |

---

## 6. Frontend (suite-ui)

| Tech | Version |
|------|---------|
| React | 18.2 |
| TypeScript | 5.3 |
| Vite | 5.0.11 |
| Tailwind CSS | 3.4.1 |
| shadcn/ui | Copy/paste components (NOT a npm library) |
| Radix UI | 18 primitives |
| Zustand | 4.4.7 (state management) |
| react-router-dom | 6.21.2 |

**Location**: `suite-ui/aldeci/` — 4,118 TS/TSX files, 56 screens, 87 routes
**Dev server**: `cd suite-ui/aldeci && npm run dev` → port **3001**
**API proxy**: Vite proxies `/api/*`, `/health`, `/evidence`, `/graph`, `/inputs` → `http://localhost:8000`

### UI Pages (10 main + 46 sub-pages)

| Category | Route Prefix | Pages |
|----------|-------------|-------|
| **Dashboard** | `/`, `/dashboard` | Dashboard (main landing) |
| **Core** | `/nerve-center`, `/core/*` | NerveCenter, KnowledgeGraphExplorer, BrainPipelineDashboard, ExposureCaseCenter |
| **Data Fabric** | `/ingest` | DataFabric (file upload + ingestion) |
| **Intelligence** | `/intelligence`, `/feeds/*` | IntelligenceHub, LiveFeedDashboard |
| **Decisions** | `/decisions`, `/ai-engine/*` | DecisionEngine, MultiLLMPage, AlgorithmicLab, Predictions, Policies, MLDashboard |
| **Attack Lab** | `/attack/*` | AttackSimulation, AttackPaths, MPTEConsole, MicroPentest, Reachability |
| **Code Security** | `/code/*` | CodeScanning, SecretsDetection, IaCScanning, SBOMGeneration, Inventory |
| **Cloud Security** | `/cloud/*` | CloudPosture, ContainerSecurity, RuntimeProtection, ThreatFeeds, CorrelationEngine |
| **Protect** | `/protect/*` | Remediation, Playbooks, PlaybookEditor, BulkOperations, Workflows, Collaboration, Integrations, AutoFixDashboard |
| **Evidence** | `/evidence/*` | ComplianceReports, EvidenceBundles, AuditLogs, Reports, SLSAProvenance, EvidenceAnalytics, SOC2EvidenceUI |
| **Settings** | `/settings/*` | Users, Teams, IntegrationsSettings, Marketplace, SystemHealth, Webhooks, OverlayConfig, LogViewer |
| **Copilot** | `/copilot` | Copilot (AI assistant chat) |

---

## 7. Brain Pipeline — 12-Step Data Flow

The Brain Pipeline (`suite-core/core/brain_pipeline.py`) orchestrates the full vulnerability triage flow:

```
Step 1:  Connect Everything      → Normalize inputs (SBOM, SARIF, CVE, VEX)
Step 2:  Common Language          → Translate to UnifiedFinding model
Step 3:  Fix Identity Confusion   → Fuzzy matching (deduplicate CVEs, assets)
Step 4:  Exposure Cases           → Collapse findings into exposure cases
Step 5:  Build Brain Map          → Knowledge Graph (nodes + edges)
Step 6:  Threat Reality Signals   → Enrich with EPSS, KEV, CVSS scores
Step 7:  Smart Algorithms         → GNN attack paths, Monte Carlo simulation
Step 8:  Policy Decisions         → Automated policy evaluation
Step 9:  Multi-LLM Consensus     → OpenAI + Claude + Gemini vote
Step 10: MicroPenTest            → Prove exploitability (MPTE engine)
Step 11: Playbook Remediation    → Auto-trigger remediation playbooks
Step 12: SOC2 Evidence Pack      → Generate compliance evidence bundles
```

---

## 8. How to Run Locally

### Backend (API Server)

```bash
cd /path/to/Fixops
export PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations"
export FIXOPS_MODE=demo              # or "enterprise"
export FIXOPS_API_TOKEN=demo-token-12345
uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend (Vite Dev Server)

```bash
cd suite-ui/aldeci
npm install        # first time only
npm run dev        # → http://localhost:3001
```

The Vite config proxies `/api/*`, `/health`, `/evidence`, `/graph`, `/inputs` → `http://localhost:8000`.

### Full Stack (Quick)

```bash
# Terminal 1 — Backend
PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations" \
FIXOPS_MODE=demo FIXOPS_API_TOKEN=demo-token-12345 \
uvicorn apps.api.app:app --host 0.0.0.0 --port 8000

# Terminal 2 — Frontend
cd suite-ui/aldeci && npm run dev
```

Open http://localhost:3001 in browser.

---

## 9. Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_MODE` | `enterprise` | Operating mode: `demo` or `enterprise` |
| `FIXOPS_API_TOKEN` | `demo-token-12345` | API authentication token (for `strategy: token`) |
| `FIXOPS_JWT_SECRET` | auto-generated | JWT signing secret (**required in enterprise mode**) |
| `FIXOPS_JWT_EXP_MINUTES` | `120` | JWT token expiry in minutes |
| `FIXOPS_DATA_DIR` | `.fixops_data` | Base directory for persistent data files |
| `FIXOPS_ALLOWED_ORIGINS` | localhost:3000/3001/5173/8000 | CORS allowed origins (comma-separated) |
| `FIXOPS_VERSION` | `0.1.0` | Version reported by `/api/v1/status` |
| `FIXOPS_DISABLE_TELEMETRY` | _(unset)_ | Set to `1` to disable OpenTelemetry |
| `FIXOPS_FAIL_FAST` | _(unset)_ | Set to `1` to make router import failures fatal |
| `FIXOPS_SKIP_PATH_SECURITY` | _(unset)_ | Set to `1` to skip path allow-list checks (CI only) |
| `FIXOPS_EVIDENCE_KEY` | _(unset)_ | Encryption key for evidence bundles |
| `OPENAI_API_KEY` / `FIXOPS_OPENAI_KEY` | _(unset)_ | OpenAI GPT-4 API key |
| `ANTHROPIC_API_KEY` / `FIXOPS_ANTHROPIC_KEY` | _(unset)_ | Anthropic Claude API key |
| `GOOGLE_API_KEY` / `FIXOPS_GEMINI_KEY` | _(unset)_ | Google Gemini API key |

---

## 10. Docker

**Dockerfile**: `docker/Dockerfile` (multi-stage build, Python 3.11-slim)
**Entrypoint**: `scripts/docker-entrypoint.sh`
**Default CMD**: `api-only` → runs `uvicorn apps.api.app:app --host 0.0.0.0 --port 8000`

### Build & Run

```bash
docker build -f docker/Dockerfile -t aldeci .
docker run -p 8000:8000 -e FIXOPS_API_TOKEN=my-key aldeci             # API only
docker run -it -p 8000:8000 aldeci demo                               # Demo mode
docker run -it -p 8000:8000 aldeci interactive                        # Interactive tester
```

### What the Dockerfile Copies

Only `suite-*` directories + `scripts/`, `docs/`, `tests/`, root `*.py`, `*.txt`, `*.yml`, `*.yaml`.
**No legacy directories**. PYTHONPATH is set to all 6 suite dirs inside the image.

### Health Check

`curl -f http://localhost:8000/health` — polls every 30s, 10s timeout, 3 retries.

---

## 11. CI/CD Workflows

| Workflow | File | Triggers | Status |
|----------|------|----------|--------|
| **CI** | `ci.yml` | Push to demo branch, all PRs | ✅ Active — lint, format, pytest, diff-cover |
| **QA** | `qa.yml` | Push to main/demo, all PRs | ✅ Active — mypy, extended tests |
| **Docker Build** | `docker-build.yml` | Push to demo/main, all PRs | ✅ Active — build image, smoke test |
| **FixOps CI** | `fixops-ci.yml` | Push to demo/main, all PRs | ✅ Active — compile check, API smoke |
| **CodeQL** | `codeql.yml` | Push, PRs, weekly cron | ✅ Active — security scanning |
| Provenance | `provenance.yml` | Tags | ⚠️ References removed `cli/` dir |
| Release Sign | `release-sign.yml` | Tags | ⚠️ References removed `cli/` dir |
| Repro Verify | `repro-verify.yml` | Tags | ⚠️ References removed `cli/` dir |
| FixOps Pipeline | `fixops_pipeline.yml` | Manual | ⚠️ References `fixops.cli` module |

**⚠️ Workflows marked with ⚠️ need updating** — they reference legacy `cli/` and `fixops/` directories that were moved to `clutter-legacy` branch.

All active CI sets `PYTHONPATH: suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations:.`

---

## 12. Testing

- **Framework**: pytest (with pytest-asyncio, pytest-cov)
- **Config**: `pyproject.toml` — testpaths=`["tests"]`, markers for unit/integration/e2e/security/slow
- **Test files**: 239 `.py` files across `tests/`
- **Coverage targets**: 18% baseline (CI), 100% on new code (diff-cover vs main)

### Test Organization

```
tests/
├── test_*.py              # ~180 standalone test files (unit + integration)
├── e2e/                   # End-to-end tests (API golden path, CLI, branding, flags)
├── e2e_real_data/         # E2E with real fixtures (edge cases, CLI commands, external services)
├── fixtures/              # Test fixtures (SBOM, SARIF, design context samples)
├── harness/               # Test harness (server manager, CLI runner, fixture manager)
├── load/                  # Load testing (locustfile.py)
├── risk/                  # Risk-specific tests (enrichment, forecasting, license, secrets)
├── sidecar/               # Sidecar smoke tests
├── APP{1,2,3,4}/          # Per-app test suites (authz, contracts, idempotency, perf)
├── conftest.py            # Shared fixtures and configuration
└── sample_modules.py      # Sample module helpers
```

### Running Tests

```bash
# Full suite
PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations" \
pytest tests/ -v

# Specific markers
pytest -m "unit" tests/
pytest -m "e2e" tests/
pytest -m "security" tests/

# Single file
pytest tests/test_health_endpoints.py -v

# With coverage
pytest --cov=core --cov=apps --cov-report=term-missing tests/
```

---

## 13. Repository Structure

```
Fixops/
├── suite-api/                   # FastAPI app + 17 REST routers (41 .py)
│   └── apps/api/                # All router files + app.py entry point
├── suite-core/                  # Business logic, CLI, KG Brain (322 .py)
│   ├── core/                    # Engine, config, analytics, KG, pipeline, LLM
│   │   ├── services/enterprise/ # Enterprise services (KG, decisions, feeds, marketplace)
│   │   └── stages/              # Pipeline stages (normalise, deduplicate, enrich, decide...)
│   ├── agents/                  # AI agent framework + language/design/runtime agents
│   ├── cli/                     # CLI tools (aldeci, fixops-ci, fixops-provenance, etc.)
│   └── api/                     # 18 REST routers (brain, copilot, agents, pipeline, etc.)
├── suite-attack/                # MPTE, micro-pentest, simulations (13 .py)
│   └── api/                     # 12 attack routers (mpte, dast, sast, container, etc.)
├── suite-feeds/                 # Vulnerability feed ingestors (3 .py)
│   └── api/                     # 1 feeds router (30 endpoints)
├── suite-evidence-risk/         # Evidence bundler, risk scoring (69 .py)
│   ├── evidence/                # Evidence packaging, signing, compliance
│   ├── risk/                    # Risk scoring, adjustment, reachability
│   └── api/                     # 6 routers (evidence, risk, graph, provenance, business-context)
├── suite-integrations/          # Webhooks, IaC, IDE, MCP, OSS tools (23 .py)
│   ├── integrations/            # Integration connectors
│   ├── lib4sbom/                # SBOM normalization library
│   └── api/                     # 6 routers (integrations, webhooks, iac, ide, mcp, oss)
├── suite-ui/                    # React frontend (4,118 ts/tsx)
│   └── aldeci/                  # Vite project root
│       ├── src/pages/           # 56 page components
│       ├── src/components/      # Shared UI components
│       ├── src/services/        # API client functions
│       └── src/stores/          # Zustand state stores
├── tests/                       # pytest tests (239 .py files)
├── scripts/                     # Utility scripts, docker-entrypoint.sh
├── docker/                      # Dockerfile (multi-stage, suite architecture)
├── docs/                        # Documentation + JSON schemas
├── .github/                     # CI workflows + CodeQL config
├── pyproject.toml               # Python config (black, isort, pytest)
├── requirements.txt             # Python dependencies
├── requirements-test.txt        # Test-only dependencies
├── Makefile                     # Build shortcuts
├── sitecustomize.py             # Python startup hook
├── usercustomize.py             # Python user startup hook
├── docker-compose.demo.yml      # Docker Compose for demo
├── DEVIN_CONTEXT.md             # This file
└── DEVIN_CONTEXT_backup.md      # Previous version backup
```

---

## 14. Inter-Suite Dependency Map

```
suite-api (entry point)
├── imports from → suite-core/api/*.py      (18 routers)
├── imports from → suite-attack/api/*.py    (12 routers)
├── imports from → suite-feeds/api/*.py     (1 router)
├── imports from → suite-evidence-risk/api/*.py (6 routers)
├── imports from → suite-integrations/api/*.py  (6 routers)
└── imports from → suite-core/core/*.py     (business logic: config, analytics, storage, engine)

suite-core (business logic)
├── standalone — no imports from other suites
└── provides → knowledge_brain, brain_pipeline, llm_providers, configuration, event_bus

suite-attack → imports from suite-core/core/ (KG brain, LLM providers)
suite-feeds → imports from suite-core/core/ (configuration, event_bus)
suite-evidence-risk → imports from suite-core/core/ (configuration, storage)
suite-integrations → standalone (lib4sbom is self-contained)
```

**Key rule**: `suite-core` is the shared dependency. Other suites may import from `suite-core/core/` but NEVER from each other or from `suite-api`.

---

## 15. Database Files & Storage

ALdeci uses **file-based storage** (no external database required):

| Store | Default Location | Format |
|-------|-----------------|--------|
| Knowledge Graph | `data/analysis/knowledge_brain.db` | SQLite + NetworkX |
| Analytics | `data/analytics/{mode}/` | JSON files |
| Artifacts | `data/artifacts/` | JSON, SARIF, SBOM files |
| Evidence Bundles | `data/evidence/bundles/` | Signed ZIP bundles |
| Evidence Manifests | `data/evidence/manifests/` | JSON manifests |
| Provenance | `data/artifacts/attestations/{mode}/` | In-toto attestations |
| Uploads | `data/uploads/{mode}/` | Chunked upload staging |
| SBOM | `data/artifacts/sbom/` | CycloneDX/SPDX JSON |
| JWT Secrets | `.fixops_data/.jwt_secret` | Auto-generated key file |
| Pipeline Results | In-memory (`app.state.last_pipeline_result`) | Dict |

All paths are configurable via overlay config YAML or `FIXOPS_DATA_DIR` env var. All file operations go through `verify_allowlisted_path()` for security.

**⚠️ Never commit `.db` files or `data/` contents** — they are in `.gitignore`.

---

## 16. Cleanup History

The repository was restructured from a legacy monolith to 6-suite architecture. **549+ stale files** from 22 legacy directories were removed and preserved in the `clutter-legacy` branch.

### Removed Directories (preserved in `clutter-legacy` branch)

`agents/`, `apps/`, `backend/`, `cli/`, `config/`, `core/`, `domain/`, `evidence/`, `fixops-enterprise/`, `fixops/`, `integrations/`, `lib4sbom/`, `new_apps/`, `new_backend/`, `risk/`, `samples/`, `services/`, `simulations/`, `telemetry/`, `archive/`, `archive_not_needed/`, `suite-ui1/`, `data/`

### Why the Cleanup

The `docker/Dockerfile` previously had hardcoded `COPY` for 18+ legacy root directories. These were OLD monolith code — completely different from active `suite-*` code (`apps/api/app.py` vs `suite-api/apps/api/app.py` had **846 diff lines**). The fix: rewrite Dockerfile to use suite architecture, remove stale code.

### Devin's Fixes Ported to Suite Versions

1. **Collision detection** in `suite-evidence-risk/evidence/packager.py` — duplicate filename handling
2. **Metadata guard** in `suite-integrations/lib4sbom/normalizer.py` — `(doc.get("metadata") or {}).get("tools")`

---

## 17. Enterprise Mode & Authentication

### Mode Configuration

```bash
# Enterprise mode (production/client demos)
export FIXOPS_MODE=enterprise
export FIXOPS_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export FIXOPS_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export FIXOPS_DEMO_MODE=false
```

### Key Settings

| Variable | Purpose | Default |
|---|---|---|
| `FIXOPS_MODE` | Runtime mode | `enterprise` |
| `FIXOPS_JWT_SECRET` | JWT signing key | **Required** (no default) |
| `FIXOPS_API_TOKEN` | API authentication token | **Required** (no default) |
| `FIXOPS_DEMO_MODE` | Enable simulated data | `false` |

### Authentication Flow

All API calls require the `X-API-Key` header:
```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/api/v1/feeds/health
```

### Critical: No Demo Defaults

- `DEMO_MODE` defaults to `false` in `suite-core/config/enterprise/settings.py`
- No `demo-token` fallbacks anywhere in the codebase
- All scripts require `FIXOPS_API_TOKEN` environment variable
- Zero `[DEMO]` prefixes, zero `demo_data` flags in API responses

---

## 18. CTEM Loop — 5-Stage Flow

ALdeci implements the full **Continuous Threat Exposure Management** (CTEM) loop:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CTEM LOOP (5 Stages)                         │
│                                                                 │
│  ┌─────────┐   ┌──────────┐   ┌────────────┐   ┌──────────┐  │
│  │ 1.SCOPE │──▶│2.DISCOVER│──▶│3.PRIORITIZE│──▶│4.VALIDATE│  │
│  └─────────┘   └──────────┘   └────────────┘   └──────────┘  │
│       ▲                                              │         │
│       │         ┌──────────┐                         │         │
│       └─────────│5.MOBILIZE│◀────────────────────────┘         │
│                 └──────────┘                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Stage → API Endpoint Mapping

| Stage | Endpoints | Status |
|---|---|---|
| **1. SCOPE** | `/api/v1/brain/health`, `/api/v1/business-context/*`, `/api/v1/copilot/agents/status` | ✅ 4/4 |
| **2. DISCOVER** | `/api/v1/feeds/*`, `/api/v1/vulns/*`, `/api/v1/feeds/exploit-confidence/*` | ✅ 7/8 |
| **3. PRIORITIZE** | `/api/v1/decisions/*`, `/api/v1/brain/stats`, `/api/v1/audit/compliance/*`, `/api/v1/ml/*` | ✅ 6/8 |
| **4. VALIDATE** | `/api/v1/micro-pentest/*`, `/api/v1/pentagi/*`, `/api/v1/attack-sim/*`, `/api/v1/reachability/*`, `/api/v1/dast/*`, `/api/v1/brain/evidence/*` | ✅ 7/7 |
| **5. MOBILIZE** | `/api/v1/autofix/*`, `/api/v1/integrations`, `/api/v1/marketplace/*`, `/api/v1/reports`, `/api/v1/copilot/agents/*`, `/api/v1/llm/*` | ✅ 7/8 |

**Total: 31/35 endpoints working across all 5 CTEM stages (88.6%)**

---

## 19. Testing & Validation Scripts

### Interactive Enterprise Testing

```bash
# Start server
export FIXOPS_MODE=enterprise FIXOPS_JWT_SECRET="your-secret" FIXOPS_API_TOKEN="your-token"
uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --workers 2

# Run interactive testing script (menu-driven, all 5 CTEM stages)
bash scripts/fixops-enterprise-test.sh
```

### Automated Smoke Test

```bash
# 47 endpoints, 100% pass rate
export FIXOPS_API_TOKEN="your-token" FIXOPS_API_URL=http://localhost:8000
python3 scripts/_enterprise_smoke.py
```

### Docker Enterprise Mode

```bash
docker run -it -e FIXOPS_MODE=enterprise -p 8000:8000 devopsaico/fixops:latest enterprise
```

### Script Inventory

| Script | Purpose | Type |
|---|---|---|
| `scripts/fixops-enterprise-test.sh` | Interactive CTEM testing (688 lines) | Bash, interactive |
| `scripts/_enterprise_smoke.py` | Automated 47-endpoint smoke test | Python, automated |
| `scripts/docker-entrypoint.sh` | Docker entrypoint with enterprise mode | Bash |
| `scripts/_smoke_test.sh` | Quick bash smoke test | Bash, automated |

---

## 20. Guidelines for AI Agents & Developers

1. **ONLY edit files under `suite-*/`** — that's the active codebase
2. **Never add `__init__.py`** to any `api/` directory (breaks namespace packages across suites)
3. **Always set PYTHONPATH** to include all 6 suite dirs when running Python
4. **Router imports in `app.py`** use try/except — if a suite router fails to import, the app still starts (graceful degradation)
5. **Adding a new endpoint**: Create router in the appropriate `suite-*/api/` dir, then import + mount in `suite-api/apps/api/app.py`
6. **Adding a new feed**: Add to `suite-feeds/api/feeds_router.py` or create a new file in `suite-feeds/`
7. **Dockerfile** at `docker/Dockerfile` copies only `suite-*` dirs — no legacy code
8. **Legacy code** preserved in `clutter-legacy` branch for reference only
9. **Database files** (`.db`) are gitignored — never commit them
10. **Python version**: 3.11+ | **Node.js**: 18+
11. **Frontend components**: shadcn/ui are copy/paste components, NOT an npm-installed library
12. **Configuration**: Use `suite-core/core/configuration.py` `load_overlay()` — supports YAML overlays + env vars
13. **LLM providers**: Use `suite-core/core/llm_providers.py` — supports OpenAI, Anthropic, Google with fallback
14. **Enterprise mode**: Always use `FIXOPS_MODE=enterprise` — never demo mode for client-facing work
15. **Authentication**: All API calls need `X-API-Key` header — generate with `secrets.token_urlsafe(48)`
16. **Cross-reference**: See [API_REFERENCE.md](docs/API_REFERENCE.md), [SUITE_ARCHITECTURE.md](docs/SUITE_ARCHITECTURE.md), [DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md), [CLIENT_DEMO_GUIDE.md](docs/CLIENT_DEMO_GUIDE.md)
