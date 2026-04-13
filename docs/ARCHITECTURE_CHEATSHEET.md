# ALDECI Architecture Cheatsheet
> Branch: `features/intermediate-stage` | Stack: FastAPI + React 19 + SQLite + TrustGraph

---

## Module Map (suite-core/core/)

| Module | Description | Key Classes | LOC |
|--------|-------------|-------------|-----|
| `brain_pipeline.py` | Central AI pipeline — ingests findings, runs LLM council, emits verdicts | `BrainPipeline`, `PipelineInput`, `PipelineResult`, `FPFeedbackStore` | 4353 |
| `connectors.py` | 7 bidirectional connectors (Jira, Slack, ServiceNow, GitHub, GitLab, Confluence, AzureDevOps) | `_BaseConnector`, `JiraConnector`, `SlackConnector`, `AutomationConnectors`, `CircuitBreaker` | 3620 |
| `scanner_parsers.py` | 32 scanner normalizers — converts raw scanner output to canonical findings | `ZAPNormalizer`, `NessusNormalizer`, `SonarQubeNormalizer`, `SARIFUniversalNormalizer`, `TrivyScannerNormalizer` | 2395 |
| `security_connectors.py` | 13 PULL connectors — polls external security tools | `SnykConnector`, `AWSSecurityHubConnector`, `WizConnector`, `PrismaCloudConnector`, `DependencyTrackConnector` | 1934 |
| `pipeline_orchestrator.py` | Orchestrates multi-stage pipeline execution with event emission and analytics | `PipelineOrchestrator`, `PipelineEventEmitter`, `PipelineAnalyticsEngine`, `StageResult` | 914 |
| `trustgraph_indexer.py` | Indexes codebase entities into TrustGraph 5 Knowledge Cores | `TrustGraphIndexer` | 650 |
| `rbac.py` | Role-based access control — 6 roles, 30 persona mappings | `RBACEngine`, `BuiltinRoles`, `PersonaRoleMapping`, `Permission`, `Role` | 832 |
| `workflow_engine.py` | Event-driven workflow automation with conditions and actions | `WorkflowEngine`, `Workflow`, `WorkflowExecution`, `WorkflowAction` | 874 |
| `playbook_engine.py` | Security playbook runner — step-by-step automated response | `PlaybookEngine`, `Playbook`, `PlaybookRun`, `PlaybookStep` | 1006 |
| `analytics_engine.py` | Per-persona dashboard metrics and time-windowed aggregations | `AnalyticsEngine`, `PersonaDashboard`, `DashboardMetric`, `PersonaDashboardData` | 804 |
| `copilot_graphrag.py` | AI security copilot with GraphRAG semantic search | (see TrustGraph wiring) | — |
| `council_pipeline_adapter.py` | Bridges LLM Council (4 models + Opus escalation) to brain_pipeline | (adapter layer) | — |
| `policy_engine.py` | OPA-backed policy evaluation for findings and access | `_HttpOPAEngine` (via brain_pipeline) | — |
| `report_builder.py` | Generates compliance and executive reports | (see report_db) | — |
| `sast_engine.py` | Static analysis orchestration | — | — |
| `sbom_manager.py` | SBOM ingestion and runtime correlation | — | — |
| `threat_hunting.py` | Threat hunting queries and hypothesis tracking | — | — |
| `vuln_prioritizer.py` | CVSS + business context risk scoring | — | — |

---

## API Route Map (suite-api/apps/api/)

All routes require `Authorization: Bearer <FIXOPS_API_TOKEN>` unless marked public.

| Router File | Prefix | Auth | Key Endpoints |
|-------------|--------|------|---------------|
| `findings_routes.py` | `/api/v1/findings` | yes | `GET /`, `GET /{id}`, `PUT /{id}/status`, `PUT /{id}/assign`, `POST /bulk/status`, `GET /summary`, `GET /sla`, `POST /export` |
| `brain_router.py` | `/api/v1/brain` | yes (`read:findings`) | pipeline run, verdict fetch, feedback submission |
| `connectors_router.py` | `/api/v1/connectors` | yes | list, test, sync connectors |
| `trustgraph_routes.py` | `/api/v1/trustgraph` | yes | query, index, search knowledge graph |
| `pipeline_routes.py` | `/api/v1/pipeline` | yes | trigger pipeline, get status, list runs |
| `analytics_router.py` | `/api/v1/analytics` | yes (`read:findings`) | dashboard metrics, persona views |
| `reports_router.py` | `/api/v1/reports` | yes (`read:evidence`) | generate, list, download reports |
| `auth_router.py` | `/api/v1/auth` | public (issues tokens) | login, refresh, logout |
| `users_router.py` | `/api/v1/users` | yes | CRUD users, roles, persona assignment |
| `admin_router.py` | `/api/v1/admin` | yes (admin scope) | system config, tenant management |
| `feeds_router.py` | `/api/v1/feeds` | yes (`read:feeds`) | list feeds, refresh, status |
| `sbom_router.py` | `/api/v1/sbom` | yes | upload SBOM, query components |
| `playbook_routes.py` | `/api/v1/playbooks` | yes | run, list, edit playbooks |
| `workflow_engine_router.py` | `/api/v1/workflows` | yes | create, trigger, list workflows |
| `incident_response_router.py` | `/api/v1/incidents` | yes | open, update, close incidents |
| `copilot_router.py` | `/api/v1/copilot` | yes | ask, search, summarize |
| `health.py` | `/api/v1/health` | public | `GET /health`, `GET /ready` |

> 771 total endpoints across 64 router files. OpenAPI: `GET /docs` or `GET /openapi.json`

---

## Data Flow

```
Scanner Output (ZAP, Nessus, Snyk, etc.)
        |
        v
scanner_parsers.py  [32 normalizers]
  - Converts raw XML/JSON to canonical FindingSchema
        |
        v
pipeline_orchestrator.py  [PipelineOrchestrator]
  - Stage 1: Deduplication  (fixops_dedup.db)
  - Stage 2: Enrichment     (vuln_intelligence, threat feeds)
  - Stage 3: LLM Council    (4 free models + Opus escalation)
  - Stage 4: Risk Scoring   (CVSS + business context)
        |
        v
brain_pipeline.py  [BrainPipeline]
  - Applies policy (OPA)
  - Emits verdict + confidence
  - Writes to findings.db
        |
        v
trustgraph_indexer.py  [TrustGraphIndexer]
  - Indexes finding entity into TrustGraph Knowledge Core
  - Enables GraphRAG semantic search
        |
        v
analytics_engine.py  [PersonaDashboard]
  - Aggregates metrics per persona/role
        |
        v
Dashboard (React 19)
  - CISODashboard: /mission-control/ciso
  - SOCDashboard:  /mission-control/soc
  - FindingsExplorer: /findings
```

---

## Database Map

All SQLite databases live under `FIXOPS_DATA_DIR` (default: `data/`).

| Database | Owner Module | Key Tables / Purpose |
|----------|-------------|----------------------|
| `findings.db` | brain_pipeline, findings_routes | findings, verdicts, comments, timeline |
| `fixops_brain.db` | brain_pipeline_db | pipeline runs, step results, LLM outputs |
| `auth.db` | auth_db | users, sessions, api_keys, roles |
| `audit.db` | audit_db, audit_logger | audit_events, access_log |
| `analytics.db` | analytics_engine, analytics_db | metrics, persona_views, time_series |
| `reports.db` | report_db, report_builder | reports, templates, scheduled_reports |
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

## Frontend Pages (suite-ui/aldeci-ui-new/)

React 19 + Vite 6 + Tailwind v4. Active UI only — `suite-ui/aldeci/` is FROZEN.

| Route | Page Component | Persona | Shows |
|-------|---------------|---------|-------|
| `/mission-control/ciso` | `CISODashboard.tsx` | CISO | Risk posture KPIs, compliance status, top risks |
| `/mission-control/soc` | `SOCDashboard.tsx` | SOC T1/T2 | Alert queue, triage, LLM verdicts, SLA timers |
| `/mission-control/command` | `CommandDashboard.tsx` | SecOps Lead | Live pipeline status, connector health |
| `/mission-control/executive` | `ExecutiveView.tsx` | C-Suite | Board-ready risk summary |
| `/mission-control/risk` | `RiskOverview.tsx` | Risk Manager | Risk heatmap, trending |
| `/mission-control/sla` | `SLADashboard.tsx` | SecOps Lead | SLA breach tracking |
| `/mission-control/live` | `LiveFeed.tsx` | SOC | Real-time finding stream |
| `/findings` | `FindingsExplorer.tsx` | All | Finding list, filters, bulk actions |
| `/discover/findings` | `FindingExplorer.tsx` | Analyst | Deep finding drill-down |
| `/discover/attack-paths` | `AttackPaths.tsx` | Red Team | Attack path graph |
| `/discover/cloud` | `CloudPosture.tsx` | Cloud Sec | CSPM misconfigs |
| `/discover/code` | `CodeScanning.tsx` | Dev Sec | SAST results |
| `/discover/containers` | `ContainerSecurity.tsx` | DevOps | Container vuln scan |
| `/discover/secrets` | `SecretsDetection.tsx` | Dev Sec | Secret leaks |
| `/discover/sbom` | `SBOMInventory.tsx` | Compliance | Component inventory |
| `/discover/threat-feeds` | `ThreatFeeds.tsx` | Threat Intel | 28+ feed status |
| `/discover/knowledge-graph` | `KnowledgeGraph.tsx` | Analyst | TrustGraph visual explorer |
| `/comply/dashboard` | `ComplianceDashboard.tsx` | Compliance | SOC2, ISO27001, CIS, NIST status |
| `/comply/evidence` | `EvidenceVault.tsx` | Auditor | Evidence collection + export |
| `/comply/soc2` | `SOC2Evidence.tsx` | Compliance | SOC2 control mapping |
| `/comply/audit` | `AuditTrail.tsx` | Auditor | Full audit log |
| `/remediate` | `RemediationCenter.tsx` | DevSec | Remediation queue |
| `/remediate/autofix` | `AutoFix.tsx` | Dev | AI-generated fix PRs |
| `/remediate/workflows` | `Workflows.tsx` | SecOps | Workflow automation |
| `/remediate/playbooks` | `Playbooks.tsx` | SOC | Playbook library |
| `/validate/attack-sim` | `AttackSimulation.tsx` | Red Team | Attack simulation runs |
| `/validate/mpte` | `MPTEConsole.tsx` | Red Team | Micro pentest console |
| `/validate/fail` | `FAILEngine.tsx` | Red Team | FAIL scoring engine |
| `/ai/brain` | `BrainPipeline.tsx` | SecOps Lead | Pipeline run inspector |
| `/ai/copilot` | `CopilotDashboard.tsx` | All | AI security copilot chat |
| `/ai/multi-llm` | `MultiLLM.tsx` | Admin | LLM council monitor |
| `/hunting` | `ThreatHunting.tsx` | Threat Intel | Hunt hypothesis manager |
| `/incidents` | `IncidentResponse.tsx` | SOC | Incident lifecycle |
| `/settings` | `SettingsHub.tsx` | Admin | System settings hub |
| `/settings/health` | `SystemHealth.tsx` | Admin | Service health checks |

---

## If X Breaks, Look Here

| Symptom | First Check | File / Fix |
|---------|-------------|------------|
| API won't start | Check router import errors | `suite-api/apps/api/app.py` — comment out failing `include_router` block |
| Dashboard shows no data | Seed script not run or findings.db empty | Run: `python suite-core/core/brain_pipeline.py` with test payload |
| Auth fails / 401 everywhere | `FIXOPS_API_TOKEN` not set or wrong | Set env var; check `suite-api/apps/api/auth_deps.py` |
| LLM council not running | Feature flag off | Set `FIXOPS_FEATURE_COUNCIL=1` and `ANTHROPIC_API_KEY` |
| TrustGraph queries return empty | Index not built | Run: `python -c "from core.trustgraph_indexer import TrustGraphIndexer; TrustGraphIndexer().index_all()"` |
| Scanner findings not normalizing | Normalizer not registered | Check `scanner_parsers.py` — add to normalizer registry dict |
| Connectors not syncing | Circuit breaker tripped or bad creds | Check `connectors.py` `CircuitBreaker` state; verify env vars (e.g., `FIXOPS_JIRA_TOKEN`) |
| Feeds not refreshing | Stale threshold exceeded or feature off | Set `FIXOPS_FEATURE_FEEDS=1`; check `FIXOPS_FEEDS_REFRESH_INTERVAL` |
| RBAC permission denied | Wrong scope on route | Check `rbac.py` `BuiltinRoles`; verify user persona assignment in `auth.db` |
| UI blank / white screen | Vite build stale or API unreachable | `cd suite-ui/aldeci-ui-new && npm run dev`; check `VITE_API_BASE_URL` |
| Tests failing on import | `sitecustomize.py` not loaded | Ensure running pytest from repo root; `sitecustomize.py` auto-injects suite paths |

---

## Key Environment Variables

### Core / Runtime
| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_API_TOKEN` | — | Master API bearer token (required) |
| `FIXOPS_JWT_SECRET` | — | JWT signing secret |
| `FIXOPS_DATA_DIR` | `data/` | SQLite database directory |
| `FIXOPS_MODE` | `production` | `development` disables some checks |
| `FIXOPS_HOST` | `0.0.0.0` | API bind host |
| `ALDECI_PORT` | `8000` | API bind port |
| `FIXOPS_ALLOWED_ORIGINS` | `*` | CORS allowed origins |

### Feature Flags
| Variable | Description |
|----------|-------------|
| `FIXOPS_FEATURE_COUNCIL` | Enable LLM council (`1` to enable) |
| `FIXOPS_FEATURE_TRUSTGRAPH` | Enable TrustGraph GraphRAG |
| `FIXOPS_FEATURE_FEEDS` | Enable 28+ threat intel feeds |
| `FIXOPS_FEATURE_AUTOFIX` | Enable AI auto-fix PR generation |
| `FIXOPS_FEATURE_ATTACK_SIM` | Enable attack simulation |
| `FIXOPS_FEATURE_CSPM` | Enable cloud security posture |
| `FIXOPS_USE_COUNCIL` | Alternative council toggle (legacy) |

### AI / LLM
| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Opus escalation (LLM council) |
| `OPENAI_API_KEY` | GPT-4 council member |
| `FIXOPS_OLLAMA_URL` | Local Ollama endpoint (default: `http://localhost:11434`) |
| `FIXOPS_VLLM_URL` | vLLM endpoint for self-hosted models |
| `FIXOPS_CONSENSUS_THRESHOLD` | Min agreement % for council verdict |

### Integrations
| Variable | Description |
|----------|-------------|
| `FIXOPS_JIRA_URL` | Jira instance URL |
| `FIXOPS_JIRA_USER` | Jira username |
| `FIXOPS_JIRA_TOKEN` | Jira API token |
| `FIXOPS_JIRA_PROJECT` | Default Jira project key |
| `FIXOPS_GITHUB_TOKEN` | GitHub PAT for connector + PR generator |
| `FIXOPS_GITHUB_OWNER` | GitHub org/user |
| `FIXOPS_GITHUB_REPO` | Target repository |
| `FIXOPS_SLACK_TOKEN` | Slack bot token |
| `FIXOPS_OPA_URL` | Open Policy Agent endpoint |
| `FIXOPS_REDIS_URL` | Redis (queue mode) |

### Auth / SSO
| Variable | Description |
|----------|-------------|
| `FIXOPS_OIDC_ISSUER_URL` | OIDC provider (e.g., Okta, Auth0) |
| `FIXOPS_OIDC_CLIENT_ID` | OIDC client ID |
| `FIXOPS_OIDC_CLIENT_SECRET` | OIDC client secret |
| `FIXOPS_JWT_EXP_MINUTES` | Access token expiry (minutes) |
| `FIXOPS_JWT_REFRESH_DAYS` | Refresh token expiry (days) |

---

## Quick Commands

```bash
# Start API (dev)
cd suite-api && uvicorn apps.api.app:create_app --factory --reload --port 8000

# Start UI (dev)
cd suite-ui/aldeci-ui-new && npm run dev

# Run Beast Mode tests (fast, ~709 tests)
python -m pytest tests/test_phase*.py tests/test_connector_framework.py \
  tests/test_trustgraph.py tests/test_pipeline_api.py tests/test_persona_workflows.py \
  -x --tb=short --timeout=10 -q -o "addopts="

# Run single test file
python -m pytest tests/test_phase1_intake.py -x --tb=short -q

# Check API health
curl http://localhost:8000/api/v1/health

# Export OpenAPI spec
curl http://localhost:8000/openapi.json > docs/openapi.json

# Index codebase into TrustGraph
python -c "from core.trustgraph_indexer import TrustGraphIndexer; TrustGraphIndexer().index_all()"

# Check all SQLite DBs exist
ls data/*.db

# Start full stack (Docker)
docker compose -f docker/docker-compose.connectors.yml up -d

# Git auto-save (run every 15-20 min)
git add -A && git commit -m "beast-mode(wip): [description]" && git push origin features/intermediate-stage

# Tail API logs
uvicorn apps.api.app:create_app --factory 2>&1 | tail -f

# Check code graph stats
code-review-graph stats

# Query code graph
code-review-graph query "what calls brain_pipeline.py"
```

---

*Generated 2026-04-12 | Source of truth: `docs/ALDECI_REARCHITECTURE_v2.md`*
