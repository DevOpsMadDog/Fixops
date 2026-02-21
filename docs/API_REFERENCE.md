# ALdeci API Reference

> **Last updated**: 2026-02-19  
> **Base URL**: `http://localhost:8000`  
> **Authentication**: `X-API-Key` header or `?api_key=` query param (strategy: token) OR `Authorization: Bearer <jwt>` (strategy: jwt)  
> **Total endpoints**: 617 across 62 routers + 23 inline (in app.py)
> **See also**: [DEVIN_CONTEXT.md](../DEVIN_CONTEXT.md) · [SUITE_ARCHITECTURE.md](SUITE_ARCHITECTURE.md)

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [Health & Status](#2-health--status)
3. [suite-api Endpoints](#3-suite-api-endpoints)
4. [suite-core Endpoints](#4-suite-core-endpoints)
5. [suite-attack Endpoints](#5-suite-attack-endpoints)
6. [suite-feeds Endpoints](#6-suite-feeds-endpoints)
7. [suite-evidence-risk Endpoints](#7-suite-evidence-risk-endpoints)
8. [suite-integrations Endpoints](#8-suite-integrations-endpoints)
9. [Inline Endpoints (app.py)](#9-inline-endpoints-apppy)
10. [Common Response Patterns](#10-common-response-patterns)
11. [Error Codes](#11-error-codes)

---

## 1. Authentication

All endpoints (except `/health` and `/api/v1/health`) require authentication.

### Token Authentication (default in demo mode)
```
X-API-Key: demo-token-12345
# or
GET /api/v1/some-endpoint?api_key=demo-token-12345
```

### JWT Authentication (enterprise mode)
```
POST /api/v1/users/login
Body: { "username": "admin", "password": "..." }
Response: { "access_token": "eyJ...", "token_type": "bearer" }

# Then use:
Authorization: Bearer eyJ...
```

JWT tokens expire after `FIXOPS_JWT_EXP_MINUTES` (default: 120 minutes).

---

## 2. Health & Status

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Legacy healthcheck (Dockerfile HEALTHCHECK) |
| GET | `/api/v1/health` | No | Health status with mode, DB, feeds |
| GET | `/api/v1/ready` | No | Readiness probe |
| GET | `/api/v1/version` | No | Version info |
| GET | `/api/v1/metrics` | No | Prometheus-style metrics |
| GET | `/api/v1/health/db` | No | Database connectivity check |
| GET | `/api/v1/status` | Yes | Full status with pipeline, mode, version |
| GET | `/api/v1/search?q=` | Yes | Global search across all entities |

---

## 3. suite-api Endpoints

### Analytics (`/api/v1/analytics`) — 22 endpoints
Source: `suite-api/apps/api/analytics_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard/overview` | Dashboard overview stats |
| GET | `/dashboard/trends` | Dashboard trend data |
| GET | `/dashboard/top-risks` | Top risk items |
| GET | `/dashboard/compliance-status` | Compliance status summary |
| GET | `/findings` | List findings (paginated) |
| POST | `/findings` | Create a finding |
| GET | `/findings/{id}` | Get finding by ID |
| PUT | `/findings/{id}` | Update finding |
| GET | `/decisions` | List decisions (paginated) |
| POST | `/decisions` | Create a decision |
| GET | `/mttr` | Mean Time to Remediate metrics |
| GET | `/coverage` | Coverage metrics |
| GET | `/roi` | ROI metrics |
| GET | `/noise-reduction` | Noise reduction metrics |
| POST | `/custom-query` | Execute custom analytics query |
| GET | `/export` | Export analytics data |
| GET | `/stats` | Summary statistics |
| GET | `/summary` | Brief summary |
| GET | `/trends/severity-over-time` | Severity trend over time |
| GET | `/trends/anomalies` | Anomaly detection in trends |
| GET | `/compare` | Compare time periods |
| GET | `/risk-velocity` | Risk velocity metrics |

### Audit (`/api/v1/audit`) — 14 endpoints
Source: `suite-api/apps/api/audit_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/logs` | List audit logs (paginated) |
| GET | `/logs/export` | Export audit logs |
| GET | `/logs/{id}` | Get audit log by ID |
| GET | `/user-activity` | User activity summary |
| GET | `/policy-changes` | Policy change audit trail |
| GET | `/decision-trail` | Decision audit trail |
| GET | `/compliance/frameworks` | List compliance frameworks |
| GET | `/compliance/frameworks/{id}/status` | Framework compliance status |
| GET | `/compliance/frameworks/{id}/gaps` | Framework compliance gaps |
| POST | `/compliance/frameworks/{id}/report` | Generate compliance report |
| GET | `/compliance/controls` | List compliance controls |
| POST | `/logs/chain` | Create audit chain entry |
| GET | `/chain/verify` | Verify audit chain integrity |
| GET | `/retention` | Audit log retention settings |

### Auth (`/api/v1/auth`) — 4 endpoints
Source: `suite-api/apps/api/auth_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/sso` | List SSO configurations |
| POST | `/sso` | Create SSO configuration |
| GET | `/sso/{id}` | Get SSO config by ID |
| PUT | `/sso/{id}` | Update SSO configuration |

### Bulk Operations (`/api/v1/bulk`) — 12 endpoints
Source: `suite-api/apps/api/bulk_router.py`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/clusters/status` | Bulk update cluster status |
| POST | `/clusters/assign` | Bulk assign clusters |
| POST | `/clusters/accept-risk` | Bulk accept risk for clusters |
| POST | `/clusters/create-tickets` | Bulk create tickets for clusters |
| POST | `/export` | Bulk export data |
| GET | `/jobs/{job_id}` | Get bulk job status |
| GET | `/jobs` | List bulk jobs |
| DELETE | `/jobs/{job_id}` | Cancel bulk job |
| POST | `/findings/update` | Bulk update findings |
| POST | `/findings/delete` | Bulk delete findings |
| POST | `/findings/assign` | Bulk assign findings |
| POST | `/policies/apply` | Bulk apply policies |

### Collaboration (`/api/v1/collaboration`) — 21 endpoints
Source: `suite-api/apps/api/collaboration_router.py`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/comments` | Create comment |
| GET | `/comments` | List comments |
| PUT | `/comments/{id}/promote` | Promote comment to decision |
| POST | `/watchers` | Add watcher |
| DELETE | `/watchers` | Remove watcher |
| GET | `/watchers` | List watchers |
| GET | `/watchers/user/{user_id}` | Get user's watched items |
| POST | `/activities` | Log activity |
| GET | `/activities` | List activities |
| GET | `/mentions/{user_id}` | Get user mentions |
| PUT | `/mentions/{id}/acknowledge` | Acknowledge mention |
| GET | `/entity-types` | List entity types |
| GET | `/activity-types` | List activity types |
| POST | `/notifications/queue` | Queue notification |
| POST | `/notifications/notify-watchers` | Notify all watchers |
| GET | `/notifications/pending` | Get pending notifications |
| PUT | `/notifications/{id}/sent` | Mark notification sent |
| GET | `/notifications/preferences/{user_id}` | Get notification preferences |
| PUT | `/notifications/preferences/{user_id}` | Update notification preferences |
| POST | `/notifications/{id}/deliver` | Deliver notification |
| POST | `/notifications/process` | Process pending notifications |

### Inventory (`/api/v1/inventory`) — 19 endpoints
Source: `suite-api/apps/api/inventory_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/assets` | List assets (paginated) |
| GET | `/applications` | List applications |
| POST | `/applications` | Create application |
| GET | `/applications/{id}` | Get application |
| PUT | `/applications/{id}` | Update application |
| DELETE | `/applications/{id}` | Delete application |
| GET | `/applications/{id}/components` | Get application components |
| GET | `/applications/{id}/apis` | Get application APIs |
| POST | `/applications/{id}/dependencies` | Add dependency |
| GET | `/applications/{id}/dependencies` | List dependencies |
| GET | `/services` | List services |
| POST | `/services` | Create service |
| GET | `/services/{id}` | Get service |
| GET | `/apis` | List APIs |
| POST | `/apis` | Create API |
| GET | `/apis/{id}/security` | Get API security profile |
| GET | `/search` | Search inventory |
| GET | `/applications/{id}/license-compliance` | License compliance check |
| GET | `/applications/{id}/sbom` | Generate SBOM for application |

### Policies (`/api/v1/policies`) — 11 endpoints
Source: `suite-api/apps/api/policies_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List policies (paginated) |
| POST | `/` | Create policy |
| GET | `/{id}` | Get policy |
| PUT | `/{id}` | Update policy |
| DELETE | `/{id}` | Delete policy |
| POST | `/{id}/validate` | Validate policy |
| POST | `/{id}/test` | Test policy against sample data |
| GET | `/{id}/violations` | Get policy violations |
| POST | `/{id}/enforce` | Enforce policy |
| POST | `/simulate` | Simulate policy effect |
| GET | `/conflicts` | Detect policy conflicts |

### Remediation (`/api/v1/remediation`) — 15 endpoints
Source: `suite-api/apps/api/remediation_router.py`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/tasks` | Create remediation task |
| GET | `/tasks` | List remediation tasks |
| GET | `/tasks/{id}` | Get task details |
| PUT | `/tasks/{id}/status` | Update task status |
| PUT | `/tasks/{id}/assign` | Assign task |
| POST | `/tasks/{id}/verification` | Submit verification |
| PUT | `/tasks/{id}/ticket` | Link ticket to task |
| POST | `/sla/check` | Check SLA compliance |
| GET | `/metrics/{org_id}` | Get org remediation metrics |
| GET | `/statuses` | List valid statuses |
| POST | `/tasks/{id}/autofix` | Trigger autofix |
| GET | `/tasks/{id}/autofix/suggestions` | Get autofix suggestions |
| PUT | `/tasks/{id}/transition` | Transition task state |
| POST | `/tasks/{id}/verify` | Verify remediation |
| GET | `/metrics` | Global remediation metrics |

### Reports (`/api/v1/reports`) — 14 endpoints
Source: `suite-api/apps/api/reports_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List reports (paginated) |
| POST | `/` | Create report |
| POST | `/generate` | Generate report |
| GET | `/stats` | Report statistics |
| GET | `/{id}` | Get report |
| GET | `/{id}/download` | Download report file |
| GET | `/{id}/file` | Stream report file |
| POST | `/schedule` | Schedule report generation |
| GET | `/schedules/list` | List scheduled reports |
| GET | `/templates/list` | List report templates |
| POST | `/export/sarif` | Export as SARIF |
| POST | `/export/csv` | Export as CSV |
| GET | `/export/csv/{id}/download` | Download CSV export |
| GET | `/export/json` | Export as JSON |

### Teams (`/api/v1/teams`) — 8 endpoints
Source: `suite-api/apps/api/teams_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List teams |
| POST | `/` | Create team |
| GET | `/{id}` | Get team |
| PUT | `/{id}` | Update team |
| DELETE | `/{id}` | Delete team |
| GET | `/{id}/members` | List team members |
| POST | `/{id}/members` | Add team member |
| DELETE | `/{id}/members/{user_id}` | Remove team member |

### Users (`/api/v1/users`) — 6 endpoints
Source: `suite-api/apps/api/users_router.py`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/login` | Authenticate user (returns JWT) |
| GET | `/` | List users (paginated) |
| POST | `/` | Create user |
| GET | `/{id}` | Get user |
| PUT | `/{id}` | Update user |
| DELETE | `/{id}` | Delete user |

### Workflows (`/api/v1/workflows`) — 13 endpoints
Source: `suite-api/apps/api/workflows_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List workflows |
| POST | `/` | Create workflow |
| GET | `/{id}` | Get workflow |
| PUT | `/{id}` | Update workflow |
| DELETE | `/{id}` | Delete workflow |
| POST | `/{id}/execute` | Execute workflow |
| GET | `/{id}/history` | Execution history |
| GET | `/rules` | List workflow rules |
| PUT | `/{id}/sla` | Update workflow SLA |
| GET | `/{id}/sla` | Get workflow SLA |
| POST | `/executions/{id}/pause` | Pause execution |
| POST | `/executions/{id}/resume` | Resume execution |
| GET | `/executions/{id}/timeline` | Execution timeline |

### Validation (`/api/v1/validation`) — 3 endpoints
Source: `suite-api/apps/api/validation_router.py`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/input` | Validate input data |
| POST | `/batch` | Batch validation (compatibility report) |
| GET | `/supported-formats` | List supported validation formats |

### Marketplace (`/api/v1/marketplace`) — 12 endpoints
Source: `suite-api/apps/api/marketplace_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/packs/{framework}/{control}` | Fetch pack by framework/control |
| GET | `/browse` | Browse marketplace (paginated) |
| GET | `/recommendations` | Get personalized recommendations |
| GET | `/items/{item_id}` | Get item details |
| POST | `/contribute` | Contribute content to marketplace |
| PUT | `/items/{item_id}` | Update marketplace item |
| POST | `/items/{item_id}/rate` | Rate an item |
| POST | `/purchase/{item_id}` | Purchase item |
| GET | `/download/{token}` | Download purchased content |
| GET | `/contributors` | List contributors |
| GET | `/compliance-content/{stage}` | Get compliance content by stage |
| GET | `/stats` | Marketplace statistics |

### Health (`/api/v1`) — 4 endpoints
Source: `suite-api/apps/api/health.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness probe |
| GET | `/version` | Version info |
| GET | `/metrics` | Prometheus-style metrics |

### Enhanced Analysis (`/api/v1/enhanced`) — 4 endpoints
Source: `suite-api/apps/api/routes/enhanced.py`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/analysis` | Run enhanced vulnerability analysis |
| POST | `/compare-llms` | Compare LLM outputs |
| GET | `/capabilities` | List enhanced engine capabilities |
| GET | `/signals` | Get enhanced analysis signals |

### Logging (`/api/v1/logs`) — 5 endpoints
Source: `suite-api/apps/api/detailed_logging.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Query logs (paginated) |
| GET | `/stats` | Log statistics |
| GET | `/recent` | Recent log entries |
| DELETE | `/` | Clear logs |
| GET | `/stream` | SSE log stream |

---

## 4. suite-core Endpoints

### Brain / Knowledge Graph (`/api/v1/brain`) — 21 endpoints
Source: `suite-core/api/brain_router.py`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/nodes` | Create node (CVE, CWE, CPE, Asset, Finding) |
| GET | `/nodes` | List nodes (with filters) |
| GET | `/nodes/{id}` | Get node |
| DELETE | `/nodes/{id}` | Delete node |
| POST | `/edges` | Create edge between nodes |
| GET | `/all-edges` | List all edges |
| GET | `/edges/{node_id}` | Get edges for node |
| DELETE | `/edges` | Delete edge |
| GET | `/neighbors/{node_id}` | Get node neighbors |
| GET | `/paths` | Find paths between nodes |
| GET | `/stats` | Knowledge Graph statistics |
| GET | `/most-connected` | Most connected nodes |
| GET | `/risk/{node_id}` | Risk score for node |
| GET | `/events` | Knowledge Graph events |
| GET | `/meta/entity-types` | List entity types |
| GET | `/meta/edge-types` | List edge types |
| POST | `/ingest/cve` | Ingest CVE into graph |
| POST | `/ingest/finding` | Ingest finding |
| POST | `/ingest/scan` | Ingest scan results |
| POST | `/ingest/asset` | Ingest asset |
| POST | `/ingest/remediation` | Ingest remediation data |

### Agents (`/api/v1/agents`) — 32 endpoints
Source: `suite-core/api/agents_router.py`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/analyst/analyze` | Analyst agent: full analysis |
| POST | `/analyst/threat-intel` | Gather threat intelligence |
| POST | `/analyst/prioritize` | Prioritize vulnerabilities |
| POST | `/analyst/attack-path` | Map attack paths |
| GET | `/analyst/trending` | Trending threats |
| GET | `/analyst/risk-score/{asset_id}` | Asset risk score |
| GET | `/analyst/cve/{cve_id}` | CVE deep analysis |
| POST | `/pentest/validate` | Pentest agent: validate finding |
| POST | `/pentest/generate-poc` | Generate proof-of-concept |
| POST | `/pentest/reachability` | Reachability analysis |
| POST | `/pentest/simulate` | Simulate attack |
| GET | `/pentest/results/{task_id}` | Get pentest results |
| GET | `/pentest/evidence/{id}` | Get pentest evidence |
| POST | `/pentest/schedule` | Schedule pentest |
| POST | `/compliance/map-findings` | Map findings to frameworks |
| POST | `/compliance/gap-analysis` | Compliance gap analysis |
| POST | `/compliance/audit-evidence` | Generate audit evidence |
| POST | `/compliance/regulatory-alerts` | Regulatory alerts |
| GET | `/compliance/controls/{framework}` | Framework controls |
| GET | `/compliance/dashboard` | Compliance dashboard |
| POST | `/compliance/generate-report` | Generate compliance report |
| POST | `/remediation/generate-fix` | Generate fix |
| POST | `/remediation/create-pr` | Create PR with fix |
| POST | `/remediation/update-dependencies` | Update dependencies |
| POST | `/remediation/playbook` | Execute remediation playbook |
| GET | `/remediation/recommendations/{finding_id}` | Get remediation recommendations |
| POST | `/remediation/verify` | Verify remediation effectiveness |
| GET | `/remediation/queue` | Get remediation queue |
| POST | `/orchestrate` | Orchestrate multi-agent workflow |
| GET | `/status` | Get all agents status |
| GET | `/tasks/{task_id}` | Get agent task result |
| GET | `/health` | Agents health check |

### Additional suite-core Routers (summary)

**Algorithmic** (`/api/v1/algorithmic`) — 11 endpoints — `suite-core/api/algorithmic_router.py`
- Monte Carlo: `/monte-carlo/{quantify,cve,portfolio}`
- Causal inference: `/causal/{analyze,counterfactual,treatment-effect}`
- GNN: `/gnn/{attack-surface,critical-nodes,risk-propagation}`
- `/status`, `/capabilities`

**AutoFix** (`/api/v1/autofix`) — 12 endpoints — `suite-core/api/autofix_router.py`
- `POST /generate`, `POST /generate/bulk`, `POST /apply`, `POST /validate`, `POST /rollback`
- `GET /fixes/{id}`, `GET /suggestions/{finding_id}`, `GET /history`, `GET /stats`
- `GET /health`, `GET /fix-types`, `GET /confidence-levels`

**Copilot** (`/api/v1/copilot`) — 14 endpoints — `suite-core/api/copilot_router.py`
- Sessions: `POST /sessions`, `GET /sessions`, `GET /sessions/{id}`, `DELETE /sessions/{id}`
- Messages: `POST /sessions/{id}/messages`, `GET /sessions/{id}/messages`
- Actions: `POST /sessions/{id}/actions`, `GET /actions/{id}`
- Context: `POST /sessions/{id}/context`
- Quick: `POST /quick/analyze`, `POST /quick/pentest`, `POST /quick/report`
- `GET /suggestions`, `GET /health`

**Decisions** (`/api/v1/decisions`) — 6 endpoints — `suite-core/api/decisions.py`
- `POST /make-decision`, `GET /metrics`, `GET /recent`, `GET /ssdlc-stages`
- `GET /core-components`, `GET /evidence/{id}`

**Deduplication** (`/api/v1/dedup`) — 18 endpoints — `suite-core/api/deduplication_router.py`
- Process: `POST /process`, `POST /process/batch`
- Clusters: `GET/PUT /clusters/{id}/*`, `POST /clusters/merge`, `POST /clusters/{id}/split`
- Correlations: `GET/POST /correlations`, `POST /correlate/cross-stage`
- Stats: `GET /stats`, `GET /stats/{org_id}`, `GET /graph`
- Feedback: `POST /feedback`, `POST /baseline/compare`

**Exposure Cases** (`/api/v1/exposure-cases`) — 8 endpoints — `suite-core/api/exposure_case_router.py`
- `POST /`, `GET /`, `GET /{id}`, `PATCH /{id}`
- `POST /{id}/transition`, `POST /{id}/clusters`, `GET /{id}/transitions`
- `GET /stats/summary`

**Fuzzy Identity** (`/api/v1/identity`) — 7 endpoints — `suite-core/api/fuzzy_identity_router.py`
- `POST /canonical`, `POST /alias`, `POST /resolve`, `POST /resolve/batch`
- `GET /similar`, `GET /canonical`, `GET /stats`

**Intelligent Engine** (`/api/v1/intelligent-engine`) — 11 endpoints — `suite-core/api/intelligent_engine_routes.py`
- `GET /status`, `GET /sessions`, `POST /scan`, `GET /scan/{id}`, `POST /scan/{id}/stop`
- `POST /intelligence/gather`, `POST /plan/generate`, `POST /plan/{id}/execute`
- `GET /mindsdb/status`, `POST /mindsdb/predict`, `POST /consensus/analyze`

**LLM** (`/api/v1/llm`) — 6 endpoints — `suite-core/api/llm_router.py`
- `GET /status`, `POST /test`, `GET /settings`, `PATCH /settings`
- `GET /providers`, `GET /health`

**LLM Monitor** (`/api/v1/llm-monitor`) — 4 endpoints — `suite-core/api/llm_monitor_router.py`
- `POST /analyze`, `POST /scan/prompt`, `GET /patterns`, `GET /status`

**MindsDB / ML** (`/api/v1/ml`) — 14 endpoints — `suite-core/api/mindsdb_router.py`
- `GET /status`, `GET /models`, `POST /train`, `POST /models/{id}/train`
- `POST /predict/{anomaly,threat}`, `GET /predict/response-time`
- Analytics: `GET /stats`, `GET /analytics/{stats,health,anomalies,threats}`
- `POST /analytics/threats/{id}/acknowledge`, `POST /flush`

**Nerve Center** (`/api/v1/nerve-center`) — 9 endpoints — `suite-core/api/nerve_center.py`
- `GET /pulse`, `GET /state`, `POST /auto-remediate`, `GET /intelligence-map`
- `GET /playbooks`, `POST /playbooks/validate`, `POST /playbooks/execute/{id}`
- `GET /overlay`, `PUT /overlay`

**Pipeline** (`/api/v1/pipeline`) — 6 endpoints — `suite-core/api/pipeline_router.py`
- `POST /pipeline/run`, `GET /pipeline/runs`, `GET /pipeline/runs/{id}`
- `POST /evidence/generate`, `GET /evidence/packs`, `GET /evidence/packs/{id}`

**Predictions** (`/api/v1/predictions`) — 8 endpoints — `suite-core/api/predictions_router.py`
- `POST /attack-chain`, `POST /risk-trajectory`, `POST /simulate-attack`
- `GET /markov/states`, `GET /markov/transitions`
- `POST /bayesian/update`, `POST /bayesian/risk-assessment`, `POST /combined-analysis`

**Streaming** (`/api/v1/streaming`) — 2 endpoints — `suite-core/api/streaming_router.py`
- `GET /pipeline/{run_id}` — SSE stream for pipeline events
- `GET /events` — General event stream

**Code-to-Cloud** (`/api/v1/code-to-cloud`) — 2 endpoints — `suite-core/api/code_to_cloud_router.py`
- `POST /trace` — Trace vulnerability from code to cloud
- `GET /status` — Tracer status

---

## 5. suite-attack Endpoints

### MPTE (`/api/v1/mpte`) — 19 endpoints
Source: `suite-attack/api/mpte_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/requests` | List MPTE requests |
| POST | `/requests` | Create MPTE request |
| GET | `/requests/{id}` | Get request |
| PUT | `/requests/{id}` | Update request |
| POST | `/requests/{id}/start` | Start MPTE test |
| POST | `/requests/{id}/cancel` | Cancel MPTE test |
| GET | `/results` | List results |
| POST | `/results` | Submit result |
| GET | `/results/by-request/{id}` | Results for request |
| GET | `/configs` | List MPTE configs |
| POST | `/configs` | Create config |
| GET | `/configs/{id}` | Get config |
| PUT | `/configs/{id}` | Update config |
| DELETE | `/configs/{id}` | Delete config |
| POST | `/verify` | Verify exploitability |
| POST | `/monitoring` | Submit monitoring data |
| POST | `/scan/comprehensive` | Comprehensive scan |
| GET | `/findings/{id}/exploitability` | Finding exploitability |
| GET | `/stats` | MPTE statistics |

### Micro-Pentest (`/api/v1/micro-pentest`) — 18 endpoints
Source: `suite-attack/api/micro_pentest_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Micro-pentest health check |
| POST | `/run` | Start micro-pentest run |
| GET | `/status/{flow_id}` | Get pentest status |
| POST | `/batch` | Batch pentest run |
| POST | `/enterprise/scan` | Enterprise scan |
| GET | `/enterprise/scan/{scan_id}` | Get enterprise scan result |
| GET | `/enterprise/scans` | List enterprise scans |
| POST | `/enterprise/scan/{scan_id}/cancel` | Cancel enterprise scan |
| GET | `/enterprise/audit-logs` | Enterprise audit logs |
| GET | `/enterprise/health` | Enterprise engine health |
| GET | `/enterprise/attack-vectors` | List attack vectors |
| GET | `/enterprise/threat-categories` | List threat categories |
| GET | `/enterprise/compliance-frameworks` | List compliance frameworks |
| GET | `/enterprise/scan-modes` | List scan modes |
| POST | `/report/generate` | Generate pentest report |
| GET | `/report/download` | Download pentest report |
| GET | `/report/view` | View pentest report |
| GET | `/report/data` | Get pentest report data |

### Attack Simulation (`/api/v1/attack-simulation`) — 13 endpoints
Source: `suite-attack/api/attack_sim_router.py`
- Scenarios: `POST /scenarios`, `POST /scenarios/generate`, `GET /scenarios`, `GET /scenarios/{id}`
- Campaigns: `POST /campaigns/run`, `GET /campaigns`, `GET /campaigns/{id}`
- `GET /campaigns/{id}/attack-paths`, `GET /campaigns/{id}/breach-impact`, `GET /campaigns/{id}/recommendations`
- MITRE: `GET /mitre/heatmap`, `GET /mitre/techniques`
- `GET /health`

### Additional Attack Routers (summary)

| Router | Prefix | Endpoints | Key Endpoints |
|--------|--------|-----------|---------------|
| PentAGI | `/api/v1/pentagi` | 8 | `GET /health`, `GET /capabilities`, `POST /threat-intel`, `POST /business-impact`, `POST /simulate`, `POST /remediation`, `POST /run`, `GET /status/{test_id}` |
| Vuln Discovery | `/api/v1/vuln-discovery` | 11 | `GET/POST /discovered`, `POST /contribute`, `GET /internal`, `GET /internal/{id}`, `PATCH /internal/{id}`, `POST /train`, `GET /train/{job_id}`, `GET /stats`, `GET /contributions`, `GET /health` |
| Secrets | `/api/v1/secrets` | 7 | `GET /status`, `GET /`, `POST /`, `GET /{id}`, `POST /{id}/resolve`, `GET /scanners/status`, `POST /scan/content` |
| SAST | `/api/v1/sast` | 4 | `POST /scan/code`, `POST /scan/files`, `GET /rules`, `GET /status` |
| DAST | `/api/v1/dast` | 2 | `POST /scan`, `GET /status` |
| Container | `/api/v1/container` | 3 | `POST /scan/dockerfile`, `POST /scan/image`, `GET /status` |
| CSPM | `/api/v1/cspm` | 4 | `POST /scan/terraform`, `POST /scan/cloudformation`, `GET /rules`, `GET /status` |
| API Fuzzer | `/api/v1/api-fuzzer` | 3 | `POST /discover`, `POST /fuzz`, `GET /status` |
| Malware | `/api/v1/malware` | 4 | `POST /scan/content`, `POST /scan/files`, `GET /signatures`, `GET /status` |

---

## 6. suite-feeds Endpoints

### Feeds (`/api/v1/feeds`) — 30 endpoints
Source: `suite-feeds/api/feeds_router.py`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/epss` | Get EPSS scores (cached) |
| POST | `/epss/refresh` | Refresh EPSS data from FIRST.org |
| GET | `/kev` | Get CISA KEV catalog (cached) |
| POST | `/kev/refresh` | Refresh KEV from CISA |
| POST | `/nvd/refresh` | Refresh from NVD API |
| GET | `/nvd/recent` | Recent NVD entries |
| GET | `/nvd/{cve_id}` | Lookup CVE in NVD |
| POST | `/exploitdb/refresh` | Refresh ExploitDB |
| POST | `/osv/refresh` | Refresh OSV data |
| POST | `/github/refresh` | Refresh GitHub Advisories |
| GET | `/exploits` | List known exploits |
| GET | `/exploits/{cve_id}` | Exploits for CVE |
| POST | `/exploits` | Add exploit data |
| GET | `/threat-actors` | List threat actors |
| GET | `/threat-actors/{cve_id}` | Threat actors for CVE |
| GET | `/threat-actors/by-actor/{actor}` | CVEs by threat actor |
| POST | `/threat-actors` | Add threat actor data |
| GET | `/supply-chain` | Supply chain risks |
| GET | `/supply-chain/{package}` | Supply chain risk for package |
| POST | `/supply-chain` | Add supply chain data |
| GET | `/exploit-confidence/{cve_id}` | Exploit confidence score for CVE |
| GET | `/geo-risk/{cve_id}` | Geo-weighted risk score |
| POST | `/enrich` | Enrich findings with feed data |
| GET | `/stats` | Feed statistics |
| GET | `/categories` | List feed categories |
| GET | `/sources` | List feed sources |
| GET | `/health` | Feed health status |
| GET | `/scheduler/status` | Feed scheduler status |
| POST | `/refresh` | Refresh specific feed (alias) |
| POST | `/refresh/all` | Refresh all feeds |

---

## 7. suite-evidence-risk Endpoints

### Evidence (`/api/v1/evidence`) — 6 endpoints
Source: `suite-evidence-risk/api/evidence_router.py`
- `GET /stats`, `GET /`, `GET /{release}`, `GET /bundles/{id}/download`
- `POST /verify`, `POST /{bundle_id}/collect`

### Risk (`/api/v1/risk`) — 3 endpoints — `suite-evidence-risk/api/risk_router.py`
- `GET /`, `GET /component/{component_slug}`, `GET /cve/{cve_id}`

### Graph (`/api/v1/graph`) — 4 endpoints — `suite-evidence-risk/api/graph_router.py`
- `GET /`, `GET /lineage/{artifact}`, `GET /kev-components`, `GET /anomalies`

### Provenance (`/api/v1/provenance`) — 2 endpoints — `suite-evidence-risk/api/provenance_router.py`
- `GET /`, `GET /{artifact_name}`

### Business Context (`/api/v1/business-context`) — 3 endpoints — `suite-evidence-risk/api/business_context.py`
- `GET /jira-context/{ticket_id}`, `GET /confluence-context/{page_id}`, `POST /enrich-context`

### Business Context Enhanced (`/api/v1/business-context-enhanced`) — 4 endpoints
Source: `suite-evidence-risk/api/business_context_enhanced.py`
- `POST /upload`, `GET /sample/{format}`, `GET /formats`, `POST /validate`

### Reachability Analysis (`/api/v1/reachability`) — 7 endpoints
Source: `suite-evidence-risk/risk/reachability/api.py`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/analyze` | Analyze reachability for a CVE |
| POST | `/analyze/bulk` | Bulk reachability analysis |
| GET | `/job/{job_id}` | Get analysis job status |
| GET | `/results/{cve_id}` | Get reachability result for CVE |
| DELETE | `/results/{cve_id}` | Delete reachability result |
| GET | `/health` | Reachability engine health |
| GET | `/metrics` | Reachability analysis metrics |

---

## 8. suite-integrations Endpoints

### Integrations (`/api/v1/integrations`) — 8 endpoints — `suite-integrations/api/integrations_router.py`
- `GET /`, `POST /`, `GET /{id}`, `PUT /{id}`, `DELETE /{id}`
- `POST /{id}/test`, `GET /{id}/sync-status`, `POST /{id}/sync`

### Webhooks (`/api/v1/webhooks`) — 19 endpoints — `suite-integrations/api/webhooks_router.py`
- Mappings: `POST /mappings`, `GET /mappings`, `GET /mappings/{id}`, `PUT /mappings/{id}/sync`
- Drift: `GET /drift`, `PUT /drift/{id}/resolve`
- Events: `GET /events`
- Outbox: `POST/GET /outbox`, `GET /outbox/pending`, `PUT /outbox/{id}/process`
- `DELETE /outbox/{id}`, `POST /outbox/{id}/retry`, `GET /outbox/stats`
- `POST /outbox/{id}/execute`, `POST /outbox/process-pending`
- ALM: `POST /alm/work-items`, `PUT /alm/work-items/{id}`, `GET /alm/work-items`

### Webhook Receivers (`/api/v1/webhook-receiver`) — 4 endpoints — `suite-integrations/api/webhooks_router.py` (receiver_router)
- `POST /jira` — Receive Jira webhook
- `POST /servicenow` — Receive ServiceNow webhook
- `POST /gitlab` — Receive GitLab webhook
- `POST /azure-devops` — Receive Azure DevOps webhook

### Additional Integration Routers

| Router | Prefix | Endpoints | Key Endpoints |
|--------|--------|-----------|---------------|
| IaC | `/api/v1/iac` | 7 | `GET /`, `POST /`, `GET /{id}`, `POST /{id}/resolve`, `POST /{id}/remediate`, `GET /scanners/status`, `POST /scan/content` |
| IDE | `/api/v1/ide` | 5 | `GET /status`, `GET /config`, `POST /analyze`, `GET /suggestions`, `POST /sarif` |
| MCP | `/api/v1/mcp` | 10 | `GET /status`, `GET /clients`, `GET /tools`, `GET /resources`, `GET /prompts`, `GET /config`, `POST /configure`, `POST /clients/{id}/disconnect`, `DELETE /clients/{id}`, `GET /manifest` |
| OSS Tools | `/api/v1/oss` | 8 | `GET /status`, `POST /scan/comprehensive`, `POST /scan/trivy`, `POST /scan/grype`, `POST /verify/sigstore`, `POST /policy/evaluate`, `GET /policies`, `GET /tools` |

---

## 9. Inline Endpoints (app.py)

These endpoints are defined directly in `suite-api/apps/api/app.py` (not in separate router files):

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Legacy healthcheck (Docker/scripts) |
| GET | `/api/v1/status` | Full status (mode, pipeline, version) |
| GET | `/api/v1/search` | Global search across entities |
| POST | `/inputs/design` | Ingest design-context CSV |
| POST | `/inputs/sbom` | Ingest SBOM (CycloneDX/SPDX) |
| POST | `/inputs/cve` | Ingest CVE data |
| POST | `/inputs/vex` | Ingest VEX document |
| POST | `/inputs/cnapp` | Ingest CNAPP data |
| POST | `/inputs/sarif` | Ingest SARIF results |
| POST | `/inputs/context` | Ingest general context |
| POST | `/api/v1/ingest/multipart` | Multipart file ingestion |
| GET | `/api/v1/ingest/assets` | Asset inventory list |
| GET | `/api/v1/ingest/formats` | List supported ingestion formats |
| POST | `/inputs/{stage}/chunks/start` | Start chunked upload |
| PUT | `/inputs/{stage}/chunks/{session_id}` | Upload chunk data |
| POST | `/inputs/{stage}/chunks/{session_id}/complete` | Complete chunked upload |
| GET | `/inputs/{stage}/chunks/{session_id}` | Chunk upload status |
| GET | `/api/v1/triage` | Get triage results |
| GET | `/api/v1/triage/export` | Export triage results |
| GET | `/api/v1/graph` | Knowledge graph visualization |
| GET | `/analytics/dashboard` | Analytics dashboard data |
| GET | `/analytics/runs/{run_id}` | Get pipeline run details |
| POST | `/feedback` | Submit user feedback |

---

## 10. Common Response Patterns

### Paginated Response
```json
{
  "items": [...],
  "total": 150,
  "page": 1,
  "page_size": 20,
  "pages": 8
}
```

### Success Response
```json
{
  "status": "success",
  "data": { ... },
  "timestamp": "2026-02-19T12:00:00Z"
}
```

### Pipeline Run Result
```json
{
  "run_id": "uuid",
  "status": "completed",
  "steps": [...],
  "evidence_pack_id": "uuid",
  "duration_ms": 1234
}
```

---

## 11. Error Codes

| Code | Meaning |
|------|---------|
| 400 | Bad Request — invalid input data |
| 401 | Unauthorized — missing or invalid API key/JWT |
| 403 | Forbidden — insufficient permissions |
| 404 | Not Found — resource does not exist |
| 409 | Conflict — duplicate entry or state conflict |
| 422 | Unprocessable Entity — validation error (FastAPI default) |
| 429 | Too Many Requests — rate limited |
| 500 | Internal Server Error |
| 503 | Service Unavailable — dependency down |

Error response format:
```json
{
  "detail": "Error message describing what went wrong"
}
```

