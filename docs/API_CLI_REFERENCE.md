# FixOps API to CLI Mapping (322 Endpoints)

## Summary

| Category | API Endpoints | CLI Commands | Coverage |
|----------|---------------|--------------|----------|
| Core Pipeline & Ingestion | 22 | 7 | Full |
| Security Decision & Analysis | 21 | 3 | Partial (via run/analyze) |
| Compliance | 12 | 4 | Full |
| Reports | 10 | 4 | Full |
| Inventory | 15 | 5 | Full |
| Policies | 8 | 5 | Full |
| Integrations | 8 | 4 | Full |
| Analytics | 16 | 5 | Full |
| Audit | 10 | 3 | Full |
| Workflows | 7 | 5 | Full |
| Advanced Pen Testing | 45 | 6 | Full |
| Reachability | 7 | 3 | Full |
| Teams & Users | 14 | 8 | Full |
| PentAGI | 14 | 3 | Full |
| Evidence | 12 | 2 | Partial |
| Health & Status | 4 | 1 | Full |
| **Deduplication & Correlation** | **17** | **8** | **Full** |
| **Remediation Lifecycle** | **13** | **7** | **Full** |
| **Bulk Operations (Enhanced)** | **12** | **-** | **API Only** |
| **Team Collaboration** | **21** | **2** | **Partial** |
| **Vulnerability Intelligence Feeds** | **20** | **-** | **API Only** |
| **Webhooks** | **17** | **-** | **API Only** |
| **TOTAL** | **~322** | **~84** | **~85%** |

---

## CORE PIPELINE & INGESTION (19 API → 6 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/status` | GET | `health` | Authenticated health check |
| 2 | `/inputs/design` | POST | `run --design` | Upload design CSV |
| 3 | `/inputs/sbom` | POST | `run --sbom` | Upload SBOM (CycloneDX/SPDX) |
| 4 | `/inputs/cve` | POST | `run --cve` | Upload CVE feed |
| 5 | `/inputs/vex` | POST | `run --vex` | Upload VEX statements |
| 6 | `/inputs/cnapp` | POST | `run --cnapp` | Upload CNAPP findings |
| 7 | `/inputs/sarif` | POST | `run --sarif` | Upload SARIF scan results |
| 8 | `/inputs/context` | POST | `run --context` | Upload business context |
| 9 | `/inputs/{stage}/chunks/start` | POST | - | Chunked upload (API only) |
| 10 | `/inputs/{stage}/chunks/append` | PUT | - | Chunked upload (API only) |
| 11 | `/inputs/{stage}/chunks/complete` | POST | - | Chunked upload (API only) |
| 12 | `/inputs/{stage}/chunks/status` | GET | - | Chunked upload (API only) |
| 13 | `/pipeline/run` | GET | `run` | Execute full pipeline |
| 14 | `/pipeline/run` | GET | `make-decision` | Pipeline with exit code |
| 15 | `/pipeline/run` | GET | `ingest` | Normalize and print |
| 16 | `/pipeline/run` | GET | `analyze` | Analyze with verdict |
| 17 | `/api/v1/triage` | GET | - | Get triage results (API only) |
| 18 | `/api/v1/triage/export` | GET | - | Export triage (API only) |
| 19 | `/api/v1/graph` | GET | - | Graph visualization (API only) |
| 20 | `/api/v1/ingest/multipart` | POST | `ingest-file` | Scanner-agnostic multipart ingestion (SARIF, CycloneDX, SPDX, VEX, CNAPP, Trivy, Grype, Semgrep, Dependabot, dark web intel) |
| 21 | `/api/v1/ingest/assets` | GET | - | Get dynamic asset inventory from ingested findings |
| 22 | `/api/v1/ingest/formats` | GET | - | List available normalizer formats and plugins |

---

## SECURITY DECISION & ANALYSIS (21 API → 3 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/enhanced/compare-llms` | POST | `run` (internal) | Multi-LLM comparison |
| 2 | `/api/v1/enhanced/capabilities` | GET | `run` (internal) | Decision engine capabilities |
| 3 | `/api/v1/enhanced/multi-model` | POST | `run` (internal) | Multi-model analysis |
| 4 | `/api/v1/enhanced/consensus` | POST | `run` (internal) | Consensus decision |
| 5 | `/api/v1/risk/score` | POST | `analyze` | Risk scoring |
| 6 | `/api/v1/risk/blast-radius` | POST | `analyze` | Blast radius analysis |
| 7 | `/api/v1/risk/exposure` | GET | `analyze` | Exposure assessment |
| 8 | `/api/v1/graph/dependencies` | GET | - | Dependency graphs (API only) |
| 9 | `/api/v1/graph/components` | GET | - | Component relationships (API only) |
| 10 | `/api/v1/graph/attack-paths` | GET | - | Attack path visualization (API only) |
| 11 | `/api/v1/graph/impact` | GET | - | Impact analysis (API only) |
| 12 | `/api/v1/evidence/bundles` | GET | `get-evidence` | List evidence bundles |
| 13 | `/api/v1/evidence/bundles/{id}` | GET | `get-evidence` | Get specific bundle |
| 14 | `/api/v1/evidence/manifests/{id}` | GET | `copy-evidence` | Get manifest |
| 15 | `/api/v1/provenance/attestations` | GET | - | SLSA attestations (API only) |
| 16 | `/api/v1/provenance/verify` | POST | - | Verify provenance (API only) |
| 17-21 | Various decision endpoints | - | `run`/`analyze` | Covered by pipeline |

---

## COMPLIANCE (12 API → 4 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/compliance/frameworks` | GET | `compliance frameworks` | List all frameworks |
| 2 | `/api/v1/compliance/frameworks/{id}` | GET | `compliance status {framework}` | Get framework details |
| 3 | `/api/v1/compliance/frameworks` | POST | - | Create framework (API only) |
| 4 | `/api/v1/compliance/controls` | GET | `compliance status {framework}` | List controls |
| 5 | `/api/v1/compliance/controls/{id}` | GET | `compliance status {framework}` | Get control details |
| 6 | `/api/v1/compliance/gaps` | GET | `compliance gaps {framework}` | List compliance gaps |
| 7 | `/api/v1/compliance/gaps` | POST | - | Create gap (API only) |
| 8 | `/api/v1/compliance/gaps/{id}` | PUT | - | Update gap (API only) |
| 9 | `/api/v1/compliance/mapping` | GET | `compliance status {framework}` | Get control mapping |
| 10 | `/api/v1/compliance/coverage` | GET | `compliance status {framework}` | Coverage metrics |
| 11 | `/api/v1/compliance/report` | GET | `compliance report {framework}` | Generate report |
| 12 | `/api/v1/compliance/export` | GET | `compliance report {framework} --output` | Export report |

---

## REPORTS (10 API → 4 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/reports` | GET | `reports list` | List all reports |
| 2 | `/api/v1/reports/{id}` | GET | `reports list` | Get report details |
| 3 | `/api/v1/reports/generate` | POST | `reports generate` | Generate new report |
| 4 | `/api/v1/reports/{id}/download` | GET | `reports export {id}` | Download report |
| 5 | `/api/v1/reports/templates` | GET | `reports generate --type` | List templates |
| 6 | `/api/v1/reports/schedules` | GET | `reports schedules` | List schedules |
| 7 | `/api/v1/reports/schedules` | POST | - | Create schedule (API only) |
| 8 | `/api/v1/reports/schedules/{id}` | PUT | - | Update schedule (API only) |
| 9 | `/api/v1/reports/schedules/{id}` | DELETE | - | Delete schedule (API only) |
| 10 | `/api/v1/reports/bulk` | POST | - | Bulk generation (API only) |

---

## INVENTORY (15 API → 5 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/inventory/applications` | GET | `inventory apps` | List applications |
| 2 | `/api/v1/inventory/applications/{id}` | GET | `inventory get {id}` | Get app details |
| 3 | `/api/v1/inventory/applications` | POST | `inventory add` | Add application |
| 4 | `/api/v1/inventory/applications/{id}` | PUT | - | Update app (API only) |
| 5 | `/api/v1/inventory/applications/{id}` | DELETE | - | Delete app (API only) |
| 6 | `/api/v1/inventory/services` | GET | `inventory services` | List services |
| 7 | `/api/v1/inventory/services/{id}` | GET | `inventory get {id}` | Get service details |
| 8 | `/api/v1/inventory/services` | POST | - | Add service (API only) |
| 9 | `/api/v1/inventory/components` | GET | - | List components (API only) |
| 10 | `/api/v1/inventory/dependencies` | GET | - | List dependencies (API only) |
| 11 | `/api/v1/inventory/search` | GET | `inventory search` | Search inventory |
| 12 | `/api/v1/inventory/tags` | GET | - | List tags (API only) |
| 13 | `/api/v1/inventory/bulk` | POST | - | Bulk import (API only) |
| 14 | `/api/v1/inventory/export` | GET | - | Export inventory (API only) |
| 15 | `/api/v1/inventory/sync` | POST | - | Sync from SCM (API only) |

---

## POLICIES (8 API → 5 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/policies` | GET | `policies list` | List all policies |
| 2 | `/api/v1/policies/{id}` | GET | `policies get {id}` | Get policy details |
| 3 | `/api/v1/policies` | POST | `policies create` | Create policy |
| 4 | `/api/v1/policies/{id}` | PUT | - | Update policy (API only) |
| 5 | `/api/v1/policies/{id}` | DELETE | - | Delete policy (API only) |
| 6 | `/api/v1/policies/validate` | POST | `policies validate {id}` | Validate policy |
| 7 | `/api/v1/policies/test` | POST | `policies test {id}` | Test policy |
| 8 | `/api/v1/policies/export` | GET | - | Export policies (API only) |

---

## INTEGRATIONS (8 API → 4 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/integrations` | GET | `integrations list` | List integrations |
| 2 | `/api/v1/integrations/{id}` | GET | `integrations list` | Get integration details |
| 3 | `/api/v1/integrations` | POST | `integrations configure` | Create/configure integration |
| 4 | `/api/v1/integrations/{id}` | PUT | `integrations configure` | Update integration |
| 5 | `/api/v1/integrations/{id}` | DELETE | - | Delete integration (API only) |
| 6 | `/api/v1/integrations/test` | POST | `integrations test {name}` | Test connection |
| 7 | `/api/v1/integrations/sync` | POST | `integrations sync {name}` | Sync data |
| 8 | `/api/v1/integrations/webhooks` | GET | - | List webhooks (API only) |

---

## ANALYTICS (16 API → 5 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/analytics/dashboard` | GET | `analytics dashboard` | Dashboard metrics |
| 2 | `/api/v1/analytics/findings` | GET | `analytics dashboard` | Findings analytics |
| 3 | `/api/v1/analytics/trends` | GET | `analytics dashboard` | Trend analysis |
| 4 | `/api/v1/analytics/mttr` | GET | `analytics mttr` | Mean time to remediate |
| 5 | `/api/v1/analytics/mttd` | GET | `analytics mttr` | Mean time to detect |
| 6 | `/api/v1/analytics/coverage` | GET | `analytics coverage` | Scan coverage |
| 7 | `/api/v1/analytics/risk-score` | GET | `analytics dashboard` | Risk score trends |
| 8 | `/api/v1/analytics/roi` | GET | `analytics roi` | ROI analysis |
| 9 | `/api/v1/analytics/cost-savings` | GET | `analytics roi` | Cost savings |
| 10 | `/api/v1/analytics/export` | GET | `analytics export` | Export analytics |
| 11 | `/api/v1/analytics/query` | POST | - | Custom query (API only) |
| 12 | `/api/v1/analytics/compare` | GET | - | Period comparison (API only) |
| 13 | `/api/v1/analytics/forecast` | GET | - | Forecast (API only) |
| 14 | `/api/v1/analytics/train` | POST | `train-forecast` | Train model |
| 15 | `/api/v1/analytics/benchmarks` | GET | - | Industry benchmarks (API only) |
| 16 | `/api/v1/analytics/alerts` | GET | - | Analytics alerts (API only) |

---

## AUDIT (10 API → 3 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/audit/logs` | GET | `audit logs` | List audit logs |
| 2 | `/api/v1/audit/logs/{id}` | GET | `audit logs` | Get log details |
| 3 | `/api/v1/audit/decisions` | GET | `audit decisions` | Decision audit trail |
| 4 | `/api/v1/audit/decisions/{id}` | GET | `audit decisions` | Decision details |
| 5 | `/api/v1/audit/users` | GET | `audit logs --type user` | User activity |
| 6 | `/api/v1/audit/policies` | GET | `audit logs --type policy` | Policy changes |
| 7 | `/api/v1/audit/integrations` | GET | `audit logs --type integration` | Integration activity |
| 8 | `/api/v1/audit/export` | GET | `audit export` | Export audit logs |
| 9 | `/api/v1/audit/search` | GET | `audit logs` | Search logs |
| 10 | `/api/v1/audit/retention` | GET | - | Retention settings (API only) |

---

## WORKFLOWS (12 API → 5 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/workflows` | GET | `workflows list` | List workflows |
| 2 | `/api/v1/workflows/{id}` | GET | `workflows get {id}` | Get workflow details |
| 3 | `/api/v1/workflows` | POST | `workflows create` | Create workflow |
| 4 | `/api/v1/workflows/{id}` | PUT | - | Update workflow (API only) |
| 5 | `/api/v1/workflows/{id}` | DELETE | - | Delete workflow (API only) |
| 6 | `/api/v1/workflows/{id}/execute` | POST | `workflows execute {id}` | Execute workflow |
| 7 | `/api/v1/workflows/{id}/history` | GET | `workflows history {id}` | Execution history |
| 8 | `/api/v1/workflows/executions` | GET | `workflows history {id}` | All executions |
| 9 | `/api/v1/workflows/executions/{id}` | GET | `workflows history {id}` | Execution details |
| 10 | `/api/v1/workflows/templates` | GET | - | Workflow templates (API only) |
| 11 | `/api/v1/workflows/triggers` | GET | - | Trigger types (API only) |
| 12 | `/api/v1/workflows/actions` | GET | - | Action types (API only) |

---

## ADVANCED PEN TESTING (45 API → 6 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/pentest/run` | POST | `advanced-pentest run` | Run pen test |
| 2 | `/api/v1/pentest/status/{id}` | GET | `advanced-pentest run` | Check status |
| 3 | `/api/v1/pentest/results/{id}` | GET | `advanced-pentest run` | Get results |
| 4 | `/api/v1/pentest/threat-intel` | GET | `advanced-pentest threat-intel {cve}` | Threat intelligence |
| 5 | `/api/v1/pentest/threat-intel/{cve}` | GET | `advanced-pentest threat-intel {cve}` | CVE threat intel |
| 6 | `/api/v1/pentest/business-impact` | POST | `advanced-pentest business-impact` | Business impact |
| 7 | `/api/v1/pentest/simulate` | POST | `advanced-pentest simulate` | Attack simulation |
| 8 | `/api/v1/pentest/simulate/chain` | POST | `advanced-pentest simulate --attack-type chained_exploit` | Chained exploits |
| 9 | `/api/v1/pentest/simulate/lateral` | POST | `advanced-pentest simulate --attack-type lateral_movement` | Lateral movement |
| 10 | `/api/v1/pentest/simulate/privesc` | POST | `advanced-pentest simulate --attack-type privilege_escalation` | Privilege escalation |
| 11 | `/api/v1/pentest/remediation/{cve}` | GET | `advanced-pentest remediation {cve}` | Remediation guidance |
| 12 | `/api/v1/pentest/capabilities` | GET | `advanced-pentest capabilities` | List capabilities |
| 13-45 | Enterprise pen test endpoints | - | `advanced-pentest *` | Covered by subcommands |

---

## REACHABILITY (7 API → 3 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/reachability/analyze` | POST | `reachability analyze {cve}` | Analyze reachability |
| 2 | `/api/v1/reachability/analyze/{cve}` | GET | `reachability analyze {cve}` | Get analysis |
| 3 | `/api/v1/reachability/bulk` | POST | `reachability bulk {cves}` | Bulk analysis |
| 4 | `/api/v1/reachability/status/{job_id}` | GET | `reachability status {job_id}` | Job status |
| 5 | `/api/v1/reachability/call-graph` | GET | - | Call graph (API only) |
| 6 | `/api/v1/reachability/paths` | GET | - | Attack paths (API only) |
| 7 | `/api/v1/reachability/export` | GET | - | Export results (API only) |

---

## TEAMS & USERS (14 API → 8 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/teams` | GET | `teams list` | List teams |
| 2 | `/api/v1/teams/{id}` | GET | `teams get {id}` | Get team details |
| 3 | `/api/v1/teams` | POST | `teams create` | Create team |
| 4 | `/api/v1/teams/{id}` | PUT | - | Update team (API only) |
| 5 | `/api/v1/teams/{id}` | DELETE | - | Delete team (API only) |
| 6 | `/api/v1/teams/{id}/members` | GET | `teams get {id}` | List members |
| 7 | `/api/v1/teams/{id}/members` | POST | - | Add member (API only) |
| 8 | `/api/v1/users` | GET | `users list` | List users |
| 9 | `/api/v1/users/{id}` | GET | `users get {id}` | Get user details |
| 10 | `/api/v1/users` | POST | `users create` | Create user |
| 11 | `/api/v1/users/{id}` | PUT | - | Update user (API only) |
| 12 | `/api/v1/users/{id}` | DELETE | - | Delete user (API only) |
| 13 | `/api/v1/users/{id}/password` | PUT | `users reset-password {id}` | Reset password |
| 14 | `/api/v1/users/me` | GET | - | Current user (API only) |

---

## PENTAGI (8 API → 3 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/pentagi/requests` | GET | `pentagi list` | List requests |
| 2 | `/api/v1/pentagi/requests/{id}` | GET | `pentagi status {id}` | Get request status |
| 3 | `/api/v1/pentagi/requests` | POST | `pentagi create` | Create request |
| 4 | `/api/v1/pentagi/requests/{id}/cancel` | POST | - | Cancel request (API only) |
| 5 | `/api/v1/pentagi/results/{id}` | GET | `pentagi status {id}` | Get results |
| 6 | `/api/v1/pentagi/capabilities` | GET | - | List capabilities (API only) |
| 7 | `/api/v1/pentagi/config` | GET | - | Get config (API only) |
| 8 | `/api/v1/pentagi/config` | PUT | - | Update config (API only) |

---

## EVIDENCE (12 API → 2 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/evidence/bundles` | GET | `get-evidence` | List bundles |
| 2 | `/api/v1/evidence/bundles/{id}` | GET | `get-evidence` | Get bundle |
| 3 | `/api/v1/evidence/bundles/{id}/download` | GET | `copy-evidence` | Download bundle |
| 4 | `/api/v1/evidence/manifests` | GET | - | List manifests (API only) |
| 5 | `/api/v1/evidence/manifests/{id}` | GET | `copy-evidence` | Get manifest |
| 6 | `/api/v1/evidence/verify` | POST | - | Verify bundle (API only) |
| 7 | `/api/v1/evidence/sign` | POST | - | Sign bundle (API only) |
| 8 | `/api/v1/evidence/retention` | GET | - | Retention policy (API only) |
| 9 | `/api/v1/evidence/search` | GET | - | Search evidence (API only) |
| 10 | `/api/v1/evidence/export` | GET | `copy-evidence` | Export evidence |
| 11 | `/api/v1/evidence/compliance` | GET | - | Compliance mapping (API only) |
| 12 | `/api/v1/evidence/attestations` | GET | - | Attestations (API only) |

---

## HEALTH & STATUS (4 API → 1 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/health` | GET | `health` | Basic health check |
| 2 | `/api/v1/status` | GET | `health` | Authenticated status |
| 3 | `/api/v1/version` | GET | - | Version info (API only) |
| 4 | `/api/v1/config` | GET | `show-overlay` | Configuration |

---

## CLI COMMAND REFERENCE

| Command | Subcommands | Description |
|---------|-------------|-------------|
| `run` | - | Execute full pipeline |
| `make-decision` | - | Pipeline with exit code (0=GO, 1=NO-GO, 2=CONDITIONAL) |
| `ingest` | - | Normalize artifacts and print |
| `analyze` | - | Analyze findings with verdict |
| `stage-run` | - | Single SDLC stage |
| `get-evidence` | - | Retrieve evidence bundle |
| `copy-evidence` | - | Export evidence to directory |
| `show-overlay` | - | Show configuration |
| `health` | - | Check integration readiness |
| `demo` | - | Run demo mode |
| `train-forecast` | - | Train forecasting model |
| `teams` | list, get, create | Team management |
| `users` | list, get, create, reset-password | User management |
| `pentagi` | list, create, status | PentAGI management |
| `compliance` | frameworks, status, gaps, report | Compliance management |
| `reports` | list, generate, export, schedules | Report generation |
| `inventory` | apps, add, get, services, search | Asset inventory |
| `policies` | list, get, create, validate, test | Policy management |
| `integrations` | list, configure, test, sync | Integration management |
| `analytics` | dashboard, mttr, coverage, roi, export | Security analytics |
| `audit` | logs, decisions, export | Audit trails |
| `workflows` | list, get, create, execute, history | Workflow automation |
| `advanced-pentest` | run, threat-intel, business-impact, simulate, remediation, capabilities | Advanced pen testing |
| `reachability` | analyze, bulk, status | Vulnerability reachability |
| `correlation` | analyze, stats, status, graph, feedback | Deduplication & correlation |
| `groups` | list, get, merge, unmerge | Finding group management |
| `remediation` | list, get, assign, transition, verify, metrics, sla | Remediation lifecycle |
| `notifications` | worker, pending | Notification processing |

---

## COVERAGE SUMMARY

**Before CLI Expansion:**
- 11 CLI commands covering ~15% of API surface

**After CLI Expansion:**
- 84 CLI commands/subcommands covering ~85% of API surface
- 14 command groups added (including enterprise features)
- Full coverage for: Compliance, Reports, Inventory, Policies, Integrations, Analytics, Audit, Workflows, Advanced Pentest, Reachability, Deduplication, Remediation

**Remaining API-Only Features (~15%):**
- Chunked uploads (large file handling)
- Graph visualization endpoints
- Bulk operations
- Webhook management
- Template management
- Advanced search/query endpoints
- Retention policy management

These API-only features are typically used by the web UI or require interactive visualization that doesn't translate well to CLI.

---

## ENTERPRISE FEATURES (Implemented)

### DEDUPLICATION & CORRELATION (17 API Endpoints)

| # | API Endpoint | Method | Description |
|---|--------------|--------|-------------|
| 1 | `/api/v1/deduplication/process` | POST | Process single finding and return cluster info |
| 2 | `/api/v1/deduplication/process/batch` | POST | Process batch of findings with dedup summary |
| 3 | `/api/v1/deduplication/clusters` | GET | List clusters with filters (org_id, app_id, status, severity) |
| 4 | `/api/v1/deduplication/clusters/{cluster_id}` | GET | Get specific cluster details |
| 5 | `/api/v1/deduplication/clusters/{cluster_id}/status` | PUT | Update cluster status with audit trail |
| 6 | `/api/v1/deduplication/clusters/{cluster_id}/assign` | PUT | Assign cluster to user |
| 7 | `/api/v1/deduplication/clusters/{cluster_id}/ticket` | PUT | Link cluster to external ticket |
| 8 | `/api/v1/deduplication/clusters/{cluster_id}/related` | GET | Get related clusters via correlation links |
| 9 | `/api/v1/deduplication/correlations` | POST | Create correlation link between clusters |
| 10 | `/api/v1/deduplication/stats/{org_id}` | GET | Get deduplication statistics by org |
| 11 | `/api/v1/deduplication/stats` | GET | Get global deduplication statistics (CLI-compatible) |
| 12 | `/api/v1/deduplication/clusters/merge` | POST | Merge multiple clusters into target cluster |
| 13 | `/api/v1/deduplication/clusters/{cluster_id}/split` | POST | Split cluster by moving events to new clusters |
| 14 | `/api/v1/deduplication/graph` | GET | Get correlation graph for visualization |
| 15 | `/api/v1/deduplication/feedback` | POST | Record operator feedback for correlation corrections |
| 16 | `/api/v1/deduplication/baseline` | GET | Get baseline comparison (NEW/EXISTING/FIXED) |
| 17 | `/api/v1/deduplication/cross-stage` | POST | Correlate findings across lifecycle stages |

**CLI Commands:** `fixops correlation analyze`, `fixops correlation stats`, `fixops correlation graph`, `fixops correlation feedback`, `fixops groups list`, `fixops groups get`, `fixops groups merge`, `fixops groups unmerge`

### REMEDIATION LIFECYCLE (13 API Endpoints)

| # | API Endpoint | Method | Description |
|---|--------------|--------|-------------|
| 1 | `/api/v1/remediation/tasks` | POST | Create remediation task with SLA tracking |
| 2 | `/api/v1/remediation/tasks` | GET | List tasks with filters (org_id, app_id, status, severity) |
| 3 | `/api/v1/remediation/tasks/{task_id}` | GET | Get specific task details |
| 4 | `/api/v1/remediation/tasks/{task_id}/status` | PUT | Update task status (state machine enforced) |
| 5 | `/api/v1/remediation/tasks/{task_id}/transition` | PUT | Transition task status (CLI-compatible alias) |
| 6 | `/api/v1/remediation/tasks/{task_id}/assign` | PUT | Assign task to user |
| 7 | `/api/v1/remediation/tasks/{task_id}/verification` | POST | Submit verification evidence |
| 8 | `/api/v1/remediation/tasks/{task_id}/verify` | POST | Verify task (CLI-compatible alias) |
| 9 | `/api/v1/remediation/tasks/{task_id}/ticket` | PUT | Link task to external ticket |
| 10 | `/api/v1/remediation/sla/check` | POST | Check for SLA breaches |
| 11 | `/api/v1/remediation/metrics/{org_id}` | GET | Get MTTR and SLA compliance metrics by org |
| 12 | `/api/v1/remediation/metrics` | GET | Get global remediation metrics (CLI-compatible) |
| 13 | `/api/v1/remediation/statuses` | GET | List valid status values and transitions |

**CLI Commands:** `fixops remediation list`, `fixops remediation get`, `fixops remediation assign`, `fixops remediation transition`, `fixops remediation verify`, `fixops remediation metrics`

**State Machine:** OPEN → ASSIGNED → IN_PROGRESS → VERIFICATION → RESOLVED (with DEFERRED and WONT_FIX branches)

**SLA Policies:** Critical=24h, High=72h, Medium=168h (7d), Low=720h (30d)

### BULK OPERATIONS (8 API Endpoints)

| # | API Endpoint | Method | Description |
|---|--------------|--------|-------------|
| 1 | `/api/v1/bulk/clusters/status` | POST | Bulk update cluster status |
| 2 | `/api/v1/bulk/clusters/assign` | POST | Bulk assign clusters |
| 3 | `/api/v1/bulk/clusters/accept-risk` | POST | Bulk accept risk |
| 4 | `/api/v1/bulk/clusters/tickets` | POST | Bulk create tickets |
| 5 | `/api/v1/bulk/clusters/export` | POST | Bulk export clusters |
| 6 | `/api/v1/bulk/jobs` | GET | List all bulk jobs |
| 7 | `/api/v1/bulk/jobs/{job_id}` | GET | Get job status and results |
| 8 | `/api/v1/bulk/jobs/{job_id}/cancel` | POST | Cancel running job |

**Features:** Async job execution, per-item outcomes, partial failure handling, progress tracking

### TEAM COLLABORATION (12 API Endpoints)

| # | API Endpoint | Method | Description |
|---|--------------|--------|-------------|
| 1 | `/api/v1/collaboration/comments` | POST | Add comment with mention extraction |
| 2 | `/api/v1/collaboration/comments` | GET | Get comments for entity |
| 3 | `/api/v1/collaboration/comments/{comment_id}/promote` | PUT | Promote comment to compliance evidence |
| 4 | `/api/v1/collaboration/watchers` | POST | Add watcher to entity |
| 5 | `/api/v1/collaboration/watchers` | DELETE | Remove watcher from entity |
| 6 | `/api/v1/collaboration/watchers` | GET | Get watchers for entity |
| 7 | `/api/v1/collaboration/watchers/user/{user_id}` | GET | Get entities watched by user |
| 8 | `/api/v1/collaboration/activities` | POST | Record activity in feed |
| 9 | `/api/v1/collaboration/activities` | GET | Get activity feed with filters |
| 10 | `/api/v1/collaboration/mentions/{user_id}` | GET | Get mentions for user |
| 11 | `/api/v1/collaboration/mentions/{mention_id}/acknowledge` | PUT | Acknowledge mention |
| 12 | `/api/v1/collaboration/entity-types` | GET | List valid entity types |

**Features:** Append-only comments, @mention extraction, activity feeds, evidence promotion

### VULNERABILITY INTELLIGENCE FEEDS (20 API Endpoints)

| # | API Endpoint | Method | Description |
|---|--------------|--------|-------------|
| 1 | `/api/v1/feeds/epss` | GET | Get EPSS scores for CVEs |
| 2 | `/api/v1/feeds/epss/refresh` | POST | Refresh EPSS feed from FIRST.org |
| 3 | `/api/v1/feeds/kev` | GET | Get CISA KEV entries |
| 4 | `/api/v1/feeds/kev/refresh` | POST | Refresh KEV feed from CISA |
| 5 | `/api/v1/feeds/exploits/{cve_id}` | GET | Get exploit intelligence for CVE |
| 6 | `/api/v1/feeds/threat-actors/{cve_id}` | GET | Get threat actor mappings for CVE |
| 7 | `/api/v1/feeds/threat-actors/by-actor/{actor}` | GET | Get CVEs used by threat actor |
| 8 | `/api/v1/feeds/supply-chain/{package}` | GET | Get supply chain vulnerabilities |
| 9 | `/api/v1/feeds/cloud-bulletins` | GET | Get cloud security bulletins |
| 10 | `/api/v1/feeds/early-signals` | GET | Get zero-day early signals |
| 11 | `/api/v1/feeds/national-certs` | GET | Get national CERT advisories |
| 12 | `/api/v1/feeds/exploit-confidence/{cve_id}` | GET | Get exploit confidence score |
| 13 | `/api/v1/feeds/geo-risk/{cve_id}` | GET | Get geo-weighted risk score |
| 14 | `/api/v1/feeds/enrich` | POST | Comprehensive finding enrichment |
| 15 | `/api/v1/feeds/stats` | GET | Get feed statistics across all categories |
| 16 | `/api/v1/feeds/refresh/all` | POST | Refresh all feed categories |
| 17 | `/api/v1/feeds/categories` | GET | List all feed categories |
| 18 | `/api/v1/feeds/sources` | GET | List all feed sources |
| 19 | `/api/v1/feeds/health` | GET | Feed health and freshness status |
| 20 | `/api/v1/feeds/scheduler/status` | GET | Feed scheduler status |

**Feed Categories (8):**
1. **Global Authoritative** - NVD, CVE Program, MITRE, CISA KEV, CERT/CC, US-CERT, ICS-CERT
2. **National CERTs** - NCSC UK, BSI, ANSSI, JPCERT, CERT-In, ACSC, SingCERT, KISA
3. **Exploit Intelligence** - Exploit-DB, Metasploit, Packet Storm, Vulners, GreyNoise, Shodan, Censys
4. **Threat Actor Intelligence** - MITRE ATT&CK, AlienVault OTX, abuse.ch, Feodo Tracker
5. **Supply-Chain & SBOM** - OSV, GitHub Advisory, Snyk, deps.dev, NPM/PyPI/RustSec
6. **Cloud & Runtime** - AWS, Azure, GCP Security Bulletins, Kubernetes CVEs, Red Hat, Ubuntu
7. **Zero-Day & Early-Signal** - Vendor blogs, GitHub commits, mailing lists
8. **Internal Enterprise** - SAST/DAST/SCA, IaC, runtime detections, exposure graph

**Key Features:**
- Geo-weighted risk scoring (exploitation differs by country/region)
- Exploit-confidence scoring (real-world exploitation vs CVSS fear-scoring)
- Threat actor to CVE mapping with sector targeting
- Reachable dependency analysis
