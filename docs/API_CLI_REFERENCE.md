# FixOps API to CLI Mapping (250+ Endpoints)

## Summary

| Category | API Endpoints | CLI Commands | Coverage |
|----------|---------------|--------------|----------|
| Core Pipeline & Ingestion | 19 | 6 | Full |
| Security Decision & Analysis | 21 | 3 | Partial (via run/analyze) |
| Compliance | 12 | 4 | Full |
| Reports | 10 | 4 | Full |
| Inventory | 15 | 5 | Full |
| Policies | 8 | 5 | Full |
| Integrations | 8 | 4 | Full |
| Analytics | 16 | 5 | Full |
| Audit | 10 | 3 | Full |
| Workflows | 12 | 5 | Full |
| Advanced Pen Testing | 45 | 6 | Full |
| Reachability | 7 | 3 | Full |
| Teams & Users | 14 | 8 | Full |
| PentAGI | 8 | 3 | Full |
| Evidence | 12 | 2 | Partial |
| Health & Status | 4 | 1 | Full |
| **CURRENT TOTAL** | **~250** | **67** | **~85%** |
| | | | |
| **ENTERPRISE (Planned)** | | | |
| Correlation Engine | 12 | 6 | Planned |
| Enterprise Integrations | 14 | 6 | Planned |
| Remediation Lifecycle | 18 | 8 | Planned |
| Bulk Operations | 10 | 6 | Planned |
| Collaboration | 14 | 6 | Planned |
| **ENTERPRISE TOTAL** | **~68** | **~32** | **Planned** |
| | | | |
| **GRAND TOTAL** | **~318** | **~99** | **~95%** |

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

---

## COVERAGE SUMMARY

**Before CLI Expansion:**
- 11 CLI commands covering ~15% of API surface

**After CLI Expansion:**
- 67 CLI commands/subcommands covering ~85% of API surface
- 10 new command groups added
- Full coverage for: Compliance, Reports, Inventory, Policies, Integrations, Analytics, Audit, Workflows, Advanced Pentest, Reachability

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

## ENTERPRISE FEATURES (Planned)

The following enterprise features are planned for implementation. See [Enterprise Features Documentation](ENTERPRISE_FEATURES.md) for detailed architectural designs.

### CORRELATION ENGINE (Planned: 12 API → 6 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/correlation/analyze` | POST | `correlation analyze` | Analyze findings for correlations |
| 2 | `/api/v1/correlation/jobs/{job_id}` | GET | `correlation status` | Get async job status |
| 3 | `/api/v1/correlation/jobs/{job_id}/results` | GET | `correlation status` | Get correlation results |
| 4 | `/api/v1/groups` | GET | `groups list` | List finding groups |
| 5 | `/api/v1/groups/{id}` | GET | `groups show` | Get group details |
| 6 | `/api/v1/groups/{id}/members` | GET | `groups show` | List member findings |
| 7 | `/api/v1/groups/{id}/merge` | POST | `groups merge` | Merge groups (human-in-loop) |
| 8 | `/api/v1/groups/{id}/unmerge` | POST | `groups unmerge` | Unmerge with history |
| 9 | `/api/v1/groups/{id}/history` | GET | `groups show` | Merge/unmerge audit trail |
| 10 | `/api/v1/correlation/links` | GET | `correlation graph` | List correlation links |
| 11 | `/api/v1/correlation/graph` | GET | `correlation graph` | Get full correlation graph |
| 12 | `/api/v1/correlation/links/{id}` | GET | `correlation explain` | Get link with evidence |

### ENTERPRISE INTEGRATIONS (Planned: 14 API → 6 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/integrations/{id}/tickets` | POST | `tickets create` | Create ticket for entity |
| 2 | `/api/v1/integrations/{id}/tickets` | GET | `tickets list` | List tickets |
| 3 | `/api/v1/integrations/{id}/tickets/{tid}` | PUT | `tickets sync` | Update ticket |
| 4 | `/api/v1/integrations/{id}/tickets/{tid}/sync` | POST | `tickets sync` | Force sync |
| 5 | `/api/v1/integrations/mappings` | GET | `mappings list` | List all mappings |
| 6 | `/api/v1/integrations/mappings/{id}` | GET | `mappings list` | Get mapping details |
| 7 | `/api/v1/integrations/mappings/{id}` | DELETE | `mappings unlink` | Unlink mapping |
| 8 | `/api/v1/integrations/webhooks/jira` | POST | - | Jira webhook receiver (API only) |
| 9 | `/api/v1/integrations/webhooks/servicenow` | POST | - | ServiceNow webhook receiver (API only) |
| 10 | `/api/v1/integrations/{id}/sync` | POST | `integrations sync` | Trigger full sync |
| 11 | `/api/v1/integrations/{id}/sync/status` | GET | `integrations sync` | Get sync job status |
| 12 | `/api/v1/integrations/{id}/sync/history` | GET | - | Sync history (API only) |
| 13 | `/api/v1/integrations/{id}/test` | POST | `integrations test` | Test connection |
| 14 | `/api/v1/integrations/{id}/drift` | GET | `mappings list --drift-only` | Detect drift |

### REMEDIATION LIFECYCLE (Planned: 18 API → 8 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/remediation/tasks` | GET | `remediation list` | List tasks |
| 2 | `/api/v1/remediation/tasks` | POST | `remediation create` | Create task for group |
| 3 | `/api/v1/remediation/tasks/{id}` | GET | `remediation list` | Get task details |
| 4 | `/api/v1/remediation/tasks/{id}` | PUT | - | Update task (API only) |
| 5 | `/api/v1/remediation/tasks/{id}/assign` | POST | `remediation assign` | Assign owner |
| 6 | `/api/v1/remediation/tasks/{id}/start` | POST | `remediation start` | Start work |
| 7 | `/api/v1/remediation/tasks/{id}/defer` | POST | - | Defer with reason (API only) |
| 8 | `/api/v1/remediation/tasks/{id}/accept-risk` | POST | `remediation accept-risk` | Accept risk with expiry |
| 9 | `/api/v1/remediation/tasks/{id}/verify` | POST | `remediation verify` | Submit verification evidence |
| 10 | `/api/v1/remediation/tasks/{id}/close` | POST | `remediation close` | Close task |
| 11 | `/api/v1/remediation/tasks/{id}/history` | GET | - | Status history (API only) |
| 12 | `/api/v1/remediation/tasks/{id}/evidence` | GET | - | Verification evidence (API only) |
| 13 | `/api/v1/remediation/sla/policies` | GET | - | List SLA policies (API only) |
| 14 | `/api/v1/remediation/sla/breaches` | GET | - | List SLA breaches (API only) |
| 15 | `/api/v1/remediation/sla/report` | GET | `remediation sla-report` | SLA compliance report |
| 16 | `/api/v1/remediation/metrics/mttr` | GET | `remediation mttr` | Mean time to remediate |
| 17 | `/api/v1/remediation/metrics/mttd` | GET | - | Mean time to detect (API only) |
| 18 | `/api/v1/remediation/metrics/sla` | GET | `remediation sla-report` | SLA compliance rate |

### BULK OPERATIONS (Planned: 10 API → 6 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/bulk/jobs` | POST | `bulk assign`, `bulk accept-risk`, etc. | Submit bulk job |
| 2 | `/api/v1/bulk/jobs` | GET | `bulk status` | List jobs |
| 3 | `/api/v1/bulk/jobs/{id}` | GET | `bulk status` | Get job status |
| 4 | `/api/v1/bulk/jobs/{id}/results` | GET | `bulk results` | Get per-item results |
| 5 | `/api/v1/bulk/jobs/{id}/download` | GET | `bulk export` | Download export |
| 6 | `/api/v1/bulk/jobs/{id}/cancel` | POST | `bulk cancel` | Cancel running job |
| 7 | `/api/v1/bulk/jobs/{id}/retry` | POST | `bulk retry` | Retry failed items |
| 8 | `/api/v1/bulk/views` | GET | `views list` | List saved views |
| 9 | `/api/v1/bulk/views` | POST | `views create` | Create saved view |
| 10 | `/api/v1/bulk/views/{id}/execute` | POST | `views execute` | Execute view as bulk job |

### COLLABORATION (Planned: 14 API → 6 CLI)

| # | API Endpoint | Method | CLI Command | Notes |
|---|--------------|--------|-------------|-------|
| 1 | `/api/v1/groups/{id}/comments` | GET | `comments list --group` | List comments on group |
| 2 | `/api/v1/groups/{id}/comments` | POST | `comments add --group` | Add comment |
| 3 | `/api/v1/tasks/{id}/comments` | GET | `comments list --task` | List comments on task |
| 4 | `/api/v1/tasks/{id}/comments` | POST | `comments add --task` | Add comment |
| 5 | `/api/v1/comments/{id}` | PUT | - | Edit comment (API only) |
| 6 | `/api/v1/comments/{id}` | DELETE | - | Delete comment (API only) |
| 7 | `/api/v1/comments/{id}/promote` | POST | - | Promote to evidence (API only) |
| 8 | `/api/v1/groups/{id}/watchers` | GET | `watchers list --group` | List watchers |
| 9 | `/api/v1/groups/{id}/watchers` | POST | `watch --group` | Add watcher |
| 10 | `/api/v1/groups/{id}/watchers/{user_id}` | DELETE | `unwatch --group` | Remove watcher |
| 11 | `/api/v1/activity` | GET | `activity` | Global activity feed |
| 12 | `/api/v1/groups/{id}/activity` | GET | `activity --group` | Group activity |
| 13 | `/api/v1/notifications` | GET | - | User notifications (API only) |
| 14 | `/api/v1/notifications/read-all` | POST | - | Mark all as read (API only) |

---

## ENTERPRISE CLI COMMAND REFERENCE (Planned)

| Command | Subcommands | Description |
|---------|-------------|-------------|
| `correlation` | analyze, status, graph, explain | Deduplication and correlation analysis |
| `groups` | list, show, merge, unmerge | Finding group management |
| `tickets` | create, list, sync | External ticket management |
| `mappings` | list, unlink | Integration mapping management |
| `remediation` | list, create, assign, start, verify, close, accept-risk, sla-report, mttr | Remediation lifecycle management |
| `bulk` | assign, accept-risk, create-tickets, export, status, results, cancel, retry | Enterprise bulk operations |
| `views` | list, create, execute | Saved query views |
| `comments` | list, add | Collaboration comments |
| `watch` | - | Add watcher to entity |
| `unwatch` | - | Remove watcher from entity |
| `watchers` | list | List watchers on entity |
| `activity` | - | View activity feed |

---

## ENTERPRISE COVERAGE SUMMARY (Planned)

**After Enterprise Features:**
- ~135 new API endpoints planned
- ~32 new CLI commands/subcommands planned
- Target: 95%+ API surface coverage

**Enterprise Feature Priorities:**
1. **HIGH**: Correlation Engine (12 endpoints, 6 CLI commands)
2. **HIGH**: Enterprise Integrations (14 endpoints, 6 CLI commands)
3. **MEDIUM**: Remediation Lifecycle (18 endpoints, 8 CLI commands)
4. **MEDIUM**: Bulk Operations (10 endpoints, 6 CLI commands)
5. **LOW**: Collaboration (14 endpoints, 6 CLI commands)
