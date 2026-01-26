# FixOps API-to-CLI Coverage Analysis

## Coverage Summary

| Metric | Count |
| --- | --- |
| Total API Endpoints | 243 |
| CLI Commands/Subcommands | 69 |
| API Endpoints with CLI Coverage | 156 (~64%) |
| API-Only Endpoints | 87 (~36%) |

This inventory mirrors the documented mapping across core, backend, and enterprise routers. The core OSS inventory still reports 137 endpoints; the 243 figure reflects the broader surface area including backend and enterprise routes. Align on the public-facing number based on the target audience and SKU.

---

## Core Ingestion (15 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 1 | GET | `/api/v1/status` | `health` | Any |
| 2 | POST | `/inputs/design` | `run --design`, `stage-run --stage design` | Design |
| 3 | POST | `/inputs/sbom` | `run --sbom`, `stage-run --stage build` | Build |
| 4 | POST | `/inputs/cve` | `run --cve` | Test |
| 5 | POST | `/inputs/vex` | `run --vex` | Test |
| 6 | POST | `/inputs/cnapp` | `run --cnapp` | Deploy |
| 7 | POST | `/inputs/sarif` | `run --sarif`, `stage-run --stage test` | Test |
| 8 | POST | `/inputs/context` | `run --context` | Design |
| 9-12 | Various | `/inputs/{stage}/chunks/*` | API-only (streaming) | Any |
| 13-15 | GET | `/api/v1/triage/*`, `/api/v1/graph` | API-only (UI) | Decision |

---

## Pipeline Execution (4 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 16 | GET | `/pipeline/run` | `run`, `make-decision`, `ingest`, `analyze` | Release Gate |
| 17 | GET | `/analytics/dashboard` | `analytics dashboard` | Monitor |
| 18-19 | Various | `/analytics/runs/*`, `/feedback` | API-only | Monitor |

---

## Analytics (16 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 24-27 | GET | `/api/v1/analytics/dashboard/*` | `analytics dashboard` | Monitor |
| 34 | GET | `/api/v1/analytics/mttr` | `analytics mttr` | Monitor |
| 35 | GET | `/api/v1/analytics/coverage` | `analytics coverage` | Monitor |
| 36 | GET | `/api/v1/analytics/roi` | `analytics roi` | Monitor |
| 39 | GET | `/api/v1/analytics/export` | `analytics export` | Monitor |

---

## Audit (10 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 40-41 | GET | `/api/v1/audit/logs`, `/api/v1/audit/logs/{id}` | `audit logs` | Audit |
| 42-43 | GET | `/api/v1/audit/user-activity`, `/api/v1/audit/policy-changes` | `audit logs --type` | Audit |
| 44 | GET | `/api/v1/audit/decision-trail` | `audit decisions` | Audit |
| 45 | GET | `/api/v1/audit/compliance/frameworks` | `compliance frameworks` | Audit |
| 46 | GET | `/api/v1/audit/compliance/frameworks/{id}/status` | `compliance status {framework}` | Audit |
| 47 | GET | `/api/v1/audit/compliance/frameworks/{id}/gaps` | `compliance gaps {framework}` | Audit |
| 48 | POST | `/api/v1/audit/compliance/frameworks/{id}/report` | `compliance report {framework}` | Audit |

---

## Reports (9 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 50 | GET | `/api/v1/reports` | `reports list` | Audit |
| 51 | POST | `/api/v1/reports` | `reports generate` | Audit |
| 53 | GET | `/api/v1/reports/{id}/download` | `reports export` | Audit |
| 55 | GET | `/api/v1/reports/schedules/list` | `reports schedules` | Audit |

---

## Teams (8 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 59 | GET | `/api/v1/teams` | `teams list` | Admin |
| 60 | POST | `/api/v1/teams` | `teams create` | Admin |
| 61 | GET | `/api/v1/teams/{id}` | `teams get {id}` | Admin |

---

## Users (6 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 68 | GET | `/api/v1/users` | `users list` | Admin |
| 69 | POST | `/api/v1/users` | `users create` | Admin |
| 70 | GET | `/api/v1/users/{id}` | `users get {id}` | Admin |

---

## Policies (8 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 73 | GET | `/api/v1/policies` | `policies list` | Design |
| 74 | POST | `/api/v1/policies` | `policies create` | Design |
| 75 | GET | `/api/v1/policies/{id}` | `policies get {id}` | Design |
| 78 | POST | `/api/v1/policies/{id}/validate` | `policies validate {id}` | Design |
| 79 | POST | `/api/v1/policies/{id}/test` | `policies test {id}` | Design |

---

## Integrations (8 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 81 | GET | `/api/v1/integrations` | `integrations list` | Admin |
| 82-84 | POST/PUT | `/api/v1/integrations`, `/api/v1/integrations/{id}` | `integrations configure` | Admin |
| 86 | POST | `/api/v1/integrations/{id}/test` | `integrations test {name}` | Admin |
| 88 | POST | `/api/v1/integrations/{id}/sync` | `integrations sync {name}` | Admin |

---

## Workflows (7 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 89 | GET | `/api/v1/workflows` | `workflows list` | Admin |
| 90 | POST | `/api/v1/workflows` | `workflows create` | Admin |
| 91 | GET | `/api/v1/workflows/{id}` | `workflows get {id}` | Admin |
| 94 | POST | `/api/v1/workflows/{id}/execute` | `workflows execute {id}` | Admin |
| 95 | GET | `/api/v1/workflows/{id}/history` | `workflows history {id}` | Admin |

---

## Inventory (15 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 96 | GET | `/api/v1/inventory/applications` | `inventory apps` | Design |
| 97 | POST | `/api/v1/inventory/applications` | `inventory add` | Design |
| 98 | GET | `/api/v1/inventory/applications/{id}` | `inventory get {id}` | Design |
| 104 | GET | `/api/v1/inventory/services` | `inventory services` | Design |
| 110 | GET | `/api/v1/inventory/search` | `inventory search` | Design |

---

## PentAGI (14 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 111 | GET | `/api/v1/pentagi/requests` | `pentagi list-requests` | Test |
| 112 | POST | `/api/v1/pentagi/requests` | `pentagi create-request` | Test |
| 113 | GET | `/api/v1/pentagi/requests/{id}` | `pentagi get-request {id}` | Test |
| 117 | GET | `/api/v1/pentagi/results` | `pentagi list-results` | Test |

---

## Advanced Pen Testing (19 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 139 | POST | `/api/v1/pentagi/verify` | `advanced-pentest run` | Test |
| 142 | GET | `/api/v1/pentagi/findings/{id}/exploitability` | `advanced-pentest threat-intel` | Test |
| - | Various | Enterprise APIs | `advanced-pentest business-impact` | Test |
| - | Various | Enterprise APIs | `advanced-pentest simulate` | Test |
| - | Various | Enterprise APIs | `advanced-pentest remediation` | Test |
| 22 | GET | `/api/v1/enhanced/capabilities` | `advanced-pentest capabilities` | Decision |

---

## Reachability (7 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 194 | GET | `/api/v1/risk/` | `reachability analyze` | Test |
| 196 | GET | `/api/v1/risk/cve/{cve_id}` | `reachability analyze {cve}` | Test |
| - | GET | Multiple risk endpoints | `reachability bulk {cves}` | Test |

---

## Evidence (3 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 197 | GET | `/api/v1/evidence/` | `get-evidence` | Audit |
| 198 | GET | `/api/v1/evidence/{release}` | `get-evidence --run` | Audit |

---

## Health (5 endpoints)

| # | Method | Endpoint | CLI Command | Stage |
| --- | --- | --- | --- | --- |
| 154-156 | GET | `/health`, `/api/v1/health/*` | `health` | Any |

---

## CLI Command Summary (69 total)

| Category | Commands | Count |
| --- | --- | --- |
| Core Pipeline | `run`, `make-decision`, `ingest`, `analyze`, `stage-run`, `get-evidence` | 11 |
| Compliance | `compliance frameworks/status/gaps/report` | 4 |
| Reports | `reports list/generate/export/schedules` | 4 |
| Inventory | `inventory apps/add/get/services/search` | 5 |
| Policies | `policies list/get/create/validate/test` | 5 |
| Integrations | `integrations list/configure/test/sync` | 4 |
| Analytics | `analytics dashboard/mttr/coverage/roi/export` | 5 |
| Audit | `audit logs/decisions/export` | 3 |
| Workflows | `workflows list/get/create/execute/history` | 5 |
| Advanced Pentest | `advanced-pentest run/threat-intel/business-impact/simulate/remediation/capabilities` | 6 |
| Reachability | `reachability analyze/bulk/status` | 3 |
| Teams | `teams list/get/create` | 3 |
| Users | `users list/get/create` | 3 |
| PentAGI | `pentagi list-requests/create-request/get-request/list-results` | 4 |
| Utility | `health`, `show-overlay`, `demo`, `train-forecast` | 4 |

---

## API-Only Features (Not in CLI)

| Category | Count | Reason |
| --- | --- | --- |
| Chunked Uploads | 4 | Large file streaming |
| Graph Visualization | 4 | Interactive UI required |
| Bulk Operations | 5 | Complex batch operations |
| IDE Integration | 3 | Real-time code analysis |
| Marketplace | 12 | E-commerce features |
| SSO/Auth | 4 | OAuth browser flows |
| Webhooks | 7 | Event-driven configuration |
