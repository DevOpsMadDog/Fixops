# Complete FixOps API to CLI Mapping

## Coverage Summary

| Metric | Count |
|--------|-------|
| **Total API Endpoints** | 243 |
| **CLI Commands/Subcommands** | 67 |
| **API Endpoints with CLI Coverage** | 156 (~64%) |
| **API-Only Endpoints** | 87 (~36%) |

### Why Some APIs Don't Have CLI Coverage

| Category | Count | Reason |
|----------|-------|--------|
| Chunked Uploads | 4 | Large file handling requires streaming, better suited for API |
| Graph Visualization | 4 | Interactive visualization requires UI |
| Bulk Operations | 5 | Complex batch operations with progress tracking |
| IDE Integration | 3 | Real-time code analysis for IDE plugins |
| Marketplace | 12 | E-commerce features (purchase, download, rate) |
| SSO/Auth | 4 | OAuth flows require browser redirects |
| Real-time Monitoring | 3 | WebSocket/streaming connections |
| Enterprise-only | 45 | Advanced pen testing, requires enterprise license |
| Webhooks | 7 | Event-driven, configured via UI |

---

## Complete API Endpoint List by Router

### 1. Core Ingestion (apps/api/app.py) - 15 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 1 | GET | `/api/v1/status` | `health` | Any |
| 2 | POST | `/inputs/design` | `run --design`, `stage-run --stage design` | Design |
| 3 | POST | `/inputs/sbom` | `run --sbom`, `stage-run --stage build` | Build |
| 4 | POST | `/inputs/cve` | `run --cve` | Test |
| 5 | POST | `/inputs/vex` | `run --vex` | Test |
| 6 | POST | `/inputs/cnapp` | `run --cnapp` | Deploy |
| 7 | POST | `/inputs/sarif` | `run --sarif`, `stage-run --stage test` | Test |
| 8 | POST | `/inputs/context` | `run --context` | Design |
| 9 | POST | `/inputs/{stage}/chunks/start` | API-only | Any |
| 10 | PUT | `/inputs/{stage}/chunks/append` | API-only | Any |
| 11 | POST | `/inputs/{stage}/chunks/complete` | API-only | Any |
| 12 | GET | `/inputs/{stage}/chunks/status` | API-only | Any |
| 13 | GET | `/api/v1/triage` | API-only (UI) | Decision |
| 14 | GET | `/api/v1/triage/export` | API-only (UI) | Decision |
| 15 | GET | `/api/v1/graph` | API-only (visualization) | Decision |

### 2. Pipeline Execution (apps/api/pipeline.py) - 3 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 16 | GET | `/pipeline/run` | `run`, `make-decision`, `ingest`, `analyze` | Release Gate |
| 17 | GET | `/analytics/dashboard` | `analytics dashboard` | Monitor |
| 18 | GET | `/analytics/runs/{run_id}` | API-only | Monitor |
| 19 | POST | `/feedback` | API-only | Monitor |

### 3. Enhanced Decision Engine (apps/api/routes/enhanced.py) - 4 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 20 | POST | `/api/v1/enhanced/analysis` | `run` (internal) | Decision |
| 21 | POST | `/api/v1/enhanced/compare-llms` | `run` (internal) | Decision |
| 22 | GET | `/api/v1/enhanced/capabilities` | `advanced-pentest capabilities` | Decision |
| 23 | GET | `/api/v1/enhanced/signals` | API-only | Decision |

### 4. Analytics (apps/api/analytics_router.py) - 14 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 24 | GET | `/api/v1/analytics/dashboard/overview` | `analytics dashboard` | Monitor |
| 25 | GET | `/api/v1/analytics/dashboard/trends` | `analytics dashboard` | Monitor |
| 26 | GET | `/api/v1/analytics/dashboard/top-risks` | `analytics dashboard` | Monitor |
| 27 | GET | `/api/v1/analytics/dashboard/compliance-status` | `analytics dashboard` | Monitor |
| 28 | GET | `/api/v1/analytics/findings` | `analytics dashboard` | Monitor |
| 29 | POST | `/api/v1/analytics/findings` | API-only | Monitor |
| 30 | GET | `/api/v1/analytics/findings/{id}` | API-only | Monitor |
| 31 | PUT | `/api/v1/analytics/findings/{id}` | API-only | Monitor |
| 32 | GET | `/api/v1/analytics/decisions` | `audit decisions` | Monitor |
| 33 | POST | `/api/v1/analytics/decisions` | API-only | Monitor |
| 34 | GET | `/api/v1/analytics/mttr` | `analytics mttr` | Monitor |
| 35 | GET | `/api/v1/analytics/coverage` | `analytics coverage` | Monitor |
| 36 | GET | `/api/v1/analytics/roi` | `analytics roi` | Monitor |
| 37 | GET | `/api/v1/analytics/noise-reduction` | `analytics dashboard` | Monitor |
| 38 | POST | `/api/v1/analytics/custom-query` | API-only | Monitor |
| 39 | GET | `/api/v1/analytics/export` | `analytics export` | Monitor |

### 5. Audit (apps/api/audit_router.py) - 10 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 40 | GET | `/api/v1/audit/logs` | `audit logs` | Audit |
| 41 | GET | `/api/v1/audit/logs/{id}` | `audit logs` | Audit |
| 42 | GET | `/api/v1/audit/user-activity` | `audit logs --type user` | Audit |
| 43 | GET | `/api/v1/audit/policy-changes` | `audit logs --type policy` | Audit |
| 44 | GET | `/api/v1/audit/decision-trail` | `audit decisions` | Audit |
| 45 | GET | `/api/v1/audit/compliance/frameworks` | `compliance frameworks` | Audit |
| 46 | GET | `/api/v1/audit/compliance/frameworks/{id}/status` | `compliance status {framework}` | Audit |
| 47 | GET | `/api/v1/audit/compliance/frameworks/{id}/gaps` | `compliance gaps {framework}` | Audit |
| 48 | POST | `/api/v1/audit/compliance/frameworks/{id}/report` | `compliance report {framework}` | Audit |
| 49 | GET | `/api/v1/audit/compliance/controls` | `compliance status {framework}` | Audit |

### 6. Reports (apps/api/reports_router.py) - 9 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 50 | GET | `/api/v1/reports` | `reports list` | Audit |
| 51 | POST | `/api/v1/reports` | `reports generate` | Audit |
| 52 | GET | `/api/v1/reports/{id}` | `reports list` | Audit |
| 53 | GET | `/api/v1/reports/{id}/download` | `reports export {id}` | Audit |
| 54 | POST | `/api/v1/reports/schedule` | API-only | Audit |
| 55 | GET | `/api/v1/reports/schedules/list` | `reports schedules` | Audit |
| 56 | GET | `/api/v1/reports/templates/list` | `reports generate --type` | Audit |
| 57 | POST | `/api/v1/reports/export/sarif` | API-only | Audit |
| 58 | POST | `/api/v1/reports/export/csv` | API-only | Audit |

### 7. Teams (apps/api/teams_router.py) - 8 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 59 | GET | `/api/v1/teams` | `teams list` | Admin |
| 60 | POST | `/api/v1/teams` | `teams create` | Admin |
| 61 | GET | `/api/v1/teams/{id}` | `teams get {id}` | Admin |
| 62 | PUT | `/api/v1/teams/{id}` | API-only | Admin |
| 63 | DELETE | `/api/v1/teams/{id}` | API-only | Admin |
| 64 | GET | `/api/v1/teams/{id}/members` | `teams get {id}` | Admin |
| 65 | POST | `/api/v1/teams/{id}/members` | API-only | Admin |
| 66 | DELETE | `/api/v1/teams/{id}/members/{user_id}` | API-only | Admin |

### 8. Users (apps/api/users_router.py) - 6 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 67 | POST | `/api/v1/users/login` | API-only (auth) | Admin |
| 68 | GET | `/api/v1/users` | `users list` | Admin |
| 69 | POST | `/api/v1/users` | `users create` | Admin |
| 70 | GET | `/api/v1/users/{id}` | `users get {id}` | Admin |
| 71 | PUT | `/api/v1/users/{id}` | API-only | Admin |
| 72 | DELETE | `/api/v1/users/{id}` | API-only | Admin |

### 9. Policies (apps/api/policies_router.py) - 8 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 73 | GET | `/api/v1/policies` | `policies list` | Design |
| 74 | POST | `/api/v1/policies` | `policies create` | Design |
| 75 | GET | `/api/v1/policies/{id}` | `policies get {id}` | Design |
| 76 | PUT | `/api/v1/policies/{id}` | API-only | Design |
| 77 | DELETE | `/api/v1/policies/{id}` | API-only | Design |
| 78 | POST | `/api/v1/policies/{id}/validate` | `policies validate {id}` | Design |
| 79 | POST | `/api/v1/policies/{id}/test` | `policies test {id}` | Design |
| 80 | GET | `/api/v1/policies/{id}/violations` | API-only | Monitor |

### 10. Integrations (apps/api/integrations_router.py) - 8 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 81 | GET | `/api/v1/integrations` | `integrations list` | Admin |
| 82 | POST | `/api/v1/integrations` | `integrations configure` | Admin |
| 83 | GET | `/api/v1/integrations/{id}` | `integrations list` | Admin |
| 84 | PUT | `/api/v1/integrations/{id}` | `integrations configure` | Admin |
| 85 | DELETE | `/api/v1/integrations/{id}` | API-only | Admin |
| 86 | POST | `/api/v1/integrations/{id}/test` | `integrations test {name}` | Admin |
| 87 | GET | `/api/v1/integrations/{id}/sync-status` | API-only | Admin |
| 88 | POST | `/api/v1/integrations/{id}/sync` | `integrations sync {name}` | Admin |

### 11. Workflows (apps/api/workflows_router.py) - 7 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 89 | GET | `/api/v1/workflows` | `workflows list` | Admin |
| 90 | POST | `/api/v1/workflows` | `workflows create` | Admin |
| 91 | GET | `/api/v1/workflows/{id}` | `workflows get {id}` | Admin |
| 92 | PUT | `/api/v1/workflows/{id}` | API-only | Admin |
| 93 | DELETE | `/api/v1/workflows/{id}` | API-only | Admin |
| 94 | POST | `/api/v1/workflows/{id}/execute` | `workflows execute {id}` | Admin |
| 95 | GET | `/api/v1/workflows/{id}/history` | `workflows history {id}` | Admin |

### 12. Inventory (apps/api/inventory_router.py) - 15 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 96 | GET | `/api/v1/inventory/applications` | `inventory apps` | Design |
| 97 | POST | `/api/v1/inventory/applications` | `inventory add` | Design |
| 98 | GET | `/api/v1/inventory/applications/{id}` | `inventory get {id}` | Design |
| 99 | PUT | `/api/v1/inventory/applications/{id}` | API-only | Design |
| 100 | DELETE | `/api/v1/inventory/applications/{id}` | API-only | Design |
| 101 | GET | `/api/v1/inventory/applications/{id}/components` | API-only | Build |
| 102 | GET | `/api/v1/inventory/applications/{id}/apis` | API-only | Build |
| 103 | GET | `/api/v1/inventory/applications/{id}/dependencies` | API-only | Build |
| 104 | GET | `/api/v1/inventory/services` | `inventory services` | Design |
| 105 | POST | `/api/v1/inventory/services` | API-only | Design |
| 106 | GET | `/api/v1/inventory/services/{id}` | `inventory get {id}` | Design |
| 107 | GET | `/api/v1/inventory/apis` | API-only | Design |
| 108 | POST | `/api/v1/inventory/apis` | API-only | Design |
| 109 | GET | `/api/v1/inventory/apis/{id}/security` | API-only | Test |
| 110 | GET | `/api/v1/inventory/search` | `inventory search` | Design |

### 13. PentAGI (apps/api/pentagi_router.py) - 14 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 111 | GET | `/api/v1/pentagi/requests` | `pentagi list` | Test |
| 112 | POST | `/api/v1/pentagi/requests` | `pentagi create` | Test |
| 113 | GET | `/api/v1/pentagi/requests/{request_id}` | `pentagi status {id}` | Test |
| 114 | PUT | `/api/v1/pentagi/requests/{request_id}` | API-only | Test |
| 115 | POST | `/api/v1/pentagi/requests/{request_id}/start` | API-only | Test |
| 116 | POST | `/api/v1/pentagi/requests/{request_id}/cancel` | API-only | Test |
| 117 | GET | `/api/v1/pentagi/results` | `pentagi status {id}` | Test |
| 118 | POST | `/api/v1/pentagi/results` | API-only | Test |
| 119 | GET | `/api/v1/pentagi/results/by-request/{request_id}` | `pentagi status {id}` | Test |
| 120 | GET | `/api/v1/pentagi/configs` | API-only | Admin |
| 121 | POST | `/api/v1/pentagi/configs` | API-only | Admin |
| 122 | GET | `/api/v1/pentagi/configs/{config_id}` | API-only | Admin |
| 123 | PUT | `/api/v1/pentagi/configs/{config_id}` | API-only | Admin |
| 124 | DELETE | `/api/v1/pentagi/configs/{config_id}` | API-only | Admin |

### 14. Enhanced PentAGI (apps/api/pentagi_router_enhanced.py) - 19 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 125-138 | (same as above) | (same as above) | (same as above) | Test |
| 139 | POST | `/api/v1/pentagi/verify` | `advanced-pentest run` | Test |
| 140 | POST | `/api/v1/pentagi/monitoring` | API-only | Monitor |
| 141 | POST | `/api/v1/pentagi/scan/comprehensive` | `advanced-pentest run` | Test |
| 142 | GET | `/api/v1/pentagi/findings/{finding_id}/exploitability` | `advanced-pentest threat-intel` | Test |
| 143 | GET | `/api/v1/pentagi/stats` | API-only | Monitor |

### 15. IaC Findings (apps/api/iac_router.py) - 5 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 144 | GET | `/api/v1/iac` | API-only | Deploy |
| 145 | POST | `/api/v1/iac` | API-only | Deploy |
| 146 | GET | `/api/v1/iac/{id}` | API-only | Deploy |
| 147 | POST | `/api/v1/iac/{id}/resolve` | API-only | Deploy |
| 148 | POST | `/api/v1/iac/scan` | `stage-run --stage deploy` | Deploy |

### 16. Secrets Findings (apps/api/secrets_router.py) - 5 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 149 | GET | `/api/v1/secrets` | API-only | Test |
| 150 | POST | `/api/v1/secrets` | API-only | Test |
| 151 | GET | `/api/v1/secrets/{id}` | API-only | Test |
| 152 | POST | `/api/v1/secrets/{id}/resolve` | API-only | Test |
| 153 | POST | `/api/v1/secrets/scan` | API-only | Test |

### 17. Health (apps/api/health.py + health_router.py) - 5 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 154 | GET | `/health` | `health` | Any |
| 155 | GET | `/api/v1/health/health` | `health` | Any |
| 156 | GET | `/api/v1/health/ready` | `health` | Any |
| 157 | GET | `/api/v1/health/version` | API-only | Any |
| 158 | GET | `/api/v1/health/metrics` | API-only | Monitor |

### 18. IDE Integration (apps/api/ide_router.py) - 3 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 159 | GET | `/api/v1/ide/config` | API-only (IDE plugin) | Build |
| 160 | POST | `/api/v1/ide/analyze` | API-only (IDE plugin) | Build |
| 161 | GET | `/api/v1/ide/suggestions` | API-only (IDE plugin) | Build |

### 19. Bulk Operations (apps/api/bulk_router.py) - 5 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 162 | POST | `/api/v1/bulk/findings/update` | API-only | Admin |
| 163 | POST | `/api/v1/bulk/findings/delete` | API-only | Admin |
| 164 | POST | `/api/v1/bulk/findings/assign` | API-only | Admin |
| 165 | POST | `/api/v1/bulk/policies/apply` | API-only | Admin |
| 166 | POST | `/api/v1/bulk/export` | API-only | Audit |

### 20. Marketplace (apps/api/marketplace_router.py) - 12 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 167 | GET | `/api/v1/marketplace/packs/{framework}/{control}` | API-only | Admin |
| 168 | GET | `/api/v1/marketplace/browse` | API-only | Admin |
| 169 | GET | `/api/v1/marketplace/recommendations` | API-only | Admin |
| 170 | GET | `/api/v1/marketplace/items/{item_id}` | API-only | Admin |
| 171 | POST | `/api/v1/marketplace/contribute` | API-only | Admin |
| 172 | PUT | `/api/v1/marketplace/items/{item_id}` | API-only | Admin |
| 173 | POST | `/api/v1/marketplace/items/{item_id}/rate` | API-only | Admin |
| 174 | POST | `/api/v1/marketplace/purchase/{item_id}` | API-only | Admin |
| 175 | GET | `/api/v1/marketplace/download/{token}` | API-only | Admin |
| 176 | GET | `/api/v1/marketplace/contributors` | API-only | Admin |
| 177 | GET | `/api/v1/marketplace/compliance-content/{stage}` | API-only | Admin |
| 178 | GET | `/api/v1/marketplace/stats` | API-only | Admin |

### 21. SSO/Auth (apps/api/auth_router.py) - 4 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 179 | GET | `/api/v1/auth/sso` | API-only (OAuth) | Admin |
| 180 | POST | `/api/v1/auth/sso` | API-only (OAuth) | Admin |
| 181 | GET | `/api/v1/auth/sso/{id}` | API-only (OAuth) | Admin |
| 182 | PUT | `/api/v1/auth/sso/{id}` | API-only (OAuth) | Admin |

### 22. Backend APIs (backend/api/) - 16 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 183 | GET | `/api/v1/provenance/` | API-only | Build |
| 184 | GET | `/api/v1/provenance/{artifact_name}` | API-only | Build |
| 185 | GET | `/api/v1/pentagi/requests` | `pentagi list` | Test |
| 186 | GET | `/api/v1/pentagi/requests/{request_id}` | `pentagi status {id}` | Test |
| 187 | POST | `/api/v1/pentagi/requests` | `pentagi create` | Test |
| 188 | PATCH | `/api/v1/pentagi/requests/{request_id}` | API-only | Test |
| 189 | DELETE | `/api/v1/pentagi/requests/{request_id}` | API-only | Test |
| 190 | GET | `/api/v1/graph/` | API-only (visualization) | Decision |
| 191 | GET | `/api/v1/graph/lineage/{artifact_name}` | API-only (visualization) | Decision |
| 192 | GET | `/api/v1/graph/kev-components` | API-only | Decision |
| 193 | GET | `/api/v1/graph/anomalies` | API-only | Monitor |
| 194 | GET | `/api/v1/risk/` | `reachability analyze` | Test |
| 195 | GET | `/api/v1/risk/component/{component_slug}` | `reachability analyze` | Test |
| 196 | GET | `/api/v1/risk/cve/{cve_id}` | `reachability analyze {cve}` | Test |
| 197 | GET | `/api/v1/evidence/` | `get-evidence` | Audit |
| 198 | GET | `/api/v1/evidence/{release}` | `get-evidence` | Audit |
| 199 | GET | `/api/v1/evidence/bundles/{bundle_id}/download` | `copy-evidence` | Audit |

### 23. Enterprise APIs (fixops-enterprise/src/api/v1/) - 45 endpoints

| # | Method | Endpoint | CLI Command | Workflow Stage |
|---|--------|----------|-------------|----------------|
| 200-210 | Various | `/api/v1/enterprise/pentest/*` | `advanced-pentest run` | Test |
| 211-220 | Various | `/api/v1/enterprise/threat-intel/*` | `advanced-pentest threat-intel` | Test |
| 221-230 | Various | `/api/v1/enterprise/attack-simulation/*` | `advanced-pentest simulate` | Test |
| 231-240 | Various | `/api/v1/enterprise/remediation/*` | `advanced-pentest remediation` | Test |
| 241-243 | Various | `/api/v1/enterprise/business-impact/*` | `advanced-pentest business-impact` | Test |

---

## CLI Command Reference (67 Commands)

### Core Pipeline Commands (11)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `run` | - | `POST /inputs/* + GET /pipeline/run` | Full pipeline execution |
| `make-decision` | - | `POST /inputs/* + GET /pipeline/run` | Pipeline with exit code |
| `ingest` | - | `POST /inputs/*` | Normalize artifacts |
| `analyze` | - | `GET /pipeline/run` | Analyze with verdict |
| `stage-run` | `--stage design` | `POST /inputs/design` | Design stage |
| `stage-run` | `--stage build` | `POST /inputs/sbom` | Build stage |
| `stage-run` | `--stage test` | `POST /inputs/sarif` | Test stage |
| `stage-run` | `--stage deploy` | `POST /inputs/cnapp` | Deploy stage |
| `stage-run` | `--stage decision` | `GET /pipeline/run` | Decision stage |
| `get-evidence` | - | `GET /api/v1/evidence/*` | Retrieve evidence |
| `copy-evidence` | - | `GET /api/v1/evidence/bundles/{id}/download` | Export evidence |

### Compliance Commands (4)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `compliance` | `frameworks` | `GET /api/v1/audit/compliance/frameworks` | List frameworks |
| `compliance` | `status {framework}` | `GET /api/v1/audit/compliance/frameworks/{id}/status` | Framework status |
| `compliance` | `gaps {framework}` | `GET /api/v1/audit/compliance/frameworks/{id}/gaps` | Compliance gaps |
| `compliance` | `report {framework}` | `POST /api/v1/audit/compliance/frameworks/{id}/report` | Generate report |

### Reports Commands (4)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `reports` | `list` | `GET /api/v1/reports` | List reports |
| `reports` | `generate` | `POST /api/v1/reports` | Generate report |
| `reports` | `export {id}` | `GET /api/v1/reports/{id}/download` | Download report |
| `reports` | `schedules` | `GET /api/v1/reports/schedules/list` | List schedules |

### Inventory Commands (5)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `inventory` | `apps` | `GET /api/v1/inventory/applications` | List applications |
| `inventory` | `add` | `POST /api/v1/inventory/applications` | Add application |
| `inventory` | `get {id}` | `GET /api/v1/inventory/applications/{id}` | Get application |
| `inventory` | `services` | `GET /api/v1/inventory/services` | List services |
| `inventory` | `search` | `GET /api/v1/inventory/search` | Search inventory |

### Policies Commands (5)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `policies` | `list` | `GET /api/v1/policies` | List policies |
| `policies` | `get {id}` | `GET /api/v1/policies/{id}` | Get policy |
| `policies` | `create` | `POST /api/v1/policies` | Create policy |
| `policies` | `validate {id}` | `POST /api/v1/policies/{id}/validate` | Validate policy |
| `policies` | `test {id}` | `POST /api/v1/policies/{id}/test` | Test policy |

### Integrations Commands (4)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `integrations` | `list` | `GET /api/v1/integrations` | List integrations |
| `integrations` | `configure` | `POST/PUT /api/v1/integrations` | Configure integration |
| `integrations` | `test {name}` | `POST /api/v1/integrations/{id}/test` | Test connection |
| `integrations` | `sync {name}` | `POST /api/v1/integrations/{id}/sync` | Sync data |

### Analytics Commands (5)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `analytics` | `dashboard` | `GET /api/v1/analytics/dashboard/*` | Dashboard metrics |
| `analytics` | `mttr` | `GET /api/v1/analytics/mttr` | Mean time to remediate |
| `analytics` | `coverage` | `GET /api/v1/analytics/coverage` | Scan coverage |
| `analytics` | `roi` | `GET /api/v1/analytics/roi` | ROI analysis |
| `analytics` | `export` | `GET /api/v1/analytics/export` | Export analytics |

### Audit Commands (3)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `audit` | `logs` | `GET /api/v1/audit/logs` | List audit logs |
| `audit` | `decisions` | `GET /api/v1/audit/decision-trail` | Decision audit trail |
| `audit` | `export` | `GET /api/v1/audit/logs` + file export | Export audit logs |

### Workflows Commands (5)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `workflows` | `list` | `GET /api/v1/workflows` | List workflows |
| `workflows` | `get {id}` | `GET /api/v1/workflows/{id}` | Get workflow |
| `workflows` | `create` | `POST /api/v1/workflows` | Create workflow |
| `workflows` | `execute {id}` | `POST /api/v1/workflows/{id}/execute` | Execute workflow |
| `workflows` | `history {id}` | `GET /api/v1/workflows/{id}/history` | Execution history |

### Advanced Pen Testing Commands (6)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `advanced-pentest` | `run` | `POST /api/v1/pentagi/verify` | Run pen test |
| `advanced-pentest` | `threat-intel {cve}` | `GET /api/v1/pentagi/findings/{id}/exploitability` | Threat intelligence |
| `advanced-pentest` | `business-impact` | Enterprise API | Business impact analysis |
| `advanced-pentest` | `simulate` | Enterprise API | Attack simulation |
| `advanced-pentest` | `remediation {cve}` | Enterprise API | Remediation guidance |
| `advanced-pentest` | `capabilities` | `GET /api/v1/enhanced/capabilities` | List capabilities |

### Reachability Commands (3)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `reachability` | `analyze {cve}` | `GET /api/v1/risk/cve/{cve_id}` | Analyze reachability |
| `reachability` | `bulk {cves}` | `GET /api/v1/risk/*` (multiple) | Bulk analysis |
| `reachability` | `status {job_id}` | API-only | Job status |

### Teams Commands (3)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `teams` | `list` | `GET /api/v1/teams` | List teams |
| `teams` | `get {id}` | `GET /api/v1/teams/{id}` | Get team |
| `teams` | `create` | `POST /api/v1/teams` | Create team |

### Users Commands (4)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `users` | `list` | `GET /api/v1/users` | List users |
| `users` | `get {id}` | `GET /api/v1/users/{id}` | Get user |
| `users` | `create` | `POST /api/v1/users` | Create user |
| `users` | `reset-password {id}` | `PUT /api/v1/users/{id}` | Reset password |

### PentAGI Commands (3)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `pentagi` | `list` | `GET /api/v1/pentagi/requests` | List requests |
| `pentagi` | `create` | `POST /api/v1/pentagi/requests` | Create request |
| `pentagi` | `status {id}` | `GET /api/v1/pentagi/requests/{id}` | Get status |

### Utility Commands (5)

| Command | Subcommand | API Equivalent | Description |
|---------|------------|----------------|-------------|
| `health` | - | `GET /health` | Health check |
| `show-overlay` | - | Local config | Show configuration |
| `demo` | - | All ingestion + pipeline | Run demo mode |
| `train-forecast` | - | `POST /api/v1/analytics/train` | Train model |

---

## End-to-End Workflow Integration

### Design Phase
```bash
# CLI
python -m core.cli stage-run --stage design --input design.csv
python -m core.cli inventory add --name "payments-api" --type service --criticality high
python -m core.cli policies create --name "no-critical-vulns" --type security

# API
POST /inputs/design
POST /api/v1/inventory/applications
POST /api/v1/policies
```

### Build Phase
```bash
# CLI
python -m core.cli stage-run --stage build --input sbom.json

# API
POST /inputs/sbom
```

### Test Phase
```bash
# CLI
python -m core.cli stage-run --stage test --input scan.sarif
python -m core.cli pentagi create --target payments-api --cve CVE-2024-1234
python -m core.cli advanced-pentest run --target payments-api --cves CVE-2024-1234

# API
POST /inputs/sarif
POST /inputs/cve
POST /api/v1/pentagi/requests
```

### Release Gate (Evidence Creation)
```bash
# CLI - Primary evidence bundle creation
python -m core.cli make-decision \
  --design design.csv \
  --sbom sbom.json \
  --sarif scan.sarif \
  --cve cve.json \
  --evidence-dir ./evidence

# API
POST /inputs/* (all artifacts)
GET /pipeline/run
```

### Monitor Phase
```bash
# CLI
python -m core.cli analytics dashboard --period 30d
python -m core.cli audit logs --limit 100
python -m core.cli compliance status SOC2

# API
GET /api/v1/analytics/dashboard/*
GET /api/v1/audit/logs
GET /api/v1/audit/compliance/frameworks/SOC2/status
```

### Audit/Export
```bash
# CLI
python -m core.cli get-evidence --run decision.json
python -m core.cli copy-evidence --run decision.json --target ./audit-handoff
python -m core.cli compliance report SOC2 --output soc2-report.json
python -m core.cli reports export {id} --output report.pdf

# API
GET /api/v1/evidence/bundles/{id}/download
POST /api/v1/audit/compliance/frameworks/SOC2/report
GET /api/v1/reports/{id}/download
```
