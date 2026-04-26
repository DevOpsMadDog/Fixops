# Wave A — Code & Architecture Intelligence

_Auto-generated 2026-04-26 from `suite-api/apps/api/wave_a_code_intel_router.py`._

17 endpoints across Graph, Deep Code Analysis (DCA), Reachability, Components, IDE Gateway, and Runtime Telemetry.

- **Endpoints**: 17
- **Personas**: AppSec Engineer, Platform Engineer, Developer (IDE), Architect
- **Auth**: API key (`X-API-Key`) on all `/api/v1/*` routes; tenant scope via `X-Org-ID` header
- **UI screens**: `ArchAwareGraphDashboard.tsx`, `ReachabilityDashboard.tsx`, `ComponentsDashboard.tsx`, `IDEExtensionDashboard.tsx`, `RuntimeTelemetryDashboard.tsx`
- **User stories**: US-0008, US-0010, US-0012, US-0013, US-0014, US-0024, US-0026, US-0029, US-0047, US-0065

## Endpoint Index

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/graph/architecture-detect` | Run architecture detection over a repository and persist the snapshot. |
| `GET` | `/api/v1/graph/flows/{service_id}` | Return data flows centred on the given service. |
| `GET` | `/api/v1/graph/layers/{module_id}` | Return the layer (presentation/application/domain/infra/shared) for a module. |
| `GET` | `/api/v1/graph/databases/{repo_id}` | Return databases discovered by /architecture-detect for the given repo. |
| `GET` | `/api/v1/graph/diff` | Compare two architecture snapshots and return added/removed entities. |
| `POST` | `/api/v1/dca/parse-repo` | Parse a repository into entities (functions, classes, modules). |
| `GET` | `/api/v1/dca/entities/{repo}` | Return entities recorded for a repo. |
| `GET` | `/api/v1/dca/diff` | Diff entity sets between two parse runs (`from` → `to` revisions). |
| `POST` | `/api/v1/reachability/callgraph` | Build a callgraph for a repo using the function_reachability_engine. |
| `GET` | `/api/v1/reachability/{finding_id}/proof` | Return the reachability verdict (path) for a finding. |
| `GET` | `/api/v1/components/match-by-abf` | Search SBOM component records for a given ABF (binary hash). |
| `GET` | `/api/v1/components/{purl:path}/safe-upgrade` | Resolve the next safe upgrade target for a component. |
| `GET` | `/api/v1/ide/findings` | Return findings scoped to a (repo, file) pair for IDE in-line overlay. |
| `POST` | `/api/v1/ide/authenticate-token` | Validate an IDE token and return session info. |
| `GET` | `/api/v1/ide/user-snapshot` | Return per-user IDE snapshot: recent files, scopes, finding counts. |
| `POST` | `/api/v1/runtime/map-to-code` | Resolve a runtime event/stack-trace to candidate code locations. |
| `GET` | `/api/v1/runtime/traffic/{api:path}` | Return aggregate runtime traffic for an API path. |

## Wave A — Graph / Architecture

### `POST /api/v1/graph/architecture-detect`

Run architecture detection over a repository and persist the snapshot.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `graph_architecture_detect`
- **Request body**: `ArchitectureDetectRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/graph/architecture-detect"
```

### `GET /api/v1/graph/flows/{service_id}`

Return data flows centred on the given service.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `graph_flows`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/graph/flows/{service_id}"
```

### `GET /api/v1/graph/layers/{module_id}`

Return the layer (presentation/application/domain/infra/shared) for a module.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `graph_layers`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/graph/layers/{module_id}"
```

### `GET /api/v1/graph/databases/{repo_id}`

Return databases discovered by /architecture-detect for the given repo.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `graph_databases`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/graph/databases/{repo_id}"
```

### `GET /api/v1/graph/diff`

Compare two architecture snapshots and return added/removed entities.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `graph_diff`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/graph/diff"
```

## Wave A — Deep Code Analysis

### `POST /api/v1/dca/parse-repo`

Parse a repository into entities (functions, classes, modules).

- **Auth**: Required (`X-API-Key`)
- **Handler**: `dca_parse_repo`
- **Request body**: `DCAParseRepoRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/dca/parse-repo"
```

### `GET /api/v1/dca/entities/{repo}`

Return entities recorded for a repo.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `dca_entities`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/dca/entities/{repo}"
```

### `GET /api/v1/dca/diff`

Diff entity sets between two parse runs (`from` → `to` revisions).

- **Auth**: Required (`X-API-Key`)
- **Handler**: `dca_diff`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/dca/diff"
```

## Wave A — Reachability

### `POST /api/v1/reachability/callgraph`

Build a callgraph for a repo using the function_reachability_engine.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `reachability_callgraph`
- **Request body**: `CallGraphRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/reachability/callgraph"
```

### `GET /api/v1/reachability/{finding_id}/proof`

Return the reachability verdict (path) for a finding.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `reachability_proof`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/reachability/{finding_id}/proof"
```

## Wave A — Components

### `GET /api/v1/components/match-by-abf`

Search SBOM component records for a given ABF (binary hash).

- **Auth**: Required (`X-API-Key`)
- **Handler**: `components_match_by_abf`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/components/match-by-abf"
```

### `GET /api/v1/components/{purl:path}/safe-upgrade`

Resolve the next safe upgrade target for a component.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `components_safe_upgrade`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/components/{purl:path}/safe-upgrade"
```

## Wave A — IDE Gateway

### `GET /api/v1/ide/findings`

Return findings scoped to a (repo, file) pair for IDE in-line overlay.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `ide_findings`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/ide/findings"
```

### `POST /api/v1/ide/authenticate-token`

Validate an IDE token and return session info.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `ide_authenticate_token`
- **Request body**: `IDEAuthenticateTokenRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/ide/authenticate-token"
```

### `GET /api/v1/ide/user-snapshot`

Return per-user IDE snapshot: recent files, scopes, finding counts.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `ide_user_snapshot`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/ide/user-snapshot"
```

## Wave A — Runtime Telemetry

### `POST /api/v1/runtime/map-to-code`

Resolve a runtime event/stack-trace to candidate code locations.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `runtime_map_to_code`
- **Request body**: `RuntimeMapToCodeRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/runtime/map-to-code"
```

### `GET /api/v1/runtime/traffic/{api:path}`

Return aggregate runtime traffic for an API path.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `runtime_traffic`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/runtime/traffic/{api:path}"
```

## Error Codes

| Status | Meaning |
|---|---|
| 200 | Success (GET, idempotent POST) |
| 201 | Created (POST resource creation) |
| 202 | Accepted (async task enqueued) |
| 400 | Validation failed — malformed JSON or schema violation |
| 401 | Missing or invalid `X-API-Key` |
| 403 | API key valid but lacks org/role scope |
| 404 | Resource not found |
| 409 | Conflict — resource already exists or state violation |
| 422 | Pydantic validation error (FastAPI default) |
| 429 | Rate limit exceeded |
| 500 | Engine error — see `detail` |
| 501 | Endpoint stubbed for an engine that is not yet wired |

## Notes

- Generated by `tools/extract_routes.py` from `suite-api/apps/api/wave_a_code_intel_router.py`. Re-run after router changes.
- Schemas marked `_None_` do not accept a request body. Path/query params are typed in the source.
- For request body shapes, consult the Pydantic models in the router source file or the live OpenAPI spec at `GET /openapi.json`.
