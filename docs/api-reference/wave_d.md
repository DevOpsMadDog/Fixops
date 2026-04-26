# Wave D — Connectors, Webhooks, EASM, Copilot & Policies

_Auto-generated 2026-04-26 from `suite-api/apps/api/wave_d_integrations_router.py`._

20 endpoints for universal connector field-mapping, webhook event-catalogue + subscriptions, external attack-surface seeding, NL graph copilot, AI exposure, AI Teammates, asset crown-jewel tagging, TrustGraph compaction, waiver lifecycle, and policy stage-matrices.

- **Endpoints**: 20
- **Personas**: Integration Engineer, AI Security Lead, Policy Author
- **Auth**: API key (`X-API-Key`) on all `/api/v1/*` routes; tenant scope via `X-Org-ID` header
- **UI screens**: `ConnectorMappingUI.tsx`, `WebhookCatalogueDashboard.tsx`, `EASMDashboard.tsx`, `GraphCopilotDashboard.tsx`, `AIExposureDashboard.tsx`, `AITeammatesConsole.tsx`, `PolicyStageMatrixEditor.tsx`
- **User stories**: US-0030, US-0034, US-0038, US-0044, US-0046, US-0059

## Endpoint Index

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/connectors/mapping` | Persist a single field mapping for a connector. (Multica e194a1b1) |
| `POST` | `/api/v1/connectors/mapping/dry-run` | Apply mappings to a sample payload without side effects. (Multica 4e2d5913) |
| `GET` | `/api/v1/webhooks/event-catalogue` | Return the catalogue of available webhook event types. (Multica 67a3167b) |
| `POST` | `/api/v1/webhooks/subscribe` | Register a webhook subscription. (Multica d36e7e48) |
| `POST` | `/api/v1/easm/seed-domain` | Seed an EASM root domain. (Multica 2ccc15a7) |
| `GET` | `/api/v1/easm/subsidiaries/{org}` | List discovered subsidiaries for an org. (Multica 828b955d) |
| `GET` | `/api/v1/easm/exposures` | Return exposures filtered by confidence. (Multica 0476b668) |
| `POST` | `/api/v1/copilot/graph-nl-query` | Run a natural-language query against the TrustGraph. (Multica 0817d38c) |
| `GET` | `/api/v1/copilot/{q_id}/traversal-trace` | Return the traversal trace for a previous Copilot query. (Multica 3d7e5388) |
| `GET` | `/api/v1/ai-exposure/shadow` | List discovered shadow AI services. (Multica 3e63ac8d) |
| `POST` | `/api/v1/ai-exposure/sanctioned-list` | Add an approved/sanctioned AI service. (Multica 5040fb06) |
| `POST` | `/api/v1/agents/{role}/task` | Dispatch a task to a named agent role (security_analyst, pentester, etc). |
| `POST` | `/api/v1/assets/{id}/crown-jewel-tag` | Tag an asset as a crown-jewel (or untag). (Multica 68162b9b) |
| `POST` | `/api/v1/trustgraph/compact` | Run TrustGraph compaction. (Multica d532f156) |
| `GET` | `/api/v1/trustgraph/quality-issues` | Return TrustGraph data-quality issues. (Multica 9f0ae4e6) |
| `GET` | `/api/v1/waivers` | List waivers, optionally filtered to auto-applied ones. (Multica 49049e61) |
| `POST` | `/api/v1/auto-waiver-rules` | Register an auto-waiver rule. (Multica 1f5d8fc9) |
| `POST` | `/api/v1/policies/{id}/stage-matrix` | Set the CTEM stage matrix for a policy. (Multica 61db07fb) |
| `GET` | `/api/v1/policies/{id}/stage-matrix` | Return the CTEM stage matrix for a policy. (Multica 181dc9f8) |
| `POST` | `/api/v1/evaluate` | Evaluate a context against stage-aware policies. (Multica a0585e59) |

## wave-d-integrations

### `POST /api/v1/connectors/mapping`

Persist a single field mapping for a connector. (Multica e194a1b1)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `create_connector_mapping`
- **Request body**: `ConnectorMappingRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/connectors/mapping"
```

### `POST /api/v1/connectors/mapping/dry-run`

Apply mappings to a sample payload without side effects. (Multica 4e2d5913)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `dry_run_connector_mapping`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{}' "http://localhost:8000/api/v1/connectors/mapping/dry-run"
```

### `GET /api/v1/webhooks/event-catalogue`

Return the catalogue of available webhook event types. (Multica 67a3167b)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `webhook_event_catalogue`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/webhooks/event-catalogue"
```

### `POST /api/v1/webhooks/subscribe`

Register a webhook subscription. (Multica d36e7e48)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `webhook_subscribe`
- **Request body**: `WebhookSubscribeRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/webhooks/subscribe"
```

### `POST /api/v1/easm/seed-domain`

Seed an EASM root domain. (Multica 2ccc15a7)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `easm_seed_domain`
- **Request body**: `EASMSeedDomainRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/easm/seed-domain"
```

### `GET /api/v1/easm/subsidiaries/{org}`

List discovered subsidiaries for an org. (Multica 828b955d)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `easm_subsidiaries`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/easm/subsidiaries/{org}"
```

### `GET /api/v1/easm/exposures`

Return exposures filtered by confidence. (Multica 0476b668)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `easm_exposures`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/easm/exposures"
```

### `POST /api/v1/copilot/graph-nl-query`

Run a natural-language query against the TrustGraph. (Multica 0817d38c)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `copilot_graph_nl_query`
- **Request body**: `CopilotGraphNLRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/copilot/graph-nl-query"
```

### `GET /api/v1/copilot/{q_id}/traversal-trace`

Return the traversal trace for a previous Copilot query. (Multica 3d7e5388)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `copilot_traversal_trace`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/copilot/{q_id}/traversal-trace"
```

### `GET /api/v1/ai-exposure/shadow`

List discovered shadow AI services. (Multica 3e63ac8d)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `ai_exposure_shadow`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/ai-exposure/shadow"
```

### `POST /api/v1/ai-exposure/sanctioned-list`

Add an approved/sanctioned AI service. (Multica 5040fb06)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `ai_exposure_sanctioned_list`
- **Request body**: `SanctionedAIServiceRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/ai-exposure/sanctioned-list"
```

### `POST /api/v1/agents/{role}/task`

Dispatch a task to a named agent role (security_analyst, pentester, etc).

- **Auth**: Required (`X-API-Key`)
- **Handler**: `dispatch_agent_task`
- **Request body**: `AgentTaskRequest`
- **Success**: `202` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/agents/{role}/task"
```

### `POST /api/v1/assets/{id}/crown-jewel-tag`

Tag an asset as a crown-jewel (or untag). (Multica 68162b9b)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `tag_crown_jewel`
- **Request body**: `CrownJewelTagRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/assets/{id}/crown-jewel-tag"
```

### `POST /api/v1/trustgraph/compact`

Run TrustGraph compaction. (Multica d532f156)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `trustgraph_compact`
- **Request body**: `TrustGraphCompactRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/trustgraph/compact"
```

### `GET /api/v1/trustgraph/quality-issues`

Return TrustGraph data-quality issues. (Multica 9f0ae4e6)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `trustgraph_quality_issues`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/trustgraph/quality-issues"
```

### `GET /api/v1/waivers`

List waivers, optionally filtered to auto-applied ones. (Multica 49049e61)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `list_waivers`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/waivers"
```

### `POST /api/v1/auto-waiver-rules`

Register an auto-waiver rule. (Multica 1f5d8fc9)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `create_auto_waiver_rule`
- **Request body**: `AutoWaiverRuleRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/auto-waiver-rules"
```

### `POST /api/v1/policies/{id}/stage-matrix`

Set the CTEM stage matrix for a policy. (Multica 61db07fb)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `set_policy_stage_matrix`
- **Request body**: `StageMatrixRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/policies/{id}/stage-matrix"
```

### `GET /api/v1/policies/{id}/stage-matrix`

Return the CTEM stage matrix for a policy. (Multica 181dc9f8)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `get_policy_stage_matrix`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/policies/{id}/stage-matrix"
```

### `POST /api/v1/evaluate`

Evaluate a context against stage-aware policies. (Multica a0585e59)

- **Auth**: Required (`X-API-Key`)
- **Handler**: `evaluate_at_stage`
- **Request body**: `StageEvaluateRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/evaluate"
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

- Generated by `tools/extract_routes.py` from `suite-api/apps/api/wave_d_integrations_router.py`. Re-run after router changes.
- Schemas marked `_None_` do not accept a request body. Path/query params are typed in the source.
- For request body shapes, consult the Pydantic models in the router source file or the live OpenAPI spec at `GET /openapi.json`.
