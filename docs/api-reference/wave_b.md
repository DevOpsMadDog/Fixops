# Wave B — Findings, Risk & Scoring

_Auto-generated 2026-04-26 from `suite-api/apps/api/findings_wave_b_router.py`._

16 endpoints covering finding lifecycle, scoring explainability, SBOM monitoring, and investigations.

- **Endpoints**: 16
- **Personas**: AppSec Lead, SOC Analyst, Risk Manager
- **Auth**: API key (`X-API-Key`) on all `/api/v1/*` routes; tenant scope via `X-Org-ID` header
- **UI screens**: `FindingsDashboard.tsx`, `ScoringExplainability.tsx`, `SBOMMonitoringDashboard.tsx`, `InvestigationsConsole.tsx`
- **User stories**: US-0006, US-0021, US-0043, US-0055, US-0062, US-0063

## Endpoint Index

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/findings/{finding_id}/lifecycle` | Return the lifecycle ancestor chain of a finding. |
| `GET` | `/api/v1/findings/drift` | Return rolling drift counters {new, unchanged, resolved} over a window. |
| `GET` | `/api/v1/findings` | List findings with rich filtering. |
| `GET` | `/api/v1/findings/{finding_id}/score-breakdown` | Return per-factor breakdown rows for a finding's scoring. |
| `GET` | `/api/v1/scoring/formula` | Return the org's active scoring formula with weights and audit trail. |
| `PUT` | `/api/v1/scoring/formula` | Create a new active scoring model with the supplied weights. |
| `POST` | `/api/v1/risk/quantify-fair` | Run the FAIR (Factor Analysis of Information Risk) Monte Carlo |
| `GET` | `/api/v1/risk/brs/bu/{bu_id}` | Return the per-business-unit risk score (BRS). |
| `GET` | `/api/v1/attack-paths/choke-points` | Rank attack-graph edges by their max-flow / min-cut blast-reduction |
| `GET` | `/api/v1/issues/toxic` | Return assets flagged with toxic combinations of medium-severity |
| `POST` | `/api/v1/toxic-combo-rules` | Register a custom toxic-combo rule. |
| `POST` | `/api/v1/sbom/subscribe-for-reeval` | Schedule a recurring re-eval of the SBOM via cron expression. |
| `GET` | `/api/v1/sbom/{sbom_id}/re-eval-history` | Return all known schedules and execution metadata for an SBOM. |
| `POST` | `/api/v1/investigate/rql` | Compile and execute an RQL DSL query against the org's data. |
| `GET` | `/api/v1/investigate/saved` | List saved RQL queries for the org. |
| `POST` | `/api/v1/investigate/saved` | Persist a named RQL query for re-use. |

## Wave B — Findings/Risk/Scoring

### `GET /api/v1/findings/{finding_id}/lifecycle`

Return the lifecycle ancestor chain of a finding.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `finding_lifecycle`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/findings/{finding_id}/lifecycle"
```

### `GET /api/v1/findings/drift`

Return rolling drift counters {new, unchanged, resolved} over a window.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `findings_drift`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/findings/drift"
```

### `GET /api/v1/findings`

List findings with rich filtering.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `list_findings`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/findings"
```

### `GET /api/v1/findings/{finding_id}/score-breakdown`

Return per-factor breakdown rows for a finding's scoring.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `finding_score_breakdown`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/findings/{finding_id}/score-breakdown"
```

### `GET /api/v1/scoring/formula`

Return the org's active scoring formula with weights and audit trail.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `get_scoring_formula`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/scoring/formula"
```

### `PUT /api/v1/scoring/formula`

Create a new active scoring model with the supplied weights.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `put_scoring_formula`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X PUT -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{}' "http://localhost:8000/api/v1/scoring/formula"
```

### `POST /api/v1/risk/quantify-fair`

Run the FAIR (Factor Analysis of Information Risk) Monte Carlo

- **Auth**: Required (`X-API-Key`)
- **Handler**: `quantify_fair`
- **Request body**: `FAIRQuantifyRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/risk/quantify-fair"
```

### `GET /api/v1/risk/brs/bu/{bu_id}`

Return the per-business-unit risk score (BRS).

- **Auth**: Required (`X-API-Key`)
- **Handler**: `bu_risk_score`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/risk/brs/bu/{bu_id}"
```

### `GET /api/v1/attack-paths/choke-points`

Rank attack-graph edges by their max-flow / min-cut blast-reduction

- **Auth**: Required (`X-API-Key`)
- **Handler**: `attack_path_choke_points`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/attack-paths/choke-points"
```

### `GET /api/v1/issues/toxic`

Return assets flagged with toxic combinations of medium-severity

- **Auth**: Required (`X-API-Key`)
- **Handler**: `toxic_issues`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/issues/toxic"
```

### `POST /api/v1/toxic-combo-rules`

Register a custom toxic-combo rule.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `create_toxic_combo_rule`
- **Request body**: `_None_`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{}' "http://localhost:8000/api/v1/toxic-combo-rules"
```

### `POST /api/v1/sbom/subscribe-for-reeval`

Schedule a recurring re-eval of the SBOM via cron expression.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `sbom_subscribe_reeval`
- **Request body**: `SubscribeReevalRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/sbom/subscribe-for-reeval"
```

### `GET /api/v1/sbom/{sbom_id}/re-eval-history`

Return all known schedules and execution metadata for an SBOM.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `sbom_reeval_history`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/sbom/{sbom_id}/re-eval-history"
```

### `POST /api/v1/investigate/rql`

Compile and execute an RQL DSL query against the org's data.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `investigate_rql`
- **Request body**: `RQLQueryRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/investigate/rql"
```

### `GET /api/v1/investigate/saved`

List saved RQL queries for the org.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `list_saved_queries`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/investigate/saved"
```

### `POST /api/v1/investigate/saved`

Persist a named RQL query for re-use.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `save_query`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{}' "http://localhost:8000/api/v1/investigate/saved"
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

- Generated by `tools/extract_routes.py` from `suite-api/apps/api/findings_wave_b_router.py`. Re-run after router changes.
- Schemas marked `_None_` do not accept a request body. Path/query params are typed in the source.
- For request body shapes, consult the Pydantic models in the router source file or the live OpenAPI spec at `GET /openapi.json`.
