# DuckDB Cross-Domain Analytics

_Auto-generated 2026-04-26 from `suite-api/apps/api/duckdb_analytics_router.py`._

Cross-domain SQL analytics over the 60+ embedded SQLite engines via DuckDB.

- **Endpoints**: 9
- **Personas**: Risk Analyst, Executive Reporting
- **Auth**: API key (`X-API-Key`) on all `/api/v1/*` routes; tenant scope via `X-Org-ID` header
- **UI screens**: `ExecutiveDashboard.tsx`, `RiskSummaryDashboard.tsx`
- **User stories**: _n/a_

## Endpoint Index

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/duckdb-analytics/risk-summary` |  |
| `GET` | `/api/v1/duckdb-analytics/asset-vulnerability` |  |
| `GET` | `/api/v1/duckdb-analytics/threat-intel-correlation` |  |
| `GET` | `/api/v1/duckdb-analytics/compliance-trend` |  |
| `GET` | `/api/v1/duckdb-analytics/executive-dashboard` |  |
| `GET` | `/api/v1/duckdb-analytics/domains` |  |
| `POST` | `/api/v1/duckdb-analytics/custom-query` |  |
| `GET` | `/api/v1/duckdb-analytics/health` |  |
| `GET` | `/api/v1/duckdb-analytics/status` |  |

## DuckDB Analytics

### `GET /api/v1/duckdb-analytics/risk-summary`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `risk_summary`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/duckdb-analytics/risk-summary"
```

### `GET /api/v1/duckdb-analytics/asset-vulnerability`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `asset_vulnerability`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/duckdb-analytics/asset-vulnerability"
```

### `GET /api/v1/duckdb-analytics/threat-intel-correlation`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `threat_intel_correlation`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/duckdb-analytics/threat-intel-correlation"
```

### `GET /api/v1/duckdb-analytics/compliance-trend`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `compliance_trend`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/duckdb-analytics/compliance-trend"
```

### `GET /api/v1/duckdb-analytics/executive-dashboard`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `executive_dashboard`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/duckdb-analytics/executive-dashboard"
```

### `GET /api/v1/duckdb-analytics/domains`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `domains`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/duckdb-analytics/domains"
```

### `POST /api/v1/duckdb-analytics/custom-query`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `custom_query`
- **Request body**: `CustomQueryRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/duckdb-analytics/custom-query"
```

### `GET /api/v1/duckdb-analytics/health`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `health`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/duckdb-analytics/health"
```

### `GET /api/v1/duckdb-analytics/status`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `status`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/duckdb-analytics/status"
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

- Generated by `tools/extract_routes.py` from `suite-api/apps/api/duckdb_analytics_router.py`. Re-run after router changes.
- Schemas marked `_None_` do not accept a request body. Path/query params are typed in the source.
- For request body shapes, consult the Pydantic models in the router source file or the live OpenAPI spec at `GET /openapi.json`.
