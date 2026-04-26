# GraphRAG

_Auto-generated 2026-04-26 from `suite-api/apps/api/graphrag_router.py`._

Graph-based retrieval-augmented generation over TrustGraph cores with traced query history.

- **Endpoints**: 8
- **Personas**: Security Analyst, AI Engineer
- **Auth**: API key (`X-API-Key`) on all `/api/v1/*` routes; tenant scope via `X-Org-ID` header
- **UI screens**: `GraphRAGConsole.tsx`
- **User stories**: US-0029

## Endpoint Index

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/graphrag/query` |  |
| `POST` | `/api/v1/graphrag/builder` |  |
| `POST` | `/api/v1/graphrag/query-with-trace` |  |
| `GET` | `/api/v1/graphrag/traced-history` |  |
| `GET` | `/api/v1/graphrag/traced-stats` |  |
| `POST` | `/api/v1/graphrag/cache/clear` |  |
| `GET` | `/api/v1/graphrag/health` |  |
| `GET` | `/api/v1/graphrag/status` |  |

## GraphRAG

### `POST /api/v1/graphrag/query`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `query`
- **Request body**: `GraphQueryRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/graphrag/query"
```

### `POST /api/v1/graphrag/builder`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `builder`
- **Request body**: `BuilderRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/graphrag/builder"
```

### `POST /api/v1/graphrag/query-with-trace`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `query_with_trace`
- **Request body**: `TracedQueryRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/graphrag/query-with-trace"
```

### `GET /api/v1/graphrag/traced-history`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `traced_history`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/graphrag/traced-history"
```

### `GET /api/v1/graphrag/traced-stats`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `traced_stats`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/graphrag/traced-stats"
```

### `POST /api/v1/graphrag/cache/clear`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `cache_clear`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{}' "http://localhost:8000/api/v1/graphrag/cache/clear"
```

### `GET /api/v1/graphrag/health`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `health`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/graphrag/health"
```

### `GET /api/v1/graphrag/status`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `status`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/graphrag/status"
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

- Generated by `tools/extract_routes.py` from `suite-api/apps/api/graphrag_router.py`. Re-run after router changes.
- Schemas marked `_None_` do not accept a request body. Path/query params are typed in the source.
- For request body shapes, consult the Pydantic models in the router source file or the live OpenAPI spec at `GET /openapi.json`.
