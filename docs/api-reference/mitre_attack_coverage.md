# MITRE ATT&CK Coverage

_Auto-generated 2026-04-26 from `suite-api/apps/api/mitre_attack_coverage_router.py`._

Coverage analytics: techniques inventoried, detection mappings, gap analysis, heatmaps.

- **Endpoints**: 10
- **Personas**: Detection Engineer, SOC Lead
- **Auth**: API key (`X-API-Key`) on all `/api/v1/*` routes; tenant scope via `X-Org-ID` header
- **UI screens**: `MITRECoverageDashboard.tsx`
- **User stories**: _n/a_

## Endpoint Index

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/mitre-attack-coverage/seed` |  |
| `POST` | `/api/v1/mitre-attack-coverage/techniques` |  |
| `GET` | `/api/v1/mitre-attack-coverage/techniques` |  |
| `POST` | `/api/v1/mitre-attack-coverage/detections` |  |
| `GET` | `/api/v1/mitre-attack-coverage/detections` |  |
| `GET` | `/api/v1/mitre-attack-coverage/coverage` |  |
| `GET` | `/api/v1/mitre-attack-coverage/gaps` |  |
| `GET` | `/api/v1/mitre-attack-coverage/heatmap` |  |
| `GET` | `/api/v1/mitre-attack-coverage/health` |  |
| `GET` | `/api/v1/mitre-attack-coverage/status` |  |

## MITRE ATT&CK Coverage

### `POST /api/v1/mitre-attack-coverage/seed`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `seed`
- **Request body**: `SeedRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/mitre-attack-coverage/seed"
```

### `POST /api/v1/mitre-attack-coverage/techniques`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `add_technique`
- **Request body**: `TechniqueRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/mitre-attack-coverage/techniques"
```

### `GET /api/v1/mitre-attack-coverage/techniques`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `list_techniques`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/mitre-attack-coverage/techniques"
```

### `POST /api/v1/mitre-attack-coverage/detections`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `log_detection`
- **Request body**: `DetectionRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/mitre-attack-coverage/detections"
```

### `GET /api/v1/mitre-attack-coverage/detections`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `list_detections`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/mitre-attack-coverage/detections"
```

### `GET /api/v1/mitre-attack-coverage/coverage`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `coverage`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/mitre-attack-coverage/coverage"
```

### `GET /api/v1/mitre-attack-coverage/gaps`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `gaps`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/mitre-attack-coverage/gaps"
```

### `GET /api/v1/mitre-attack-coverage/heatmap`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `heatmap`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/mitre-attack-coverage/heatmap"
```

### `GET /api/v1/mitre-attack-coverage/health`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `health`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/mitre-attack-coverage/health"
```

### `GET /api/v1/mitre-attack-coverage/status`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `status`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/mitre-attack-coverage/status"
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

- Generated by `tools/extract_routes.py` from `suite-api/apps/api/mitre_attack_coverage_router.py`. Re-run after router changes.
- Schemas marked `_None_` do not accept a request body. Path/query params are typed in the source.
- For request body shapes, consult the Pydantic models in the router source file or the live OpenAPI spec at `GET /openapi.json`.
