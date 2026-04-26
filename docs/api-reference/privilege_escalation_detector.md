# Privilege Escalation Detector

_Auto-generated 2026-04-26 from `suite-api/apps/api/privilege_escalation_detector_router.py`._

Detects privilege escalation events, AD attack-paths, and rule heatmaps.

- **Endpoints**: 10
- **Personas**: IAM Engineer, SOC Analyst
- **Auth**: API key (`X-API-Key`) on all `/api/v1/*` routes; tenant scope via `X-Org-ID` header
- **UI screens**: `PrivilegeEscalationDashboard.tsx`
- **User stories**: US-0021

## Endpoint Index

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/privilege-escalation-detector/events` |  |
| `GET` | `/api/v1/privilege-escalation-detector/events` |  |
| `GET` | `/api/v1/privilege-escalation-detector/events/{event_id}/analyze` |  |
| `POST` | `/api/v1/privilege-escalation-detector/rules` |  |
| `GET` | `/api/v1/privilege-escalation-detector/rules` |  |
| `GET` | `/api/v1/privilege-escalation-detector/heatmap` |  |
| `POST` | `/api/v1/privilege-escalation-detector/ad-attack-path` |  |
| `GET` | `/api/v1/privilege-escalation-detector/stats` |  |
| `GET` | `/api/v1/privilege-escalation-detector/health` |  |
| `GET` | `/api/v1/privilege-escalation-detector/status` |  |

## Privilege Escalation Detector

### `POST /api/v1/privilege-escalation-detector/events`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `record_event`
- **Request body**: `PrivilegeEventRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/privilege-escalation-detector/events"
```

### `GET /api/v1/privilege-escalation-detector/events`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `list_events`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/privilege-escalation-detector/events"
```

### `GET /api/v1/privilege-escalation-detector/events/{event_id}/analyze`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `analyze_event`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/privilege-escalation-detector/events/{event_id}/analyze"
```

### `POST /api/v1/privilege-escalation-detector/rules`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `create_rule`
- **Request body**: `DetectionRuleRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/privilege-escalation-detector/rules"
```

### `GET /api/v1/privilege-escalation-detector/rules`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `list_rules`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/privilege-escalation-detector/rules"
```

### `GET /api/v1/privilege-escalation-detector/heatmap`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `get_heatmap`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/privilege-escalation-detector/heatmap"
```

### `POST /api/v1/privilege-escalation-detector/ad-attack-path`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `build_attack_path`
- **Request body**: `ADAttackPathRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/privilege-escalation-detector/ad-attack-path"
```

### `GET /api/v1/privilege-escalation-detector/stats`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `stats`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/privilege-escalation-detector/stats"
```

### `GET /api/v1/privilege-escalation-detector/health`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `health`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/privilege-escalation-detector/health"
```

### `GET /api/v1/privilege-escalation-detector/status`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `status`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/privilege-escalation-detector/status"
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

- Generated by `tools/extract_routes.py` from `suite-api/apps/api/privilege_escalation_detector_router.py`. Re-run after router changes.
- Schemas marked `_None_` do not accept a request body. Path/query params are typed in the source.
- For request body shapes, consult the Pydantic models in the router source file or the live OpenAPI spec at `GET /openapi.json`.
