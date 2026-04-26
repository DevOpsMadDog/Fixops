# Wave C — System, Org, PBOM, Provenance & Admin

_Auto-generated 2026-04-26 from `suite-api/apps/api/wave_c_router.py`._

21 endpoints across system health, org tree, PBOM extras, provenance attestation, change tracking, scopes, air-gap, admin/user tokens, CSPM, skills, rules, and LLM cost-routing.

- **Endpoints**: 21
- **Personas**: Platform Admin, Compliance Lead, SecOps Engineer
- **Auth**: API key (`X-API-Key`) on all `/api/v1/*` routes; tenant scope via `X-Org-ID` header
- **UI screens**: `OrgHierarchyDashboard.tsx`, `PBOMConsole.tsx`, `ProvenanceAttestationDashboard.tsx`, `AirGapBundleDashboard.tsx`, `AdminTokensDashboard.tsx`, `UserTokensDashboard.tsx`, `RuleAuthoringConsole.tsx`
- **User stories**: US-0001, US-0002, US-0003, US-0004, US-0005, US-0007, US-0011, US-0017, US-0018, US-0039, US-0042, US-0061, US-0064, US-0066, US-0067, US-0068, US-0069

## Endpoint Index

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/system/compliance-posture` | Aggregate posture across SOC2/ISO/PCI/HIPAA/FedRAMP/NIST + FIPS readiness. |
| `POST` | `/api/v1/system/fips-self-test` | Execute Known-Answer-Tests against the cryptographic provider. |
| `GET` | `/api/v1/system/fips-mode` | Return FIPS mode for tenant, plus active provider + readiness summary. |
| `GET` | `/api/v1/system/ha-status` | Report HA cluster health. |
| `POST` | `/api/v1/organizations` | Create a new organisation node within tenant ``X-Org-ID``. |
| `PATCH` | `/api/v1/organizations/{org_pk}/parent` |  |
| `POST` | `/api/v1/pbom/record-step` | Convenience endpoint: record a single pipeline step in one call. |
| `GET` | `/api/v1/pbom/artifact/{digest}/propagation` | Walk all runs that produced an artifact, plus deployment targets. |
| `GET` | `/api/v1/provenance/{artifact}/attestation` | Return the latest in-toto SLSA attestation envelope for an artifact. |
| `GET` | `/api/v1/changes/material` | Query the material change ledger with optional filters. |
| `GET` | `/api/v1/scopes` | Return the canonical OAuth-style scope registry. |
| `GET` | `/api/v1/air-gap/feed-status` | Report freshness of feed bundles imported into an air-gapped install. |
| `GET` | `/api/v1/admin/tokens` | Admin: list every API token in the system. PII-redacted. |
| `POST` | `/api/v1/users/me/tokens` | Create a new API token. The raw key is returned exactly once. |
| `GET` | `/api/v1/users/me/tokens` | List tokens created by the calling user (PII-redacted). |
| `POST` | `/api/v1/cspm/snapshot-scan` | Run a CSPM scan against a cloud account snapshot (agentless). |
| `POST` | `/api/v1/skills/uninstall` | Remove a skill from the active registry; optionally purge cached files. |
| `GET` | `/api/v1/rules/dsl` |  |
| `PATCH` | `/api/v1/rules/{key}/enabled` | Enable or disable a rule across the rules registry. |
| `POST` | `/api/v1/llm/approve-spend/{estimate_id}` | Approve a pending LLM spend transaction by ID. |
| `GET` | `/api/v1/llm/rules/{key}/context-requirement` | Return the contract describing what context this rule needs. |

## Wave C — System

### `GET /api/v1/system/compliance-posture`

Aggregate posture across SOC2/ISO/PCI/HIPAA/FedRAMP/NIST + FIPS readiness.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `system_compliance_posture`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/system/compliance-posture"
```

### `POST /api/v1/system/fips-self-test`

Execute Known-Answer-Tests against the cryptographic provider.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `system_fips_self_test`
- **Request body**: `Optional[FIPSSelfTestRequest]`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/system/fips-self-test"
```

### `GET /api/v1/system/fips-mode`

Return FIPS mode for tenant, plus active provider + readiness summary.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `system_fips_mode`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/system/fips-mode"
```

### `GET /api/v1/system/ha-status`

Report HA cluster health.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `system_ha_status`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/system/ha-status"
```

## Wave C — Organizations

### `POST /api/v1/organizations`

Create a new organisation node within tenant ``X-Org-ID``.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `create_organization`
- **Request body**: `CreateOrgRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/organizations"
```

### `PATCH /api/v1/organizations/{org_pk}/parent`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `update_organization_parent`
- **Request body**: `UpdateParentRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X PATCH -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/organizations/{org_pk}/parent"
```

## Wave C — PBOM (extras)

### `POST /api/v1/pbom/record-step`

Convenience endpoint: record a single pipeline step in one call.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `pbom_record_step`
- **Request body**: `PBOMRecordStepRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/pbom/record-step"
```

### `GET /api/v1/pbom/artifact/{digest}/propagation`

Walk all runs that produced an artifact, plus deployment targets.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `pbom_artifact_propagation`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/pbom/artifact/{digest}/propagation"
```

## Wave C — Provenance

### `GET /api/v1/provenance/{artifact}/attestation`

Return the latest in-toto SLSA attestation envelope for an artifact.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `provenance_attestation`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/provenance/{artifact}/attestation"
```

## Wave C — Changes

### `GET /api/v1/changes/material`

Query the material change ledger with optional filters.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `changes_material`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/changes/material"
```

## Wave C — Scopes

### `GET /api/v1/scopes`

Return the canonical OAuth-style scope registry.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `list_scopes`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/scopes"
```

## Wave C — Air Gap

### `GET /api/v1/air-gap/feed-status`

Report freshness of feed bundles imported into an air-gapped install.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `air_gap_feed_status`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/air-gap/feed-status"
```

## Wave C — Admin Tokens

### `GET /api/v1/admin/tokens`

Admin: list every API token in the system. PII-redacted.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `admin_list_tokens`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/admin/tokens"
```

## Wave C — User Tokens

### `POST /api/v1/users/me/tokens`

Create a new API token. The raw key is returned exactly once.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `create_my_token`
- **Request body**: `CreateMyTokenRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/users/me/tokens"
```

### `GET /api/v1/users/me/tokens`

List tokens created by the calling user (PII-redacted).

- **Auth**: Required (`X-API-Key`)
- **Handler**: `list_my_tokens`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/users/me/tokens"
```

## Wave C — CSPM

### `POST /api/v1/cspm/snapshot-scan`

Run a CSPM scan against a cloud account snapshot (agentless).

- **Auth**: Required (`X-API-Key`)
- **Handler**: `cspm_snapshot_scan`
- **Request body**: `CSPMSnapshotScanRequest`
- **Success**: `201` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/cspm/snapshot-scan"
```

## Wave C — Skills

### `POST /api/v1/skills/uninstall`

Remove a skill from the active registry; optionally purge cached files.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `skills_uninstall`
- **Request body**: `SkillUninstallRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/skills/uninstall"
```

## Wave C — Rules

### `GET /api/v1/rules/dsl`

_(undocumented)_

- **Auth**: Required (`X-API-Key`)
- **Handler**: `list_dsl_rules`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/rules/dsl"
```

### `PATCH /api/v1/rules/{key}/enabled`

Enable or disable a rule across the rules registry.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `toggle_rule_enabled`
- **Request body**: `ToggleRuleRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X PATCH -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/rules/{key}/enabled"
```

## Wave C — LLM

### `POST /api/v1/llm/approve-spend/{estimate_id}`

Approve a pending LLM spend transaction by ID.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `llm_approve_spend`
- **Request body**: `ApproveSpendRequest`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -X POST -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" -H "Content-Type: application/json" -d '{"example": "payload — see schema for full shape"}' "http://localhost:8000/api/v1/llm/approve-spend/{estimate_id}"
```

### `GET /api/v1/llm/rules/{key}/context-requirement`

Return the contract describing what context this rule needs.

- **Auth**: Required (`X-API-Key`)
- **Handler**: `llm_rule_context_requirement`
- **Request body**: `_None_`
- **Success**: `200` JSON
- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure

**Example**

```bash
curl -sS -H "X-API-Key: $ALDECI_API_KEY" -H "X-Org-ID: $ALDECI_ORG_ID" "http://localhost:8000/api/v1/llm/rules/{key}/context-requirement"
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

- Generated by `tools/extract_routes.py` from `suite-api/apps/api/wave_c_router.py`. Re-run after router changes.
- Schemas marked `_None_` do not accept a request body. Path/query params are typed in the source.
- For request body shapes, consult the Pydantic models in the router source file or the live OpenAPI spec at `GET /openapi.json`.
