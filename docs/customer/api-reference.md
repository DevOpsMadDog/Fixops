# ALDECI API Reference

## Overview

ALDECI exposes a single versioned REST API at `/api/v1/`. All endpoints require authentication via `X-API-Key` header (or `Authorization: Bearer <jwt>` for JWT-authenticated sessions). The complete machine-readable OpenAPI specification is served live at:

```
GET https://aldeci.fly.dev/api/v1/openapi.json
GET https://aldeci.fly.dev/docs          (Swagger UI)
GET https://aldeci.fly.dev/redoc         (ReDoc UI)
```

This document provides narrative guidance and `curl` examples for the most-used endpoints. Use the OpenAPI spec for parameter-level detail, schema definitions, and the full endpoint inventory.

---

## Authentication

### API Key (primary)

Set `FIXOPS_API_TOKEN` in the server environment (via `flyctl secrets set` for Fly.io deployments). Pass it in every request:

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" https://aldeci.fly.dev/api/v1/status
```

### JWT Bearer Token

Obtain a JWT via the login endpoint and pass it as a Bearer token:

```bash
# Step 1 — obtain token
TOKEN=$(curl -s -X POST https://aldeci.fly.dev/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@example.com","password":"YOURPASS"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Step 2 — use token
curl -H "Authorization: Bearer $TOKEN" https://aldeci.fly.dev/api/v1/findings
```

### OAuth2

Machine-to-machine flows use `POST /api/v1/oauth2/token` with `grant_type=client_credentials`.

### Error responses

| HTTP Code | Meaning |
|-----------|---------|
| `401` | Missing or invalid `X-API-Key` / JWT |
| `403` | Valid credentials but insufficient RBAC scope |
| `422` | Request validation failure (see `detail` field) |
| `429` | Rate limit exceeded |
| `503` | Downstream connector unavailable |

---

## Platform Health

### `GET /api/v1/health` — liveness probe (no auth)

Returns 200 when the API process is alive. Used by Fly.io health checks.

```bash
curl https://aldeci.fly.dev/api/v1/health
# {"status":"ok"}
```

### `GET /api/v1/status` — platform status

Returns mode, version, and engine availability.

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" https://aldeci.fly.dev/api/v1/status
```

---

## Findings

Findings are the central resource in ALDECI. Every scanner result, after normalisation through the Brain Pipeline, becomes a finding with a stable `finding_id` and an `org_id` for tenant isolation.

### `GET /api/v1/findings` — list findings

**Scope required:** `read:findings`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `org_id` | string | Tenant identifier (required for multi-tenant deployments) |
| `severity` | string | Filter: `critical`, `high`, `medium`, `low`, `info` |
| `status` | string | Filter: `open`, `in_progress`, `resolved`, `accepted` |
| `scanner` | string | Source scanner name (e.g. `trivy`, `semgrep`) |
| `limit` | int | Page size (default 50, max 500) |
| `offset` | int | Pagination offset |

```bash
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/findings?org_id=acme&severity=critical&limit=20" \
  | python3 -m json.tool
```

---

### `POST /api/v1/findings` — create finding manually

**Scope required:** `write:findings`

Use this to inject findings from sources not covered by the connector framework (e.g. manual penetration test notes).

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/findings \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "acme",
    "title": "SQL injection in /api/orders endpoint",
    "severity": "critical",
    "source_scanner": "manual_pentest",
    "asset_id": "app://orders-service",
    "description": "Unsanitised user input in ORDER BY clause allows blind SQLi",
    "cve_ids": [],
    "remediation": "Parameterise all SQL queries"
  }' | python3 -m json.tool
```

---

### `GET /api/v1/findings/{finding_id}` — get single finding

```bash
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/findings/FND-abc123" | python3 -m json.tool
```

---

### `POST /api/v1/findings/correlate` — correlate related findings

Groups findings by asset, CVE, or attack chain. Useful for de-duplicating scanner output across multiple tools reporting the same underlying vulnerability.

**Scope required:** `write:findings`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/findings/correlate \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "acme", "strategy": "cve_and_asset"}' \
  | python3 -m json.tool
```

---

## Scanner Ingestion

### `POST /api/v1/scanner-ingest/upload` — upload scanner report

Accepts multipart file upload. Max 100 MB. Supported extensions: `.json`, `.xml`, `.sarif`, `.nessus`, `.yaml`, `.csv`, `.html`, `.txt`, `.cdx`, `.spdx`.

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@trivy-results.json" \
  -F "scanner_type=trivy" \
  -F "org_id=acme" | python3 -m json.tool
```

**Response fields:** `ingested_count`, `normalised_count`, `scanner_detected`, `job_id`, `errors`.

---

### `POST /api/v1/scanner-ingest/webhook/{type}` — webhook receiver

Accepts raw body (JSON or XML) from a scanner's built-in webhook. Max 50 MB.

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/webhook/snyk \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @snyk-output.json | python3 -m json.tool
```

Valid `{type}` values: `trivy`, `snyk`, `semgrep`, `zap`, `nessus`, `bandit`, `grype`, `nuclei`, `checkov`, `tfsec`, `kubeaudit`, and others. Retrieve the full list from `/api/v1/scanner-ingest/supported`.

---

### `POST /api/v1/scanner-ingest/detect` — auto-detect scanner type

Submit a file without specifying the scanner; ALDECI will identify the format and normalise accordingly.

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/detect \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@unknown-report.json" \
  -F "org_id=acme" | python3 -m json.tool
```

---

### `GET /api/v1/scanner-ingest/supported` — list supported scanners

No authentication required for this endpoint.

```bash
curl https://aldeci.fly.dev/api/v1/scanner-ingest/supported
```

---

### `GET /api/v1/scanner-ingest/stats` — ingestion statistics

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/scanner-ingest/stats?org_id=acme"
```

---

## Risk Acceptance

### `POST /api/v1/risk-acceptance` — create risk acceptance

Record a formal decision to accept a finding's risk, with justification and expiry.

**Scope required:** `write:findings`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/risk-acceptance \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "acme",
    "finding_id": "FND-abc123",
    "rationale": "Mitigated by WAF rule WAF-009 pending fix in Q3",
    "accepted_by": "ciso@example.com",
    "expires_at": "2026-09-30T00:00:00Z"
  }' | python3 -m json.tool
```

---

### `GET /api/v1/risk-acceptance` — list risk acceptances

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/risk-acceptance?org_id=acme"
```

---

## Audit Log

The audit log captures every API write operation with actor identity, timestamp, IP address, and payload hash. It is append-only within the retention window.

### `GET /api/v1/audit` — search audit log

**Scope required:** `read:findings`

```bash
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/audit?org_id=acme&limit=50&action=finding.create" \
  | python3 -m json.tool
```

**Query parameters:**

| Parameter | Description |
|-----------|-------------|
| `org_id` | Tenant filter |
| `actor` | Filter by user or service account ID |
| `action` | Event type (e.g. `finding.create`, `evidence.generate`) |
| `from_ts` | ISO 8601 start timestamp |
| `to_ts` | ISO 8601 end timestamp |
| `limit` | Page size (default 100) |

Retention defaults to 90 days. Configure via environment variable `FIXOPS_AUDIT_RETENTION_DAYS` (see `suite-core/core/audit_log.py:_retention_days_from_env`). Daily purge runs automatically unless `FIXOPS_DISABLE_AUDIT_RETENTION=1`.

---

## AI Council Verdict

### `POST /api/v1/council` — request a verdict

Submit a finding for multi-model AI consensus analysis. The council convenes up to four LLM models; if consensus cannot be reached, Opus escalation is triggered automatically.

**Scope required:** `read:findings`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/council \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "FND-abc123",
    "org_id": "acme",
    "context": {"asset_criticality": "tier-1", "exploit_available": true}
  }' | python3 -m json.tool
```

**Response fields:** `verdict` (`exploit`, `remediate`, `accept`, `monitor`), `confidence` (0–1), `reasoning`, `model_votes` (per-model breakdown), `council_id`.

---

### `GET /api/v1/council/status` — council health

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/council/status
```

---

### `GET /api/v1/llm/council/status` — LLM council status alias

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/llm/council/status
```

---

## Evidence Bundles

### `POST /api/v1/evidence/bundles/generate` — generate evidence bundle

Creates a cryptographically signed bundle containing finding details, council verdict, audit trail entries, and compliance mappings. Suitable for audit submission and compliance evidence libraries.

**Scope required:** `read:findings`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/evidence/bundles/generate \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "acme",
    "finding_ids": ["FND-abc123", "FND-def456"],
    "include_council_verdict": true,
    "include_audit_trail": true
  }' | python3 -m json.tool
```

---

### `GET /api/v1/evidence/bundles` — list bundles

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/evidence/bundles?org_id=acme"
```

---

### `POST /api/v1/evidence/verify` — verify bundle integrity

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/evidence/verify \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"bundle_id": "EVB-xyz789", "org_id": "acme"}' \
  | python3 -m json.tool
```

**Response fields:** `verified` (bool), `hash_chain_valid`, `signature_valid`, `bundle_id`, `generated_at`.

---

### `GET /api/v1/evidence/bundles/{bundle_id}/download` — download bundle

Returns the bundle as a ZIP archive containing JSON evidence files and a manifest with SHA-256 hashes.

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/evidence/bundles/EVB-xyz789/download" \
  -o evidence-bundle.zip
```

---

## Connectors

### `POST /api/v1/connectors` — register connector

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/connectors \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "jira",
    "name": "JIRA Production",
    "org_id": "acme",
    "config": {"base_url": "https://acme.atlassian.net", "email": "sec@acme.com", "api_token": "XXX", "project_key": "SEC"}
  }' | python3 -m json.tool
```

### `GET /api/v1/connectors` — list registered connectors

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/connectors?org_id=acme"
```

### `GET /api/v1/connectors/{connector_id}` — connector health and last-sync info

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/connectors/CONN-abc"
```

---

## RBAC

### `POST /api/v1/rbac/assign` — assign role to user

**Scope required:** `admin:org`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/rbac/assign \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "acme", "user_id": "u-123", "role": "analyst"}' \
  | python3 -m json.tool
```

### `GET /api/v1/rbac/roles` — list all role definitions

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" https://aldeci.fly.dev/api/v1/rbac/roles
```

### `GET /api/v1/rbac/users/{user_id}/scopes` — effective scopes for a user

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/rbac/users/u-123/scopes?org_id=acme"
```

---

## Rate Limits

Default limits apply per API key per organisation:

| Tier | Requests/minute | Burst |
|------|----------------|-------|
| Starter | 60 | 120 |
| Pro | 300 | 600 |
| Enterprise | 1000 | 2000 |

Rate limit headers are returned on every response:

```
X-RateLimit-Limit: 300
X-RateLimit-Remaining: 287
X-RateLimit-Reset: 1717200060
```

When a limit is exceeded the API returns `429 Too Many Requests`. Implement exponential backoff with jitter starting at 1 second.

Rate limits are configurable via the Tenant Rate Limiter at `POST /api/v1/tenant-rate-limiter/config` (scope: `admin:all`).

---

## Pagination

All list endpoints use `limit`/`offset` pagination. The response envelope includes:

```json
{
  "items": [...],
  "total": 1423,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

---

## Full Specification

The canonical machine-readable spec is served live and reflects the running instance:

```bash
curl https://aldeci.fly.dev/api/v1/openapi.json -o openapi.json
```

Import into Postman, Insomnia, or any OpenAPI-compatible client for full schema validation and auto-generated request builders.
