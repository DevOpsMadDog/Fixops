# ALDECI API Reference

> **Code-verified against the running codebase on 2026-06-01.**
> Every endpoint path, request shape, response field, and error code in this document
> was read directly from the handler or Pydantic model — nothing is invented.
> Where behaviour requires configuration (env vars, Stripe), that is stated explicitly.

---

## Base URL

| Deployment | Base URL |
|------------|----------|
| Fly.io hosted | `https://aldeci.fly.dev` |
| Self-hosted | Your configured domain |

All endpoints are versioned under `/api/v1/`.

Machine-readable OpenAPI spec (live, reflects running instance):

```
GET /api/v1/openapi.json   — JSON schema
GET /docs                  — Swagger UI
GET /redoc                 — ReDoc UI
```

---

## Authentication

ALDECI accepts three credential forms on every protected endpoint. All three
validate against the same auth middleware.

### 1. API Key header (preferred for service-to-service)

```
X-API-Key: <your-api-key>
```

The API key is obtained via the signup flow (see below) or minted by an admin
via `POST /api/v1/auth/keys`. It is SHA-256 hashed at rest — the plaintext
is shown only once at creation.

### 2. JWT Bearer token

```
Authorization: Bearer <jwt>
```

Obtain a JWT from `POST /api/v1/users/login` or `POST /api/v1/auth/login`.
Access tokens expire after 2 hours (configurable via `FIXOPS_JWT_EXPIRE_HOURS`).
Refresh tokens last 7 days (`FIXOPS_JWT_REFRESH_DAYS`).

**Required environment variable:** `FIXOPS_JWT_SECRET` — must be at least 32
characters. If absent or too short, JWT auth is disabled and the login endpoint
returns `503`.

### 3. Query parameter (browser / report downloads only)

```
GET /api/v1/findings?api_key=<your-api-key>
```

Use only for browser-opened URLs. Do not use in programmatic clients.

### Dev / demo mode

When `FIXOPS_MODE=dev` (or `demo`, `development`, `local`), auth is relaxed so
the API starts without credentials configured. **Never use in production.**

### Environment variable summary

| Variable | Purpose | Required |
|----------|---------|---------|
| `FIXOPS_API_TOKEN` | Static API key(s) — comma-separated for multiple | Recommended |
| `FIXOPS_JWT_SECRET` | HMAC-SHA256 signing key, >= 32 chars | Required for JWT auth |
| `FIXOPS_JWT_EXPIRE_HOURS` | Access token TTL (default `2`) | Optional |
| `FIXOPS_JWT_REFRESH_DAYS` | Refresh token TTL (default `7`) | Optional |
| `FIXOPS_MODE` | Set `dev` to relax auth for local development | Optional |

---

## Signup and Credential Flow

This is the complete path from zero to an authenticated API call.

### Step 1 — Sign up

```http
POST /api/v1/auth/signup
Content-Type: application/json
```

**Request body:**

| Field | Type | Constraints |
|-------|------|-------------|
| `email` | string | Valid email format |
| `password` | string | Minimum 12 characters (NIST SP 800-63B) |
| `first_name` | string | 1–128 chars, not blank |
| `last_name` | string | 1–128 chars, not blank |

Optional headers:

| Header | Effect |
|--------|--------|
| `X-Org-ID: <slug>` | Pin the new account to a specific org ID. If omitted, org is auto-derived as `org-<user_id>`. |

**Rate limit:** 5 requests/minute per IP.

**curl example:**

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "correct-horse-battery",
    "first_name": "Alex",
    "last_name": "Smith"
  }' | python3 -m json.tool
```

**Response (201):**

```json
{
  "user_id": "usr-a1b2c3d4",
  "email": "admin@example.com",
  "org_id": "org-a1b2c3d4",
  "api_key": "aldeci_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "api_key_id": "key-e5f6g7h8",
  "message": "Account created. Your API key is in the `api_key` field — save it now, it will not be shown again. Check your email for a verification link.",
  "email_verified": false
}
```

**Save `api_key` immediately.** It is the plaintext key returned once and
never stored in plaintext. The signing user is assigned role `admin` and
scope `admin:all`.

**Error codes:**

| Code | Condition |
|------|-----------|
| `409` | Email already registered |
| `422` | Invalid email format, blank name, or password too short |
| `429` | Rate limit exceeded (5/min per IP) |

### Step 2 — Use the API key

```bash
export ALDECI_API_KEY="aldeci_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export ALDECI_ORG_ID="org-a1b2c3d4"

curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/status | python3 -m json.tool
```

### Step 3 — (Optional) Obtain a JWT for browser sessions

```bash
TOKEN=$(curl -s -X POST https://aldeci.fly.dev/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"correct-horse-battery"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -H "Authorization: Bearer $TOKEN" \
  "https://aldeci.fly.dev/api/v1/findings?org_id=$ALDECI_ORG_ID"
```

The JWT payload includes `role`, `scopes`, and `org_id` claims that are used
for RBAC and tenant isolation.

### Step 4 — (Admin) Mint additional managed API keys

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/auth/keys \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-pipeline",
    "user_id": "usr-a1b2c3d4",
    "role": "security_analyst",
    "scopes": ["read:findings", "write:findings"],
    "ttl_days": 90
  }' | python3 -m json.tool
```

Response includes `plaintext_key` (shown once) and `key_prefix` for
identification. Requires `admin:all` scope.

---

## Tenant Isolation and the X-Org-ID Header

All tenant-scoped endpoints resolve `org_id` in priority order:

1. `request.state.org_id` — set by the auth middleware from the JWT `org_id` claim
2. `X-Org-ID` request header
3. `?org_id=` query parameter
4. Hard default `"default"`

**When using API keys** (which do not carry an `org_id` claim), send the
`X-Org-ID` header on every request:

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
     -H "X-Org-ID: $ALDECI_ORG_ID" \
     https://aldeci.fly.dev/api/v1/findings
```

Cross-org access returns `404` (not `403`) to prevent existence leakage.

---

## Pagination

All list endpoints accept `limit` and `offset` query parameters and return a
standard envelope:

```json
{
  "items": [ ... ],
  "total": 1423,
  "limit": 50,
  "offset": 0
}
```

Some endpoints also return `X-Total-Count` as a response header. The `total`
field always reflects the full tenant row count, not just `len(items)`.

Default and maximum values vary by endpoint:

| Endpoint | Default limit | Max limit |
|----------|--------------|-----------|
| `GET /api/v1/users` | 50 | 500 |
| `GET /api/v1/findings` | 50 | 500 |
| `GET /api/v1/audit` | 100 | — |
| `GET /api/v1/auth/sso` | 100 | 1000 |

---

## Tier Gating

Some endpoints require a billing tier. Tier enforcement uses `STRIPE_SECRET_KEY`:

- **When `STRIPE_SECRET_KEY` is not set** (self-hosted / dev): all orgs are
  default-allowed at `enterprise` level regardless of tier — no 402 is ever
  returned.
- **When `STRIPE_SECRET_KEY` is set**: the org's tier is looked up from
  `data/org_tiers.db`. If the org's tier is below the required minimum,
  the endpoint returns **402 Payment Required**.

Tier order: `starter` < `pro` < `enterprise`

| Endpoint | Minimum tier |
|----------|-------------|
| `POST /api/v1/risk-quantifier/scenarios` | `pro` |
| `GET /api/v1/risk-quantifier/portfolio` | `pro` |
| `GET /api/v1/risk-quantifier/roi` | `pro` |
| `POST /api/v1/exec-reporting/reports` | `pro` |
| `GET /api/v1/exec-reporting/reports` | `pro` |
| `GET /api/v1/exec-reporting/kpis` | `pro` |
| `POST /api/v1/exec-reporting/board-presentations` | `enterprise` |
| `GET /api/v1/exec-reporting/board-presentations` | `enterprise` |

Set an org's tier via the Stripe webhook handler or directly:

```bash
# Admin override (requires admin:all)
curl -s -X POST https://aldeci.fly.dev/api/v1/billing/tier \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "acme", "tier": "pro"}'
```

---

## Endpoints Requiring Configuration

The following endpoints return `501 Not Implemented` or `503 Service Unavailable`
until the indicated environment variable or external service is configured.
They are not broken — they are honest about their dependency.

| Endpoint | Status | Requires | How to enable |
|----------|--------|---------|---------------|
| `GET /api/v1/peer-insights/trends` | `501` | External peer data feed | Configure and ingest a peer-data feed |
| `POST /api/v1/openclaw/campaigns/{id}/start` | `501` | Pentest connector | Set `PENTEST_CONNECTOR_URL` env var |
| `POST /api/v1/openclaw/campaigns/{id}/advance` | `501` | Pentest connector | Set `PENTEST_CONNECTOR_URL` env var |
| `GET /api/v1/ml-anomaly/...` | `503` | ML anomaly backend | Configure and start the ML anomaly service |
| `GET /api/v1/cloud-drift/...` | `503` | Cloud provider credentials | Configure CSPM cloud credentials |

These endpoints are fully wired in the routing layer and will activate once the
dependency is satisfied — no code change required.

---

## Error Codes Reference

| HTTP Code | Meaning |
|-----------|---------|
| `401` | Missing or invalid credential (`X-API-Key` / JWT absent or unrecognisable) |
| `403` | Valid credential but insufficient RBAC scope |
| `404` | Resource not found — also used for cross-org access (prevents existence leakage) |
| `409` | Conflict (e.g. email already registered) |
| `422` | Request validation failure — see `detail` field for field-level errors |
| `429` | Rate limit exceeded |
| `402` | Billing tier below minimum for this endpoint (only when `STRIPE_SECRET_KEY` set) |
| `501` | Endpoint not yet connected to its upstream (see table above) |
| `503` | Upstream service unavailable or not configured |

---

## Platform Health

### `GET /api/v1/health` — liveness probe (no auth)

Returns 200 when the API process is alive. Used by load-balancer health checks.

```bash
curl https://aldeci.fly.dev/api/v1/health
# {"status":"ok"}
```

### `GET /api/v1/status` — platform status (auth required)

Returns mode, version, and engine availability.

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" https://aldeci.fly.dev/api/v1/status
```

---

## Findings

Findings are the central resource. Every scanner result normalised through the
12-step Brain Pipeline becomes a finding with a stable `finding_id` and an
`org_id` for tenant isolation.

### `GET /api/v1/findings` — list findings

**Scope:** `read:findings`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `status` | string | `open`, `in_progress`, `resolved`, `accepted` |
| `scanner` | string | Source scanner (e.g. `trivy`, `semgrep`) |
| `limit` | int | Page size (default 50, max 500) |
| `offset` | int | Pagination offset |

`org_id` is resolved from auth state / `X-Org-ID` header / `?org_id=` param.

```bash
curl -s \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  "https://aldeci.fly.dev/api/v1/findings?severity=critical&limit=20" \
  | python3 -m json.tool
```

### `POST /api/v1/findings` — create finding

**Scope:** `write:findings`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/findings \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "SQL injection in /api/orders",
    "severity": "critical",
    "source_scanner": "manual_pentest",
    "asset_id": "app://orders-service",
    "description": "Unsanitised user input in ORDER BY clause allows blind SQLi",
    "remediation": "Parameterise all SQL queries"
  }' | python3 -m json.tool
```

### `GET /api/v1/findings/{finding_id}` — get single finding

```bash
curl -s \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  "https://aldeci.fly.dev/api/v1/findings/FND-abc123" \
  | python3 -m json.tool
```

### `POST /api/v1/findings/correlate` — correlate related findings

**Scope:** `write:findings`

Groups findings by asset, CVE, or attack chain to de-duplicate multi-scanner output.

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/findings/correlate \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d '{"strategy": "cve_and_asset"}' \
  | python3 -m json.tool
```

---

## Scanner Ingestion

### `POST /api/v1/scanner-ingest/upload` — upload scanner report

Accepts multipart file upload.

**Limits (verified from source):**
- Maximum upload size: **50 MB** (enforced via `MAX_UPLOAD_BYTES`)
- Allowed extensions: `.json`, `.sarif`, `.xml`, `.csv`, `.txt`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@trivy-results.json" \
  -F "scanner_type=trivy" \
  -F "org_id=$ALDECI_ORG_ID" \
  | python3 -m json.tool
```

**Response fields:** `ingested_count`, `normalised_count`, `scanner_detected`, `job_id`, `errors`.

### `POST /api/v1/scanner-ingest/webhook/{type}` — webhook receiver

Accepts raw scanner webhook body (JSON or XML). Max 50 MB.

```bash
curl -s -X POST \
  https://aldeci.fly.dev/api/v1/scanner-ingest/webhook/snyk \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @snyk-output.json | python3 -m json.tool
```

Valid `{type}` values: `trivy`, `snyk`, `semgrep`, `zap`, `nessus`, `bandit`,
`grype`, `nuclei`, `checkov`, `tfsec`, `kubeaudit`, and others. Full list:

### `POST /api/v1/scanner-ingest/detect` — auto-detect scanner type

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/detect \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@unknown-report.json" \
  -F "org_id=$ALDECI_ORG_ID" \
  | python3 -m json.tool
```

### `GET /api/v1/scanner-ingest/supported` — list supported scanners (no auth)

```bash
curl https://aldeci.fly.dev/api/v1/scanner-ingest/supported
```

### `GET /api/v1/scanner-ingest/stats` — ingestion statistics

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  "https://aldeci.fly.dev/api/v1/scanner-ingest/stats"
```

---

## Connectors

### `POST /api/v1/connectors/register` — register a connector

Supported types: `jira`, `github`, `slack`.

The request body accepts either a **typed key** (preferred) or a generic
**`config` alias** — both are validated by the same Pydantic model for the
connector type.

**Form 1 — typed key (preferred):**

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/connectors/register \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "github-prod",
    "type": "github",
    "github": {
      "token": "ghp_XXXXXXXXXXXXXXXXXXXX",
      "owner": "your-github-org",
      "repo": "your-repo"
    }
  }' | python3 -m json.tool
```

**Form 2 — generic `config` alias:**

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/connectors/register \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "github-prod",
    "type": "github",
    "config": {
      "token": "ghp_XXXXXXXXXXXXXXXXXXXX",
      "owner": "your-github-org",
      "repo": "your-repo"
    }
  }' | python3 -m json.tool
```

If neither the typed key nor `config` is provided, the API returns **400** with
a helpful error explaining exactly what field to send and listing required fields.

**Jira config fields:**

| Field | Type | Notes |
|-------|------|-------|
| `base_url` | string | Must start with `https://` |
| `email` | string | Jira user email |
| `api_token` | string | Jira API token |
| `project_key` | string | Uppercase, e.g. `SEC` |
| `issue_type` | string | Default `"Bug"` |

**GitHub config fields:**

| Field | Type | Notes |
|-------|------|-------|
| `token` | string | Personal access token or GitHub App token |
| `owner` | string | Org or user name |
| `repo` | string | Repository name |

**Slack config fields:**

| Field | Type | Notes |
|-------|------|-------|
| `webhook_url` | string | Must start with `https://hooks.slack.com/` |
| `channel` | string | Optional channel override |

**Response:**

```json
{
  "status": "registered",
  "name": "github-prod",
  "type": "github",
  "configured": true
}
```

### `GET /api/v1/connectors` — list registered connectors

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  https://aldeci.fly.dev/api/v1/connectors
```

### `POST /api/v1/connectors/test` — test all connectors

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/connectors/test \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  | python3 -m json.tool
```

---

## AI Council Verdict

### `POST /api/v1/council` — request a verdict

Submit a finding for multi-model AI consensus analysis. Up to four LLM models
convene; if consensus is not reached, Opus escalation is triggered automatically.

**Scope:** `read:findings`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/council \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "FND-abc123",
    "context": {"asset_criticality": "tier-1", "exploit_available": true}
  }' | python3 -m json.tool
```

**Response fields:** `verdict` (`exploit`, `remediate`, `accept`, `monitor`),
`confidence` (0–1), `reasoning`, `model_votes` (per-model breakdown), `council_id`.

### `GET /api/v1/council/status` — council health

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/council/status
```

---

## Evidence Bundles

### `POST /api/v1/evidence/bundles/generate` — generate evidence bundle

Creates a cryptographically signed bundle (SHA-256 hash chain) containing
finding details, council verdict, audit trail entries, and compliance mappings.

**Scope:** `read:findings`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/evidence/bundles/generate \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_ids": ["FND-abc123", "FND-def456"],
    "include_council_verdict": true,
    "include_audit_trail": true
  }' | python3 -m json.tool
```

### `GET /api/v1/evidence/bundles` — list bundles

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  https://aldeci.fly.dev/api/v1/evidence/bundles
```

### `POST /api/v1/evidence/verify` — verify bundle integrity

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/evidence/verify \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"bundle_id": "EVB-xyz789"}' \
  | python3 -m json.tool
```

**Response fields:** `verified` (bool), `hash_chain_valid`, `signature_valid`,
`bundle_id`, `generated_at`.

### `GET /api/v1/evidence/bundles/{bundle_id}/download` — download bundle

Returns a ZIP archive containing JSON evidence files and a SHA-256 manifest.

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/evidence/bundles/EVB-xyz789/download" \
  -o evidence-bundle.zip
```

---

## Audit Log

The audit log captures every API write operation with actor identity, timestamp,
IP address, and payload hash. It is append-only within the retention window.

Retention defaults to 90 days. Configure via `FIXOPS_AUDIT_RETENTION_DAYS`.
Daily purge runs automatically unless `FIXOPS_DISABLE_AUDIT_RETENTION=1`.

### `GET /api/v1/audit` — search audit log

**Scope:** `read:findings`

**Query parameters:**

| Parameter | Description |
|-----------|-------------|
| `actor` | Filter by user or service account ID |
| `action` | Event type (e.g. `finding.create`, `evidence.generate`) |
| `from_ts` | ISO 8601 start timestamp |
| `to_ts` | ISO 8601 end timestamp |
| `limit` | Page size (default 100) |
| `offset` | Pagination offset |

```bash
curl -s \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  "https://aldeci.fly.dev/api/v1/audit?limit=50&action=finding.create" \
  | python3 -m json.tool
```

---

## Risk Acceptance

### `POST /api/v1/risk-acceptance` — create risk acceptance

**Scope:** `write:findings`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/risk-acceptance \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "FND-abc123",
    "rationale": "Mitigated by WAF rule WAF-009 pending fix in Q3",
    "accepted_by": "ciso@example.com",
    "expires_at": "2026-09-30T00:00:00Z"
  }' | python3 -m json.tool
```

### `GET /api/v1/risk-acceptance` — list risk acceptances

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  https://aldeci.fly.dev/api/v1/risk-acceptance
```

---

## API Key Management

All key management endpoints require `admin:all` scope.

### `POST /api/v1/auth/keys` — create a managed API key

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/auth/keys \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-pipeline",
    "user_id": "usr-a1b2c3d4",
    "role": "security_analyst",
    "scopes": ["read:findings", "write:findings"],
    "ttl_days": 90
  }' | python3 -m json.tool
```

Response includes `plaintext_key` (shown once) and `key_prefix` for
identification. Keys are SHA-256 hashed at rest.

### `POST /api/v1/auth/keys/{key_id}/rotate` — rotate a key

Creates a replacement key and puts the old key in a grace period.

```bash
curl -s -X POST \
  "https://aldeci.fly.dev/api/v1/auth/keys/key-e5f6g7h8/rotate" \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"performed_by": "admin@example.com"}' \
  | python3 -m json.tool
```

### `DELETE /api/v1/auth/keys/{key_id}` — revoke a key immediately

```bash
curl -s -X DELETE \
  "https://aldeci.fly.dev/api/v1/auth/keys/key-e5f6g7h8" \
  -H "X-API-Key: $ALDECI_API_KEY"
```

### `GET /api/v1/auth/keys` — list managed keys

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/auth/keys
```

### `GET /api/v1/auth/keys/expiring` — keys expiring soon

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/auth/keys/expiring?within_days=7"
```

---

## RBAC

### `GET /api/v1/rbac/roles` — list role definitions

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/rbac/roles
```

Available roles: `admin`, `security_analyst`, `developer`, `viewer`.

### `POST /api/v1/rbac/assign` — assign role to user

**Scope:** `admin:all`

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/rbac/assign \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "usr-a1b2c3d4", "role": "security_analyst"}' \
  | python3 -m json.tool
```

### `GET /api/v1/rbac/users/{user_id}/scopes` — effective scopes for a user

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  "https://aldeci.fly.dev/api/v1/rbac/users/usr-a1b2c3d4/scopes"
```

---

## Risk Quantification (Pro tier+)

All risk-quantifier endpoints require `pro` tier (or self-hosted with no Stripe key).

### `POST /api/v1/risk-quantifier/scenarios` — create FAIR risk scenario

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/risk-quantifier/scenarios \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SQL injection breach scenario",
    "threat_event": "Attacker exfiltrates customer PII via blind SQLi",
    "asset_value_usd": 2000000,
    "loss_magnitude_low": 50000,
    "loss_magnitude_high": 800000,
    "probability_low": 0.05,
    "probability_high": 0.25
  }' | python3 -m json.tool
```

### `GET /api/v1/risk-quantifier/portfolio` — total org risk exposure

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  https://aldeci.fly.dev/api/v1/risk-quantifier/portfolio
```

---

## Executive Reporting (Pro/Enterprise tier)

### `POST /api/v1/exec-reporting/reports` — create executive report (Pro+)

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/exec-reporting/reports \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d '{"report_type": "monthly", "title": "June 2026 Security Posture"}' \
  | python3 -m json.tool
```

### `POST /api/v1/exec-reporting/board-presentations` — board presentation (Enterprise)

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/exec-reporting/board-presentations \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d '{"title": "Q2 2026 Board Security Update"}' \
  | python3 -m json.tool
```

---

## Rate Limits

Default limits apply per API key per organisation. Specific auth endpoints have
stricter limits enforced in-process (no Slowapi dependency required):

| Endpoint | Limit |
|----------|-------|
| `POST /api/v1/auth/signup` | 5/min per IP |
| `POST /api/v1/auth/login` | 10/min per IP |
| `POST /api/v1/auth/forgot-password` | 5/min per IP |
| `POST /api/v1/auth/reset-password` | 10/min per IP |
| `POST /api/v1/auth/dev-token` | 10/min per IP (dev mode only) |
| `POST /api/v1/scanner-ingest/upload` | 30/min per IP |

When a rate limit is exceeded the API returns `429 Too Many Requests` with
a message indicating retry timing.

---

## Full Specification

The canonical machine-readable spec reflects the running instance:

```bash
curl https://aldeci.fly.dev/openapi.json -o openapi.json
```

Import into Postman, Insomnia, or any OpenAPI-compatible client for full schema
validation and auto-generated request builders.
