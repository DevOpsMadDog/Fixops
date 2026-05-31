# ALDECI Troubleshooting Guide

Use this guide to diagnose issues before opening a support ticket. Each section follows the pattern: **Symptom → Checks → Resolution**.

---

## API Authentication Failures

### Symptom: `401 Unauthorized` on every request

**Check 1 — Is the key correct?**

```bash
echo "Key length: ${#ALDECI_API_KEY}"
# Should be non-zero. If empty, you have not set the variable.
```

**Check 2 — Is the server expecting a key?**

```bash
curl -v https://aldeci.fly.dev/api/v1/health
# This endpoint requires no auth. If it returns 200, the server is up.
```

**Check 3 — Are you using the right header?**

The header is `X-API-Key`, not `Authorization`. Common mistake when copying from generic API docs:

```bash
# Correct
curl -H "X-API-Key: $ALDECI_API_KEY" https://aldeci.fly.dev/api/v1/status

# Wrong
curl -H "Authorization: $ALDECI_API_KEY" https://aldeci.fly.dev/api/v1/status
```

**Check 4 — JWT token expired?**

JWTs default to a 1-hour lifetime. Re-authenticate via `POST /api/v1/users/login` and obtain a new token. If you are using a service account, switch to API key auth which has no expiry.

**Resolution:** Confirm `FIXOPS_API_TOKEN` is set on the server (`flyctl secrets list --app aldeci`). If missing, set it: `flyctl secrets set FIXOPS_API_TOKEN=<value>`.

---

## `403 Forbidden` — Valid Key, Access Denied

### Symptom: `403` with message about insufficient scope

The request is authenticated but your role does not have the required permission.

**Check — What scopes does your token have?**

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/rbac/users/YOUR_USER_ID/scopes?org_id=your-org"
```

**Common scope mismatches:**

| Endpoint | Required scope | Common role that has it |
|----------|---------------|------------------------|
| `POST /api/v1/findings` | `write:findings` | `security_engineer`, `org_admin` |
| `POST /api/v1/connectors` | `write:integrations` | `security_engineer`, `org_admin` |
| `POST /api/v1/rbac/assign` | `admin:org` | `org_admin`, `super_admin` |
| `GET /api/v1/audit` | `read:findings` | `analyst` and above |

**Resolution:** Ask your `org_admin` to assign a higher role via `POST /api/v1/rbac/assign`.

---

## Scanner Ingestion Errors

### Symptom: `422 Unprocessable Entity` on file upload

This means the file format was not recognised or failed validation.

**Check 1 — File extension**

Allowed extensions: `.json`, `.xml`, `.sarif`, `.nessus`, `.yaml`, `.yml`, `.csv`, `.html`, `.txt`, `.log`, `.cdx`, `.spdx`, `.vex`. Files with other extensions are rejected before parsing.

**Check 2 — Scanner type mismatch**

If you specify `scanner_type=trivy` but upload a Snyk report, the normaliser will fail. Either specify the correct type or use `POST /api/v1/scanner-ingest/detect` for auto-detection.

**Check 3 — Truncated file**

Some CI pipelines truncate large output files. Verify the file is complete:

```bash
python3 -c "import json; json.load(open('report.json'))" && echo "valid JSON"
```

**Check 4 — File too large**

Maximum upload size is 100 MB. Webhook ingestion maximum is 50 MB. Split large reports into per-scan files if needed.

**Resolution:** Use `POST /api/v1/scanner-ingest/detect` with the `--verbose` flag (via curl `-v`) to see what the auto-detector identified, then re-ingest with the correct `scanner_type`.

---

### Symptom: `422` with "Invalid scanner type format"

The `scanner_type` field only accepts alphanumeric characters, hyphens, and underscores (1–64 characters). Values like `Trivy 0.50` or `snyk/code` are rejected.

Use the canonical slug: `trivy`, `snyk`, `semgrep`, `zap`, `nessus`, `bandit`, etc. Full list at `GET /api/v1/scanner-ingest/supported`.

---

## Connector / Integration Failures

### Symptom: `503 Service Unavailable` when triggering a connector sync

The upstream service (GitHub, Jira, etc.) is unreachable or returned an error.

**Check 1 — Connector health**

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/connectors/CONN-ID"
# Look for "status" and "last_error" fields
```

**Check 2 — Credentials still valid?**

Tokens expire. GitHub PATs have configurable expiry (default no expiry, but organisation policies may enforce 90-day rotation). Jira API tokens do not expire but can be revoked. Check the `last_error` field for `401` or `403` messages from the upstream.

**Check 3 — Network path**

From an air-gapped or VPC-isolated ALDECI deployment, the connector must be able to reach the upstream service. Test:

```bash
flyctl ssh console --app aldeci -C "curl -s -o /dev/null -w '%{http_code}' https://api.github.com"
```

**Resolution:** Re-register the connector with fresh credentials via `PUT /api/v1/connectors/{connector_id}`.

---

### Symptom: Jira issues not being created

**Check 1 — Project key exists**

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/jira-sync/projects"
```

If the project key `SEC` is not in the list, the integration will silently fail to create issues. Create the project in Jira first.

**Check 2 — Issue type**

ALDECI defaults to issue type `Bug`. If your Jira project uses a custom issue type scheme that excludes `Bug`, create a project-level configuration to map to the correct type.

---

## Dashboard Shows No Data

### Symptom: Findings page is empty after ingestion

**Check 1 — `org_id` mismatch**

The most common cause. If findings were ingested with `org_id=acme` but the UI is filtering on `org_id=ACME` (case-sensitive mismatch), results will be empty.

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/findings?org_id=acme"
# Try both cases if uncertain
```

**Check 2 — Scanner not yet ingested**

Verify ingestion completed:

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/scanner-ingest/stats?org_id=acme"
# Check "total_ingested" and "last_ingested_at"
```

**Check 3 — Brain Pipeline still processing**

Large ingestion jobs (thousands of findings) queue through the Brain Pipeline. Check `brain_pipeline_status` on individual findings:

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/findings?org_id=acme&limit=5" \
  | python3 -c "import sys,json; [print(f['id'], f.get('brain_pipeline_status')) for f in json.load(sys.stdin).get('items',[])]"
```

Status `queued` or `processing` is expected for recent ingestion. Status `failed` indicates a pipeline error — check the application logs.

---

### Symptom: Compliance dashboard shows 0% for all frameworks

**Check — Framework data populated?**

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/compliance-engine/frameworks?org_id=acme"
```

If the response is an empty array, no findings have been processed through the compliance mapping engine yet. Compliance scores populate automatically as findings flow through the Brain Pipeline; they will not appear until at least one scan has been ingested and processed.

---

## Slow Boot / 502 on Fresh Deploy

### Symptom: `502 Bad Gateway` immediately after deploying

ALDECI boots with approximately 6,722 API routes. Cold-start time on a `shared-cpu-1x` Fly.io instance is approximately 40–60 seconds. The `fly.toml` health check is configured with a 360-second grace period to accommodate this.

**Check — Is the instance still starting?**

```bash
flyctl logs --app aldeci | tail -30
# Look for: "Application startup complete" from uvicorn
```

**Check — Is the health check passing yet?**

```bash
flyctl status --app aldeci
# Machine state should move from "starting" to "running"
```

**Resolution:** Wait 90 seconds and retry. If the instance has not started after 5 minutes, check logs for import errors:

```bash
flyctl logs --app aldeci | grep "ERROR\|ImportError\|Exception"
```

---

## CSP Errors in Browser

### Symptom: Browser console shows Content-Security-Policy violations

ALDECI's CSP is set for the default `aldeci.fly.dev` domain. When using a custom domain:

1. The CSP `frame-ancestors` directive may need updating.
2. If embedding ALDECI in an iframe, add your parent domain to `frame-ancestors`.

Contact your account representative for a custom CSP configuration. Do not disable CSP entirely — it protects against XSS attacks.

---

## AI Council Verdict Not Returning

### Symptom: `POST /api/v1/council` times out or returns `503`

**Check 1 — OpenRouter key configured?**

```bash
flyctl secrets list --app aldeci | grep OPENROUTER
```

If `OPENROUTER_API_KEY` is not set, the council will not function. Set it:

```bash
flyctl secrets set OPENROUTER_API_KEY=sk-or-v1-XXXX --app aldeci
```

**Check 2 — Council status**

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/council/status
```

A `degraded` status with `available_models: 0` confirms the key issue.

**Check 3 — Individual model failure**

The council tolerates partial model failures and produces a verdict with however many models responded. A `confidence` below 0.4 in the response indicates fewer than the expected quorum of models participated.

---

## Evidence Bundle Verification Fails

### Symptom: `POST /api/v1/evidence/verify` returns `verified: false`

**Possible causes:**

1. **Bundle was modified after generation.** The bundle ZIP or its contents were altered. Re-generate the bundle from the original finding data.
2. **Clock skew.** The signing timestamp is in the future relative to the verifier clock. Ensure server time is NTP-synchronized.
3. **Key rotation.** If the RSA signing key was rotated after the bundle was generated, the signature will no longer verify. ALDECI retains old public keys for verification purposes; contact support if key rotation was performed manually.

---

## Getting Support

If this guide does not resolve your issue:

1. Collect the request ID from the response header `X-Request-ID`.
2. Export relevant audit log entries: `GET /api/v1/audit?org_id=YOUR_ORG&limit=20`.
3. Include the ALDECI version from `GET /api/v1/status`.
4. Email `support@devopsai.co` with the above context.

For production-down situations, refer to the [Incident Response Runbook](incident-response-runbook.md).
