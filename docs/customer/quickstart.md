# ALDECI Quickstart — First Verdict in 5 Minutes

> **Code-verified on 2026-06-01.** Every curl command and endpoint path was
> confirmed against the live handler code before being written here.

This guide takes a new customer from zero to a confirmed security finding with
an AI council verdict and a signed evidence bundle.

---

## Prerequisites

| Item | Requirement |
|------|-------------|
| Network | HTTPS outbound to your ALDECI host (or `aldeci.fly.dev`) |
| Tool | `curl` and `python3` (for JSON formatting) |
| Scanner output | Any `.json`, `.sarif`, `.xml`, `.csv`, or `.txt` scanner report |

---

## Step 1 — Sign Up and Get Your API Key

Send one request. The response contains `api_key` — **save it now, it is
shown only once and never stored in plaintext**.

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "correct-horse-battery-staple",
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
  "message": "Account created. Your API key is in the `api_key` field — save it now, it will not be shown again.",
  "email_verified": false
}
```

Export the key and org ID for the rest of this guide:

```bash
export ALDECI_API_KEY="aldeci_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export ALDECI_ORG_ID="org-a1b2c3d4"
```

**Verify the key works:**

```bash
curl -s \
  -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/status | python3 -m json.tool
# {"status":"ok","mode":"enterprise",...}
```

> **Boot note.** On a fresh Fly.io deploy the API takes 40–60 seconds to
> initialise. If you see a `502` immediately after deployment, wait and retry.

---

## Step 2 — Ingest a Scanner Report

Upload an existing report from any supported scanner. Supported extensions:
`.json`, `.sarif`, `.xml`, `.csv`, `.txt`. Maximum size: 50 MB.

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@trivy-report.json" \
  -F "scanner_type=trivy" \
  -F "org_id=$ALDECI_ORG_ID" \
  | python3 -m json.tool
```

Let ALDECI detect the scanner format automatically (omit `scanner_type`):

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/detect \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@unknown-report.xml" \
  -F "org_id=$ALDECI_ORG_ID" \
  | python3 -m json.tool
```

**Response fields to note:** `ingested_count`, `normalised_count`,
`scanner_detected`, `job_id`.

Supported scanner types (full list):

```bash
curl https://aldeci.fly.dev/api/v1/scanner-ingest/supported
```

---

## Step 3 — List Findings

All tenant-scoped endpoints resolve your org from the `X-Org-ID` header.
Include it on every request.

```bash
curl -s \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  "https://aldeci.fly.dev/api/v1/findings?limit=20" \
  | python3 -m json.tool
```

Filter to critical findings only:

```bash
curl -s \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  "https://aldeci.fly.dev/api/v1/findings?severity=critical&limit=10" \
  | python3 -m json.tool
```

Results are paginated: `{"items":[...], "total":142, "limit":20, "offset":0}`.
Use `?offset=20` to get the next page.

Export a finding ID for the next steps:

```bash
export FINDING_ID="FND-abc123"   # replace with a real ID from your findings
```

---

## Step 4 — Get an AI Council Verdict

Submit the finding to the LLM Council. Up to four AI models convene; if
consensus is not reached, escalation is triggered automatically.

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/council \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"finding_id\": \"$FINDING_ID\",
    \"context\": {\"asset_criticality\": \"tier-1\"}
  }" | python3 -m json.tool
```

**Response fields:** `verdict` (`exploit`, `remediate`, `accept`, `monitor`),
`confidence` (0–1 float), `reasoning`, `model_votes`, `council_id`.

Check that the council is healthy:

```bash
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/council/status | python3 -m json.tool
```

---

## Step 5 — Generate and Verify an Evidence Bundle

Generate a cryptographically signed audit bundle for the finding and its verdict.

```bash
# Generate
export BUNDLE_ID=$(curl -s -X POST \
  https://aldeci.fly.dev/api/v1/evidence/bundles/generate \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "X-Org-ID: $ALDECI_ORG_ID" \
  -H "Content-Type: application/json" \
  -d "{\"finding_ids\":[\"$FINDING_ID\"],\"include_council_verdict\":true,\"include_audit_trail\":true}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('bundle_id',''))")

echo "Bundle: $BUNDLE_ID"

# Verify the hash chain
curl -s -X POST https://aldeci.fly.dev/api/v1/evidence/verify \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"bundle_id\":\"$BUNDLE_ID\"}" \
  | python3 -m json.tool
```

A `"verified": true` response confirms the hash chain is intact.

Download the bundle as a ZIP for audit submission:

```bash
curl -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/evidence/bundles/$BUNDLE_ID/download" \
  -o evidence-bundle.zip
```

---

## What's Next

| Task | Guide |
|------|-------|
| Connect Jira, Slack, GitHub | [integrations.md](integrations.md) |
| Full API reference | [api-reference.md](api-reference.md) |
| Encryption, RBAC, compliance posture | [security-whitepaper.md](security-whitepaper.md) |
| Troubleshoot 401/403/422 errors | [troubleshooting.md](troubleshooting.md) |
| Incident response at 3am | [incident-response-runbook.md](incident-response-runbook.md) |
