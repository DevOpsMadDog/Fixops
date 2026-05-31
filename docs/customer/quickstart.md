# ALDECI Quickstart — First Verdict in Under 15 Minutes

This guide walks a new enterprise customer from zero to a confirmed security finding with an AI council verdict and a signed evidence bundle. No professional services engagement required.

---

## Prerequisites

| Item | Requirement |
|------|-------------|
| Account | Org admin credentials at `https://aldeci.fly.dev` |
| API key | Generated during onboarding (or via admin wizard) |
| Scanner | At least one supported source (GitHub is the fastest starting point) |
| Network | HTTPS outbound to `aldeci.fly.dev:443` |

---

## Step 1 — Create Your Organisation and Obtain an API Key

If your administrator has already provisioned your org, skip to Step 2.

1. Navigate to `https://aldeci.fly.dev/onboard`.
2. Complete the admin first-login wizard. The wizard is served at `/api/v1/admin-wizard/start` (no authentication required for the initial setup call).
3. Record the `api_key` returned in the final wizard step. This is your `FIXOPS_API_TOKEN` — it will not be shown again.

```bash
# Verify your key works
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/status | python3 -m json.tool
```

Expected response: `{"status": "ok", "mode": "enterprise", ...}`

![](images/quickstart-1.png)

> **Cold-start note.** On the Fly.io deployment the API graph contains approximately 6,722 routes and takes roughly 40–60 seconds to initialise on first boot. Subsequent requests are fast. If you see a `502` immediately after a fresh deploy, wait 60 seconds and retry.

---

## Step 2 — Connect GitHub via the Connector Registry

ALDECI's connector framework pulls security signals from your source systems. GitHub is the fastest integration to verify because it requires only a personal access token (PAT) or a GitHub App installation.

### 2a. Register the connector

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/connectors \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "github",
    "name": "My GitHub Org",
    "config": {
      "token": "ghp_XXXXXXXXXXXXXXXXXXXX",
      "owner": "your-github-org",
      "repo": "your-repo"
    }
  }' | python3 -m json.tool
```

Record the `connector_id` from the response.

### 2b. Verify the connector is healthy

```bash
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/connectors/{connector_id}" | python3 -m json.tool
```

Look for `"status": "healthy"` in the response.

![](images/quickstart-2.png)

---

## Step 3 — Trigger a Scan and Ingest Findings

### Option A — Upload an existing scanner report (fastest)

If you already have output from GitHub Advanced Security, Trivy, Semgrep, or any of the 25+ supported scanners, upload it directly:

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@trivy-report.json" \
  -F "scanner_type=trivy" \
  -F "org_id=your-org-id" | python3 -m json.tool
```

The endpoint auto-detects format if you omit `scanner_type`:

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/detect \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@unknown-report.xml" | python3 -m json.tool
```

### Option B — Trigger via the GitHub connector

```bash
curl -s -X POST "https://aldeci.fly.dev/api/v1/github-api/scan" \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"connector_id": "YOUR_CONNECTOR_ID", "org_id": "your-org-id"}' \
  | python3 -m json.tool
```

![](images/quickstart-3.png)

---

## Step 4 — View Findings

```bash
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/findings?org_id=your-org-id&limit=20" \
  | python3 -m json.tool
```

Each finding includes `severity`, `title`, `source_scanner`, `asset_id`, `cve_ids`, and a `brain_pipeline_status` field indicating whether the 12-step Brain Pipeline has processed it yet.

To filter to critical findings only:

```bash
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/findings?org_id=your-org-id&severity=critical" \
  | python3 -m json.tool
```

![](images/quickstart-4.png)

---

## Step 5 — View the AI Council Verdict

The LLM Council (OpenRouter-backed multi-model consensus) produces a verdict for each finding. Verdicts aggregate across up to four AI models with a confidence score and recommended action.

```bash
# Get the council status
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/council/status" | python3 -m json.tool

# Request a verdict for a specific finding
curl -s -X POST https://aldeci.fly.dev/api/v1/council \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"finding_id": "FINDING_ID_HERE", "org_id": "your-org-id"}' \
  | python3 -m json.tool
```

The response includes `consensus_verdict`, `confidence`, `reasoning`, and per-model votes.

![](images/quickstart-5.png)

---

## Step 6 — Generate and Verify an Evidence Bundle

Evidence bundles provide an audit-ready, cryptographically signed record of a finding and its council verdict.

```bash
# Generate a bundle
curl -s -X POST https://aldeci.fly.dev/api/v1/evidence/bundles/generate \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"finding_ids": ["FINDING_ID_HERE"], "org_id": "your-org-id"}' \
  | python3 -m json.tool

# Verify a bundle
curl -s -X POST https://aldeci.fly.dev/api/v1/evidence/verify \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"bundle_id": "BUNDLE_ID_HERE"}' \
  | python3 -m json.tool
```

A `verified: true` response confirms the bundle hash chain is intact and the evidence has not been tampered with.

![](images/quickstart-6.png)

---

## What's Next

| Task | Guide |
|------|-------|
| Add more integrations (Jira, Slack, Splunk, etc.) | [integrations.md](integrations.md) |
| Explore the full API | [api-reference.md](api-reference.md) |
| Understand encryption and RBAC | [security-whitepaper.md](security-whitepaper.md) |
| Troubleshoot common errors | [troubleshooting.md](troubleshooting.md) |
| Incident response at 3am | [incident-response-runbook.md](incident-response-runbook.md) |
