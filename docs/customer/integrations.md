# ALDECI Integration Catalog

ALDECI connects to your existing security and DevOps toolchain via a unified connector framework. Each integration is registered once, credentials are stored server-side (never in client requests after registration), and data flows into the Brain Pipeline automatically.

The machine-readable list of supported connector types is available at:

```bash
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/scanner-ingest/supported | python3 -m json.tool
```

---

## Authentication Model for All Integrations

1. Register the connector via `POST /api/v1/connectors` with credentials in the request body.
2. ALDECI stores credentials server-side, scoped to your `org_id`.
3. All subsequent trigger calls reference the `connector_id` — credentials are never re-sent.
4. Requires scope `write:integrations` (roles: `org_admin`, `super_admin`).

---

## Source Code & CI/CD

### GitHub

**What it ingests:** Code scanning alerts (SARIF), Dependabot alerts, secret scanning alerts, repository metadata.

**API endpoint:** `POST /api/v1/github-api/scan`

**Credentials needed:**

| Variable | Description |
|----------|-------------|
| `token` | GitHub PAT with `security_events`, `read:org` scopes, or a GitHub App installation token |
| `owner` | GitHub org or user name |
| `repo` | Repository name (optional — omit to scan all repos in org) |

**Registration:**

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/connectors \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "github",
    "name": "GitHub Production",
    "config": {"token": "ghp_XXX", "owner": "acme-corp"}
  }'
```

**Common errors:**

- `422 Unprocessable Entity` — token missing required scopes; verify `security_events` is granted.
- `403 Forbidden` — GitHub App not installed on the target org; check App installation settings.

---

### GitLab

**What it ingests:** GitLab CI/CD pipeline security reports, SAST/DAST/dependency scanning results.

**API endpoint:** `POST /api/v1/gitlab-pipeline/sync`

**Credentials needed:**

| Variable | Description |
|----------|-------------|
| `token` | GitLab personal access token or project access token with `read_api` scope |
| `project_id` | Numeric GitLab project ID |
| `gitlab_url` | Base URL (default `https://gitlab.com`) — for self-hosted instances |

**Common errors:**

- `401` — Token expired or wrong scope; GitLab tokens expire by default after 1 year.
- `503` — Self-hosted GitLab URL unreachable from ALDECI; confirm network path or use scanner-ingest upload instead.

---

### Bitbucket Cloud

**What it ingests:** Bitbucket Pipelines security scan reports, repository security alerts.

**API endpoint:** `POST /api/v1/bitbucket/sync`

**Credentials needed:** `workspace`, `username`, `app_password` (Bitbucket App Password with `Repositories: Read`, `Pipelines: Read`).

---

### CircleCI

**What it ingests:** CircleCI pipeline artefacts tagged as security reports.

**API endpoint:** `POST /api/v1/circleci/sync`

**Credentials needed:** `token` (CircleCI personal API token), `project_slug` (e.g. `gh/acme-corp/my-repo`).

---

### Jenkins

**What it ingests:** Jenkins build artefacts — SARIF reports, Trivy JSON, OWASP ZAP XML.

**API endpoint:** `POST /api/v1/jenkins/sync`

**Credentials needed:** `url`, `username`, `api_token`, `job_name`.

---

### ArgoCD

**What it ingests:** Argo application sync status, drift detection, out-of-sync resources.

**API endpoint:** `POST /api/v1/argocd/sync`

**Credentials needed:** `server_url`, `token` (ArgoCD API token), `project` (optional filter).

---

## Vulnerability Scanners

### Trivy

**What it ingests:** Container image vulnerability reports, filesystem scans, IaC misconfiguration results (JSON and SARIF formats).

**Ingest via upload:**

```bash
trivy image --format json --output trivy-report.json myimage:latest

curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@trivy-report.json" \
  -F "scanner_type=trivy" \
  -F "org_id=your-org-id"
```

**Ingest via webhook:** Trivy CI results can be posted directly:

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/webhook/trivy \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @trivy-report.json
```

**Common errors:**

- `422` — Trivy binary not found on the ALDECI host; use file upload path instead of direct scan trigger.
- `415` — File format not recognised; ensure `--format json` or `--format sarif` was passed to Trivy.

---

### Snyk

**What it ingests:** Snyk Open Source, Snyk Code, Snyk Container, and Snyk IaC findings.

**API endpoint:** `POST /api/v1/scanner-ingest/webhook/snyk` or file upload.

**Credentials needed (for direct pull):** `SNYK_TOKEN` environment variable on the ALDECI host, or upload Snyk JSON reports via the file upload endpoint.

**Supported formats:** Snyk JSON (`snyk test --json`), SARIF (`snyk test --sarif`).

---

### Semgrep

**What it ingests:** SAST findings from Semgrep OSS or Semgrep Pro rules.

**Ingest via upload:**

```bash
semgrep --json -o semgrep-results.json .
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@semgrep-results.json" \
  -F "scanner_type=semgrep"
```

> If Semgrep is installed on the ALDECI host, direct scan can be triggered via the scan engine. When the binary is absent the engine returns `status: "unavailable"` with an honest empty findings list — no fabricated results are returned.

---

### OWASP ZAP

**What it ingests:** DAST findings from ZAP active or passive scans (XML or JSON report format).

**Ingest via upload:**

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@zap-report.xml" \
  -F "scanner_type=zap"
```

---

### Nessus / Tenable

**What it ingests:** Nessus `.nessus` XML reports, Tenable.io vulnerability exports.

**Supported format:** `.nessus` XML files (Nessus native format).

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@scan.nessus" \
  -F "scanner_type=nessus"
```

---

### Checkmarx One

**What it ingests:** SAST/SCA/IaC scan results via the Checkmarx One API.

**API endpoints:** Full proxy under `/api/v1/checkmarx/` — list projects, trigger scans, retrieve results.

**Credentials needed:** `tenant`, `client_id`, `client_secret` (Checkmarx One OAuth2 client credentials).

---

## Endpoint Detection & Response (EDR/XDR)

### CrowdStrike Falcon

**What it ingests:** Detections, incidents, device inventory, vulnerabilities from Falcon Spotlight.

**API endpoint:** `POST /api/v1/connectors` with `type: "crowdstrike"`.

**Credentials needed:** `client_id`, `client_secret` (CrowdStrike API client with `Detections: Read`, `Vulnerabilities: Read` scopes), `base_url` (e.g. `https://api.crowdstrike.com`).

**Common errors:**

- `403` — API client lacks required scopes; regenerate the client with `Detections: Read` and `Spotlight Vulnerabilities: Read`.

---

### SentinelOne

**What it ingests:** Threats, alerts, agent inventory.

**API endpoint:** `POST /api/v1/connectors` with `type: "sentinelone"`.

**Credentials needed:** `api_token`, `base_url` (your SentinelOne management console URL).

---

### Microsoft Defender XDR

**What it ingests:** Incidents, alerts, advanced hunting results via Microsoft Graph Security API.

**API endpoint:** `GET/POST /api/v1/defender-xdr/incidents`, `/alerts`.

**Credentials needed:** Azure AD `tenant_id`, `client_id`, `client_secret` with `SecurityIncident.Read.All` and `SecurityAlert.Read.All` Graph API permissions.

---

## Cloud Security

### AWS Security Hub

**What it ingests:** Security Hub findings aggregated across all enabled standards (CIS, NIST, PCI DSS, AWS Foundational).

**API endpoint:** `POST /api/v1/aws-securityhub/sync`

**Credentials needed:** `aws_access_key_id`, `aws_secret_access_key`, `aws_region`. An IAM role with `securityhub:GetFindings` and `securityhub:DescribeHub` permissions is required.

---

### Amazon Inspector v2

**What it ingests:** Container image CVEs, EC2 instance vulnerabilities, Lambda function vulnerabilities.

**API endpoint:** `POST /api/v1/amazon-inspector/sync`

**Credentials needed:** Same IAM credentials as Security Hub; add `inspector2:ListFindings` permission.

---

### GCP Security Command Center

**What it ingests:** SCC findings, sources, and assets.

**API endpoint:** `POST /api/v1/connectors` with `type: "gcp_scc"`.

**Credentials needed:** `project_id` or `org_id`, Google service account JSON key with `securitycenter.findings.list` IAM permission.

> When credentials are absent or unconfigured the GCP SCC connector returns `configured: false` with an empty findings list. It does not fabricate findings.

---

### Azure Microsoft Defender for Cloud (formerly Azure Defender)

**What it ingests:** Azure Defender security alerts and recommendations via Microsoft Defender XDR or Purview DLP router.

**API endpoint:** `POST /api/v1/defender-xdr/sync`

**Credentials needed:** Azure AD app registration with `SecurityAlert.Read.All`.

---

### Lacework

**What it ingests:** CSPM findings, cloud activity anomalies.

**API endpoint:** `POST /api/v1/lacework/sync`

**Credentials needed:** `keyId`, `secret`, `account` (Lacework tenant subdomain).

---

### AWS IAM

**What it ingests:** IAM policy analysis, unused permissions, access advisor data.

**API endpoint:** `GET /api/v1/aws-iam/analysis`

**Credentials needed:** IAM credentials with `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails`, `iam:ListPolicies`.

---

## Observability & SIEM

### Datadog

**What it ingests:** Datadog Cloud SIEM security signals, logs, and infrastructure monitors.

**API endpoint:** `POST /api/v1/datadog-security/sync`

**Credentials needed:** `api_key`, `app_key`, `site` (e.g. `datadoghq.com` or `datadoghq.eu`).

---

### Splunk

**What it ingests:** Splunk Enterprise Security notable events and Splunk SOAR cases.

**API endpoint:** `POST /api/v1/connectors` with `type: "splunk"`. Use the integration marketplace for configuration.

**Credentials needed:** `base_url`, `token` (Splunk HEC token or REST API token), `index`.

---

### Elasticsearch / OpenSearch

**What it ingests:** Security events, audit logs stored in Elasticsearch indices.

**API endpoint:** `POST /api/v1/connectors` with `type: "elasticsearch"`.

**Credentials needed:** `hosts` (list of ES node URLs), `username`, `password` or `api_key`.

---

## ITSM & Ticketing

### Jira

**What it ingests / writes:** Bidirectional — ALDECI creates Jira issues for findings and reads back status/resolution.

**API endpoints:** `POST /api/v1/jira-sync/push` (ALDECI → Jira), `POST /api/v1/jira-sync/pull` (Jira → ALDECI). Jira Cloud OAuth2 available via `GET/POST /api/v1/jira-cloud/*`.

**Credentials needed:** `base_url`, `email`, `api_token` (Jira API token from `id.atlassian.com`), `project_key`.

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/jira-sync/push \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"finding_id": "FINDING_ID", "project_key": "SEC", "org_id": "your-org-id"}'
```

**Common errors:**

- `401` — Jira API token revoked; regenerate at `id.atlassian.com/manage-profile/security/api-tokens`.
- `404` — Project key does not exist in your Jira instance.

---

### ServiceNow

**What it ingests / writes:** ALDECI creates ServiceNow incidents and change requests for security findings, and syncs resolution status back.

**API endpoints:** `POST /api/v1/servicenow-sync/push`, `GET /api/v1/servicenow-sync/status`. Webhook receiver at `POST /api/v1/servicenow-sync/webhook` (no authentication required — use IP allowlisting).

**Credentials needed:** `instance_url` (e.g. `https://acme.service-now.com`), `username`, `password` or OAuth2 client credentials.

---

## Notifications & ChatOps

### Slack

**What it ingests / sends:** ALDECI sends finding alerts, council verdicts, and evidence bundle links to configured Slack channels.

**API endpoints:** `POST /api/v1/integrations/slack/notify`, `POST /api/v1/slack-chatops/command`.

**Credentials needed:** `bot_token` (Slack bot OAuth token with `chat:write`, `channels:read` scopes), `channel_id`.

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/integrations/slack/notify \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"channel_id": "C01XXXXX", "message": "ALDECI: 3 critical findings detected"}'
```

---

### PagerDuty

**What it ingests / sends:** ALDECI creates PagerDuty incidents for critical findings and reads on-call schedules to route notifications.

**API endpoints:** `POST /api/v1/pagerduty/incidents`, `GET /api/v1/pagerduty/schedules`, `GET /api/v1/pagerduty/oncall-users`. PagerDuty Events v2 API at `/api/v1/pagerduty-events/trigger`.

**Credentials needed:** `api_token` (PagerDuty REST API key), `routing_key` (PagerDuty integration key for Events v2).

> When PagerDuty credentials are absent, all list methods return empty arrays. No fabricated incidents are created.

---

### Microsoft Teams

**What it ingests / sends:** Alert notifications via Teams incoming webhooks or the Bot Framework.

**API endpoint:** `POST /api/v1/microsoft-teams/notify`

**Credentials needed:** `webhook_url` (Teams incoming webhook URL).

---

## Identity & Access

### Auth0

**What it ingests:** Auth0 authentication logs, anomaly detection events, user management.

**API endpoint:** `POST /api/v1/connectors` with `type: "auth0"`.

**Credentials needed:** `domain`, `client_id`, `client_secret`, `audience` (`https://YOUR_DOMAIN/api/v2/`).

---

### SailPoint IdentityNow

**What it ingests:** Access certifications, role assignments, policy violations, user lifecycle events.

**API endpoint:** `POST /api/v1/connectors` with `type: "sailpoint"`.

**Credentials needed:** `tenant`, `client_id`, `client_secret` (SailPoint PAT or OAuth2 client credentials).

---

## Data Platforms

### MongoDB Atlas

**What it ingests:** Atlas security alerts, data lake audit events, access logs.

**API endpoint:** `POST /api/v1/connectors` with `type: "mongodb_atlas"`.

**Credentials needed:** Atlas Project API key (`publicKey`, `privateKey`), `project_id`.

---

### Databricks

**What it ingests:** Workspace audit logs, cluster security events.

**API endpoint:** `POST /api/v1/connectors` with `type: "databricks"`.

**Credentials needed:** `host` (workspace URL), `token` (Databricks personal access token).

---

### BigQuery

**What it ingests:** GCP audit logs exported to BigQuery, Cloud Logging sink data.

**API endpoint:** `POST /api/v1/connectors` with `type: "bigquery"`.

**Credentials needed:** Google service account JSON key with `bigquery.jobs.create` and `bigquery.tables.getData` permissions, `project_id`, `dataset_id`.

---

### AWS Redshift

**What it ingests:** Redshift audit logs, user activity logs.

**API endpoint:** `POST /api/v1/connectors` with `type: "redshift"`.

**Credentials needed:** `host`, `port`, `database`, `user`, `password` or IAM role ARN.

---

### Snowflake

**What it ingests:** Snowflake access history, login events, query audit trail.

**API endpoint:** `GET/POST /api/v1/snowflake/query`, `/api/v1/snowflake/audit`

**Credentials needed:** `account`, `user`, `password` or key-pair authentication, `warehouse`, `database`, `schema`.

---

## Container & Infrastructure

### Harbor Container Registry

**What it ingests:** Container image vulnerability scan results from Harbor's built-in Trivy/Clair scanners.

**API endpoint:** `GET /api/v1/harbor/vulnerabilities`

**Credentials needed:** `url`, `username`, `password`, `project` name.

---

### Google Artifact Registry

**What it ingests:** Container image vulnerability scan results from GAR's built-in Artifact Analysis.

**API endpoint:** `GET /api/v1/gar/vulnerabilities`

**Credentials needed:** Google service account JSON key with `containeranalysis.occurrences.list` permission, `project_id`, `location`, `repository`.

---

### Terraform Cloud

**What it ingests:** Workspace run results, Sentinel policy checks, IaC security scan outputs.

**API endpoint:** `GET /api/v1/terraform-cloud/workspaces`, `/runs`

**Credentials needed:** `token` (Terraform Cloud team or user API token), `organization`.

---

### Ansible Tower / AWX

**What it ingests:** Job execution results, compliance playbook outcomes.

**API endpoint:** `POST /api/v1/ansible-tower/sync`

**Credentials needed:** `url`, `username`, `password` or `token`.

---

### Harness CD

**What it ingests:** Pipeline execution security gates, OPA policy evaluation results.

**API endpoint:** `GET /api/v1/harness/pipelines`

**Credentials needed:** `api_key`, `account_id`.

---

## Edge & CDN

### Cloudflare

**What it ingests:** WAF firewall events, DDoS attack logs, bot management events.

**API endpoint:** `POST /api/v1/connectors` with `type: "cloudflare"`.

**Credentials needed:** `api_token` (Cloudflare API token with `Zone: Firewall Services: Read`, `Zone: Analytics: Read`), `zone_id`.

---

### AWS WAF

**What it ingests:** WAF sampled requests, rule match events via AWS Security Hub or direct WAF API.

**API endpoint:** `POST /api/v1/connectors` with `type: "aws_waf"`. Alternatively use the AWS Security Hub integration which aggregates WAF events automatically.

**Credentials needed:** AWS IAM credentials with `wafv2:GetSampledRequests` permission, `region`.

---

### Fastly

**What it ingests:** Fastly WAF security events, Next-Gen WAF (formerly Signal Sciences) attack signals.

**API endpoint:** `GET /api/v1/fastly/events`

**Credentials needed:** `api_key`, `service_id`.

---

### Akamai

**What it ingests:** Kona Site Defender security events, API Gateway threat intelligence.

**API endpoint:** `GET /api/v1/akamai/events`

**Credentials needed:** EdgeGrid credentials (`host`, `client_token`, `client_secret`, `access_token`).

---

## Email Security

### Proofpoint TAP

**What it ingests:** Targeted attack protection events, click events, message blocked logs.

**API endpoint:** `GET /api/v1/proofpoint-tap/events`

**Credentials needed:** `service_principal`, `secret`, `base_url`.

---

## n8n Workflow Automation

**What it ingests / triggers:** ALDECI can trigger n8n workflows on finding events and receive enrichment callbacks.

**API endpoint:** `POST /api/v1/n8n/trigger`, `GET /api/v1/n8n/executions`

**Credentials needed:** `webhook_url` (n8n webhook trigger URL), optional `api_key` for n8n REST API callbacks.

---

## Universal File Upload (Any Scanner)

For scanners not listed above, use the universal upload endpoint. ALDECI will attempt auto-detection:

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -F "file=@report.json" \
  -F "org_id=your-org-id"
```

Supported auto-detected formats: JSON (Trivy, Snyk, OWASP ZAP, Semgrep, Grype, Nuclei, Bandit, pip-audit, npm-audit, Syft SBOM, CycloneDX), XML (Nessus, ZAP, Checkstyle, PMD), SARIF 2.1.

Check what is supported at any time:

```bash
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  https://aldeci.fly.dev/api/v1/scanner-ingest/supported
```
