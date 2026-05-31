# ALDECI Customer Documentation

Welcome to ALDECI's enterprise documentation hub. This directory contains everything an IT team, SOC, or compliance officer needs to self-serve onboarding, operate the platform day-to-day, and respond to incidents without calling support.

All documents reference real source files and real API endpoints. Claims that are in progress (e.g. SOC 2 Type II attestation) are explicitly marked as such.

---

## Documents

### [Quickstart](quickstart.md)

Get from zero to a confirmed security finding with an AI council verdict and a signed evidence bundle in under 15 minutes. Covers account creation, connecting GitHub as your first scanner, ingesting findings, viewing the LLM council verdict, and generating an evidence bundle.

**Start here if you are new to ALDECI.**

---

### [Integration Catalog](integrations.md)

Detailed setup guide for every supported connector. For each integration: what data it ingests, what credentials are required, the API endpoint that triggers it, and how to diagnose common errors.

Covers 40+ integrations across:
- Source code and CI/CD (GitHub, GitLab, Bitbucket, CircleCI, Jenkins, ArgoCD)
- Vulnerability scanners (Trivy, Snyk, Semgrep, ZAP, Nessus, Checkmarx, Semgrep)
- EDR/XDR (CrowdStrike, SentinelOne, Microsoft Defender XDR)
- Cloud security (AWS Security Hub, Amazon Inspector, GCP SCC, Lacework)
- SIEM and observability (Datadog, Splunk, Elasticsearch)
- ITSM and ticketing (Jira, ServiceNow)
- Notifications (Slack, PagerDuty, Microsoft Teams)
- Identity (Auth0, SailPoint)
- Data platforms (MongoDB Atlas, Databricks, BigQuery, Redshift, Snowflake)
- Container and infrastructure (Harbor, GAR, Terraform Cloud, Ansible Tower)
- Edge and CDN (Cloudflare, AWS WAF, Fastly, Akamai)
- Workflow automation (n8n)

---

### [API Reference](api-reference.md)

Narrative API reference for the 15 most-used endpoints with working `curl` examples. Covers authentication patterns, findings CRUD, scanner ingestion, risk acceptance, audit log search, AI council verdicts, and evidence bundles.

The full machine-readable OpenAPI specification is served live at `GET /api/v1/openapi.json`.

---

### [Security Whitepaper](security-whitepaper.md)

ALDECI's own security posture. Covers:
- Encryption in transit (TLS 1.3, HTTPS-enforced) and at rest (AES-256 volume encryption)
- Authentication: API key, JWT, OAuth2/OIDC, SAML 2.0
- Authorisation: 6-role RBAC with scope inheritance, per-tenant data isolation
- Audit logging: append-only, configurable 90-day retention, daily purge daemon
- Multi-tenancy: `org_id` scoping across all resources
- Compliance posture: SOC 2 Type II in progress (letter expected Q4 2026), CIS/NIST/ISO/PCI/HIPAA control mappings available
- FIPS-mode readiness, air-gap deployment

---

### [Troubleshooting](troubleshooting.md)

Decision-tree style diagnosis for the most common issues. Covers:
- `401` and `403` authentication and authorisation failures
- Scanner ingestion `422` errors (format mismatch, extension rejection, oversized files)
- Connector `503` errors (expired credentials, network path)
- Empty dashboard (org_id mismatch, pipeline still processing)
- Slow boot or `502` on fresh deploy (expected 40–60 second cold start)
- CSP errors on custom domains
- AI council not returning (missing `OPENROUTER_API_KEY`)
- Evidence bundle verification failures

---

### [Incident Response Runbook](incident-response-runbook.md)

Step-by-step procedures for on-call engineers. Covers:
- Assessing severity (P1/P2/P3 decision table)
- Checking Fly.io health and reading logs
- Rolling back a deploy to a previous image
- Rotating the primary API key (verified `flyctl secrets set` procedure, no redeploy required)
- Rotating JWT signing secret
- Mass-revoking per-service-account API keys
- Exporting audit logs for incident disclosure
- Database integrity check and snapshot recovery
- Disk space exhaustion and volume extension
- Support escalation contacts and what to include in a ticket

---

## Getting Help

| Purpose | Contact |
|---------|---------|
| Technical support | support@devopsai.co |
| Security disclosures | security@devopsai.co |
| Compliance and SOC 2 requests | Via your account representative |
| Billing and licensing | billing@devopsai.co |

Response targets: 4 hours during business hours (AEST), 24 hours off-hours. P1 production-down: contact your account representative directly.
