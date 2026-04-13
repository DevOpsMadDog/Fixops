# ALDECI CTEM+ Platform — Administrator Guide

> Version: 1.0 | Branch: `features/intermediate-stage`
> Last updated: 2026-04-12

---

## Table of Contents

1. [Initial Setup Wizard](#1-initial-setup-wizard)
2. [User Management and RBAC](#2-user-management-and-rbac)
3. [SSO Configuration (OIDC / SAML)](#3-sso-configuration-oidc--saml)
4. [API Key Management](#4-api-key-management)
5. [Scanner Integration](#5-scanner-integration)
6. [Compliance Framework Setup](#6-compliance-framework-setup)
7. [Notification Channels](#7-notification-channels)
8. [SLA Configuration](#8-sla-configuration)
9. [Data Retention Policies](#9-data-retention-policies)
10. [System Health Monitoring](#10-system-health-monitoring)

---

## 1. Initial Setup Wizard

### 1.1 First Boot Checklist

After the platform starts for the first time, complete the following steps in order:

```
[ ] 1. Access the UI at http://localhost:3000 (or your configured domain)
[ ] 2. Log in with the bootstrap admin token (FIXOPS_API_TOKEN)
[ ] 3. Navigate to Settings → System → Initial Setup
[ ] 4. Change the default API token to a strong secret
[ ] 5. Set organization name, timezone, and locale
[ ] 6. Create the first human admin user
[ ] 7. Disable or rotate the bootstrap token
[ ] 8. Configure at least one scanner integration
[ ] 9. Run TrustGraph indexer: docker compose --profile init run --rm trustgraph-init
[ ] 10. Configure notification channels
```

### 1.2 Bootstrap API Call (curl)

Verify the platform is live and your token works before proceeding:

```bash
export ALDECI_URL=http://localhost:8000
export API_TOKEN=your-api-token

curl -s -H "X-API-Key: $API_TOKEN" "$ALDECI_URL/health" | python3 -m json.tool
```

### 1.3 Organization Configuration

```bash
# Set organization metadata
curl -X POST "$ALDECI_URL/api/v1/settings/organization" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Security",
    "timezone": "America/New_York",
    "contact_email": "security@acme.com",
    "industry": "finance",
    "employee_count": 5000
  }'
```

---

## 2. User Management and RBAC

### 2.1 RBAC Role Definitions

ALDECI implements six RBAC roles with strictly enforced least-privilege access:

| Role | Description | Key Permissions |
|------|-------------|-----------------|
| `super_admin` | Full platform control | All permissions including destructive operations |
| `admin` | Organization administration | User management, scanner config, no data deletion |
| `security_engineer` | Technical security operations | Run scans, triage findings, manage integrations |
| `analyst` | Security analysis | View findings, create reports, read-only on configs |
| `developer` | Developer self-service | View own project findings, request remediation |
| `read_only` | Audit / compliance view | Read-only across all resources |

### 2.2 Create a User

```bash
curl -X POST "$ALDECI_URL/api/v1/users" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jane.smith",
    "email": "jane.smith@acme.com",
    "role": "security_engineer",
    "display_name": "Jane Smith"
  }'
```

### 2.3 Update User Role

```bash
curl -X PATCH "$ALDECI_URL/api/v1/users/{user_id}/role" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "analyst"}'
```

### 2.4 Deactivate / Delete User

```bash
# Deactivate (preserves audit history)
curl -X POST "$ALDECI_URL/api/v1/users/{user_id}/deactivate" \
  -H "X-API-Key: $API_TOKEN"

# Delete (requires super_admin)
curl -X DELETE "$ALDECI_URL/api/v1/users/{user_id}" \
  -H "X-API-Key: $API_TOKEN"
```

### 2.5 Persona Assignment

Beyond roles, ALDECI supports 30 security personas (SOC Analyst, CISO, DevSecOps Engineer, Compliance Officer, etc.). Assign personas to tailor dashboard views and workflow automations:

```bash
curl -X POST "$ALDECI_URL/api/v1/users/{user_id}/persona" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"persona": "ciso"}'
```

---

## 3. SSO Configuration (OIDC / SAML)

### 3.1 OIDC (OpenID Connect)

Tested with: Okta, Auth0, Azure AD, Google Workspace, Keycloak.

```bash
curl -X POST "$ALDECI_URL/api/v1/settings/auth/oidc" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "provider": "okta",
    "client_id": "0oaXXXXXXXXXXXXXX",
    "client_secret": "your-client-secret",
    "discovery_url": "https://your-org.okta.com/.well-known/openid-configuration",
    "redirect_uri": "https://aldeci.your-domain.com/auth/callback",
    "scopes": ["openid", "email", "profile", "groups"],
    "role_claim": "groups",
    "role_mapping": {
      "Security-Engineers": "security_engineer",
      "Security-Analysts": "analyst",
      "CISO-Group": "admin"
    }
  }'
```

### 3.2 SAML 2.0

```bash
curl -X POST "$ALDECI_URL/api/v1/settings/auth/saml" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "idp_metadata_url": "https://your-idp.com/saml/metadata",
    "sp_entity_id": "https://aldeci.your-domain.com",
    "sp_acs_url": "https://aldeci.your-domain.com/auth/saml/acs",
    "attribute_mapping": {
      "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
      "role": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
    }
  }'
```

### 3.3 Environment Variables for SSO

```bash
# Add to .env
FIXOPS_OIDC_ENABLED=1
FIXOPS_OIDC_CLIENT_ID=...
FIXOPS_OIDC_CLIENT_SECRET=...
FIXOPS_OIDC_DISCOVERY_URL=https://your-idp.com/.well-known/openid-configuration
FIXOPS_JWT_SECRET=...   # Used to sign internal session tokens after SSO
```

---

## 4. API Key Management

### 4.1 Generate a New API Key

```bash
curl -X POST "$ALDECI_URL/api/v1/api-keys" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-cd-pipeline",
    "role": "security_engineer",
    "expires_in_days": 90,
    "allowed_ips": ["10.0.0.0/8", "192.168.1.0/24"]
  }'
```

Response includes the key — **store it securely, it is shown only once**.

### 4.2 List API Keys

```bash
curl "$ALDECI_URL/api/v1/api-keys" -H "X-API-Key: $API_TOKEN"
```

### 4.3 Revoke an API Key

```bash
curl -X DELETE "$ALDECI_URL/api/v1/api-keys/{key_id}" \
  -H "X-API-Key: $API_TOKEN"
```

### 4.4 Key Rotation Policy

- Rotate all API keys every 90 days minimum
- Use short-lived keys (7-30 days) for CI/CD pipelines
- Enable IP allowlisting for service-to-service keys
- Monitor key usage via the audit log: `GET /api/v1/audit?actor_type=api_key`

---

## 5. Scanner Integration

### 5.1 Supported Scanners

| Scanner | Type | Coverage |
|---------|------|----------|
| Trivy | Container / IaC / SBOM | CVE, misconfig, secrets |
| Snyk | SAST / SCA | Code, dependencies, containers |
| Semgrep | SAST | Code patterns, secrets |
| GitHub Advanced Security | SAST / Dependabot | Code scanning, secret scanning |
| AWS Security Hub | CSPM | AWS posture findings |
| Azure Defender | CSPM | Azure posture findings |
| GCP Security Command Center | CSPM | GCP posture findings |
| OWASP Dependency-Check | SCA | 28+ vulnerability databases |
| Dependency-Track | SBOM lifecycle | CycloneDX ingestion |

### 5.2 Configure Trivy

```bash
curl -X POST "$ALDECI_URL/api/v1/scanners/trivy" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "scan_targets": ["container_images", "iac", "sbom"],
    "severity_threshold": "MEDIUM",
    "ignore_unfixed": false,
    "registry": {
      "url": "registry.your-company.com",
      "username": "scanner",
      "password": "..."
    }
  }'
```

### 5.3 Configure GitHub Advanced Security

```bash
curl -X POST "$ALDECI_URL/api/v1/scanners/github" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "github_token": "ghp_...",
    "organizations": ["your-org"],
    "include_dependabot": true,
    "include_code_scanning": true,
    "include_secret_scanning": true
  }'
```

### 5.4 Configure AWS Security Hub

```bash
curl -X POST "$ALDECI_URL/api/v1/scanners/aws" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "regions": ["us-east-1", "us-west-2", "eu-west-1"],
    "role_arn": "arn:aws:iam::123456789:role/AldeciFindingsReader",
    "standards": ["aws-foundational-security", "cis-aws-benchmark-v3"]
  }'
```

### 5.5 Scanner Normalization

All 32 scanner normalizers run automatically when findings are ingested. No configuration required — the `PipelineOrchestrator` detects the input format (SARIF, CycloneDX, vendor JSON) and routes to the correct normalizer.

---

## 6. Compliance Framework Setup

### 6.1 Supported Frameworks

| Framework | Version | Automated Controls |
|-----------|---------|-------------------|
| SOC 2 Type II | 2017 | CC6, CC7, CC8, CC9 |
| ISO 27001 | 2022 | Annex A controls |
| NIST CSF | 2.0 | All 6 functions |
| CIS Controls | v8 | IG1, IG2, IG3 |
| PCI DSS | 4.0 | Requirements 6, 11 |
| HIPAA | 2024 | Technical safeguards |
| FedRAMP | Rev 5 | Low / Moderate / High |

### 6.2 Enable a Framework

```bash
curl -X POST "$ALDECI_URL/api/v1/compliance/frameworks" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "framework": "soc2",
    "target_date": "2026-12-31",
    "responsible_owner": "jane.smith@acme.com",
    "auto_collect_evidence": true
  }'
```

### 6.3 Compliance Dashboard

Navigate to **Mission Control → Compliance** for the CISO compliance posture view showing:
- Control pass/fail status by framework
- Evidence collection progress
- Gap analysis and remediation roadmap
- Export-ready audit reports (PDF, CSV)

---

## 7. Notification Channels

### 7.1 Slack

```bash
curl -X POST "$ALDECI_URL/api/v1/notifications/channels" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "slack",
    "name": "security-alerts",
    "config": {
      "webhook_url": "https://hooks.slack.com/services/T.../B.../...",
      "channel": "#security-alerts",
      "severity_filter": ["CRITICAL", "HIGH"],
      "mention_on_critical": "@security-team"
    }
  }'
```

### 7.2 PagerDuty

```bash
curl -X POST "$ALDECI_URL/api/v1/notifications/channels" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "pagerduty",
    "name": "on-call-escalation",
    "config": {
      "integration_key": "your-pagerduty-integration-key",
      "severity_filter": ["CRITICAL"],
      "dedup_key_template": "aldeci-{finding_id}"
    }
  }'
```

### 7.3 Email (SMTP)

```bash
curl -X POST "$ALDECI_URL/api/v1/notifications/channels" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "email",
    "name": "ciso-digest",
    "config": {
      "smtp_host": "smtp.your-company.com",
      "smtp_port": 587,
      "smtp_tls": true,
      "from": "aldeci@your-company.com",
      "to": ["ciso@your-company.com"],
      "schedule": "daily_digest",
      "severity_filter": ["CRITICAL", "HIGH", "MEDIUM"]
    }
  }'
```

### 7.4 Webhook (Generic)

```bash
curl -X POST "$ALDECI_URL/api/v1/notifications/channels" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "webhook",
    "name": "jira-integration",
    "config": {
      "url": "https://your-company.atlassian.net/rest/api/2/issue",
      "method": "POST",
      "headers": {"Authorization": "Bearer YOUR_JIRA_TOKEN"},
      "severity_filter": ["CRITICAL", "HIGH"],
      "template": "jira_issue"
    }
  }'
```

---

## 8. SLA Configuration

### 8.1 Default SLA Timelines

| Severity | Default Remediation SLA | Default Acknowledgment SLA |
|----------|------------------------|---------------------------|
| CRITICAL | 24 hours | 1 hour |
| HIGH | 7 days | 4 hours |
| MEDIUM | 30 days | 24 hours |
| LOW | 90 days | 72 hours |
| INFO | 180 days | — |

### 8.2 Configure Custom SLAs

```bash
curl -X PUT "$ALDECI_URL/api/v1/settings/sla" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "critical": {"acknowledge_hours": 1, "remediate_hours": 24},
    "high":     {"acknowledge_hours": 4, "remediate_hours": 168},
    "medium":   {"acknowledge_hours": 24, "remediate_hours": 720},
    "low":      {"acknowledge_hours": 72, "remediate_hours": 2160}
  }'
```

### 8.3 SLA Breach Notifications

Configure escalation when SLAs are at risk:

```bash
curl -X POST "$ALDECI_URL/api/v1/settings/sla/escalation" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "warn_at_percent": 75,
    "breach_channel": "on-call-escalation",
    "warn_channel": "security-alerts",
    "escalate_to": ["ciso@acme.com"]
  }'
```

---

## 9. Data Retention Policies

### 9.1 Default Retention

| Data Type | Default Retention |
|-----------|------------------|
| Security findings | 2 years |
| Audit logs | 7 years |
| Scan raw results | 90 days |
| Notification history | 1 year |
| TrustGraph entities | Indefinite |
| Demo / seed data | Deleted on first real scan |

### 9.2 Configure Retention

```bash
curl -X PUT "$ALDECI_URL/api/v1/settings/retention" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "findings_days": 730,
    "audit_logs_days": 2555,
    "raw_scan_results_days": 90,
    "notification_history_days": 365
  }'
```

### 9.3 Manual Data Purge

```bash
# Purge findings older than specified date (requires super_admin)
curl -X POST "$ALDECI_URL/api/v1/admin/purge" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": "findings",
    "older_than_days": 730,
    "dry_run": true
  }'
```

Always run with `dry_run: true` first and review the count before executing.

---

## 10. System Health Monitoring

### 10.1 Health API

```bash
# Basic liveness
curl "$ALDECI_URL/health"

# Extended system status (admin token required)
curl -H "X-API-Key: $API_TOKEN" "$ALDECI_URL/api/v1/admin/health"
```

Response includes: API latency, database size, queue depth, active scanners, TrustGraph status, LLM Council availability.

### 10.2 Admin Dashboard

Navigate to **Settings → System → Health** for a real-time view of:
- Container resource usage (CPU, memory, disk)
- API request rate and error rate (last 24h)
- Scanner job queue status
- TrustGraph indexer last run and entity count
- LLM Council availability (per-model)
- Scheduled job status (backups, feed refreshes)

### 10.3 Database Maintenance

```bash
# Check database sizes (run inside container)
docker compose exec aldeci python3 -c "
import os, sqlite3
for db in ['fixops.db', 'fixops_exposure_cases.db', 'fixops_dedup.db']:
    path = f'/app/data/{db}'
    if os.path.exists(path):
        size = os.path.getsize(path) / 1024 / 1024
        print(f'{db}: {size:.1f} MB')
"

# Run SQLite VACUUM to reclaim space
docker compose exec aldeci python3 -c "
import sqlite3
for db in ['/app/data/fixops.db']:
    conn = sqlite3.connect(db)
    conn.execute('VACUUM')
    conn.close()
    print(f'VACUUMed {db}')
"
```

### 10.4 Threat Intel Feed Status

```bash
# Check feed refresh status
curl -H "X-API-Key: $API_TOKEN" "$ALDECI_URL/api/v1/feeds/status"
```

Feeds auto-refresh every 6 hours. Manual refresh:

```bash
curl -X POST -H "X-API-Key: $API_TOKEN" "$ALDECI_URL/api/v1/feeds/refresh"
```

---

*For deployment configuration see `docs/DEPLOYMENT_GUIDE.md`. For API usage see `docs/API_QUICKSTART.md`. For security controls see `docs/SECURITY_WHITEPAPER.md`.*
