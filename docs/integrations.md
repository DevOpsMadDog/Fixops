# ALdeci Integrations Guide

ALdeci connects to 12 external tools for bidirectional security data flow.

## Ticketing & Collaboration

### Jira
```bash
curl -X POST http://localhost:8005/api/v1/integrations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Jira",
    "integration_type": "jira",
    "config": {
      "base_url": "https://yourorg.atlassian.net",
      "project_key": "SEC",
      "token": "your-api-token",
      "email": "you@company.com"
    }
  }'
```

### Slack
```bash
curl -X POST http://localhost:8005/api/v1/integrations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Security Alerts",
    "integration_type": "slack",
    "config": { "webhook_url": "https://hooks.slack.com/services/T.../B.../xxx" }
  }'
```

### ServiceNow
Config keys: `base_url`, `username`, `password`, `table` (default: `incident`).

### Confluence
Config keys: `base_url`, `space_key`, `token`, `email`.

## Source Code Management

### GitHub
Config keys: `token` (or env `GITHUB_TOKEN`), `owner`, `repo`.

### GitLab
Config keys: `base_url` (default: `https://gitlab.com`), `token`, `project_id`.

### Azure DevOps
Config keys: `organization`, `project`, `token`.

## Security Scanners

### Snyk
```bash
curl -X POST http://localhost:8005/api/v1/integrations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Snyk Scanner",
    "integration_type": "snyk",
    "config": {
      "org_id": "your-snyk-org-id",
      "token_env": "SNYK_TOKEN"
    }
  }'
```
Set `SNYK_TOKEN` in your environment, or pass `"token": "..."` directly.

### SonarQube
Config keys: `base_url`, `project_key`, `token` (or env `SONARQUBE_TOKEN`).

### Dependabot (GitHub)
Config keys: `owner`, `repo`, `token` (or env `GITHUB_TOKEN`).
Uses the GitHub Dependabot Alerts API.

## Cloud Security

### AWS Security Hub
Config keys: `region` (default: `us-east-1`), `profile` (optional).
Uses boto3 — relies on standard AWS credentials (env vars, instance profile, or `~/.aws/credentials`).

### Azure Defender for Cloud
Config keys: `subscription_id`, `tenant_id`, `client_id`, `client_secret` (or env `AZURE_CLIENT_SECRET`).
Uses OAuth2 client credentials flow.

## Managing Integrations

```bash
# List all integrations
curl http://localhost:8005/api/v1/integrations

# Test connectivity
curl -X POST http://localhost:8005/api/v1/integrations/{id}/sync

# Update config
curl -X PUT http://localhost:8005/api/v1/integrations/{id} \
  -H "Content-Type: application/json" \
  -d '{"config": {"token": "new-token"}}'

# Disable
curl -X PUT http://localhost:8005/api/v1/integrations/{id} \
  -d '{"status": "inactive"}'
```

## Integration Status

| Tool | Type | Auth | Status |
|------|------|------|--------|
| Jira | Ticketing | API Token | ✅ Full |
| ServiceNow | Ticketing | Basic/OAuth | ✅ Full |
| Slack | Notification | Webhook | ✅ Full |
| Confluence | Documentation | API Token | ✅ Full |
| GitHub | SCM | PAT | ✅ Full |
| GitLab | SCM | PAT/OAuth | ✅ Full |
| Azure DevOps | SCM | PAT | ✅ Full |
| Snyk | Scanner | API Token | ✅ Full |
| SonarQube | Scanner | Token | ✅ Full |
| Dependabot | Scanner | GitHub PAT | ✅ Full |
| AWS Security Hub | Cloud | IAM/boto3 | ✅ Full |
| Azure Defender | Cloud | OAuth2 | ✅ Full |

