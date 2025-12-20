# FixOps API and CLI Reference

This document provides a comprehensive mapping between FixOps API endpoints and their corresponding CLI commands.

## Overview

FixOps provides two interfaces for interacting with the platform:

1. **REST API** - For programmatic access, web UI, and integrations
2. **CLI** - For CI/CD pipelines, local development, and command-line workflows

**Coverage Summary:**
- Total API Endpoints: ~250
- CLI Commands/Subcommands: 67
- Coverage: ~85%

---

## Quick Reference

| CLI Command | Description | Primary API Endpoints |
|-------------|-------------|----------------------|
| `run` | Execute full pipeline | `/inputs/*`, `/pipeline/run` |
| `make-decision` | Pipeline with exit code | `/inputs/*`, `/pipeline/run` |
| `analyze` | Analyze findings | `/inputs/*`, `/pipeline/run` |
| `compliance` | Compliance management | `/api/v1/compliance/*` |
| `reports` | Report generation | `/api/v1/reports/*` |
| `inventory` | Asset inventory | `/api/v1/inventory/*` |
| `policies` | Policy management | `/api/v1/policies/*` |
| `integrations` | Integration management | `/api/v1/integrations/*` |
| `analytics` | Security analytics | `/api/v1/analytics/*` |
| `audit` | Audit trails | `/api/v1/audit/*` |
| `workflows` | Workflow automation | `/api/v1/workflows/*` |
| `advanced-pentest` | Advanced pen testing | `/api/v1/pentest/*` |
| `reachability` | Vulnerability reachability | `/api/v1/reachability/*` |

---

## Core Pipeline & Ingestion

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/status` | Authenticated health check |
| POST | `/inputs/design` | Upload design CSV |
| POST | `/inputs/sbom` | Upload SBOM (CycloneDX/SPDX) |
| POST | `/inputs/cve` | Upload CVE feed |
| POST | `/inputs/vex` | Upload VEX statements |
| POST | `/inputs/cnapp` | Upload CNAPP findings |
| POST | `/inputs/sarif` | Upload SARIF scan results |
| POST | `/inputs/context` | Upload business context |
| POST | `/inputs/{stage}/chunks/start` | Initialize chunked upload |
| PUT | `/inputs/{stage}/chunks/append` | Append chunk data |
| POST | `/inputs/{stage}/chunks/complete` | Complete chunked upload |
| GET | `/inputs/{stage}/chunks/status` | Check upload status |
| GET | `/pipeline/run` | Execute pipeline |
| GET | `/api/v1/triage` | Get triage results |
| GET | `/api/v1/triage/export` | Export triage data |
| GET | `/api/v1/graph` | Graph visualization |
| GET | `/api/v1/analytics/dashboard` | Dashboard data |
| POST | `/api/v1/feedback` | Submit feedback |

### CLI Commands

```bash
# Execute full pipeline with all artifacts
python -m core.cli run \
  --design design.csv \
  --sbom sbom.json \
  --sarif scan.sarif \
  --cve cve.json \
  --vex vex.json \
  --context context.yaml \
  --output pipeline-result.json

# Execute pipeline and use decision as exit code (CI/CD gate)
# Exit codes: 0=GO, 1=NO-GO, 2=CONDITIONAL
python -m core.cli make-decision \
  --design design.csv \
  --sbom sbom.json \
  --sarif scan.sarif \
  --cve cve.json

# Analyze findings with verdict output
python -m core.cli analyze \
  --design design.csv \
  --sbom sbom.json \
  --sarif scan.sarif \
  --cve cve.json \
  --format json \
  --output analysis.json

# Normalize artifacts and print pipeline response
python -m core.cli ingest \
  --design design.csv \
  --sbom sbom.json

# Run single SDLC stage
python -m core.cli stage-run \
  --stage build \
  --input artifact.json \
  --app my-service \
  --output canonical-output.json

# Check integration health
python -m core.cli health \
  --overlay config/fixops.overlay.yml \
  --pretty
```

---

## Compliance Management

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/compliance/frameworks` | List all frameworks |
| GET | `/api/v1/compliance/frameworks/{id}` | Get framework details |
| POST | `/api/v1/compliance/frameworks` | Create framework |
| GET | `/api/v1/compliance/controls` | List controls |
| GET | `/api/v1/compliance/controls/{id}` | Get control details |
| GET | `/api/v1/compliance/gaps` | List compliance gaps |
| POST | `/api/v1/compliance/gaps` | Create gap |
| PUT | `/api/v1/compliance/gaps/{id}` | Update gap |
| GET | `/api/v1/compliance/mapping` | Get control mapping |
| GET | `/api/v1/compliance/coverage` | Coverage metrics |
| GET | `/api/v1/compliance/report` | Generate report |
| GET | `/api/v1/compliance/export` | Export report |

### CLI Commands

```bash
# List all compliance frameworks
python -m core.cli compliance frameworks
python -m core.cli compliance frameworks --format table

# Get compliance status for a specific framework
python -m core.cli compliance status SOC2
python -m core.cli compliance status ISO27001
python -m core.cli compliance status PCI_DSS
python -m core.cli compliance status NIST_SSDF
python -m core.cli compliance status HIPAA
python -m core.cli compliance status GDPR
python -m core.cli compliance status FedRAMP

# List compliance gaps for a framework
python -m core.cli compliance gaps SOC2
python -m core.cli compliance gaps ISO27001 --format table

# Generate compliance report
python -m core.cli compliance report SOC2
python -m core.cli compliance report ISO27001 --output compliance-report.json
```

**Supported Frameworks:**
- SOC2 (2017) - 64 controls
- ISO27001 (2022) - 93 controls
- PCI_DSS (4.0) - 78 controls
- NIST_SSDF (1.1) - 42 controls
- HIPAA (2013) - 54 controls
- GDPR (2018) - 99 controls
- FedRAMP (2023) - 325 controls

---

## Reports

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reports` | List all reports |
| GET | `/api/v1/reports/{id}` | Get report details |
| POST | `/api/v1/reports/generate` | Generate new report |
| GET | `/api/v1/reports/{id}/download` | Download report |
| GET | `/api/v1/reports/templates` | List templates |
| GET | `/api/v1/reports/schedules` | List schedules |
| POST | `/api/v1/reports/schedules` | Create schedule |
| PUT | `/api/v1/reports/schedules/{id}` | Update schedule |
| DELETE | `/api/v1/reports/schedules/{id}` | Delete schedule |
| POST | `/api/v1/reports/bulk` | Bulk generation |

### CLI Commands

```bash
# List all reports
python -m core.cli reports list
python -m core.cli reports list --format table

# Generate a new report
python -m core.cli reports generate \
  --type executive_summary \
  --title "Q4 Security Report"

# Available report types:
# - executive_summary
# - technical_detail
# - compliance_audit
# - vulnerability_assessment

# Export a report
python -m core.cli reports export {report_id} --output report.pdf

# List report schedules
python -m core.cli reports schedules
```

---

## Inventory Management

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/inventory/applications` | List applications |
| GET | `/api/v1/inventory/applications/{id}` | Get app details |
| POST | `/api/v1/inventory/applications` | Add application |
| PUT | `/api/v1/inventory/applications/{id}` | Update application |
| DELETE | `/api/v1/inventory/applications/{id}` | Delete application |
| GET | `/api/v1/inventory/services` | List services |
| GET | `/api/v1/inventory/services/{id}` | Get service details |
| POST | `/api/v1/inventory/services` | Add service |
| GET | `/api/v1/inventory/components` | List components |
| GET | `/api/v1/inventory/dependencies` | List dependencies |
| GET | `/api/v1/inventory/search` | Search inventory |
| GET | `/api/v1/inventory/tags` | List tags |
| POST | `/api/v1/inventory/bulk` | Bulk import |
| GET | `/api/v1/inventory/export` | Export inventory |
| POST | `/api/v1/inventory/sync` | Sync from SCM |

### CLI Commands

```bash
# List all applications
python -m core.cli inventory apps
python -m core.cli inventory apps --format table

# Add a new application
python -m core.cli inventory add \
  --name "payments-api" \
  --type application \
  --criticality high \
  --owner "platform-team"

# Get application/service details
python -m core.cli inventory get {app_id}

# List all services
python -m core.cli inventory services
python -m core.cli inventory services --format table

# Search inventory
python -m core.cli inventory search --query "payment"
python -m core.cli inventory search --query "critical"
```

---

## Policy Management

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/policies` | List all policies |
| GET | `/api/v1/policies/{id}` | Get policy details |
| POST | `/api/v1/policies` | Create policy |
| PUT | `/api/v1/policies/{id}` | Update policy |
| DELETE | `/api/v1/policies/{id}` | Delete policy |
| POST | `/api/v1/policies/validate` | Validate policy |
| POST | `/api/v1/policies/test` | Test policy |
| GET | `/api/v1/policies/export` | Export policies |

### CLI Commands

```bash
# List all policies
python -m core.cli policies list
python -m core.cli policies list --format table

# Get policy details
python -m core.cli policies get {policy_id}
python -m core.cli policies get "critical-vuln-block"

# Create a new policy
python -m core.cli policies create \
  --name "block-critical-vulns" \
  --type guardrail \
  --severity critical \
  --rules '{"block_on": ["critical"], "allow_exceptions": false}'

# Policy types:
# - guardrail
# - compliance
# - threshold
# - custom

# Validate a policy
python -m core.cli policies validate {policy_id}

# Test a policy against sample input
python -m core.cli policies test {policy_id} \
  --input '{"severity": "critical", "cvss": 9.8}'
```

---

## Integration Management

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/integrations` | List integrations |
| GET | `/api/v1/integrations/{id}` | Get integration details |
| POST | `/api/v1/integrations` | Create integration |
| PUT | `/api/v1/integrations/{id}` | Update integration |
| DELETE | `/api/v1/integrations/{id}` | Delete integration |
| POST | `/api/v1/integrations/test` | Test connection |
| POST | `/api/v1/integrations/sync` | Sync data |
| GET | `/api/v1/integrations/webhooks` | List webhooks |

### CLI Commands

```bash
# List all integrations
python -m core.cli integrations list
python -m core.cli integrations list --format table

# Configure a new integration
python -m core.cli integrations configure Jira \
  --type ticketing \
  --url "https://company.atlassian.net" \
  --token "your-api-token" \
  --project "SEC"

python -m core.cli integrations configure Slack \
  --type notification \
  --token "xoxb-your-token" \
  --channel "#security-alerts"

python -m core.cli integrations configure GitHub \
  --type scm \
  --url "https://api.github.com" \
  --token "ghp_your-token"

# Integration types:
# - ticketing (Jira, ServiceNow)
# - notification (Slack, PagerDuty)
# - documentation (Confluence)
# - alerting (PagerDuty, OpsGenie)
# - scm (GitHub, GitLab)

# Test an integration connection
python -m core.cli integrations test Jira
python -m core.cli integrations test Slack

# Sync data with an integration
python -m core.cli integrations sync Jira
```

---

## Analytics

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/analytics/dashboard` | Dashboard metrics |
| GET | `/api/v1/analytics/findings` | Findings analytics |
| GET | `/api/v1/analytics/trends` | Trend analysis |
| GET | `/api/v1/analytics/mttr` | Mean time to remediate |
| GET | `/api/v1/analytics/mttd` | Mean time to detect |
| GET | `/api/v1/analytics/coverage` | Scan coverage |
| GET | `/api/v1/analytics/risk-score` | Risk score trends |
| GET | `/api/v1/analytics/roi` | ROI analysis |
| GET | `/api/v1/analytics/cost-savings` | Cost savings |
| GET | `/api/v1/analytics/export` | Export analytics |
| POST | `/api/v1/analytics/query` | Custom query |
| GET | `/api/v1/analytics/compare` | Period comparison |
| GET | `/api/v1/analytics/forecast` | Forecast |
| POST | `/api/v1/analytics/train` | Train model |
| GET | `/api/v1/analytics/benchmarks` | Industry benchmarks |
| GET | `/api/v1/analytics/alerts` | Analytics alerts |

### CLI Commands

```bash
# Get dashboard metrics
python -m core.cli analytics dashboard
python -m core.cli analytics dashboard --period 7d
python -m core.cli analytics dashboard --period 30d
python -m core.cli analytics dashboard --period 90d
python -m core.cli analytics dashboard --period 12m

# Get mean time to remediate metrics
python -m core.cli analytics mttr
python -m core.cli analytics mttr --period 30d

# Get security scan coverage
python -m core.cli analytics coverage

# Get ROI and cost savings analysis
python -m core.cli analytics roi
python -m core.cli analytics roi --period 12m

# Export analytics data
python -m core.cli analytics export --output-format json
python -m core.cli analytics export --output-format csv --output analytics.csv

# Train forecasting model
python -m core.cli train-forecast --history incidents.json
```

---

## Audit Logs

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/audit/logs` | List audit logs |
| GET | `/api/v1/audit/logs/{id}` | Get log details |
| GET | `/api/v1/audit/decisions` | Decision audit trail |
| GET | `/api/v1/audit/decisions/{id}` | Decision details |
| GET | `/api/v1/audit/users` | User activity |
| GET | `/api/v1/audit/policies` | Policy changes |
| GET | `/api/v1/audit/integrations` | Integration activity |
| GET | `/api/v1/audit/export` | Export audit logs |
| GET | `/api/v1/audit/search` | Search logs |
| GET | `/api/v1/audit/retention` | Retention settings |

### CLI Commands

```bash
# View audit logs
python -m core.cli audit logs
python -m core.cli audit logs --limit 100
python -m core.cli audit logs --format table

# Filter by event type
python -m core.cli audit logs --type decision
python -m core.cli audit logs --type policy
python -m core.cli audit logs --type user
python -m core.cli audit logs --type integration
python -m core.cli audit logs --type all

# View decision audit trail
python -m core.cli audit decisions
python -m core.cli audit decisions --limit 50

# Export audit logs
python -m core.cli audit export --output audit-logs.json
```

---

## Workflow Automation

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/workflows` | List workflows |
| GET | `/api/v1/workflows/{id}` | Get workflow details |
| POST | `/api/v1/workflows` | Create workflow |
| PUT | `/api/v1/workflows/{id}` | Update workflow |
| DELETE | `/api/v1/workflows/{id}` | Delete workflow |
| POST | `/api/v1/workflows/{id}/execute` | Execute workflow |
| GET | `/api/v1/workflows/{id}/history` | Execution history |
| GET | `/api/v1/workflows/executions` | All executions |
| GET | `/api/v1/workflows/executions/{id}` | Execution details |
| GET | `/api/v1/workflows/templates` | Workflow templates |
| GET | `/api/v1/workflows/triggers` | Trigger types |
| GET | `/api/v1/workflows/actions` | Action types |

### CLI Commands

```bash
# List all workflows
python -m core.cli workflows list
python -m core.cli workflows list --format table

# Get workflow details
python -m core.cli workflows get {workflow_id}

# Create a new workflow
python -m core.cli workflows create \
  --name "critical-vuln-alert" \
  --description "Alert on critical vulnerabilities" \
  --trigger finding \
  --trigger-config '{"severity": "critical"}' \
  --actions '[{"type": "slack", "channel": "#security"}]'

# Trigger types:
# - finding (triggered by new findings)
# - schedule (cron-based)
# - manual (user-triggered)
# - webhook (external trigger)

# Execute a workflow manually
python -m core.cli workflows execute {workflow_id}

# View workflow execution history
python -m core.cli workflows history {workflow_id}
python -m core.cli workflows history {workflow_id} --limit 50
```

---

## Advanced Penetration Testing

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/pentest/run` | Run pen test |
| GET | `/api/v1/pentest/status/{id}` | Check status |
| GET | `/api/v1/pentest/results/{id}` | Get results |
| GET | `/api/v1/pentest/threat-intel` | Threat intelligence |
| GET | `/api/v1/pentest/threat-intel/{cve}` | CVE threat intel |
| POST | `/api/v1/pentest/business-impact` | Business impact |
| POST | `/api/v1/pentest/simulate` | Attack simulation |
| POST | `/api/v1/pentest/simulate/chain` | Chained exploits |
| POST | `/api/v1/pentest/simulate/lateral` | Lateral movement |
| POST | `/api/v1/pentest/simulate/privesc` | Privilege escalation |
| GET | `/api/v1/pentest/remediation/{cve}` | Remediation guidance |
| GET | `/api/v1/pentest/capabilities` | List capabilities |

### CLI Commands

```bash
# Run advanced penetration test
python -m core.cli advanced-pentest run \
  --target "https://api.example.com" \
  --cves "CVE-2024-1234,CVE-2024-5678"

# Get threat intelligence for a CVE
python -m core.cli advanced-pentest threat-intel CVE-2024-1234

# Analyze business impact of vulnerabilities
python -m core.cli advanced-pentest business-impact \
  --target "payments-api" \
  --cves "CVE-2024-1234,CVE-2024-5678"

# Simulate attack chain
python -m core.cli advanced-pentest simulate \
  --target "https://api.example.com" \
  --attack-type single_exploit

python -m core.cli advanced-pentest simulate \
  --target "https://api.example.com" \
  --attack-type chained_exploit

python -m core.cli advanced-pentest simulate \
  --target "https://api.example.com" \
  --attack-type privilege_escalation

python -m core.cli advanced-pentest simulate \
  --target "https://api.example.com" \
  --attack-type lateral_movement

# Generate remediation guidance
python -m core.cli advanced-pentest remediation CVE-2024-1234

# List advanced pentest capabilities
python -m core.cli advanced-pentest capabilities
```

---

## Reachability Analysis

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/reachability/analyze` | Analyze reachability |
| GET | `/api/v1/reachability/analyze/{cve}` | Get analysis |
| POST | `/api/v1/reachability/bulk` | Bulk analysis |
| GET | `/api/v1/reachability/status/{job_id}` | Job status |
| GET | `/api/v1/reachability/call-graph` | Call graph |
| GET | `/api/v1/reachability/paths` | Attack paths |
| GET | `/api/v1/reachability/export` | Export results |

### CLI Commands

```bash
# Analyze reachability for a CVE
python -m core.cli reachability analyze CVE-2024-1234
python -m core.cli reachability analyze CVE-2024-1234 --sbom sbom.json

# Bulk reachability analysis
python -m core.cli reachability bulk "CVE-2024-1234,CVE-2024-5678,CVE-2024-9012"

# Check reachability analysis job status
python -m core.cli reachability status {job_id}
```

---

## Teams & Users

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/teams` | List teams |
| GET | `/api/v1/teams/{id}` | Get team details |
| POST | `/api/v1/teams` | Create team |
| PUT | `/api/v1/teams/{id}` | Update team |
| DELETE | `/api/v1/teams/{id}` | Delete team |
| GET | `/api/v1/teams/{id}/members` | List members |
| POST | `/api/v1/teams/{id}/members` | Add member |
| GET | `/api/v1/users` | List users |
| GET | `/api/v1/users/{id}` | Get user details |
| POST | `/api/v1/users` | Create user |
| PUT | `/api/v1/users/{id}` | Update user |
| DELETE | `/api/v1/users/{id}` | Delete user |
| PUT | `/api/v1/users/{id}/password` | Reset password |
| GET | `/api/v1/users/me` | Current user |

### CLI Commands

```bash
# List all teams
python -m core.cli teams list
python -m core.cli teams list --format table

# Get team details
python -m core.cli teams get {team_id}

# Create a new team
python -m core.cli teams create \
  --name "Platform Security" \
  --description "Platform security team"

# List all users
python -m core.cli users list
python -m core.cli users list --format table

# Get user details
python -m core.cli users get {user_id}

# Create a new user
python -m core.cli users create \
  --email "user@example.com" \
  --name "John Doe" \
  --role admin

# Reset user password
python -m core.cli users reset-password {user_id}
```

---

## PentAGI Integration

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/pentagi/requests` | List requests |
| GET | `/api/v1/pentagi/requests/{id}` | Get request status |
| POST | `/api/v1/pentagi/requests` | Create request |
| POST | `/api/v1/pentagi/requests/{id}/cancel` | Cancel request |
| GET | `/api/v1/pentagi/results/{id}` | Get results |
| GET | `/api/v1/pentagi/capabilities` | List capabilities |
| GET | `/api/v1/pentagi/config` | Get config |
| PUT | `/api/v1/pentagi/config` | Update config |

### CLI Commands

```bash
# List PentAGI requests
python -m core.cli pentagi list

# Create a new PentAGI request
python -m core.cli pentagi create \
  --target "https://api.example.com" \
  --cve "CVE-2024-1234"

# Check request status
python -m core.cli pentagi status {request_id}
```

---

## Evidence Management

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/evidence/bundles` | List bundles |
| GET | `/api/v1/evidence/bundles/{id}` | Get bundle |
| GET | `/api/v1/evidence/bundles/{id}/download` | Download bundle |
| GET | `/api/v1/evidence/manifests` | List manifests |
| GET | `/api/v1/evidence/manifests/{id}` | Get manifest |
| POST | `/api/v1/evidence/verify` | Verify bundle |
| POST | `/api/v1/evidence/sign` | Sign bundle |
| GET | `/api/v1/evidence/retention` | Retention policy |
| GET | `/api/v1/evidence/search` | Search evidence |
| GET | `/api/v1/evidence/export` | Export evidence |
| GET | `/api/v1/evidence/compliance` | Compliance mapping |
| GET | `/api/v1/evidence/attestations` | Attestations |

### CLI Commands

```bash
# Retrieve evidence bundle
python -m core.cli get-evidence --run pipeline-result.json

# Copy evidence to directory for audit handoff
python -m core.cli copy-evidence \
  --run pipeline-result.json \
  --target ./audit-handoff
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FIXOPS_DB_PATH` | SQLite database path | `.fixops_data/fixops.db` |
| `FIXOPS_API_TOKEN` | API authentication token | - |
| `FIXOPS_OVERLAY` | Default overlay file path | - |
| `FIXOPS_DISABLE_TELEMETRY` | Disable telemetry | `0` |

### CLI Commands

```bash
# Show overlay configuration
python -m core.cli show-overlay --overlay config/fixops.overlay.yml

# Run demo mode
python -m core.cli demo --mode demo
python -m core.cli demo --mode enterprise
```

---

## Exit Codes

The `make-decision` command returns exit codes for CI/CD integration:

| Exit Code | Decision | Description |
|-----------|----------|-------------|
| 0 | GO | Safe to proceed |
| 1 | NO-GO | Block deployment |
| 2 | CONDITIONAL | Requires manual review |

---

## API-Only Features

The following features are available only via API (not CLI):

- Chunked uploads for large files
- Graph visualization endpoints
- Bulk operations
- Webhook management
- Template management
- Advanced search/query endpoints
- Retention policy management
- Real-time notifications

These features are typically used by the web UI or require interactive visualization.
