# FixOps Docker Showcase Guide

> **Complete runnable reference for all 303 API endpoints and 111 CLI commands inside Docker**

This guide provides copy-paste Docker commands to run and showcase every FixOps feature.

---

## Prerequisites

```bash
# Pull the FixOps image
docker pull devopsaico/fixops:latest

# Or build locally
docker build -t fixops:local .
```

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_API_TOKEN` | `demo-token-12345` | API authentication token |
| `FIXOPS_DISABLE_TELEMETRY` | `1` | Disable OpenTelemetry |
| `FIXOPS_MODE` | `demo` | Operating mode |

---

## Quick Start

```bash
# Start API server (runs on port 8000)
docker run -d --name fixops -p 8000:8000 devopsaico/fixops:latest

# Verify it's running
curl http://localhost:8000/health

# Run CLI commands
docker exec fixops python -m core.cli --help

# Interactive shell
docker exec -it fixops bash
```

---

## CLI Command Reference (All 28 Groups)

All CLI commands use: `docker exec fixops python -m core.cli <command> [options]`

Or for one-off commands: `docker run --rm devopsaico/fixops:latest cli <command> [options]`

---

### 1. demo - Run Demo Pipeline

**Purpose:** Quick validation with bundled fixtures. No external data needed.

```bash
# Run demo mode
docker exec fixops python -m core.cli demo --mode demo --pretty

# Run enterprise mode
docker exec fixops python -m core.cli demo --mode enterprise --pretty

# Save output to file
docker exec fixops python -m core.cli demo --mode demo --output /app/data/pipeline.json --pretty

# Quiet mode (no summary)
docker exec fixops python -m core.cli demo --mode demo --quiet
```

---

### 2. run - Execute Full Pipeline

**Purpose:** Production pipeline execution with overlay configuration.

```bash
# Run with default overlay
docker exec fixops python -m core.cli run --overlay /app/config/fixops.overlay.yml

# Run with specific inputs
docker exec fixops python -m core.cli run \
  --overlay /app/config/fixops.overlay.yml \
  --design /app/samples/design.csv \
  --sbom /app/samples/sbom.json \
  --sarif /app/samples/scan.sarif \
  --output /app/data/pipeline-result.json

# Enable specific modules
docker exec fixops python -m core.cli run \
  --overlay /app/config/fixops.overlay.yml \
  --enable policy_automation \
  --enable compliance \
  --enable ssdlc

# Offline mode (no feed refresh)
docker exec fixops python -m core.cli run --offline --overlay /app/config/fixops.overlay.yml
```

---

### 3. ingest - Normalize Security Artifacts

**Purpose:** Import SBOM, SARIF, CVE files into FixOps.

```bash
# Ingest SBOM
docker exec fixops python -m core.cli ingest --sbom /app/samples/sbom.json

# Ingest SARIF scan results
docker exec fixops python -m core.cli ingest --sarif /app/samples/scan.sarif

# Ingest multiple artifacts
docker exec fixops python -m core.cli ingest \
  --sbom /app/samples/sbom.json \
  --sarif /app/samples/scan.sarif \
  --cve /app/samples/cve.json

# With custom output
docker exec fixops python -m core.cli ingest --sbom /app/samples/sbom.json --output /app/data/normalized.json
```

---

### 4. stage-run - Run Single Pipeline Stage

**Purpose:** Debug specific stages (build, test, deploy, design).

```bash
# Run build stage
docker exec fixops python -m core.cli stage-run --stage build --input /app/samples/design.csv

# Run test stage
docker exec fixops python -m core.cli stage-run --stage test --input /app/samples/scan.sarif

# Run deploy stage
docker exec fixops python -m core.cli stage-run --stage deploy --input /app/samples/sbom.json
```

---

### 5. make-decision - Get Remediation Decision

**Purpose:** Automated accept/reject based on policy.

```bash
# Make decision on findings
docker exec fixops python -m core.cli make-decision --input /app/data/findings.json

# With specific policy
docker exec fixops python -m core.cli make-decision --input /app/data/findings.json --policy critical-only
```

---

### 6. analyze - Analyze Findings

**Purpose:** Quick security assessment and verdict.

```bash
# Analyze findings
docker exec fixops python -m core.cli analyze --input /app/data/findings.json

# With verbose output
docker exec fixops python -m core.cli analyze --input /app/data/findings.json --verbose
```

---

### 7. health - Check Integration Readiness

**Purpose:** Verify connectors before pipeline run.

```bash
# Check all integrations
docker exec fixops python -m core.cli health

# Check specific integration
docker exec fixops python -m core.cli health --integration jira
```

---

### 8. get-evidence - Copy Evidence Bundle

**Purpose:** Extract signed evidence for audits.

```bash
# Get evidence from pipeline run
docker exec fixops python -m core.cli get-evidence --run /app/data/pipeline.json --target /app/data/evidence

# Copy to specific directory
docker exec fixops python -m core.cli copy-evidence --run /app/data/pipeline.json --target /app/data/audit-handoff
```

---

### 9. show-overlay - Print Overlay Configuration

**Purpose:** Debug configuration without exposing secrets.

```bash
# Show default overlay
docker exec fixops python -m core.cli show-overlay --overlay /app/config/fixops.overlay.yml

# Show sanitized (no secrets)
docker exec fixops python -m core.cli show-overlay --overlay /app/config/fixops.overlay.yml --sanitize
```

---

### 10. teams - Manage Teams

**Purpose:** Create, list, delete security teams.

```bash
# List all teams
docker exec fixops python -m core.cli teams list

# Create a team
docker exec fixops python -m core.cli teams create --name "Security Team" --description "Main security team"

# Get team details
docker exec fixops python -m core.cli teams get --id team-123

# Delete a team
docker exec fixops python -m core.cli teams delete --id team-123
```

---

### 11. users - Manage Users

**Purpose:** User administration.

```bash
# List all users
docker exec fixops python -m core.cli users list

# Create a user
docker exec fixops python -m core.cli users create --email "user@example.com" --name "John Doe" --role admin

# Get user details
docker exec fixops python -m core.cli users get --id user-123

# Delete a user
docker exec fixops python -m core.cli users delete --id user-123
```

---

### 12. groups - Manage Finding Groups

**Purpose:** Cluster related findings.

```bash
# List all groups
docker exec fixops python -m core.cli groups list

# Get group details
docker exec fixops python -m core.cli groups get --id group-123

# Merge groups
docker exec fixops python -m core.cli groups merge --source group-123 --target group-456

# Unmerge/split group
docker exec fixops python -m core.cli groups unmerge --id group-123 --event-ids event-1,event-2
```

---

### 13. pentagi - Manage PentAGI Testing

**Purpose:** Basic pentest job management.

```bash
# List pentest requests
docker exec fixops python -m core.cli pentagi list-requests

# Create pentest request
docker exec fixops python -m core.cli pentagi create-request \
  --target "https://example.com" \
  --scope "web application"

# Get request details
docker exec fixops python -m core.cli pentagi get-request --id req-123

# List results
docker exec fixops python -m core.cli pentagi list-results

# List configurations
docker exec fixops python -m core.cli pentagi list-configs

# Create configuration
docker exec fixops python -m core.cli pentagi create-config --name "default" --settings '{"timeout": 300}'
```

---

### 14. micro-pentest - Run Micro Penetration Tests

**Purpose:** Quick CVE-specific penetration tests.

```bash
# Run micro pentest for specific CVE
docker exec fixops python -m core.cli micro-pentest run \
  --cve-ids CVE-2024-1234 \
  --target-urls https://example.com \
  --context "Production web application"

# Run batch micro pentests
docker exec fixops python -m core.cli micro-pentest run \
  --cve-ids CVE-2024-1234,CVE-2024-5678 \
  --target-urls https://app1.com,https://app2.com

# Check status
docker exec fixops python -m core.cli micro-pentest status --flow-id 12345
```

---

### 15. advanced-pentest - AI-Powered Pentest

**Purpose:** Multi-LLM consensus penetration testing.

```bash
# Run advanced pentest
docker exec fixops python -m core.cli advanced-pentest run \
  --target https://example.com \
  --scope "full application"

# With specific LLM providers
docker exec fixops python -m core.cli advanced-pentest run \
  --target https://example.com \
  --providers gpt,claude,gemini
```

---

### 16. compliance - Manage Compliance

**Purpose:** Framework status and reports.

```bash
# List supported frameworks
docker exec fixops python -m core.cli compliance frameworks

# Get compliance status
docker exec fixops python -m core.cli compliance status --framework PCI-DSS

# Get compliance gaps
docker exec fixops python -m core.cli compliance gaps --framework SOC2

# Generate compliance report
docker exec fixops python -m core.cli compliance report --framework PCI-DSS --format pdf --output /app/data/compliance.pdf
```

---

### 17. reports - Generate Reports

**Purpose:** Security reports in various formats.

```bash
# List generated reports
docker exec fixops python -m core.cli reports list

# Generate new report
docker exec fixops python -m core.cli reports generate --type executive --format pdf

# Export report data
docker exec fixops python -m core.cli reports export --id report-123 --format json

# List report schedules
docker exec fixops python -m core.cli reports schedules
```

---

### 18. inventory - Manage App Inventory

**Purpose:** Track applications and services.

```bash
# List all applications
docker exec fixops python -m core.cli inventory apps

# Add an application
docker exec fixops python -m core.cli inventory add \
  --name "MyApp" \
  --type web \
  --criticality high

# Get application details
docker exec fixops python -m core.cli inventory get --id app-123

# List all services
docker exec fixops python -m core.cli inventory services

# Search applications
docker exec fixops python -m core.cli inventory search --query "payment"
```

---

### 19. policies - Manage Security Policies

**Purpose:** CRUD for decision policies.

```bash
# List all policies
docker exec fixops python -m core.cli policies list

# Get policy details
docker exec fixops python -m core.cli policies get --id policy-123

# Create a policy
docker exec fixops python -m core.cli policies create \
  --name "Critical Only" \
  --rules '{"severity": "critical", "action": "block"}'

# Validate a policy
docker exec fixops python -m core.cli policies validate --id policy-123

# Test a policy
docker exec fixops python -m core.cli policies test --id policy-123 --input /app/data/test-findings.json
```

---

### 20. integrations - Manage Connectors

**Purpose:** Configure Jira, Slack, GitHub, etc.

```bash
# List all integrations
docker exec fixops python -m core.cli integrations list

# Configure an integration
docker exec fixops python -m core.cli integrations configure \
  --type jira \
  --url https://company.atlassian.net \
  --token $JIRA_TOKEN

# Test an integration
docker exec fixops python -m core.cli integrations test --id integration-123

# Sync data with integration
docker exec fixops python -m core.cli integrations sync --id integration-123
```

---

### 21. analytics - View Security Metrics

**Purpose:** Dashboard and MTTR stats.

```bash
# Get dashboard metrics
docker exec fixops python -m core.cli analytics dashboard

# Get MTTR metrics
docker exec fixops python -m core.cli analytics mttr --days 90

# Get security coverage
docker exec fixops python -m core.cli analytics coverage

# Get ROI analysis
docker exec fixops python -m core.cli analytics roi

# Export analytics data
docker exec fixops python -m core.cli analytics export --format csv --output /app/data/analytics.csv
```

---

### 22. audit - View Audit Logs

**Purpose:** Compliance audit trail.

```bash
# View audit logs
docker exec fixops python -m core.cli audit logs --days 30

# View decision audit trail
docker exec fixops python -m core.cli audit decisions --days 7

# Export audit logs
docker exec fixops python -m core.cli audit export --format json --output /app/data/audit.json
```

---

### 23. workflows - Manage Automation

**Purpose:** Workflow definitions and execution.

```bash
# List all workflows
docker exec fixops python -m core.cli workflows list

# Get workflow details
docker exec fixops python -m core.cli workflows get --id workflow-123

# Create a workflow
docker exec fixops python -m core.cli workflows create \
  --name "Auto-Triage" \
  --trigger "new_finding" \
  --actions '["assign", "notify"]'

# Execute a workflow manually
docker exec fixops python -m core.cli workflows execute --id workflow-123

# View execution history
docker exec fixops python -m core.cli workflows history --id workflow-123
```

---

### 24. remediation - Manage Remediation Tasks

**Purpose:** Track fix progress and SLAs.

```bash
# List remediation tasks
docker exec fixops python -m core.cli remediation list --status open

# Get specific task
docker exec fixops python -m core.cli remediation get --id task-123

# Assign a task
docker exec fixops python -m core.cli remediation assign --id task-123 --user user-456

# Transition task status
docker exec fixops python -m core.cli remediation transition --id task-123 --status in_progress

# Verify a remediation
docker exec fixops python -m core.cli remediation verify --id task-123

# Get remediation metrics
docker exec fixops python -m core.cli remediation metrics

# Get SLA compliance report
docker exec fixops python -m core.cli remediation sla
```

---

### 25. reachability - Analyze Vulnerability Reach

**Purpose:** Check if CVE is reachable in code.

```bash
# Analyze reachability for a CVE
docker exec fixops python -m core.cli reachability analyze --cve CVE-2024-1234

# Bulk reachability analysis
docker exec fixops python -m core.cli reachability bulk --file /app/data/cves.txt

# Check job status
docker exec fixops python -m core.cli reachability status --job-id job-123
```

---

### 26. correlation - Manage Deduplication

**Purpose:** Find and manage duplicate findings.

```bash
# Analyze correlations
docker exec fixops python -m core.cli correlation analyze

# Get correlation statistics
docker exec fixops python -m core.cli correlation stats

# View correlation graph
docker exec fixops python -m core.cli correlation graph

# Provide feedback on correlations
docker exec fixops python -m core.cli correlation feedback --id corr-123 --correct true
```

---

### 27. notifications - Notification Queue

**Purpose:** Manage alert delivery.

```bash
# List pending notifications
docker exec fixops python -m core.cli notifications pending

# Run notification worker
docker exec fixops python -m core.cli notifications worker
```

---

### 28. Probabilistic Models

**Purpose:** Train and use risk prediction models.

```bash
# Train forecast model
docker exec fixops python -m core.cli train-forecast --data /app/data/incidents.csv

# Train Bayesian Network model
docker exec fixops python -m core.cli train-bn-lr --data /app/data/training.csv

# Predict exploitation risk
docker exec fixops python -m core.cli predict-bn-lr --input /app/data/cves.json

# Backtest model
docker exec fixops python -m core.cli backtest-bn-lr --model /app/data/model.pkl --test /app/data/test.csv
```

---

## API Endpoint Reference (All 303 Endpoints)

All API calls use: `curl -H "X-API-Key: demo-token-12345" http://localhost:8000/<endpoint>`

Start the container first:
```bash
docker run -d --name fixops -p 8000:8000 devopsaico/fixops:latest
```

---

### Health & Status Endpoints

```bash
# Health check (no auth required)
curl http://localhost:8000/health

# Readiness check
curl http://localhost:8000/ready

# Version info
curl http://localhost:8000/version

# Metrics
curl http://localhost:8000/metrics

# API status
curl -H "X-API-Key: demo-token-12345" http://localhost:8000/api/v1/status
```

---

### Input Endpoints (Upload Security Artifacts)

```bash
# Upload design CSV
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@design.csv;type=text/csv" \
  http://localhost:8000/inputs/design

# Upload SBOM
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@sbom.json;type=application/json" \
  http://localhost:8000/inputs/sbom

# Upload CVE data
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@cve.json;type=application/json" \
  http://localhost:8000/inputs/cve

# Upload VEX
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@vex.json;type=application/json" \
  http://localhost:8000/inputs/vex

# Upload CNAPP findings
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@cnapp.json;type=application/json" \
  http://localhost:8000/inputs/cnapp

# Upload SARIF scan results
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@scan.sarif;type=application/json" \
  http://localhost:8000/inputs/sarif

# Upload context
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"environment": "production", "criticality": "high"}' \
  http://localhost:8000/inputs/context
```

---

### Pipeline Endpoints

```bash
# Run pipeline
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/pipeline/run | jq

# Get pipeline status
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/pipeline/status

# Get pipeline results
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/pipeline/results | jq
```

---

### Validation Endpoints

```bash
# Validate input
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"format": "sbom", "content": {...}}' \
  http://localhost:8000/api/v1/validate/input

# Batch validation
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"items": [...]}' \
  http://localhost:8000/api/v1/validate/batch

# Get supported formats
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/validate/supported-formats | jq
```

---

### Enhanced Decision Endpoints (Multi-LLM)

```bash
# Get LLM capabilities
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/enhanced/capabilities | jq

# Compare LLM recommendations
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "demo-app",
    "security_findings": [
      {"rule_id": "SAST001", "severity": "high", "description": "SQL injection"}
    ],
    "business_context": {"environment": "production", "criticality": "high"}
  }' \
  http://localhost:8000/api/v1/enhanced/compare-llms | jq

# Get consensus decision
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"findings": [...], "context": {...}}' \
  http://localhost:8000/api/v1/enhanced/consensus | jq
```

---

### Threat Intelligence Feeds Endpoints

```bash
# Get EPSS data
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/epss | jq

# Refresh EPSS feed
curl -H "X-API-Key: demo-token-12345" \
  -X POST http://localhost:8000/api/v1/feeds/epss/refresh

# Get KEV data
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/kev | jq

# Refresh KEV feed
curl -H "X-API-Key: demo-token-12345" \
  -X POST http://localhost:8000/api/v1/feeds/kev/refresh

# Get exploits for CVE
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/exploits/CVE-2024-1234 | jq

# Search exploits
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cve_ids": ["CVE-2024-1234", "CVE-2024-5678"]}' \
  http://localhost:8000/api/v1/feeds/exploits

# Get threat actors for CVE
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/threat-actors/CVE-2024-1234 | jq

# Get threat actor details
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/threat-actors/by-actor/APT29 | jq

# Get supply chain risk
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/supply-chain/lodash | jq

# Get exploit confidence
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/exploit-confidence/CVE-2024-1234 | jq

# Get geo risk
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/geo-risk/CVE-2024-1234 | jq

# Enrich CVE data
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cve_id": "CVE-2024-1234"}' \
  http://localhost:8000/api/v1/feeds/enrich | jq

# Get feed stats
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/stats | jq

# Get feed categories
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/categories | jq

# Get feed sources
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/sources | jq

# Get feed health
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/health | jq

# Get scheduler status
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/scheduler/status | jq

# Refresh all feeds
curl -H "X-API-Key: demo-token-12345" \
  -X POST http://localhost:8000/api/v1/feeds/refresh/all
```

---

### Teams Endpoints

```bash
# List teams
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/teams | jq

# Create team
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "Security Team", "description": "Main security team"}' \
  http://localhost:8000/api/v1/teams

# Get team
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/teams/team-123 | jq

# Update team
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"name": "Updated Team Name"}' \
  http://localhost:8000/api/v1/teams/team-123

# Delete team
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  http://localhost:8000/api/v1/teams/team-123

# Get team members
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/teams/team-123/members | jq

# Add team member
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user-456", "role": "member"}' \
  http://localhost:8000/api/v1/teams/team-123/members

# Remove team member
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  http://localhost:8000/api/v1/teams/team-123/members/user-456
```

---

### Users Endpoints

```bash
# Login
curl -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "password"}' \
  http://localhost:8000/api/v1/users/login | jq

# List users
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/users | jq

# Create user
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "name": "John Doe", "role": "analyst"}' \
  http://localhost:8000/api/v1/users

# Get user
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/users/user-123 | jq

# Update user
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"name": "Jane Doe"}' \
  http://localhost:8000/api/v1/users/user-123

# Delete user
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  http://localhost:8000/api/v1/users/user-123
```

---

### Policies Endpoints

```bash
# List policies
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/policies | jq

# Create policy
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Critical Blocker",
    "description": "Block critical vulnerabilities",
    "rules": [{"severity": "critical", "action": "block"}]
  }' \
  http://localhost:8000/api/v1/policies

# Get policy
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/policies/policy-123 | jq

# Update policy
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"name": "Updated Policy"}' \
  http://localhost:8000/api/v1/policies/policy-123

# Delete policy
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  http://localhost:8000/api/v1/policies/policy-123

# Validate policy
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/policies/policy-123/validate | jq

# Test policy
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"findings": [...]}' \
  http://localhost:8000/api/v1/policies/policy-123/test | jq

# Get policy violations
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/policies/policy-123/violations | jq
```

---

### Inventory Endpoints

```bash
# List applications
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/applications | jq

# Create application
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "MyApp", "type": "web", "criticality": "high"}' \
  http://localhost:8000/api/v1/inventory/applications

# Get application
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/applications/app-123 | jq

# Update application
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"criticality": "critical"}' \
  http://localhost:8000/api/v1/inventory/applications/app-123

# Delete application
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  http://localhost:8000/api/v1/inventory/applications/app-123

# Get application components
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/applications/app-123/components | jq

# Get application APIs
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/applications/app-123/apis | jq

# Get application dependencies
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/applications/app-123/dependencies | jq

# List services
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/services | jq

# Create service
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "Payment Service", "type": "microservice"}' \
  http://localhost:8000/api/v1/inventory/services

# Get service
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/services/svc-123 | jq

# List APIs
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/apis | jq

# Create API
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "User API", "version": "v1"}' \
  http://localhost:8000/api/v1/inventory/apis

# Get API security
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/apis/api-123/security | jq

# Search inventory
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/inventory/search?q=payment" | jq
```

---

### Integrations Endpoints

```bash
# List integrations
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/integrations | jq

# Create integration
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "jira",
    "name": "Jira Cloud",
    "config": {"url": "https://company.atlassian.net", "project": "SEC"}
  }' \
  http://localhost:8000/api/v1/integrations

# Get integration
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/integrations/int-123 | jq

# Update integration
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"config": {"project": "VULN"}}' \
  http://localhost:8000/api/v1/integrations/int-123

# Delete integration
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  http://localhost:8000/api/v1/integrations/int-123

# Test integration
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/integrations/int-123/test | jq

# Get sync status
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/integrations/int-123/sync-status | jq

# Trigger sync
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/integrations/int-123/sync
```

---

### Analytics Endpoints

```bash
# Get dashboard overview
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/dashboard/overview | jq

# Get trends
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/dashboard/trends | jq

# Get top risks
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/dashboard/top-risks | jq

# Get compliance status
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/dashboard/compliance-status | jq

# List findings
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/findings | jq

# Create finding
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"title": "SQL Injection", "severity": "critical", "cve_id": "CVE-2024-1234"}' \
  http://localhost:8000/api/v1/analytics/findings

# Legacy dashboard
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/analytics/dashboard | jq

# Get run details
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/analytics/runs/run-123 | jq
```

---

### Micro Pentest Endpoints

```bash
# Run micro pentest
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_ids": ["CVE-2024-1234"],
    "target_urls": ["https://example.com"],
    "context": "Production web application"
  }' \
  http://localhost:8000/api/v1/micro-pentest/run | jq

# Get pentest status
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/micro-pentest/status/12345 | jq

# Run batch pentests
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "tests": [
      {"cve_ids": ["CVE-2024-1234"], "target_urls": ["https://app1.com"]},
      {"cve_ids": ["CVE-2024-5678"], "target_urls": ["https://app2.com"]}
    ]
  }' \
  http://localhost:8000/api/v1/micro-pentest/batch | jq
```

---

### PentAGI Endpoints

```bash
# List requests
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/pentagi/requests | jq

# Create request
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scope": "web application"}' \
  http://localhost:8000/api/v1/pentagi/requests

# Get request
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/pentagi/requests/req-123 | jq

# Update request
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"status": "approved"}' \
  http://localhost:8000/api/v1/pentagi/requests/req-123

# Start request
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/pentagi/requests/req-123/start

# Cancel request
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/pentagi/requests/req-123/cancel

# List results
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/pentagi/results | jq

# Create result
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"request_id": "req-123", "findings": [...]}' \
  http://localhost:8000/api/v1/pentagi/results

# Get results by request
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/pentagi/results/by-request/req-123 | jq

# List configs
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/pentagi/configs | jq

# Create config
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "default", "settings": {"timeout": 300}}' \
  http://localhost:8000/api/v1/pentagi/configs

# Get config
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/pentagi/configs/cfg-123 | jq

# Update config
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"settings": {"timeout": 600}}' \
  http://localhost:8000/api/v1/pentagi/configs/cfg-123

# Delete config
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  http://localhost:8000/api/v1/pentagi/configs/cfg-123

# Verify exploitability
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cve_id": "CVE-2024-1234", "target": "https://example.com"}' \
  http://localhost:8000/api/v1/pentagi/verify | jq

# Monitoring scan
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "schedule": "daily"}' \
  http://localhost:8000/api/v1/pentagi/monitoring

# Comprehensive scan
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "depth": "full"}' \
  http://localhost:8000/api/v1/pentagi/scan/comprehensive | jq

# Get finding exploitability
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/pentagi/findings/finding-123/exploitability | jq

# Get stats
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/pentagi/stats | jq
```

---

### Bulk Operations Endpoints

```bash
# Bulk update cluster status
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cluster_ids": ["c1", "c2"], "status": "resolved"}' \
  http://localhost:8000/api/v1/bulk/clusters/status | jq

# Bulk assign clusters
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cluster_ids": ["c1", "c2"], "assignee": "user-123"}' \
  http://localhost:8000/api/v1/bulk/clusters/assign | jq

# Bulk accept risk
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cluster_ids": ["c1", "c2"], "reason": "False positive"}' \
  http://localhost:8000/api/v1/bulk/clusters/accept-risk | jq

# Bulk create tickets
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cluster_ids": ["c1", "c2"], "integration_id": "jira-123"}' \
  http://localhost:8000/api/v1/bulk/clusters/create-tickets | jq

# Bulk export
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"format": "csv", "filters": {"severity": "critical"}}' \
  http://localhost:8000/api/v1/bulk/export | jq

# Get job status
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/bulk/jobs/job-123 | jq

# List jobs
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/bulk/jobs | jq

# Delete job
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  http://localhost:8000/api/v1/bulk/jobs/job-123

# Bulk update findings
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"finding_ids": ["f1", "f2"], "status": "resolved"}' \
  http://localhost:8000/api/v1/bulk/findings/update | jq

# Bulk delete findings
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"finding_ids": ["f1", "f2"]}' \
  http://localhost:8000/api/v1/bulk/findings/delete | jq

# Bulk assign findings
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"finding_ids": ["f1", "f2"], "assignee": "user-123"}' \
  http://localhost:8000/api/v1/bulk/findings/assign | jq

# Bulk apply policies
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"policy_id": "policy-123", "scope": "all"}' \
  http://localhost:8000/api/v1/bulk/policies/apply | jq
```

---

### Collaboration Endpoints

```bash
# Create comment
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"entity_type": "finding", "entity_id": "f-123", "content": "This needs review"}' \
  http://localhost:8000/api/v1/collaboration/comments

# List comments
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/collaboration/comments?entity_type=finding&entity_id=f-123" | jq

# Promote comment
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  http://localhost:8000/api/v1/collaboration/comments/comment-123/promote

# Add watcher
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"entity_type": "finding", "entity_id": "f-123", "user_id": "user-456"}' \
  http://localhost:8000/api/v1/collaboration/watchers

# Remove watcher
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  -H "Content-Type: application/json" \
  -d '{"entity_type": "finding", "entity_id": "f-123", "user_id": "user-456"}' \
  http://localhost:8000/api/v1/collaboration/watchers

# List watchers
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/collaboration/watchers?entity_type=finding&entity_id=f-123" | jq

# Get user's watched entities
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/watchers/user/user-123 | jq

# Create activity
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"entity_type": "finding", "entity_id": "f-123", "action": "status_change", "details": {...}}' \
  http://localhost:8000/api/v1/collaboration/activities

# List activities
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/collaboration/activities?entity_type=finding&entity_id=f-123" | jq

# Get mentions
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/mentions/user-123 | jq

# Acknowledge mention
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  http://localhost:8000/api/v1/collaboration/mentions/mention-123/acknowledge

# Get entity types
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/entity-types | jq

# Get activity types
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/activity-types | jq

# Queue notification
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user-123", "type": "mention", "content": "You were mentioned"}' \
  http://localhost:8000/api/v1/collaboration/notifications/queue

# Notify watchers
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"entity_type": "finding", "entity_id": "f-123", "event": "status_change"}' \
  http://localhost:8000/api/v1/collaboration/notifications/notify-watchers

# Get pending notifications
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/notifications/pending | jq

# Mark notification sent
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  http://localhost:8000/api/v1/collaboration/notifications/notif-123/sent

# Get notification preferences
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/notifications/preferences/user-123 | jq

# Update notification preferences
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"email": true, "slack": false}' \
  http://localhost:8000/api/v1/collaboration/notifications/preferences/user-123

# Deliver notification
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/collaboration/notifications/notif-123/deliver

# Process notifications
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/collaboration/notifications/process
```

---

### Marketplace Endpoints

```bash
# Get compliance packs
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/packs/PCI-DSS/control-1 | jq

# Browse marketplace
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/browse | jq

# Get recommendations
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/recommendations | jq

# Get item details
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/items/item-123 | jq

# Contribute item
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Policy Pack", "type": "policy", "content": {...}}' \
  http://localhost:8000/api/v1/marketplace/contribute

# Update item
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"description": "Updated description"}' \
  http://localhost:8000/api/v1/marketplace/items/item-123

# Rate item
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"rating": 5, "review": "Great policy pack!"}' \
  http://localhost:8000/api/v1/marketplace/items/item-123/rate

# Purchase item
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/marketplace/purchase/item-123 | jq

# Download item
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/download/token-abc123

# List contributors
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/contributors | jq

# Get compliance content
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/compliance-content/design | jq

# Get marketplace stats
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/stats | jq
```

---

### Triage Endpoints

```bash
# Get triage data
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/triage | jq

# Export triage data
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/triage/export | jq
```

---

### Graph Endpoints

```bash
# Get risk graph
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/graph | jq
```

---

### Feedback Endpoints

```bash
# Submit feedback
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"type": "decision", "entity_id": "dec-123", "rating": 5, "comment": "Good decision"}' \
  http://localhost:8000/feedback
```

---

### IDE Integration Endpoints

```bash
# Get IDE config
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/ide/config | jq

# Analyze code
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"code": "SELECT * FROM users WHERE id = $1", "language": "sql"}' \
  http://localhost:8000/api/v1/ide/analyze | jq

# Get suggestions
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/ide/suggestions?file=app.py&line=42" | jq
```

---

### SSO/Auth Endpoints

```bash
# List SSO configs
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/auth/sso | jq

# Create SSO config
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"provider": "okta", "client_id": "xxx", "client_secret": "yyy"}' \
  http://localhost:8000/api/v1/auth/sso

# Get SSO config
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/auth/sso/sso-123 | jq

# Update SSO config
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}' \
  http://localhost:8000/api/v1/auth/sso/sso-123
```

---

## End-to-End Demo Recipes

### Recipe 1: Full Security Assessment

```bash
# 1. Start container
docker run -d --name fixops -p 8000:8000 devopsaico/fixops:latest

# 2. Wait for health
sleep 5 && curl http://localhost:8000/health

# 3. Upload artifacts
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@sbom.json;type=application/json" \
  http://localhost:8000/inputs/sbom

curl -H "X-API-Key: demo-token-12345" \
  -F "file=@scan.sarif;type=application/json" \
  http://localhost:8000/inputs/sarif

# 4. Run pipeline
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/pipeline/run | jq

# 5. Get dashboard
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/dashboard/overview | jq

# 6. Cleanup
docker stop fixops && docker rm fixops
```

### Recipe 2: LLM Decision Comparison

```bash
# 1. Start container
docker run -d --name fixops -p 8000:8000 devopsaico/fixops:latest
sleep 5

# 2. Compare LLM recommendations
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "payment-service",
    "security_findings": [
      {"rule_id": "SAST001", "severity": "critical", "description": "SQL injection in user input"},
      {"rule_id": "SAST002", "severity": "high", "description": "Hardcoded credentials"}
    ],
    "business_context": {"environment": "production", "criticality": "high"}
  }' \
  http://localhost:8000/api/v1/enhanced/compare-llms | jq

# 3. Cleanup
docker stop fixops && docker rm fixops
```

### Recipe 3: Compliance Check

```bash
# 1. Start container
docker run -d --name fixops -p 8000:8000 devopsaico/fixops:latest
sleep 5

# 2. Check compliance status
docker exec fixops python -m core.cli compliance status --framework PCI-DSS

# 3. Get compliance gaps
docker exec fixops python -m core.cli compliance gaps --framework PCI-DSS

# 4. Generate report
docker exec fixops python -m core.cli compliance report --framework PCI-DSS --format json

# 5. Cleanup
docker stop fixops && docker rm fixops
```

---

## Troubleshooting

### Container won't start

```bash
# Check logs
docker logs fixops

# Check if port is in use
lsof -i :8000
```

### API returns 401

```bash
# Verify token
curl -H "X-API-Key: demo-token-12345" http://localhost:8000/api/v1/status

# Check container env
docker exec fixops env | grep FIXOPS
```

### CLI command not found

```bash
# Verify CLI is available
docker exec fixops python -m core.cli --help

# Check Python path
docker exec fixops which python
```

---

## Related Documentation

- [Feature Code Mapping](FEATURE_CODE_MAPPING.md) - Detailed code paths and flows
- [Product Status](FIXOPS_PRODUCT_STATUS.md) - Implementation status and roadmap
- [README](../README.md) - Main documentation
