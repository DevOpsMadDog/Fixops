# FixOps API & CLI Sample Data and Usage Guide

This directory contains comprehensive sample data files and usage examples for all FixOps API endpoints and CLI commands. Use these for demos, testing, and reference.

## Quick Start

```bash
# Set environment variables
export FIXOPS_API_TOKEN="your-api-token"
export FIXOPS_API_URL="http://127.0.0.1:8000"

# Start the API server
uvicorn apps.api.app:app --reload

# Or use the interactive wrapper script
./scripts/fixops-interactive.sh
```

## Directory Structure

```
samples/api-examples/
├── core-pipeline/       # Pipeline ingestion samples
├── security-decision/   # Security analysis samples
├── compliance/          # Compliance framework samples
├── reports/             # Report generation samples
├── inventory/           # Asset inventory samples
├── policies/            # Security policy samples
├── integrations/        # Integration configuration samples
├── analytics/           # Analytics and metrics samples
├── audit/               # Audit log samples
├── workflows/           # Workflow automation samples
├── pentest/             # Penetration testing samples
├── reachability/        # Reachability analysis samples
├── teams-users/         # Team and user management samples
├── pentagi/             # AI-powered testing samples
├── evidence/            # Evidence bundle samples
├── deduplication/       # Finding correlation samples
├── remediation/         # Remediation task samples
├── bulk-operations/     # Bulk operation samples
├── collaboration/       # Team collaboration samples
├── feeds/               # Vulnerability feed samples
└── health/              # Health check samples
```

---

## 1. Core Pipeline & Ingestion

### Upload Design Input
```bash
curl -X POST "$FIXOPS_API_URL/inputs/design" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/core-pipeline/design-input.json
```

### Upload SBOM (Software Bill of Materials)
```bash
curl -X POST "$FIXOPS_API_URL/inputs/sbom" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@samples/api-examples/core-pipeline/sbom.json;type=application/json"
```

### Upload CVE Feed
```bash
curl -X POST "$FIXOPS_API_URL/inputs/cve" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@samples/api-examples/core-pipeline/cve-feed.json;type=application/json"
```

### Upload SARIF Scan Results
```bash
curl -X POST "$FIXOPS_API_URL/inputs/sarif" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@samples/api-examples/core-pipeline/sarif-scan.json;type=application/json"
```

### Upload VEX Document
```bash
curl -X POST "$FIXOPS_API_URL/inputs/vex" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/core-pipeline/vex-document.json
```

### Upload CNAPP Findings
```bash
curl -X POST "$FIXOPS_API_URL/inputs/cnapp" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/core-pipeline/cnapp-findings.json
```

### Upload Context
```bash
curl -X POST "$FIXOPS_API_URL/inputs/context" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/core-pipeline/context.json
```

### Run Pipeline
```bash
curl -X GET "$FIXOPS_API_URL/pipeline/run" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Get Pipeline Status
```bash
curl -X GET "$FIXOPS_API_URL/pipeline/status" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 2. Security Decision & Analysis

### Compare LLM Analyses
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/enhanced/compare-llms" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/security-decision/compare-llms-request.json | jq
```

### Calculate Risk Score
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/enhanced/risk-score" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/security-decision/risk-score-request.json | jq
```

### Check Guardrails
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/enhanced/guardrail-check" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/security-decision/guardrail-check-request.json | jq
```

### Get Enhanced Capabilities
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/enhanced/capabilities" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Get Decision History
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/enhanced/decisions?limit=10" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 3. Compliance

### List Compliance Frameworks
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/compliance/frameworks" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Submit Framework Assessment
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/compliance/assessments" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/compliance/framework-assessment.json | jq
```

### Check Policy Compliance
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/compliance/policy-check" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/compliance/policy-check-request.json | jq
```

### Get Compliance Status
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/compliance/status?application=payment-gateway" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 4. Reports

### Generate Report
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/reports/generate" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/reports/report-generation-request.json | jq
```

### List Reports
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/reports?limit=10" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Download Report
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/reports/{report_id}/download" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" -o report.pdf
```

---

## 5. Inventory

### Register Application
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/inventory/applications" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/inventory/application-registration.json | jq
```

### List Applications
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/inventory/applications" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Submit Asset Discovery
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/inventory/assets/discover" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/inventory/asset-discovery.json | jq
```

### List Assets
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/inventory/assets?type=ec2_instance" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 6. Policies

### Create Security Policy
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/policies" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/policies/security-policy.json | jq
```

### List Policies
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/policies" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Evaluate Policy
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/policies/{policy_id}/evaluate" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"application": "payment-gateway", "environment": "production"}' | jq
```

---

## 7. Integrations

### Configure Jira Integration
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/integrations/jira" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/integrations/jira-integration.json | jq
```

### Configure Slack Integration
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/integrations/slack" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/integrations/slack-integration.json | jq
```

### List Integrations
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/integrations" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Test Integration
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/integrations/{integration_id}/test" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 8. Analytics

### Get Dashboard Data
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/analytics/dashboard" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/analytics/dashboard-request.json | jq
```

### Query Metrics
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/analytics/metrics" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/analytics/metrics-query.json | jq
```

### Get Trends
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/analytics/trends?period=30d" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 9. Audit

### Query Audit Logs
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/audit/logs" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/audit/audit-log-query.json | jq
```

### Get Audit Event
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/audit/events/{event_id}" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Export Audit Logs
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/audit/export" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format": "csv", "date_range": {"start": "2025-01-01", "end": "2025-01-15"}}' \
  -o audit-export.csv
```

---

## 10. Workflows

### Create Workflow
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/workflows" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/workflows/workflow-definition.json | jq
```

### List Workflows
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/workflows" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Trigger Workflow
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/workflows/{workflow_id}/trigger" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"context": {"vulnerability_id": "CVE-2021-44228"}}' | jq
```

### Get Workflow Execution Status
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/workflows/executions/{execution_id}" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 11. Advanced Penetration Testing

### Create Pentest Request
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/pentest/requests" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/pentest/pentest-request.json | jq
```

### Submit Pentest Finding
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/pentest/findings" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/pentest/finding-submission.json | jq
```

### List Pentest Engagements
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/pentest/engagements" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Get Pentest Report
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/pentest/{pentest_id}/report" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" -o pentest-report.pdf
```

---

## 12. Reachability Analysis

### Analyze Vulnerability Reachability
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/reachability/analyze" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/reachability/reachability-analysis.json | jq
```

### Get Reachability Status
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/reachability/status?application=payment-gateway" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### List Call Paths
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/reachability/call-paths?cve_id=CVE-2021-44228" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 13. Teams & Users

### Create Team
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/teams" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/teams-users/team-creation.json | jq
```

### List Teams
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/teams" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Create User
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/users" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/teams-users/user-creation.json | jq
```

### List Users
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/users" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Assign User to Team
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/teams/{team_id}/members" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user-001", "role": "developer"}' | jq
```

---

## 14. PentAGI (AI-Powered Testing)

### Create PentAGI Task
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/pentagi/tasks" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/pentagi/pentagi-task.json | jq
```

### Get PentAGI Task Status
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/pentagi/tasks/{task_id}" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### List PentAGI Findings
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/pentagi/tasks/{task_id}/findings" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 15. Evidence Management

### Create Evidence Bundle
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/evidence/bundles" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/evidence/evidence-bundle.json | jq
```

### List Evidence Bundles
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/evidence/bundles" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Download Evidence Bundle
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/evidence/bundles/{bundle_id}/download" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" -o evidence-bundle.zip
```

### Add Artifact to Bundle
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/evidence/bundles/{bundle_id}/artifacts" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@scan-results.pdf" \
  -F "metadata={\"name\": \"Scan Results\", \"type\": \"scan_report\"}"
```

---

## 16. Health & Status

### Health Check
```bash
curl -X GET "$FIXOPS_API_URL/health" | jq
```

### API Status
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/status" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Get System Metrics
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/system/metrics" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 17. Deduplication & Correlation

### Correlate Findings
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/deduplication/correlate" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/deduplication/dedup-request.json | jq
```

### Get Correlation Results
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/deduplication/results/{dedup_id}" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### List Duplicate Groups
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/deduplication/groups?application=payment-gateway" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 18. Remediation Lifecycle

### Create Remediation Task
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/remediation/tasks" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/remediation/remediation-task.json | jq
```

### List Remediation Tasks
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/remediation/tasks?status=in_progress" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Update Task Status
```bash
curl -X PATCH "$FIXOPS_API_URL/api/v1/remediation/tasks/{task_id}" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "completed", "verification": {"method": "scan", "verified": true}}' | jq
```

### Get SLA Compliance
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/remediation/sla-compliance" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 19. Bulk Operations

### Execute Bulk Update
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/bulk/execute" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/bulk-operations/bulk-update.json | jq
```

### Preview Bulk Operation
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/bulk/preview" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/bulk-operations/bulk-update.json | jq
```

### Get Bulk Operation Status
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/bulk/operations/{operation_id}" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Rollback Bulk Operation
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/bulk/operations/{operation_id}/rollback" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## 20. Team Collaboration

### Add Comment
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/collaboration/comments" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/collaboration/collaboration-comment.json | jq
```

### List Comments
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/collaboration/comments?entity_type=vulnerability&entity_id=vuln-001" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Add Watcher
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/collaboration/watchers" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_type": "vulnerability", "entity_id": "vuln-001", "user_email": "user@example.com"}' | jq
```

---

## 21. Vulnerability Intelligence Feeds

### Configure Feeds
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/feeds/configure" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @samples/api-examples/feeds/feed-configuration.json | jq
```

### Get Feed Stats
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/feeds/stats" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Get Feed Health
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/feeds/health" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

### Refresh Feeds
```bash
curl -X POST "$FIXOPS_API_URL/api/v1/feeds/refresh" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"feeds": ["nvd", "cisa_kev", "epss"]}' | jq
```

### Search CVEs
```bash
curl -X GET "$FIXOPS_API_URL/api/v1/feeds/cves?keyword=log4j&severity=critical" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | jq
```

---

## CLI Commands

### Run Demo Pipeline
```bash
python -m core.cli demo --mode demo --output out/pipeline-demo.json --pretty
```

### Run Enterprise Pipeline
```bash
python -m core.cli demo --mode enterprise --output out/pipeline-enterprise.json --pretty
```

### Run Full Pipeline with Custom Inputs
```bash
python -m core.cli run \
  --overlay config/fixops.overlay.yml \
  --enable policy_automation --enable compliance --enable ssdlc --enable probabilistic \
  --design samples/api-examples/core-pipeline/design-input.json \
  --sbom samples/api-examples/core-pipeline/sbom.json \
  --sarif samples/api-examples/core-pipeline/sarif-scan.json \
  --cve samples/api-examples/core-pipeline/cve-feed.json \
  --evidence-dir out/evidence \
  --output out/pipeline-output.json
```

### Show Overlay Configuration
```bash
python -m core.cli show-overlay --overlay config/fixops.overlay.yml
```

### Copy Evidence Bundle
```bash
python -m core.cli copy-evidence --run out/pipeline-output.json --target ./hand-off
```

### Run Offline (No Feed Refresh)
```bash
python -m core.cli run --offline --design design.json --sbom sbom.json
```

---

## Docker Usage

### Build Interactive Image
```bash
docker build -f Dockerfile.interactive -t fixops-interactive .
```

### Run Interactive Mode
```bash
docker run -it fixops-interactive
```

### Run API-Only Mode
```bash
docker run -d -p 8000:8000 fixops-interactive api-only
```

### Run All Tests
```bash
docker run -it fixops-interactive test-all
```

### Run CLI Command
```bash
docker run -it fixops-interactive cli demo --mode demo
```

### Start Shell
```bash
docker run -it fixops-interactive shell
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FIXOPS_API_TOKEN` | API authentication token | `demo-token` |
| `FIXOPS_API_URL` | API server URL | `http://127.0.0.1:8000` |
| `FIXOPS_MODE` | Operating mode (demo/enterprise) | `demo` |
| `FIXOPS_DISABLE_TELEMETRY` | Disable telemetry | `0` |
| `FIXOPS_JWT_SECRET` | JWT signing secret | Required in non-demo |
| `EDITOR` | Editor for interactive mode | `nano` |

---

## Sample Data Files Reference

| File | Description | Use Case |
|------|-------------|----------|
| `core-pipeline/design-input.json` | Application architecture design | Pipeline input |
| `core-pipeline/sbom.json` | CycloneDX SBOM | Dependency analysis |
| `core-pipeline/cve-feed.json` | CVE vulnerability feed | Vulnerability matching |
| `core-pipeline/sarif-scan.json` | SARIF scan results | SAST/DAST findings |
| `core-pipeline/vex-document.json` | VEX statements | Vulnerability status |
| `core-pipeline/cnapp-findings.json` | Cloud security findings | CNAPP integration |
| `core-pipeline/context.json` | Business context | Risk assessment |
| `security-decision/compare-llms-request.json` | LLM comparison request | Multi-model analysis |
| `security-decision/risk-score-request.json` | Risk scoring request | SSVC/EPSS analysis |
| `compliance/framework-assessment.json` | Compliance assessment | PCI-DSS/SOC2 audit |
| `policies/security-policy.json` | Security policy rules | Deployment gates |
| `integrations/jira-integration.json` | Jira configuration | Ticket creation |
| `integrations/slack-integration.json` | Slack configuration | Notifications |
| `pentest/pentest-request.json` | Pentest engagement | Security testing |
| `pentest/finding-submission.json` | Pentest finding | Vulnerability report |
| `remediation/remediation-task.json` | Remediation task | Fix tracking |
| `feeds/feed-configuration.json` | Feed configuration | Threat intel |

---

## Tips for Demos

1. **Start with Health Check**: Always verify the API is running first
2. **Use the Interactive Script**: `./scripts/fixops-interactive.sh` provides a guided experience
3. **Load Real Data**: Use the `[l]` option in interactive mode to load your own files
4. **Show the Pipeline Flow**: Upload design -> SBOM -> CVE -> SARIF -> Run Pipeline
5. **Demonstrate Multi-LLM**: The compare-llms endpoint shows AI consensus
6. **Highlight Compliance**: Show framework assessments and policy checks
7. **Use Docker**: The containerized version is self-contained and easy to demo
