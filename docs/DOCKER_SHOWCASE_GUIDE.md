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

## CLI Command Reference

All CLI commands use: `docker exec fixops python -m core.cli <command> [options]`

Or for one-off commands: `docker run --rm devopsaico/fixops:latest cli <command> [options]`

---

### 1. demo - Run Demo Pipeline

**Purpose:** Quick validation with bundled fixtures. No external data needed.

**What it operates on:** Bundled sample files in `/app/samples/` and `/app/simulations/demo_pack/` (design.csv, sbom.json, scan.sarif, cve.json). These are included in the Docker image.

**Prerequisites:** None - works out of the box with bundled fixtures.

**Data flow:** Reads bundled fixtures → Normalizes → Runs risk scoring → Generates evidence bundle → Outputs pipeline result JSON.

```bash
# Run demo mode
docker exec fixops python -m core.cli demo --mode demo --pretty

# Run enterprise mode (enables encryption)
docker exec fixops python -m core.cli demo --mode enterprise --pretty

# Save output to file
docker exec fixops python -m core.cli demo --mode demo --output /app/data/pipeline.json --pretty

# Quiet mode (no summary)
docker exec fixops python -m core.cli demo --mode demo --quiet
```

---

### 2. run - Execute Full Pipeline

**Purpose:** Production pipeline execution with overlay configuration.

**What it operates on:** Your security artifacts (SBOM, SARIF, CVE, design files) specified via command-line flags. Processes them through the full FixOps pipeline.

**Prerequisites:** 
- Security artifact files (SBOM, SARIF, CVE, design CSV)
- Overlay configuration file (`/app/config/fixops.overlay.yml`)
- Optional: External service credentials in overlay for connectors

**Data flow:** Input files → Normalization → Risk scoring (EPSS/KEV/CVSS) → Decision engine → Evidence bundle → Output JSON.

```bash
# Run with default overlay
docker exec fixops python -m core.cli run --overlay /app/config/fixops.overlay.yml

# Run with specific inputs (YOUR files)
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

# Offline mode (no feed refresh - for air-gapped environments)
docker exec fixops python -m core.cli run --offline --overlay /app/config/fixops.overlay.yml
```

---

### 3. ingest - Normalize Security Artifacts

**Purpose:** Import SBOM, SARIF, CVE files into FixOps and normalize to common format.

**What it operates on:** Your security scan output files:
- SBOM (CycloneDX, SPDX format) - Software Bill of Materials
- SARIF - Static analysis results (from tools like Semgrep, CodeQL, etc.)
- CVE - Vulnerability data in JSON format

**Prerequisites:** Security artifact files from your scanners/tools.

**Data flow:** Raw file → Format detection → Parsing → Normalization to FixOps schema → Stored in database.

```bash
# Ingest SBOM (e.g., from Syft, Trivy, etc.)
docker exec fixops python -m core.cli ingest --sbom /app/samples/sbom.json

# Ingest SARIF scan results (e.g., from Semgrep, CodeQL)
docker exec fixops python -m core.cli ingest --sarif /app/samples/scan.sarif

# Ingest multiple artifacts at once
docker exec fixops python -m core.cli ingest \
  --sbom /app/samples/sbom.json \
  --sarif /app/samples/scan.sarif \
  --cve /app/samples/cve.json

# With custom output location
docker exec fixops python -m core.cli ingest --sbom /app/samples/sbom.json --output /app/data/normalized.json
```

---

### 4. stage-run - Run Single Pipeline Stage

**Purpose:** Debug specific stages (build, test, deploy, design) independently.

**What it operates on:** Single input file for a specific SDLC stage:
- `build` stage: design.csv (architecture/design decisions)
- `test` stage: scan.sarif (test/scan results)
- `deploy` stage: sbom.json (deployment artifacts)

**Prerequisites:** Input file matching the stage type.

**Data flow:** Single stage input → Stage-specific processing → Stage output.

```bash
# Run build stage (processes design decisions)
docker exec fixops python -m core.cli stage-run --stage build --input /app/samples/design.csv

# Run test stage (processes scan results)
docker exec fixops python -m core.cli stage-run --stage test --input /app/samples/scan.sarif

# Run deploy stage (processes SBOM)
docker exec fixops python -m core.cli stage-run --stage deploy --input /app/samples/sbom.json
```

---

### 5. make-decision - Get Remediation Decision

**Purpose:** Get automated accept/reject decision based on security policy.

**What it operates on:** Findings JSON file containing security findings to evaluate against policies.

**Prerequisites:** 
- Findings file (from pipeline run or manual creation)
- Optional: Policy name if not using default

**Data flow:** Findings → Policy evaluation → Decision (accept/reject/defer/escalate) → Exit code reflects decision.

```bash
# Make decision on findings (uses default policy)
docker exec fixops python -m core.cli make-decision --input /app/data/findings.json

# With specific policy
docker exec fixops python -m core.cli make-decision --input /app/data/findings.json --policy critical-only
```

---

### 6. analyze - Analyze Findings

**Purpose:** Quick security assessment and verdict without full pipeline.

**What it operates on:** Findings JSON file for quick analysis.

**Prerequisites:** Findings file.

**Data flow:** Findings → Analysis → Verdict output.

```bash
# Analyze findings
docker exec fixops python -m core.cli analyze --input /app/data/findings.json

# With verbose output
docker exec fixops python -m core.cli analyze --input /app/data/findings.json --verbose
```

---

### 7. health - Check Integration Readiness

**Purpose:** Verify external connectors are configured and reachable before pipeline run.

**What it operates on:** Integration configurations in the database and overlay file.

**Prerequisites:** None for check; integrations must be configured to pass.

**Data flow:** Reads integration configs → Tests connectivity → Reports status.

```bash
# Check all integrations
docker exec fixops python -m core.cli health

# Check specific integration
docker exec fixops python -m core.cli health --integration jira
```

---

### 8. get-evidence - Copy Evidence Bundle

**Purpose:** Extract cryptographically signed evidence bundle for compliance audits.

**What it operates on:** Pipeline run result JSON that references an evidence bundle.

**Prerequisites:** Must have run a pipeline first (`demo` or `run` command) that generated an evidence bundle.

**Data flow:** Pipeline result → Locate evidence bundle → Copy to target directory.

```bash
# Get evidence from pipeline run
docker exec fixops python -m core.cli get-evidence --run /app/data/pipeline.json --target /app/data/evidence

# Copy to specific directory for audit handoff
docker exec fixops python -m core.cli copy-evidence --run /app/data/pipeline.json --target /app/data/audit-handoff
```

---

### 9. show-overlay - Print Overlay Configuration

**Purpose:** Debug configuration without exposing secrets.

**What it operates on:** Overlay YAML configuration file.

**Prerequisites:** Overlay file exists.

**Data flow:** Reads overlay → Sanitizes secrets → Prints to stdout.

```bash
# Show default overlay
docker exec fixops python -m core.cli show-overlay --overlay /app/config/fixops.overlay.yml

# Show sanitized (secrets masked)
docker exec fixops python -m core.cli show-overlay --overlay /app/config/fixops.overlay.yml --sanitize
```

---

### 10. teams - Manage Teams

**Purpose:** Create, list, delete security teams for organizing users and assigning findings.

**What it operates on:** Teams table in FixOps database (`fixops.db`).

**Prerequisites:** None for list; team must exist for get/delete.

**Data flow:** CRUD operations on teams table.

```bash
# List all teams (shows teams in database)
docker exec fixops python -m core.cli teams list

# Create a team
docker exec fixops python -m core.cli teams create --name "Security Team" --description "Main security team"

# Get team details (requires team ID from list)
docker exec fixops python -m core.cli teams get --id team-123

# Delete a team
docker exec fixops python -m core.cli teams delete --id team-123
```

---

### 11. users - Manage Users

**Purpose:** User administration for the FixOps instance.

**What it operates on:** Users table in FixOps database.

**Prerequisites:** None for list; user must exist for get/delete.

**Data flow:** CRUD operations on users table.

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

**Purpose:** Cluster related findings together for bulk management.

**What it operates on:** Finding groups (clusters) in FixOps database. Groups are created when findings are correlated.

**Prerequisites:** Findings must exist (from pipeline runs) to have groups.

**Data flow:** CRUD operations on finding_groups table.

```bash
# List all groups (clusters of related findings)
docker exec fixops python -m core.cli groups list

# Get group details
docker exec fixops python -m core.cli groups get --id group-123

# Merge two groups together
docker exec fixops python -m core.cli groups merge --source group-123 --target group-456

# Unmerge/split events from a group
docker exec fixops python -m core.cli groups unmerge --id group-123 --event-ids event-1,event-2
```

---

### 13. pentagi - Manage PentAGI Testing

**Purpose:** Basic pentest job management via PentAGI service.

**What it operates on:** PentAGI requests and results in database. Actual pentests run on PentAGI service.

**Prerequisites:** 
- PentAGI service must be running (use `docker-compose.pentagi.yml`)
- Target URL must be accessible from PentAGI container

**Data flow:** Create request → PentAGI executes → Results stored → Query results.

```bash
# List pentest requests
docker exec fixops python -m core.cli pentagi list-requests

# Create pentest request (target must be accessible)
docker exec fixops python -m core.cli pentagi create-request \
  --target "https://example.com" \
  --scope "web application"

# Get request details
docker exec fixops python -m core.cli pentagi get-request --id req-123

# List results (after pentest completes)
docker exec fixops python -m core.cli pentagi list-results

# List configurations
docker exec fixops python -m core.cli pentagi list-configs

# Create configuration
docker exec fixops python -m core.cli pentagi create-config --name "default" --settings '{"timeout": 300}'
```

---

### 14. micro-pentest - Run Micro Penetration Tests

**Purpose:** Quick CVE-specific penetration tests to verify exploitability.

**What it operates on:** Specific CVEs against target URLs. Tests if the CVE is exploitable on the target.

**Prerequisites:**
- PentAGI service must be running
- Target URLs must be accessible
- CVE IDs must be valid

**Data flow:** CVE + Target → PentAGI micro-test → Exploitability result.

```bash
# Run micro pentest for specific CVE against target
docker exec fixops python -m core.cli micro-pentest run \
  --cve-ids CVE-2024-1234 \
  --target-urls https://example.com \
  --context "Production web application"

# Run batch micro pentests (multiple CVEs, multiple targets)
docker exec fixops python -m core.cli micro-pentest run \
  --cve-ids CVE-2024-1234,CVE-2024-5678 \
  --target-urls https://app1.com,https://app2.com

# Check status of running pentest
docker exec fixops python -m core.cli micro-pentest status --flow-id 12345
```

---

### 15. advanced-pentest - AI-Powered Pentest

**Purpose:** Multi-LLM consensus penetration testing using GPT, Claude, Gemini.

**What it operates on:** Target application URL. Uses multiple LLMs to plan and execute pentest.

**Prerequisites:**
- PentAGI service running
- LLM API keys configured (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
- Target accessible

**Data flow:** Target → LLM planning → Pentest execution → Consensus results.

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

**Purpose:** Framework status and compliance reports.

**What it operates on:** Compliance data in FixOps database:
- `compliance_frameworks` - Framework definitions (PCI-DSS, SOC2, HIPAA, etc.)
- `compliance_controls` - Individual controls per framework
- `compliance_gaps` - Gaps found during security assessments

**Prerequisites:** 
- For meaningful reports: Run pipeline first to populate compliance data
- Frameworks are pre-seeded; gaps are populated from security findings

**Data flow:** Security findings → Mapped to compliance controls → Gaps identified → Report generated.

```bash
# List supported frameworks
docker exec fixops python -m core.cli compliance frameworks

# Get compliance status (shows coverage % for framework)
docker exec fixops python -m core.cli compliance status --framework PCI-DSS

# Get compliance gaps (shows what's missing)
docker exec fixops python -m core.cli compliance gaps --framework SOC2

# Generate compliance report (PDF/JSON)
# NOTE: Report reflects ALL findings ingested into FixOps, not a specific app
docker exec fixops python -m core.cli compliance report --framework PCI-DSS --format pdf --output /app/data/compliance.pdf
```

**To get meaningful compliance data, first ingest security artifacts:**
```bash
# 1. Upload your security artifacts
curl -H "X-API-Key: demo-token-12345" -F "file=@sbom.json" http://localhost:8000/inputs/sbom
curl -H "X-API-Key: demo-token-12345" -F "file=@scan.sarif" http://localhost:8000/inputs/sarif

# 2. Run pipeline to analyze and map to compliance
curl -H "X-API-Key: demo-token-12345" http://localhost:8000/pipeline/run

# 3. Now compliance reports will have data
docker exec fixops python -m core.cli compliance status --framework PCI-DSS
```

---

### 17. reports - Generate Reports

**Purpose:** Security reports in various formats (PDF, HTML, JSON).

**What it operates on:** All security data in FixOps database (findings, decisions, compliance, etc.).

**Prerequisites:** Data must exist from pipeline runs for meaningful reports.

**Data flow:** Query database → Aggregate data → Generate report in requested format.

```bash
# List generated reports
docker exec fixops python -m core.cli reports list

# Generate new report (executive summary of all findings)
docker exec fixops python -m core.cli reports generate --type executive --format pdf

# Export report data
docker exec fixops python -m core.cli reports export --id report-123 --format json

# List report schedules
docker exec fixops python -m core.cli reports schedules
```

---

### 18. inventory - Manage App Inventory

**Purpose:** Track applications and services in your organization.

**What it operates on:** Application inventory in FixOps database. Used to associate findings with specific apps.

**Prerequisites:** None for list; apps must be added to query them.

**Data flow:** CRUD operations on applications/services tables.

```bash
# List all applications in inventory
docker exec fixops python -m core.cli inventory apps

# Add an application to inventory
docker exec fixops python -m core.cli inventory add \
  --name "MyApp" \
  --type web \
  --criticality high

# Get application details
docker exec fixops python -m core.cli inventory get --id app-123

# List all services
docker exec fixops python -m core.cli inventory services

# Search applications by name
docker exec fixops python -m core.cli inventory search --query "payment"
```

---

### 19. policies - Manage Security Policies

**Purpose:** CRUD for decision policies that control accept/reject behavior.

**What it operates on:** Policies table in FixOps database. Policies define rules for automated decisions.

**Prerequisites:** None for list; policy must exist for get/validate/test.

**Data flow:** CRUD operations; test applies policy to sample findings.

```bash
# List all policies
docker exec fixops python -m core.cli policies list

# Get policy details
docker exec fixops python -m core.cli policies get --id policy-123

# Create a policy (rules define when to block/allow)
docker exec fixops python -m core.cli policies create \
  --name "Critical Only" \
  --rules '{"severity": "critical", "action": "block"}'

# Validate a policy (check syntax)
docker exec fixops python -m core.cli policies validate --id policy-123

# Test a policy against sample findings
docker exec fixops python -m core.cli policies test --id policy-123 --input /app/data/test-findings.json
```

---

### 20. integrations - Manage Connectors

**Purpose:** Configure external integrations (Jira, Slack, GitHub, etc.).

**What it operates on:** Integrations table in FixOps database. Stores connection configs for external systems.

**Prerequisites:** 
- For configure: External system credentials (tokens, URLs)
- For test/sync: Integration must be configured first

**Data flow:** Configure → Test connectivity → Sync data bidirectionally.

```bash
# List all configured integrations
docker exec fixops python -m core.cli integrations list

# Configure a Jira integration
docker exec fixops python -m core.cli integrations configure \
  --type jira \
  --url https://company.atlassian.net \
  --token $JIRA_TOKEN

# Test an integration connection
docker exec fixops python -m core.cli integrations test --id integration-123

# Sync data with integration (push findings to Jira, etc.)
docker exec fixops python -m core.cli integrations sync --id integration-123
```

---

### 21. analytics - View Security Metrics

**Purpose:** Dashboard and MTTR (Mean Time To Remediate) statistics.

**What it operates on:** Aggregated data from all findings, remediations, and decisions in FixOps database.

**Prerequisites:** Data must exist from pipeline runs for meaningful metrics.

**Data flow:** Query database → Aggregate metrics → Display/export.

```bash
# Get dashboard metrics (summary of security posture)
docker exec fixops python -m core.cli analytics dashboard

# Get MTTR metrics (how fast are vulns being fixed)
docker exec fixops python -m core.cli analytics mttr --days 90

# Get security scan coverage
docker exec fixops python -m core.cli analytics coverage

# Get ROI analysis (cost savings from automation)
docker exec fixops python -m core.cli analytics roi

# Export analytics data
docker exec fixops python -m core.cli analytics export --format csv --output /app/data/analytics.csv
```

---

### 22. audit - View Audit Logs

**Purpose:** Compliance audit trail of all actions in FixOps.

**What it operates on:** Audit logs table in FixOps database. Records all user actions, decisions, changes.

**Prerequisites:** Actions must have occurred to have audit logs.

**Data flow:** Query audit_logs table → Filter by date/type → Display/export.

```bash
# View audit logs (last 30 days)
docker exec fixops python -m core.cli audit logs --days 30

# View decision audit trail (who approved/rejected what)
docker exec fixops python -m core.cli audit decisions --days 7

# Export audit logs for compliance
docker exec fixops python -m core.cli audit export --format json --output /app/data/audit.json
```

---

### 23. workflows - Manage Automation

**Purpose:** Workflow definitions and execution for automated responses.

**What it operates on:** Workflows table in FixOps database. Defines triggers and actions.

**Prerequisites:** None for list; workflow must exist for get/execute.

**Data flow:** Define workflow → Trigger fires → Actions execute.

```bash
# List all workflows
docker exec fixops python -m core.cli workflows list

# Get workflow details
docker exec fixops python -m core.cli workflows get --id workflow-123

# Create a workflow (auto-assign critical findings)
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

**Purpose:** Track fix progress and SLA compliance.

**What it operates on:** Remediation tasks in FixOps database. Tasks are created from findings.

**Prerequisites:** Findings must exist (from pipeline runs) to have remediation tasks.

**Data flow:** Finding → Remediation task created → Assigned → Tracked → Verified.

```bash
# List remediation tasks (filter by status)
docker exec fixops python -m core.cli remediation list --status open

# Get specific task details
docker exec fixops python -m core.cli remediation get --id task-123

# Assign a task to a user
docker exec fixops python -m core.cli remediation assign --id task-123 --user user-456

# Transition task status
docker exec fixops python -m core.cli remediation transition --id task-123 --status in_progress

# Verify a remediation (mark as fixed)
docker exec fixops python -m core.cli remediation verify --id task-123

# Get remediation metrics (MTTR, etc.)
docker exec fixops python -m core.cli remediation metrics

# Get SLA compliance report
docker exec fixops python -m core.cli remediation sla
```

---

### 25. reachability - Analyze Vulnerability Reach

**Purpose:** Check if a CVE is actually reachable in your code (not just present in dependencies).

**What it operates on:** CVE IDs and your codebase. Analyzes call graphs to determine if vulnerable code is reachable.

**Prerequisites:** 
- CVE ID(s) to analyze
- Code/SBOM data must be ingested for accurate analysis

**Data flow:** CVE → Code analysis → Call graph → Reachability determination.

```bash
# Analyze reachability for a single CVE
docker exec fixops python -m core.cli reachability analyze --cve CVE-2024-1234

# Bulk reachability analysis (file with CVE IDs, one per line)
docker exec fixops python -m core.cli reachability bulk --file /app/data/cves.txt

# Check job status (for async analysis)
docker exec fixops python -m core.cli reachability status --job-id job-123
```

---

### 26. correlation - Manage Deduplication

**Purpose:** Find and manage duplicate/related findings across scans.

**What it operates on:** Findings in FixOps database. Identifies duplicates across different scanners/runs.

**Prerequisites:** Multiple findings must exist (from multiple scans) to find correlations.

**Data flow:** Findings → Similarity analysis → Correlation groups → Feedback loop.

```bash
# Analyze correlations (find duplicates)
docker exec fixops python -m core.cli correlation analyze

# Get correlation statistics
docker exec fixops python -m core.cli correlation stats

# View correlation graph (relationships between findings)
docker exec fixops python -m core.cli correlation graph

# Provide feedback on correlations (improve accuracy)
docker exec fixops python -m core.cli correlation feedback --id corr-123 --correct true
```

---

### 27. notifications - Notification Queue

**Purpose:** Manage alert delivery to users via configured channels.

**What it operates on:** Notification queue in FixOps database. Notifications are queued by workflows/events.

**Prerequisites:** Notifications must be queued (from workflows, events, etc.).

**Data flow:** Event → Notification queued → Worker processes → Delivered via channel.

```bash
# List pending notifications
docker exec fixops python -m core.cli notifications pending

# Run notification worker (processes and delivers pending notifications)
docker exec fixops python -m core.cli notifications worker
```

---

### 28. Probabilistic Models

**Purpose:** Train and use machine learning models for risk prediction.

**What it operates on:** Historical incident data for training; CVE data for prediction.

**Prerequisites:**
- Training: Historical incident CSV with labeled data
- Prediction: Trained model file + CVE data to score

**Data flow:** Training data → Model training → Model file → Prediction on new CVEs.

```bash
# Train forecast model (requires historical incident data)
docker exec fixops python -m core.cli train-forecast --data /app/data/incidents.csv

# Train Bayesian Network model
docker exec fixops python -m core.cli train-bn-lr --data /app/data/training.csv

# Predict exploitation risk for CVEs
docker exec fixops python -m core.cli predict-bn-lr --input /app/data/cves.json

# Backtest model accuracy
docker exec fixops python -m core.cli backtest-bn-lr --model /app/data/model.pkl --test /app/data/test.csv
```

---

### 29. playbook - Execute FixOps Playbooks (YAML DSL)

**Purpose:** Execute declarative YAML-based workflows for security automation, compliance validation, and remediation.

**What it operates on:** Playbook YAML files that define automated workflows with steps, conditions, and actions. Playbooks can:
- Evaluate OPA policies
- Create Jira tickets
- Send Slack notifications
- Generate compliance reports
- Collect and sign evidence bundles

**Prerequisites:**
- Playbook YAML file (see `config/playbooks/` for examples)
- Optional: Overlay configuration for connector credentials (Jira, Slack, etc.)
- Optional: SARIF/JSON findings file for input

**Data flow:** Playbook YAML → Parse & validate → Execute steps in order → Resolve templates → Call connectors → Return execution result.

```bash
# List available playbooks
docker exec fixops python -m core.cli playbook list

# List playbooks from custom directory
docker exec fixops python -m core.cli playbook list --dir /app/config/playbooks

# Validate a playbook (check syntax without executing)
docker exec fixops python -m core.cli playbook validate \
  --playbook /app/config/playbooks/soc2-access-control-validation.yaml

# Run a playbook (basic execution)
docker exec fixops python -m core.cli playbook run \
  --playbook /app/config/playbooks/soc2-access-control-validation.yaml

# Run with inputs
docker exec fixops python -m core.cli playbook run \
  --playbook /app/config/playbooks/soc2-access-control-validation.yaml \
  --input severity_threshold=critical \
  --input auto_create_tickets=true

# Run with findings file (SARIF format)
docker exec fixops python -m core.cli playbook run \
  --playbook /app/config/playbooks/soc2-access-control-validation.yaml \
  --findings /app/samples/scan.sarif

# Run with overlay (for connector credentials)
docker exec fixops python -m core.cli playbook run \
  --playbook /app/config/playbooks/soc2-access-control-validation.yaml \
  --overlay /app/config/fixops.overlay.yml

# Dry run (validate and show what would execute without running)
docker exec fixops python -m core.cli playbook run \
  --playbook /app/config/playbooks/soc2-access-control-validation.yaml \
  --dry-run \
  --pretty

# Save execution result to file
docker exec fixops python -m core.cli playbook run \
  --playbook /app/config/playbooks/soc2-access-control-validation.yaml \
  --output /app/data/playbook-result.json \
  --pretty
```

**Example Playbook (SOC2 Access Control Validation):**

The bundled playbook at `config/playbooks/soc2-access-control-validation.yaml` demonstrates:
- OPA policy evaluation
- Compliance control checks (CC6.1, CC6.2, CC6.3, CC6.7)
- Evidence collection and signing
- Conditional Jira ticket creation
- Slack notifications
- Compliance report generation

**Playbook Actions Available:**
| Action | Description |
|--------|-------------|
| `opa.evaluate` | Evaluate OPA policy |
| `opa.assert` | Assert OPA policy passes |
| `evidence.collect` | Collect compliance evidence |
| `evidence.sign` | Sign evidence bundle |
| `compliance.check_control` | Check compliance control |
| `compliance.generate_report` | Generate compliance report |
| `jira.create_issue` | Create Jira ticket |
| `jira.update_issue` | Update Jira ticket |
| `jira.add_comment` | Add comment to Jira |
| `confluence.create_page` | Create Confluence page |
| `notify.slack` | Send Slack notification |
| `notify.email` | Send email notification |
| `pentest.request` | Request penetration test |
| `workflow.approve` | Approve workflow item |
| `data.filter` | Filter data set |

**See also:** [Playbook Language Reference](PLAYBOOK_LANGUAGE_REFERENCE.md) for complete syntax documentation.

---

## API Endpoint Reference (All 303 Endpoints)

All API calls use: `curl -H "X-API-Key: demo-token-12345" http://localhost:8000/<endpoint>`

Start the container first:
```bash
docker run -d --name fixops -p 8000:8000 devopsaico/fixops:latest
```

---

### Health & Status Endpoints

**What it operates on:** FixOps API server health and readiness state.

**Prerequisites:** Container must be running. No authentication required for health/ready.

**Data flow:** Server state → Health response.

```bash
# Health check (no auth required)
curl http://localhost:8000/health

# Readiness check
curl http://localhost:8000/ready

# Version info
curl http://localhost:8000/version

# Metrics (Prometheus format)
curl http://localhost:8000/metrics

# API status (requires auth)
curl -H "X-API-Key: demo-token-12345" http://localhost:8000/api/v1/status
```

---

### Input Endpoints (Upload Security Artifacts)

**What it operates on:** Uploads YOUR security scan artifacts to FixOps for processing:
- **design.csv** - Architecture/design decisions from threat modeling
- **sbom.json** - Software Bill of Materials (CycloneDX/SPDX format from Syft, Trivy, etc.)
- **cve.json** - CVE vulnerability data
- **vex.json** - Vulnerability Exploitability eXchange data
- **cnapp.json** - Cloud-Native Application Protection Platform findings
- **sarif** - Static Analysis Results Interchange Format (from Semgrep, CodeQL, etc.)
- **context** - Business context (environment, criticality)

**Prerequisites:** Security artifact files from your scanners/tools.

**Data flow:** File upload → Format validation → Normalization → Stored in database → Ready for pipeline.

```bash
# Upload design CSV (threat model decisions)
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@design.csv;type=text/csv" \
  http://localhost:8000/inputs/design

# Upload SBOM (from Syft, Trivy, etc.)
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@sbom.json;type=application/json" \
  http://localhost:8000/inputs/sbom

# Upload CVE data
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@cve.json;type=application/json" \
  http://localhost:8000/inputs/cve

# Upload VEX (Vulnerability Exploitability eXchange)
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@vex.json;type=application/json" \
  http://localhost:8000/inputs/vex

# Upload CNAPP findings (cloud security)
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@cnapp.json;type=application/json" \
  http://localhost:8000/inputs/cnapp

# Upload SARIF scan results (from Semgrep, CodeQL, etc.)
curl -H "X-API-Key: demo-token-12345" \
  -F "file=@scan.sarif;type=application/json" \
  http://localhost:8000/inputs/sarif

# Upload business context (affects risk scoring)
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"environment": "production", "criticality": "high"}' \
  http://localhost:8000/inputs/context
```

---

### Pipeline Endpoints

**What it operates on:** Processes ALL uploaded artifacts through the FixOps pipeline:
- Normalizes inputs
- Enriches with threat intelligence (EPSS, KEV, exploits)
- Scores risk
- Makes decisions
- Generates evidence bundle

**Prerequisites:** Upload at least one artifact first (SBOM, SARIF, etc.) via `/inputs/*` endpoints.

**Data flow:** Uploaded artifacts → Normalization → Enrichment → Risk scoring → Decision → Evidence bundle → Results.

```bash
# Run pipeline (processes all uploaded artifacts)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/pipeline/run | jq

# Get pipeline status (check if running)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/pipeline/status

# Get pipeline results (after run completes)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/pipeline/results | jq
```

---

### Validation Endpoints

**What it operates on:** Validates input format before upload. Checks if your files are valid SBOM, SARIF, etc.

**Prerequisites:** None - validation is stateless.

**Data flow:** Input content → Format detection → Schema validation → Validation result.

```bash
# Validate input format
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"format": "sbom", "content": {...}}' \
  http://localhost:8000/api/v1/validate/input

# Batch validation (multiple items)
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

**What it operates on:** Security findings you provide. Uses multiple LLMs (GPT, Claude, Gemini) to analyze and recommend remediation actions.

**Prerequisites:** 
- For full functionality: LLM API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
- Without keys: Returns mock/demo responses

**Data flow:** Findings + Context → Multiple LLMs → Consensus → Recommendation.

```bash
# Get LLM capabilities (shows which LLMs are configured)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/enhanced/capabilities | jq

# Compare LLM recommendations (each LLM gives its opinion)
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

# Get consensus decision (LLMs vote on best action)
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"findings": [...], "context": {...}}' \
  http://localhost:8000/api/v1/enhanced/consensus | jq
```

---

### Threat Intelligence Feeds Endpoints

**What it operates on:** External threat intelligence data:
- **EPSS** - Exploit Prediction Scoring System (probability of exploitation)
- **KEV** - CISA Known Exploited Vulnerabilities catalog
- **Exploits** - Known exploit code/PoCs
- **Threat Actors** - APT groups associated with CVEs
- **Supply Chain** - Package/dependency risk data

**Prerequisites:** None for queries. Internet access required for feed refresh.

**Data flow:** Query → Local cache → (Optional: Refresh from external sources) → Results.

```bash
# Get EPSS data (exploitation probability scores)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/epss | jq

# Refresh EPSS feed (fetches latest from FIRST.org)
curl -H "X-API-Key: demo-token-12345" \
  -X POST http://localhost:8000/api/v1/feeds/epss/refresh

# Get KEV data (CISA Known Exploited Vulnerabilities)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/kev | jq

# Refresh KEV feed (fetches latest from CISA)
curl -H "X-API-Key: demo-token-12345" \
  -X POST http://localhost:8000/api/v1/feeds/kev/refresh

# Get exploits for specific CVE
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/exploits/CVE-2024-1234 | jq

# Search exploits for multiple CVEs
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cve_ids": ["CVE-2024-1234", "CVE-2024-5678"]}' \
  http://localhost:8000/api/v1/feeds/exploits

# Get threat actors associated with CVE
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/threat-actors/CVE-2024-1234 | jq

# Get threat actor details by name
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/threat-actors/by-actor/APT29 | jq

# Get supply chain risk for package
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/supply-chain/lodash | jq

# Get exploit confidence score for CVE
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/exploit-confidence/CVE-2024-1234 | jq

# Get geo risk (geographic targeting) for CVE
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/geo-risk/CVE-2024-1234 | jq

# Enrich CVE with all available intelligence
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cve_id": "CVE-2024-1234"}' \
  http://localhost:8000/api/v1/feeds/enrich | jq

# Get feed statistics
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/stats | jq

# Get feed categories
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/categories | jq

# Get feed sources
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/sources | jq

# Get feed health status
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/health | jq

# Get scheduler status (feed refresh schedule)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/feeds/scheduler/status | jq

# Refresh all feeds at once
curl -H "X-API-Key: demo-token-12345" \
  -X POST http://localhost:8000/api/v1/feeds/refresh/all
```

---

### Teams Endpoints

**What it operates on:** Teams table in FixOps database. Teams organize users for finding assignment and notifications.

**Prerequisites:** None for list/create. Team must exist for get/update/delete.

**Data flow:** CRUD operations on teams table.

```bash
# List all teams
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/teams | jq

# Create team
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "Security Team", "description": "Main security team"}' \
  http://localhost:8000/api/v1/teams

# Get team by ID
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

**What it operates on:** Users table in FixOps database. Manages user accounts, authentication, and roles.

**Prerequisites:** None for list/create. User must exist for get/update/delete.

**Data flow:** CRUD operations on users table.

```bash
# Login (returns auth token)
curl -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "password"}' \
  http://localhost:8000/api/v1/users/login | jq

# List all users
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/users | jq

# Create user
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "name": "John Doe", "role": "analyst"}' \
  http://localhost:8000/api/v1/users

# Get user by ID
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

**What it operates on:** Policies table in FixOps database. Policies define rules for automated security decisions (block, allow, defer, escalate).

**Prerequisites:** None for list/create. Policy must exist for get/update/delete/validate/test.

**Data flow:** CRUD operations; validate checks syntax; test applies policy to sample findings.

```bash
# List all policies
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/policies | jq

# Create policy (defines when to block/allow)
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Critical Blocker",
    "description": "Block critical vulnerabilities",
    "rules": [{"severity": "critical", "action": "block"}]
  }' \
  http://localhost:8000/api/v1/policies

# Get policy by ID
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

# Validate policy (check syntax/rules)
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/policies/policy-123/validate | jq

# Test policy against sample findings
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"findings": [...]}' \
  http://localhost:8000/api/v1/policies/policy-123/test | jq

# Get policy violations (findings that violated this policy)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/policies/policy-123/violations | jq
```

---

### Inventory Endpoints

**What it operates on:** Application inventory in FixOps database. Tracks your organization's applications, services, APIs, and their dependencies.

**Prerequisites:** None for list/create. Entity must exist for get/update/delete.

**Data flow:** CRUD operations on applications/services/APIs tables. Dependencies are linked from SBOM data.

```bash
# List all applications in inventory
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/applications | jq

# Create application (register an app in inventory)
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "MyApp", "type": "web", "criticality": "high"}' \
  http://localhost:8000/api/v1/inventory/applications

# Get application by ID
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

# Get application components (from SBOM)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/applications/app-123/components | jq

# Get application APIs
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/applications/app-123/apis | jq

# Get application dependencies (from SBOM)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/applications/app-123/dependencies | jq

# List all services
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/services | jq

# Create service
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "Payment Service", "type": "microservice"}' \
  http://localhost:8000/api/v1/inventory/services

# Get service by ID
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/services/svc-123 | jq

# List all APIs
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/apis | jq

# Create API
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "User API", "version": "v1"}' \
  http://localhost:8000/api/v1/inventory/apis

# Get API security posture
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/inventory/apis/api-123/security | jq

# Search inventory by name
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/inventory/search?q=payment" | jq
```

---

### Integrations Endpoints

**What it operates on:** Integrations table in FixOps database. Configures connections to external systems (Jira, Slack, GitHub, etc.).

**Prerequisites:** 
- For create: External system credentials (URL, API token)
- For test/sync: Integration must be configured first

**Data flow:** Configure → Test connectivity → Sync data bidirectionally.

```bash
# List all configured integrations
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/integrations | jq

# Create integration (e.g., Jira)
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "jira",
    "name": "Jira Cloud",
    "config": {"url": "https://company.atlassian.net", "project": "SEC"}
  }' \
  http://localhost:8000/api/v1/integrations

# Get integration by ID
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/integrations/int-123 | jq

# Update integration config
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"config": {"project": "VULN"}}' \
  http://localhost:8000/api/v1/integrations/int-123

# Delete integration
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  http://localhost:8000/api/v1/integrations/int-123

# Test integration connectivity
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/integrations/int-123/test | jq

# Get sync status
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/integrations/int-123/sync-status | jq

# Trigger sync (push findings to Jira, etc.)
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/integrations/int-123/sync
```

---

### Enterprise Connectors & Outbox Endpoints

**What it operates on:** Outbox queue for sending data to external systems (Jira, ServiceNow, GitLab, Azure DevOps, GitHub). Full CRUD operations on external tickets/issues.

**Prerequisites:** 
- Integration must be configured first
- Connector credentials (API tokens) in environment or config
- For execute: Outbox item must exist

**Data flow:** Finding → Outbox item created → Execute via connector → External system updated → Status tracked.

**Supported Connectors:**
| Connector | Operations | Status |
|-----------|------------|--------|
| **Jira** | `create_issue`, `update_issue`, `transition_issue`, `add_comment` | Full CRUD |
| **ServiceNow** | `create_incident`, `update_incident`, `add_work_note` | Full CRUD |
| **GitLab** | `create_issue`, `update_issue`, `add_comment` | Full CRUD |
| **Azure DevOps** | `create_work_item`, `update_work_item`, `add_comment` | Full CRUD |
| **GitHub** | `create_issue`, `update_issue`, `add_comment` | Full CRUD |
| **Confluence** | `create_page`, `update_page` | Bidirectional |
| **Slack** | `post_message` | Outbound only |

```bash
# List outbox items (pending external actions)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/webhooks/outbox | jq

# Get outbox item details
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/webhooks/outbox/outbox-123 | jq

# Execute single outbox item (sends to Jira/ServiceNow/etc)
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/webhooks/outbox/outbox-123/execute | jq

# Process all pending outbox items (batch execution)
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/webhooks/outbox/process-pending | jq
```

**Webhook Receivers (inbound from external systems):**
```bash
# Jira webhook (receives issue updates)
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"webhookEvent": "jira:issue_updated", "issue": {...}}' \
  http://localhost:8000/api/v1/webhooks/jira

# ServiceNow webhook
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"sys_id": "...", "state": "resolved"}' \
  http://localhost:8000/api/v1/webhooks/servicenow

# GitLab webhook
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"object_kind": "issue", "object_attributes": {...}}' \
  http://localhost:8000/api/v1/webhooks/gitlab

# Azure DevOps webhook
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"eventType": "workitem.updated", "resource": {...}}' \
  http://localhost:8000/api/v1/webhooks/azure-devops
```

---

### Multi-Tenancy (org_id) Support

**What it operates on:** Many API endpoints accept an `org_id` parameter for multi-tenancy. Note: Not all endpoints currently filter data by org_id - some accept the parameter for future use or logging purposes only.

**Prerequisites:** None - defaults to "default" org if not specified.

**Data flow:** Request with org_id → Endpoints that support filtering will scope data to org.

**Current limitations:** Some endpoints (e.g., `/api/v1/users/*`, `/api/v1/webhooks/mappings`) accept org_id but do not yet filter data by organization. Full multi-tenancy data isolation is a work in progress.

**How to use org_id:**
```bash
# Via query parameter
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/analytics/dashboard/overview?org_id=acme-corp" | jq

# Via X-Org-ID header
curl -H "X-API-Key: demo-token-12345" \
  -H "X-Org-ID: acme-corp" \
  http://localhost:8000/api/v1/analytics/dashboard/overview | jq

# Without org_id (uses "default")
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/dashboard/overview | jq
```

**Routers with org_id support:**
- `/api/v1/analytics/*` - Analytics and dashboard
- `/api/v1/audit/*` - Audit logs
- `/api/v1/feeds/*` - Threat intelligence feeds
- `/api/v1/integrations/*` - Integration configs
- `/api/v1/inventory/*` - Asset inventory
- `/api/v1/marketplace/*` - Marketplace items
- `/api/v1/pentagi/*` - Pen testing
- `/api/v1/policies/*` - Security policies
- `/api/v1/reports/*` - Reports
- `/api/v1/teams/*` - Team management
- `/api/v1/users/*` - User management
- `/api/v1/webhooks/*` - Webhooks and outbox
- `/api/v1/workflows/*` - Workflow automation

---

### Analytics Endpoints

**What it operates on:** Aggregated data from all findings, decisions, and compliance data in FixOps database.

**Prerequisites:** Data must exist from pipeline runs for meaningful metrics.

**Data flow:** Query database → Aggregate metrics → Return dashboard/trends/findings.

```bash
# Get dashboard overview (summary of security posture)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/dashboard/overview | jq

# Get trends (how metrics change over time)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/dashboard/trends | jq

# Get top risks (highest priority vulnerabilities)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/dashboard/top-risks | jq

# Get compliance status (framework coverage)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/dashboard/compliance-status | jq

# List all findings
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/analytics/findings | jq

# Create finding manually
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"title": "SQL Injection", "severity": "critical", "cve_id": "CVE-2024-1234"}' \
  http://localhost:8000/api/v1/analytics/findings

# Legacy dashboard endpoint
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/analytics/dashboard | jq

# Get pipeline run details
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/analytics/runs/run-123 | jq
```

---

### Micro Pentest Endpoints

**What it operates on:** Runs targeted penetration tests for specific CVEs against target URLs to verify exploitability.

**Prerequisites:**
- PentAGI service must be running (use `docker-compose.pentagi.yml`)
- Target URLs must be accessible from the container
- Valid CVE IDs

**Data flow:** CVE + Target → PentAGI micro-test → Exploitability result.

```bash
# Run micro pentest for specific CVE against target
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_ids": ["CVE-2024-1234"],
    "target_urls": ["https://example.com"],
    "context": "Production web application"
  }' \
  http://localhost:8000/api/v1/micro-pentest/run | jq

# Get pentest status (check if complete)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/micro-pentest/status/12345 | jq

# Run batch pentests (multiple CVEs/targets)
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

**What it operates on:** PentAGI pentest requests and results. Full penetration testing via PentAGI service.

**Prerequisites:**
- PentAGI service must be running (use `docker-compose.pentagi.yml`)
- Target must be accessible from PentAGI container

**Data flow:** Create request → Approve → Start → PentAGI executes → Results stored.

```bash
# List all pentest requests
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/pentagi/requests | jq

# Create pentest request
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scope": "web application"}' \
  http://localhost:8000/api/v1/pentagi/requests

# Get request by ID
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/pentagi/requests/req-123 | jq

# Update request (e.g., approve)
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"status": "approved"}' \
  http://localhost:8000/api/v1/pentagi/requests/req-123

# Start pentest execution
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/pentagi/requests/req-123/start

# Cancel pentest
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/pentagi/requests/req-123/cancel

# List all pentest results
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

**What it operates on:** Multiple findings, clusters, or policies at once. Useful for batch processing large numbers of items.

**Prerequisites:** 
- Findings/clusters must exist (from pipeline runs)
- For create-tickets: Integration must be configured

**Data flow:** Batch request → Async job created → Job processes items → Results available.

```bash
# Bulk update cluster status (resolve multiple at once)
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cluster_ids": ["c1", "c2"], "status": "resolved"}' \
  http://localhost:8000/api/v1/bulk/clusters/status | jq

# Bulk assign clusters to user
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cluster_ids": ["c1", "c2"], "assignee": "user-123"}' \
  http://localhost:8000/api/v1/bulk/clusters/assign | jq

# Bulk accept risk (mark as accepted)
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cluster_ids": ["c1", "c2"], "reason": "False positive"}' \
  http://localhost:8000/api/v1/bulk/clusters/accept-risk | jq

# Bulk create tickets in Jira/etc
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"cluster_ids": ["c1", "c2"], "integration_id": "jira-123"}' \
  http://localhost:8000/api/v1/bulk/clusters/create-tickets | jq

# Bulk export findings to CSV/JSON
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"format": "csv", "filters": {"severity": "critical"}}' \
  http://localhost:8000/api/v1/bulk/export | jq

# Get bulk job status (check if complete)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/bulk/jobs/job-123 | jq

# List all bulk jobs
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/bulk/jobs | jq

# Delete bulk job
curl -H "X-API-Key: demo-token-12345" \
  -X DELETE \
  http://localhost:8000/api/v1/bulk/jobs/job-123

# Bulk update findings status
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"finding_ids": ["f1", "f2"], "status": "resolved"}' \
  http://localhost:8000/api/v1/bulk/findings/update | jq

# Bulk delete findings
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"finding_ids": ["f1", "f2"]}' \
  http://localhost:8000/api/v1/bulk/findings/delete | jq

# Bulk assign findings to user
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"finding_ids": ["f1", "f2"], "assignee": "user-123"}' \
  http://localhost:8000/api/v1/bulk/findings/assign | jq

# Bulk apply policy to all findings
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"policy_id": "policy-123", "scope": "all"}' \
  http://localhost:8000/api/v1/bulk/policies/apply | jq
```

---

### Collaboration Endpoints

**What it operates on:** Comments, watchers, activities, and notifications on findings and other entities. Enables team collaboration on security issues.

**Prerequisites:** 
- Entity (finding, cluster, etc.) must exist to comment/watch
- Users must exist to assign watchers

**Data flow:** User action → Activity recorded → Watchers notified → Notifications delivered.

```bash
# Create comment on a finding
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"entity_type": "finding", "entity_id": "f-123", "content": "This needs review"}' \
  http://localhost:8000/api/v1/collaboration/comments

# List comments on entity
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/collaboration/comments?entity_type=finding&entity_id=f-123" | jq

# Promote comment (highlight as important)
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  http://localhost:8000/api/v1/collaboration/comments/comment-123/promote

# Add watcher to entity (get notified of changes)
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

# List watchers on entity
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/collaboration/watchers?entity_type=finding&entity_id=f-123" | jq

# Get user's watched entities
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/watchers/user/user-123 | jq

# Create activity (log an action)
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"entity_type": "finding", "entity_id": "f-123", "action": "status_change", "details": {...}}' \
  http://localhost:8000/api/v1/collaboration/activities

# List activities on entity (audit trail)
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/collaboration/activities?entity_type=finding&entity_id=f-123" | jq

# Get mentions for user (@mentions)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/mentions/user-123 | jq

# Acknowledge mention
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  http://localhost:8000/api/v1/collaboration/mentions/mention-123/acknowledge

# Get supported entity types
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/entity-types | jq

# Get supported activity types
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/activity-types | jq

# Queue notification for user
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user-123", "type": "mention", "content": "You were mentioned"}' \
  http://localhost:8000/api/v1/collaboration/notifications/queue

# Notify all watchers of event
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"entity_type": "finding", "entity_id": "f-123", "event": "status_change"}' \
  http://localhost:8000/api/v1/collaboration/notifications/notify-watchers

# Get pending notifications
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/notifications/pending | jq

# Mark notification as sent
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  http://localhost:8000/api/v1/collaboration/notifications/notif-123/sent

# Get user's notification preferences
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/collaboration/notifications/preferences/user-123 | jq

# Update notification preferences
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"email": true, "slack": false}' \
  http://localhost:8000/api/v1/collaboration/notifications/preferences/user-123

# Deliver notification immediately
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/collaboration/notifications/notif-123/deliver

# Process all pending notifications
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/collaboration/notifications/process
```

---

### Marketplace Endpoints

**What it operates on:** FixOps marketplace for sharing/downloading policy packs, compliance templates, and integrations.

**Prerequisites:** None for browse/download. Must be authenticated for contribute/purchase.

**Data flow:** Browse → Select item → Purchase/Download → Apply to your instance.

```bash
# Get compliance pack for specific control
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/packs/PCI-DSS/control-1 | jq

# Browse marketplace items
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/browse | jq

# Get personalized recommendations
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/recommendations | jq

# Get item details
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/marketplace/items/item-123 | jq

# Contribute item to marketplace
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Policy Pack", "type": "policy", "content": {...}}' \
  http://localhost:8000/api/v1/marketplace/contribute

# Update contributed item
curl -H "X-API-Key: demo-token-12345" \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"description": "Updated description"}' \
  http://localhost:8000/api/v1/marketplace/items/item-123

# Rate and review item
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"rating": 5, "review": "Great policy pack!"}' \
  http://localhost:8000/api/v1/marketplace/items/item-123/rate

# Purchase item (get download token)
curl -H "X-API-Key: demo-token-12345" \
  -X POST \
  http://localhost:8000/api/v1/marketplace/purchase/item-123 | jq

# Download purchased item
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

**What it operates on:** Triage queue of findings awaiting review. Provides prioritized list for security analysts.

**Prerequisites:** Findings must exist from pipeline runs.

**Data flow:** Findings → Prioritization → Triage queue → Export.

```bash
# Get triage data (prioritized findings queue)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/triage | jq

# Export triage data for external processing
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/triage/export | jq
```

---

### Graph Endpoints

**What it operates on:** Risk relationship graph showing connections between findings, assets, and vulnerabilities.

**Prerequisites:** Findings and inventory data must exist.

**Data flow:** Query relationships → Build graph → Return visualization data.

```bash
# Get risk graph (relationships between findings/assets)
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/graph | jq
```

---

### Feedback Endpoints

**What it operates on:** User feedback on decisions, findings, and recommendations. Used to improve ML models.

**Prerequisites:** Entity (decision, finding) must exist.

**Data flow:** User feedback → Stored → Used for model training.

```bash
# Submit feedback on a decision
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"type": "decision", "entity_id": "dec-123", "rating": 5, "comment": "Good decision"}' \
  http://localhost:8000/feedback
```

---

### IDE Integration Endpoints

**What it operates on:** Code snippets from IDE plugins. Provides real-time security analysis in developer IDEs.

**Prerequisites:** None - stateless analysis.

**Data flow:** Code snippet → Security analysis → Suggestions returned to IDE.

```bash
# Get IDE plugin configuration
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/ide/config | jq

# Analyze code snippet for security issues
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"code": "SELECT * FROM users WHERE id = $1", "language": "sql"}' \
  http://localhost:8000/api/v1/ide/analyze | jq

# Get suggestions for specific file/line
curl -H "X-API-Key: demo-token-12345" \
  "http://localhost:8000/api/v1/ide/suggestions?file=app.py&line=42" | jq
```

---

### SSO/Auth Endpoints

**What it operates on:** SSO (Single Sign-On) configurations for enterprise authentication (Okta, Azure AD, etc.).

**Prerequisites:** 
- For create: SSO provider credentials (client_id, client_secret)
- Admin privileges required

**Data flow:** Configure SSO → Users authenticate via provider → Token issued.

```bash
# List all SSO configurations
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/auth/sso | jq

# Create SSO configuration (e.g., Okta)
curl -H "X-API-Key: demo-token-12345" \
  -H "Content-Type: application/json" \
  -d '{"provider": "okta", "client_id": "xxx", "client_secret": "yyy"}' \
  http://localhost:8000/api/v1/auth/sso

# Get SSO config by ID
curl -H "X-API-Key: demo-token-12345" \
  http://localhost:8000/api/v1/auth/sso/sso-123 | jq

# Update SSO config (enable/disable)
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
