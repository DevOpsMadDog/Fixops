# FixOps Playbook Language Reference

FixOps Playbooks are a declarative YAML-based Domain-Specific Language (DSL) for automating vulnerability management, compliance validation, and security remediation workflows. This document provides a complete reference for the playbook syntax, actions, expressions, and execution model.

## Overview

FixOps Playbooks enable security teams to define automated workflows without writing code. Playbooks are sandboxed and can only execute pre-approved actions through validated connectors, ensuring security and auditability.

**Key Features:**
- Declarative YAML syntax for workflow definition
- 25+ pre-approved action types (Jira, Confluence, Slack, OPA, compliance, etc.)
- Template variable resolution with `{{ }}` syntax
- Conditional execution with `when`, `unless`, and `depends_on`
- Error handling with retry and continue-on-failure
- Execution trace for debugging and audit
- Integration with enterprise connectors (Jira, Confluence, Slack, ServiceNow, etc.)

## Quick Start

```yaml
apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: my-first-playbook
  version: "1.0.0"
  description: "A simple playbook example"

spec:
  inputs:
    severity_threshold:
      type: string
      default: "high"

  steps:
    - name: check-policy
      action: opa.evaluate
      params:
        policy: "security/baseline.rego"
        input: "{{ inputs.findings }}"

    - name: create-ticket
      action: jira.create_issue
      condition:
        when: "steps.check-policy.status == 'failed'"
      params:
        project: "SEC"
        summary: "Security policy violation detected"
        priority: "High"
```

## CLI Commands

### Run a Playbook

```bash
# Basic execution
python -m core.cli playbook run --playbook config/playbooks/my-playbook.yaml

# With inputs
python -m core.cli playbook run \
  --playbook config/playbooks/compliance-check.yaml \
  --input severity_threshold=critical \
  --input auto_create_tickets=true

# With findings file
python -m core.cli playbook run \
  --playbook config/playbooks/soc2-validation.yaml \
  --findings data/scan-results.sarif

# Dry run (validate without executing)
python -m core.cli playbook run \
  --playbook config/playbooks/my-playbook.yaml \
  --dry-run

# With overlay configuration for connectors
python -m core.cli playbook run \
  --playbook config/playbooks/my-playbook.yaml \
  --overlay config/fixops.overlay.yml

# Output to file
python -m core.cli playbook run \
  --playbook config/playbooks/my-playbook.yaml \
  --output results/execution.json \
  --pretty
```

### Validate a Playbook

```bash
python -m core.cli playbook validate --playbook config/playbooks/my-playbook.yaml
```

### List Available Playbooks

```bash
# Default directory
python -m core.cli playbook list

# Custom directory
python -m core.cli playbook list --dir /path/to/playbooks
```

## Document Structure

Every playbook has four top-level sections:

```yaml
apiVersion: fixops.io/v1    # Required: API version
kind: Playbook              # Required: Document type
metadata:                   # Required: Playbook metadata
  name: ...
  version: ...
spec:                       # Required: Playbook specification
  inputs: ...
  steps: ...
  outputs: ...
  triggers: ...
```

### apiVersion

The API version for the playbook schema. Currently supported: `fixops.io/v1`

### kind

The type of document. Supported values:
- `Playbook` - General automation workflow
- `CompliancePack` - Compliance validation workflow
- `TestPack` - Security testing workflow
- `MitigationPack` - Remediation workflow

### metadata

Playbook metadata for identification and organization:

```yaml
metadata:
  name: soc2-access-control-validation    # Required: Unique identifier
  version: "1.0.0"                        # Required: Semantic version
  description: "Validates SOC2 access controls"
  author: "Security Team"
  license: MIT
  tags:
    - soc2
    - compliance
    - access-control
  compliance_frameworks:
    - SOC2
    - ISO27001
  ssdlc_stages:
    - test
    - deploy
    - operate
```

### spec

The playbook specification containing inputs, steps, outputs, and triggers.

## Inputs

Inputs define the parameters that can be passed to a playbook at execution time:

```yaml
spec:
  inputs:
    findings:
      type: sarif              # Input type
      required: true           # Whether input is required
      description: "SARIF findings from security scanners"
    
    severity_threshold:
      type: string
      default: "high"          # Default value if not provided
      description: "Minimum severity to flag"
    
    auto_create_tickets:
      type: boolean
      default: true
```

**Supported Input Types:**
- `string` - Text value
- `boolean` - true/false
- `number` - Numeric value
- `sarif` - SARIF findings document
- `sbom` - Software Bill of Materials
- `object` - JSON object
- `array` - JSON array

## Steps

Steps define the sequence of actions to execute:

```yaml
spec:
  steps:
    - name: step-name           # Required: Unique step identifier
      action: action.type       # Required: Action to execute
      params:                   # Action parameters
        key: value
      condition:                # Optional: Execution conditions
        when: "expression"
        unless: "expression"
        depends_on:
          - previous-step
      timeout: "60s"            # Optional: Step timeout
      on_success:               # Optional: Success handler
        set:
          variable: value
      on_failure:               # Optional: Failure handler
        retry: 2
        continue: false
```

### Step Conditions

Control when a step executes:

```yaml
condition:
  # Execute only if expression is true
  when: "steps.check-policy.status == 'failed'"
  
  # Skip if expression is true
  unless: "inputs.skip_notifications == true"
  
  # Wait for dependencies to complete
  depends_on:
    - step-one
    - step-two
```

### Timeout

Specify maximum execution time for a step:

```yaml
timeout: "30s"    # 30 seconds
timeout: "5m"     # 5 minutes
timeout: "1h"     # 1 hour
```

### Error Handling

Configure behavior on step failure:

```yaml
on_failure:
  retry: 3        # Retry up to 3 times
  continue: true  # Continue to next step even if this fails
```

## Actions Reference

FixOps provides 25+ pre-approved action types organized by category.

### Policy Evaluation

#### opa.evaluate

Evaluate an OPA (Open Policy Agent) policy:

```yaml
- name: evaluate-policy
  action: opa.evaluate
  params:
    policy: "security/baseline.rego"
    input: "{{ inputs.findings }}"
    data:
      severity_threshold: "{{ inputs.severity_threshold }}"
```

**Parameters:**
- `policy` (string, required): Path to the Rego policy file
- `input` (object, required): Input data for policy evaluation
- `data` (object, optional): Additional data for policy

**Output:**
```json
{
  "result": "pass|fail",
  "details": { ... }
}
```

#### opa.assert

Assert that a policy passes (fails step if policy fails):

```yaml
- name: assert-policy
  action: opa.assert
  params:
    policy: "security/required.rego"
    input: "{{ inputs.findings }}"
```

### Evidence Management

#### evidence.collect

Collect evidence for compliance audits:

```yaml
- name: collect-evidence
  action: evidence.collect
  params:
    evidence_types:
      - mfa_configuration
      - rbac_configuration
      - access_review_logs
    retention_days: 365
```

**Parameters:**
- `evidence_types` (array, required): Types of evidence to collect
- `retention_days` (number, optional): How long to retain evidence

**Output:**
```json
{
  "collected": true,
  "evidence_id": "ev-20240115120000",
  "evidence_types": ["mfa_configuration", "rbac_configuration"]
}
```

#### evidence.sign

Cryptographically sign an evidence bundle:

```yaml
- name: sign-evidence
  action: evidence.sign
  params:
    evidence_id: "{{ steps.collect-evidence.output.evidence_id }}"
    algorithm: "RSA-SHA256"
```

**Parameters:**
- `evidence_id` (string, required): ID of evidence to sign
- `algorithm` (string, optional): Signing algorithm (default: RSA-SHA256)

#### evidence.assert

Assert evidence meets requirements:

```yaml
- name: assert-evidence
  action: evidence.assert
  params:
    evidence_type: "mfa_configuration"
    requirements:
      - "mfa_enabled == true"
```

### Compliance Checks

#### compliance.check_control

Check a specific compliance control:

```yaml
- name: check-mfa
  action: compliance.check_control
  params:
    framework: SOC2
    control: "CC6.1"
    evidence_type: "mfa_configuration"
    description: "Multi-factor authentication must be enabled"
```

**Parameters:**
- `framework` (string, required): Compliance framework (SOC2, ISO27001, PCI-DSS, etc.)
- `control` (string, required): Control identifier
- `evidence_type` (string, optional): Type of evidence to check
- `description` (string, optional): Control description

**Output:**
```json
{
  "status": "pass|fail",
  "framework": "SOC2",
  "control": "CC6.1",
  "details": { ... }
}
```

#### compliance.map_finding

Map a security finding to compliance controls:

```yaml
- name: map-finding
  action: compliance.map_finding
  params:
    finding_id: "{{ inputs.finding.id }}"
    framework: SOC2
```

#### compliance.generate_report

Generate a compliance report:

```yaml
- name: generate-report
  action: compliance.generate_report
  params:
    framework: SOC2
    controls:
      - CC6.1
      - CC6.2
      - CC6.3
    format: pdf
    include_evidence: true
```

**Parameters:**
- `framework` (string, required): Compliance framework
- `controls` (array, optional): Specific controls to include
- `format` (string, optional): Output format (pdf, html, json)
- `include_evidence` (boolean, optional): Include evidence in report

**Output:**
```json
{
  "report_id": "rpt-20240115120000",
  "framework": "SOC2",
  "format": "pdf"
}
```

### Security Testing

#### pentest.request

Request a penetration test:

```yaml
- name: request-pentest
  action: pentest.request
  params:
    target: "{{ inputs.target_url }}"
    scope:
      - web_application
      - api
    priority: high
```

**Parameters:**
- `target` (string, required): Target URL or identifier
- `scope` (array, optional): Testing scope
- `priority` (string, optional): Request priority

#### pentest.validate_exploitability

Validate if a vulnerability is exploitable:

```yaml
- name: validate-exploit
  action: pentest.validate_exploitability
  params:
    finding_id: "{{ inputs.finding.id }}"
    cve: "{{ inputs.finding.cve }}"
```

**Output:**
```json
{
  "exploitable": true|false,
  "confidence": 0.85
}
```

#### scanner.run

Run a security scanner:

```yaml
- name: run-scanner
  action: scanner.run
  params:
    scanner: "semgrep"
    target: "{{ inputs.repository }}"
    rules:
      - security
      - owasp
```

### Notifications

#### notify.slack

Send a Slack notification:

```yaml
- name: notify-team
  action: notify.slack
  params:
    channel: "#security-alerts"
    message: |
      :warning: *Security Alert*
      
      A critical vulnerability was detected.
      Ticket: {{ steps.create-ticket.output.issue_key }}
```

**Parameters:**
- `channel` (string, required): Slack channel
- `message` (string, required): Message content (supports Slack markdown)

#### notify.email

Send an email notification:

```yaml
- name: notify-email
  action: notify.email
  params:
    to: "security-team@company.com"
    subject: "Security Alert: {{ inputs.finding.severity }}"
    body: "A security issue requires attention."
```

#### notify.pagerduty

Create a PagerDuty incident:

```yaml
- name: page-oncall
  action: notify.pagerduty
  params:
    service: "security-oncall"
    severity: critical
    summary: "Critical vulnerability detected"
```

### Issue Tracking (Jira)

#### jira.create_issue

Create a Jira issue:

```yaml
- name: create-ticket
  action: jira.create_issue
  params:
    project: "SEC"
    issue_type: "Bug"
    priority: "High"
    summary: "Security vulnerability: {{ inputs.finding.title }}"
    description: |
      ## Vulnerability Details
      
      **Severity:** {{ inputs.finding.severity }}
      **CVE:** {{ inputs.finding.cve }}
      
      ### Description
      {{ inputs.finding.description }}
      
      ### Remediation
      {{ inputs.finding.remediation }}
    labels:
      - security
      - vulnerability
      - automated
```

**Parameters:**
- `project` (string, required): Jira project key
- `issue_type` (string, optional): Issue type (Bug, Task, Story, etc.)
- `priority` (string, optional): Priority (Critical, High, Medium, Low)
- `summary` (string, required): Issue summary
- `description` (string, optional): Issue description (supports Jira markdown)
- `labels` (array, optional): Issue labels
- `assignee` (string, optional): Assignee username
- `components` (array, optional): Issue components

**Output:**
```json
{
  "issue_key": "SEC-123",
  "issue_id": "10001"
}
```

#### jira.update_issue

Update an existing Jira issue:

```yaml
- name: update-ticket
  action: jira.update_issue
  params:
    issue_key: "{{ steps.create-ticket.output.issue_key }}"
    status: "In Progress"
    priority: "Critical"
```

#### jira.add_comment

Add a comment to a Jira issue:

```yaml
- name: add-comment
  action: jira.add_comment
  params:
    issue_key: "{{ inputs.issue_key }}"
    comment: |
      Automated update from FixOps:
      
      Validation completed at {{ now() }}
      Status: {{ steps.validate.output.status }}
```

### Documentation (Confluence)

#### confluence.create_page

Create a Confluence page:

```yaml
- name: create-doc
  action: confluence.create_page
  params:
    space: "SEC"
    title: "Security Report - {{ date() }}"
    content: |
      <h1>Security Assessment Report</h1>
      <p>Generated by FixOps on {{ date() }}</p>
      
      <h2>Findings Summary</h2>
      <p>Total findings: {{ inputs.findings_count }}</p>
```

**Parameters:**
- `space` (string, required): Confluence space key
- `title` (string, required): Page title
- `content` (string, required): Page content (HTML or Confluence storage format)
- `parent_id` (string, optional): Parent page ID

**Output:**
```json
{
  "page_id": "pg-001",
  "title": "Security Report - 2024-01-15"
}
```

#### confluence.update_page

Update an existing Confluence page:

```yaml
- name: update-doc
  action: confluence.update_page
  params:
    page_id: "{{ steps.create-doc.output.page_id }}"
    content: "Updated content..."
```

### Workflow Control

#### workflow.approve

Mark a workflow item as approved:

```yaml
- name: approve-change
  action: workflow.approve
  params:
    workflow_id: "{{ inputs.workflow_id }}"
    approver: "{{ inputs.approver }}"
    comment: "Approved after security review"
```

#### workflow.reject

Reject a workflow item:

```yaml
- name: reject-change
  action: workflow.reject
  params:
    workflow_id: "{{ inputs.workflow_id }}"
    reason: "Security requirements not met"
```

#### workflow.escalate

Escalate a workflow item:

```yaml
- name: escalate-issue
  action: workflow.escalate
  params:
    workflow_id: "{{ inputs.workflow_id }}"
    escalation_level: 2
    reason: "SLA breach imminent"
```

### Data Operations

#### data.filter

Filter a dataset:

```yaml
- name: filter-critical
  action: data.filter
  params:
    data: "{{ inputs.findings }}"
    field: "severity"
    value: "critical"
```

**Output:**
```json
{
  "filtered": true,
  "count": 5,
  "data": [ ... ]
}
```

#### data.aggregate

Aggregate data:

```yaml
- name: aggregate-by-severity
  action: data.aggregate
  params:
    data: "{{ inputs.findings }}"
    group_by: "severity"
    operation: "count"
```

#### data.transform

Transform data:

```yaml
- name: transform-findings
  action: data.transform
  params:
    data: "{{ inputs.findings }}"
    mapping:
      id: "finding_id"
      severity: "risk_level"
```

## Template Variables

FixOps uses `{{ }}` syntax for template variable resolution.

### Available Variables

#### inputs

Access playbook inputs:

```yaml
{{ inputs.severity_threshold }}
{{ inputs.findings }}
{{ inputs.auto_create_tickets }}
```

#### steps

Access results from previous steps:

```yaml
{{ steps.step-name.status }}          # Step status: success, failed, skipped
{{ steps.step-name.output }}          # Step output object
{{ steps.step-name.output.issue_key }} # Specific output field
{{ steps.step-name.error }}           # Error message if failed
```

#### variables

Access variables set by previous steps:

```yaml
{{ variables.my_variable }}
```

### Template Examples

```yaml
# String interpolation
summary: "Alert: {{ inputs.finding.title }}"

# Nested access
description: "CVE: {{ inputs.finding.cve }}, Severity: {{ inputs.finding.severity }}"

# Step output reference
comment: "Ticket created: {{ steps.create-ticket.output.issue_key }}"

# Multi-line with templates
message: |
  Security Alert
  
  Finding: {{ inputs.finding.title }}
  Severity: {{ inputs.finding.severity }}
  Ticket: {{ steps.create-ticket.output.issue_key }}
```

## Expression Language

FixOps supports a safe expression language for conditions.

### Comparison Operators

```yaml
# Equality
when: "steps.check.status == 'failed'"
when: "inputs.severity == 'critical'"

# Inequality
when: "steps.check.status != 'success'"

# Numeric comparisons
when: "inputs.score > 80"
when: "inputs.count >= 10"
when: "inputs.risk < 5"
when: "inputs.priority <= 2"
```

### Logical Operators

```yaml
# AND
when: "inputs.severity == 'critical' and inputs.auto_remediate == true"

# OR
when: "inputs.severity == 'critical' or inputs.severity == 'high'"

# NOT
when: "not inputs.skip_notification"
```

### Boolean Values

```yaml
when: "true"
when: "false"
when: "inputs.enabled"
```

## Outputs

Define playbook outputs for downstream consumption:

```yaml
spec:
  outputs:
    compliance_status:
      type: object
      description: "Overall compliance status"
      from: "steps.generate-report.output"
    
    remediation_tickets:
      type: array
      description: "Created Jira tickets"
      from:
        - "steps.create-mfa-ticket.output"
        - "steps.create-rbac-ticket.output"
    
    evidence_bundle:
      type: evidence_bundle
      description: "Signed evidence bundle"
      from: "steps.sign-evidence.output"
```

## Triggers

Define when a playbook should be automatically executed:

```yaml
spec:
  triggers:
    # Trigger on pipeline completion
    - event: pipeline.completed
      filter:
        stage: deploy
        environment: production
    
    # Scheduled trigger (cron)
    - event: schedule.cron
      filter:
        expression: "0 0 * * 1"  # Weekly on Monday
    
    # Trigger on compliance control failure
    - event: compliance.control_failed
      filter:
        framework: SOC2
        control_prefix: "CC6"
    
    # Trigger on new finding
    - event: finding.created
      filter:
        severity:
          - critical
          - high
    
    # Trigger on guardrail failure
    - event: guardrail.fail
      filter:
        guardrail: "no-critical-vulns"
    
    # Manual trigger (always available)
    - event: manual
```

### Trigger Events

| Event | Description |
|-------|-------------|
| `pipeline.completed` | Pipeline execution completed |
| `schedule.cron` | Scheduled execution (cron expression) |
| `finding.created` | New security finding detected |
| `finding.updated` | Existing finding updated |
| `compliance.control_failed` | Compliance control check failed |
| `guardrail.fail` | Security guardrail triggered |
| `manual` | Manual execution via CLI or API |

## Global Conditions

Define conditions that must be met for the playbook to execute:

```yaml
spec:
  conditions:
    frameworks:
      - SOC2
      - ISO27001
    min_severity: medium
```

If conditions are not met, the playbook is skipped entirely.

## Complete Example

Here's a complete playbook for SOC2 access control validation:

```yaml
apiVersion: fixops.io/v1
kind: CompliancePack
metadata:
  name: soc2-access-control-validation
  version: "1.0.0"
  description: "Validates SOC2 access control requirements"
  author: "FixOps Security Team"
  tags:
    - soc2
    - access-control
    - compliance
  compliance_frameworks:
    - SOC2

spec:
  inputs:
    findings:
      type: sarif
      required: true
      description: "SARIF findings from security scanners"
    severity_threshold:
      type: string
      default: "high"
    auto_create_tickets:
      type: boolean
      default: true

  conditions:
    frameworks:
      - SOC2
    min_severity: medium

  steps:
    - name: evaluate-access-controls
      action: opa.evaluate
      params:
        policy: "soc2/access-control.rego"
        input: "{{ inputs.findings }}"
      timeout: "60s"

    - name: check-mfa-requirement
      action: compliance.check_control
      condition:
        depends_on:
          - evaluate-access-controls
      params:
        framework: SOC2
        control: "CC6.1"
        evidence_type: "mfa_configuration"

    - name: collect-evidence
      action: evidence.collect
      condition:
        depends_on:
          - check-mfa-requirement
      params:
        evidence_types:
          - mfa_configuration
          - rbac_configuration
        retention_days: 365

    - name: create-ticket
      action: jira.create_issue
      condition:
        when: "steps.check-mfa-requirement.status == 'failed'"
        depends_on:
          - check-mfa-requirement
      params:
        project: "SEC"
        issue_type: "Bug"
        priority: "High"
        summary: "SOC2 CC6.1 - MFA requirement not met"
        description: |
          ## SOC2 Compliance Gap
          
          **Control:** CC6.1 - Multi-Factor Authentication
          **Status:** Failed
          
          ### Required Actions
          1. Enable MFA for all privileged accounts
          2. Configure MFA enforcement policy

    - name: notify-team
      action: notify.slack
      condition:
        when: "steps.check-mfa-requirement.status == 'failed'"
        depends_on:
          - create-ticket
      params:
        channel: "#security-alerts"
        message: |
          :warning: *SOC2 Compliance Gap Detected*
          
          Control CC6.1 (MFA) failed validation.
          Ticket: {{ steps.create-ticket.output.issue_key }}

    - name: generate-report
      action: compliance.generate_report
      condition:
        depends_on:
          - check-mfa-requirement
      params:
        framework: SOC2
        controls:
          - CC6.1
        format: pdf
        include_evidence: true

  outputs:
    compliance_status:
      type: object
      from: "steps.generate-report.output"
    ticket:
      type: object
      from: "steps.create-ticket.output"

  triggers:
    - event: schedule.cron
      filter:
        expression: "0 0 * * 1"
    - event: manual
```

## Execution Model

### Step Ordering

Steps execute in order, respecting `depends_on` dependencies. Steps with no dependencies on each other may execute in parallel in future versions.

### Status Values

| Status | Description |
|--------|-------------|
| `pending` | Step not yet started |
| `running` | Step currently executing |
| `success` | Step completed successfully |
| `failed` | Step failed (error occurred) |
| `skipped` | Step skipped (condition not met or dependency failed) |

### Execution Context

Each step has access to:
- `inputs` - Playbook inputs
- `steps` - Results from previous steps
- `variables` - Variables set by previous steps

### Error Handling

By default, playbook execution stops on the first failed step. Configure `on_failure.continue: true` to continue execution.

## Security Model

FixOps Playbooks are designed with security in mind:

1. **Sandboxed Execution**: Playbooks can only execute pre-approved actions
2. **No Arbitrary Code**: No `eval()`, `exec()`, or shell commands
3. **Safe Expression Language**: Limited operators, no function calls
4. **Connector Validation**: All external calls go through validated connectors
5. **Audit Trail**: Full execution trace for compliance

## Best Practices

1. **Use descriptive step names**: Make it clear what each step does
2. **Add timeouts**: Prevent runaway steps with appropriate timeouts
3. **Handle failures gracefully**: Use `on_failure` for retry and continue logic
4. **Use conditions wisely**: Skip unnecessary steps with `when`/`unless`
5. **Document your playbooks**: Use metadata description and input descriptions
6. **Test with dry-run**: Validate playbooks before production execution
7. **Version your playbooks**: Use semantic versioning in metadata

## File Locations

| Path | Description |
|------|-------------|
| `config/playbooks/` | Default playbook directory |
| `config/playbook-schema.yaml` | JSON Schema for validation |
| `core/playbook_runner.py` | Playbook execution engine |

## Related Documentation

- [Docker Showcase Guide](DOCKER_SHOWCASE_GUIDE.md) - Docker examples for playbook execution
- [Feature Code Mapping](FEATURE_CODE_MAPPING.md) - Code paths for playbook features
- [Enterprise Features](ENTERPRISE_FEATURES.md) - Enterprise playbook capabilities
