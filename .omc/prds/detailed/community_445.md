# PRD — Community 445: Compliance Template — Build Remediation Steps Method

## Master Goal Mapping
- **Platform Goal**: Generate actionable remediation steps for controls that have no evidence — drives auto-remediation workflows
- **Persona**: Security Engineer, Compliance Officer, SOAR automation system
- **ALDECI Pillar**: GRC / Automated Remediation
- **Backend**: `suite-evidence-risk/compliance/templates/base.py`

## Architecture Diagram
```mermaid
graph TD
    A[ComplianceTemplate] --> B[build_remediation_steps(rule)]
    B --> C[rule.remediation field check]
    C -->|has remediation| D[Parse remediation string into steps]
    C -->|no remediation| E[Return generic steps based on severity]
    D --> F[Returns: List of step strings]
    E --> F
    F --> G[VulnRemediationEngine: create remediation workflow]
    F --> H[SecurityPlaybookEngine: generate playbook steps]
```

## Code Proof
- **File**: `suite-evidence-risk/compliance/templates/base.py`
- **Node label** (from graph): `"Build remediation steps for a control with no evidence."`
- **ComplianceRule.remediation**: Optional[str] — free-text remediation guidance
- **Pattern**: If rule.remediation set → parse into numbered steps; else → default steps by severity

## Inter-Dependencies
- **Upstream**: `assess_compliance()` → for each failed check calls `build_remediation_steps`
- **Downstream**: `vulnerability_remediation_engine.py` — creates remediation tickets
- **Playbooks**: `ir_playbook_engine.py` — uses steps to build IR playbook

## Data Flow
```
assess_compliance fails check → build_remediation_steps(rule) →
['1. Enable MFA on all admin accounts', '2. Review access logs...'] →
vuln_remediation_engine.create_ticket(steps) →
Assigned to owner → SLA countdown starts
```

## Acceptance Criteria
- [ ] Returns ordered list of remediation step strings
- [ ] Uses rule.remediation if available
- [ ] Falls back to severity-based defaults (critical → 4 steps, high → 3, etc.)
- [ ] Steps are actionable (verb-first: "Enable", "Review", "Configure")
- [ ] Empty list never returned (minimum 1 generic step)

## Effort Estimate
**S** — 1 day (complete)

## Status
**DONE** — Core compliance remediation method
