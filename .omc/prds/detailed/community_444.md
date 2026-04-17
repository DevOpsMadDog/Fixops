# PRD — Community 444: Compliance Template — Build Compliance Statement Method

## Master Goal Mapping
- **Platform Goal**: Generate human-readable compliance statements for auditors from control assessment results
- **Persona**: Auditor, Compliance Officer (receives the generated statement)
- **ALDECI Pillar**: GRC / Compliance Reporting
- **Backend**: `suite-evidence-risk/compliance/templates/base.py`

## Architecture Diagram
```mermaid
graph TD
    A[ComplianceTemplate subclass] --> B[build_compliance_statement(control, checks)]
    B --> C[template: framework_name + control.id + control.name]
    B --> D[checks: passed_count / total_count]
    B --> E[evidence list: human-readable summary]
    B --> F[remediation_steps if any checks failed]
    B --> G[Returns: formatted string for audit report]
    G --> H[executive_reporting_engine: embed in board deck]
```

## Code Proof
- **File**: `suite-evidence-risk/compliance/templates/base.py`
- **Node label** (from graph): `"Build a human-readable compliance statement for auditors."`
- **Base class**: `ComplianceTemplate(ABC)` with `framework_name`, `version`, `rules: List[ComplianceRule]`
- **ComplianceCheck**: `{ rule_id, passed: bool, message, evidence: List[str] }`
- **ComplianceRule**: `{ id, name, description, severity, checks, remediation }`

## Inter-Dependencies
- **Upstream**: `ComplianceTemplate.assess_compliance()` → calls `build_compliance_statement`
- **Downstream**: Executive reporting engine, audit report generator
- **Subclasses**: SOC2Template, PCIDSSTemplate, ISO27001Template in same package

## Data Flow
```
assess_compliance(data) → runs all rules → ComplianceCheck results →
build_compliance_statement(rule, checks) →
"[Framework] Control [ID]: [Name] — X/Y checks passed. Evidence: [...]. Remediation: [...]"
→ embedded in PDF audit report
```

## Acceptance Criteria
- [ ] Statement includes framework name, control ID, name
- [ ] Pass/fail ratio clearly stated
- [ ] Evidence list summarised
- [ ] Remediation steps included when checks failed
- [ ] Human-readable (no JSON/code in output)
- [ ] Works for all 4 supported frameworks

## Effort Estimate
**S** — 1 day (complete)

## Status
**DONE** — Core compliance template method
