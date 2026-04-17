# PRD — Community 446: Compliance Engine — Assess Compliance Method

## Master Goal Mapping
- **Platform Goal**: Core compliance assessment — run all framework rules against current security posture data
- **Persona**: Compliance Automation System, Compliance Officer
- **ALDECI Pillar**: GRC / Continuous Compliance Monitoring
- **Backend**: `suite-evidence-risk/compliance/compliance_engine.py`

## Architecture Diagram
```mermaid
graph TD
    A[Compliance Engine] --> B[assess_compliance(framework, data)]
    B --> C[Load framework rules: SOC2/PCI/ISO/NIST]
    B --> D[For each ComplianceRule: run checks against data]
    D --> E[ComplianceCheck: passed/failed + evidence]
    E --> F[build_compliance_statement per rule]
    E --> G[build_remediation_steps for failures]
    B --> H[Persist: SQLite compliance.db]
    B --> I[Returns: ComplianceAssessment result]
    I --> J[Overall score: passed/total * 100]
```

## Code Proof
- **File**: `suite-evidence-risk/compliance/compliance_engine.py`
- **Node label** (from graph): `"Assess compliance against framework."`
- **Docstring**: "Maps findings to compliance controls across 6 frameworks"
- **SQLite**: `.fixops_data/compliance.db`
- **Env var**: `FIXOPS_COMPLIANCE_FRAMEWORKS` (comma-separated enabled frameworks)
- **Env var**: `FIXOPS_COMPLIANCE_DB_PATH` (override DB path)

## Inter-Dependencies
- **Upstream**: Compliance router calls `engine.assess_compliance(framework, data)` on demand or scheduled
- **Downstream**: `build_compliance_statement`, `build_remediation_steps`, `return_standard_evidence_types`
- **DB**: SQLite `compliance.db` — persists assessment history with timestamps
- **Related**: `compliance_mapping_engine.py`, `compliance_automation_engine.py`

## Data Flow
```
POST /api/v1/compliance/assess →
assess_compliance('SOC2', findings_data) →
Load SOC2 rules (CC1-CC9, A1, PI1, C1, P1) →
Each rule.checks run → ComplianceCheck results →
Score = passed_checks / total_checks * 100 →
Persist to compliance.db → return ComplianceAssessment
```

## Referenced Docs
- `suite-evidence-risk/compliance/compliance_engine.py` full docstring (lines 1-30)
- 6 frameworks: SOC2 Type II, PCI DSS 4.0, ISO 27001:2022, NIST 800-53 Rev5, NIST CSF 2.0, OWASP ASVS 4.0

## Acceptance Criteria
- [ ] All 6 frameworks supported
- [ ] Assessment persisted to SQLite with timestamp
- [ ] Cryptographic proof (hash of assessment data)
- [ ] Overall score (0-100) computed
- [ ] Per-rule pass/fail with evidence list
- [ ] `FIXOPS_COMPLIANCE_FRAMEWORKS` env var filters active frameworks
- [ ] `FIXOPS_COMPLIANCE_DB_PATH` env var overrides DB path

## Effort Estimate
**L** — 3 days (complete)

## Status
**DONE** — Core compliance assessment engine
