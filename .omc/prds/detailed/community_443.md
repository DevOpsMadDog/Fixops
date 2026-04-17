# PRD — Community 443: Compliance Engine — Standard Evidence Types Method

## Master Goal Mapping
- **Platform Goal**: Return the required evidence types for a given compliance control — drives evidence collection automation
- **Persona**: Compliance Automation System (internal), Compliance Officer
- **ALDECI Pillar**: GRC / Compliance Evidence Auto-Collection
- **Backend**: `suite-evidence-risk/compliance/compliance_engine.py`

## Architecture Diagram
```mermaid
graph TD
    A[ComplianceEngine] --> B[return_standard_evidence_types(control_id)]
    B --> C[SOC2 control map: CC1→access_reviews+policies]
    B --> D[PCI-DSS control map: Req1→network_diagrams+configs]
    B --> E[ISO 27001 control map: A.9→access_logs+reviews]
    B --> F[NIST map: AC→access_control_policies]
    B --> G[Returns: List of evidence_type strings]
    G --> H[evidence_chain_engine: collect evidence of these types]
```

## Code Proof
- **File**: `suite-evidence-risk/compliance/compliance_engine.py`
- **Node label** (from graph): `"Return standard evidence types required for a control."`
- **Pattern**: Control ID → framework prefix detection → static evidence type map lookup
- **Evidence types**: access_reviews, policies, network_diagrams, scan_results, audit_logs, config_snapshots, pen_test_reports, etc.

## Inter-Dependencies
- **Upstream**: `ComplianceEngine.auto_collect_evidence()` calls this per control
- **Downstream**: `evidence_chain_engine.py` — collects the returned evidence types
- **Frameworks**: SOC2 (CC1-CC9), PCI-DSS (12 reqs), ISO 27001 (93 controls), NIST 800-53

## Data Flow
```
auto_collect_evidence(control_id) →
return_standard_evidence_types(control_id) →
['audit_logs', 'access_reviews', 'config_snapshots'] →
For each type: evidence_chain_engine.collect(type) →
Bundle stored with SHA-256 content hash
```

## Referenced Docs
- `suite-evidence-risk/compliance/compliance_engine.py` docstring
- `tests/test_compliance_evidence_collector.py` — 35 tests

## Acceptance Criteria
- [ ] Returns non-empty list for all 200+ supported control IDs
- [ ] SOC2 CC controls map to correct TSC evidence types
- [ ] PCI-DSS requirements map to network/scan/log evidence
- [ ] ISO 27001 Annex A controls covered
- [ ] Returns empty list (not error) for unknown control IDs
- [ ] Evidence types are valid string constants

## Effort Estimate
**S** — 1 day (complete)

## Status
**DONE** — Core compliance automation method
