# Community 643 PRD — ML Risk Prediction / Model Registry

## Master Goal Mapping
- **ALDECI Domain**: ML Risk Prediction / Model Registry
- **Module**: `BaseRiskModel (ABC)`
- **Source**: `suite-core/core/model_registry.py:L107`
- **Function/Method**: `predict`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `predict` within the ML Risk Prediction / Model Registry subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["predict()"]
    B --> C[BaseRiskModel (ABC)]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/model_registry.py` — **Line**: `L107`

**Signature**: `abstractmethod def predict(*, sbom_components, sarif_findings, cve_records, context, enrichment_map) -> ModelPrediction`

```python
"""Make a risk prediction.
Parameters
----------
sbom_components: Normalized SBOM components.
sarif_findings: Normalized SARIF findings.
cve_records: Normalized CVE records.
context: Business context (criticality, exposure, etc.).
enrichment_map: Enrichment evidence (KEV, EPSS, CVSS, etc.).
Returns
-------
ModelPrediction
    Risk prediction with score, verdict, and explanation.
"""
```

## Inter-Dependencies

- `ModelPrediction dataclass`
- `sbom_engine.py`
- `ml/threat_enricher.py`
- `cve_enrichment_engine.py`

## Data Flow

SBOM+SARIF+CVE+context+enrichment → model inference → ModelPrediction(score, verdict, explanation)

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/model_registry.py` — Full module implementation

## Acceptance Criteria

- [ ] Returns ModelPrediction with score 0-100
- [ ] Accepts enrichment_map for KEV/EPSS boosts
- [ ] Handles empty input gracefully
- [ ] Verdict is one of: critical/high/medium/low/info

## Effort Estimate

**M (model-specific implementation required per backend)**

## Status

**Implemented**
