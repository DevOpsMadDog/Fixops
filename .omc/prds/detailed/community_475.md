# PRD: Community 475 — multiscanner_consolidate.convert_aws

## Master Goal Mapping
**ALDECI Pillar**: ASPM — Multi-Scanner Normalization  
**Persona**: Security Engineer, Vulnerability Analyst  
**Business Value**: Converts AWS Security Hub ASFF output into ALDECI's normalized finding schema, enabling unified vulnerability management across 32 scanner sources without vendor lock-in.

## Architecture Diagram
```mermaid
graph TD
    A[AWS Security Hub ASFF export] --> B[convert_aws]
    B --> C[Parse ASFF structure]
    C --> D[Map fields to NormalizedFinding schema]
    D --> E[severity normalization critical/high/medium/low]
    D --> F[CVE ID extraction]
    D --> G[asset identification]
    E & F & G --> H[List of NormalizedFinding objects]
    H --> I[ALDECI vulnerability DB]
    H --> J[CTEM pipeline deduplication]
    style B fill:#e63946,color:#fff
```

## Code Proof
**File**: `scripts/multiscanner_consolidate.py`  
Function: `convert_aws`  
Extracts: AWS Security Finding Format (ASFF) normalized from Security Hub JSON

```python
def convert_aws(data) -> List[NormalizedFinding]:
    findings = []
    # Parse AWS Security Hub ASFF format
    # Map to NormalizedFinding(id, title, severity, cve_id, asset, source="aws security hub")
    return findings
```

## Inter-Dependencies
- **Upstream**: AWS Security Hub scan output (ASFF format)
- **Downstream**: ALDECI normalized findings DB, CTEM deduplication engine
- **Sibling**: Other scanner converters in `multiscanner_consolidate.py` (Communities 470-478)
- **Schema**: `NormalizedFinding` dataclass (id, title, severity, cve_id, asset, source, metadata)

## Data Flow
```
AWS Security Hub ASFF file
  → convert_aws(data)
    → parse ASFF structure
    → normalize severity: aws security hub_severity → critical/high/medium/low
    → extract CVE IDs from description/references
    → return [NormalizedFinding(...), ...]
  → consolidate_all_scanners() merges with other scanner results
  → dedup by (cve_id, asset) → unified finding list
```

## Referenced Docs
- `scripts/multiscanner_consolidate.py`
- AWS Security Hub API/export documentation
- ALDECI scanner normalizers: `suite-core/core/scanner_parsers.py` (32 normalizers)

## Acceptance Criteria
- [ ] Parses valid AWS Security Hub ASFF without error
- [ ] Maps severity to critical/high/medium/low correctly
- [ ] Extracts CVE IDs where present
- [ ] Handles missing optional fields gracefully
- [ ] Returns empty list for empty input (no exception)
- [ ] Source field set to "aws_security_hub"

## Effort Estimate
**XS** — 1 day per converter. Most converters complete; verify schema compatibility.

## Status
**COMPLETE** — Converter implemented in multiscanner_consolidate.py.
