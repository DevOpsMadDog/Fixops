# PRD: Community 470 — multiscanner_consolidate.convert_snyk

## Master Goal Mapping
**ALDECI Pillar**: ASPM — Multi-Scanner Normalization  
**Persona**: Security Engineer, Vulnerability Analyst  
**Business Value**: Converts Snyk JSON output into ALDECI's normalized finding schema, enabling unified vulnerability management across 32 scanner sources without vendor lock-in.

## Architecture Diagram
```mermaid
graph TD
    A[Snyk JSON export] --> B[convert_snyk]
    B --> C[Parse JSON structure]
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
Function: `convert_snyk`  
Extracts: CVE severity, package name, fix version from Snyk JSON report

```python
def convert_snyk(data) -> List[NormalizedFinding]:
    findings = []
    # Parse Snyk JSON format
    # Map to NormalizedFinding(id, title, severity, cve_id, asset, source="snyk")
    return findings
```

## Inter-Dependencies
- **Upstream**: Snyk scan output (JSON format)
- **Downstream**: ALDECI normalized findings DB, CTEM deduplication engine
- **Sibling**: Other scanner converters in `multiscanner_consolidate.py` (Communities 470-478)
- **Schema**: `NormalizedFinding` dataclass (id, title, severity, cve_id, asset, source, metadata)

## Data Flow
```
Snyk JSON file
  → convert_snyk(data)
    → parse JSON structure
    → normalize severity: snyk_severity → critical/high/medium/low
    → extract CVE IDs from description/references
    → return [NormalizedFinding(...), ...]
  → consolidate_all_scanners() merges with other scanner results
  → dedup by (cve_id, asset) → unified finding list
```

## Referenced Docs
- `scripts/multiscanner_consolidate.py`
- Snyk API/export documentation
- ALDECI scanner normalizers: `suite-core/core/scanner_parsers.py` (32 normalizers)

## Acceptance Criteria
- [ ] Parses valid Snyk JSON without error
- [ ] Maps severity to critical/high/medium/low correctly
- [ ] Extracts CVE IDs where present
- [ ] Handles missing optional fields gracefully
- [ ] Returns empty list for empty input (no exception)
- [ ] Source field set to "snyk"

## Effort Estimate
**XS** — 1 day per converter. Most converters complete; verify schema compatibility.

## Status
**COMPLETE** — Converter implemented in multiscanner_consolidate.py.
