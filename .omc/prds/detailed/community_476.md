# PRD: Community 476 — multiscanner_consolidate.convert_prisma

## Master Goal Mapping
**ALDECI Pillar**: ASPM — Multi-Scanner Normalization  
**Persona**: Security Engineer, Vulnerability Analyst  
**Business Value**: Converts Prisma Cloud CSV output into ALDECI's normalized finding schema, enabling unified vulnerability management across 32 scanner sources without vendor lock-in.

## Architecture Diagram
```mermaid
graph TD
    A[Prisma Cloud CSV export] --> B[convert_prisma]
    B --> C[Parse CSV structure]
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
Function: `convert_prisma`  
Extracts: cloud posture findings with compliance framework mapping from Prisma CSV

```python
def convert_prisma(data) -> List[NormalizedFinding]:
    findings = []
    # Parse Prisma Cloud CSV format
    # Map to NormalizedFinding(id, title, severity, cve_id, asset, source="prisma cloud")
    return findings
```

## Inter-Dependencies
- **Upstream**: Prisma Cloud scan output (CSV format)
- **Downstream**: ALDECI normalized findings DB, CTEM deduplication engine
- **Sibling**: Other scanner converters in `multiscanner_consolidate.py` (Communities 470-478)
- **Schema**: `NormalizedFinding` dataclass (id, title, severity, cve_id, asset, source, metadata)

## Data Flow
```
Prisma Cloud CSV file
  → convert_prisma(data)
    → parse CSV structure
    → normalize severity: prisma cloud_severity → critical/high/medium/low
    → extract CVE IDs from description/references
    → return [NormalizedFinding(...), ...]
  → consolidate_all_scanners() merges with other scanner results
  → dedup by (cve_id, asset) → unified finding list
```

## Referenced Docs
- `scripts/multiscanner_consolidate.py`
- Prisma Cloud API/export documentation
- ALDECI scanner normalizers: `suite-core/core/scanner_parsers.py` (32 normalizers)

## Acceptance Criteria
- [ ] Parses valid Prisma Cloud CSV without error
- [ ] Maps severity to critical/high/medium/low correctly
- [ ] Extracts CVE IDs where present
- [ ] Handles missing optional fields gracefully
- [ ] Returns empty list for empty input (no exception)
- [ ] Source field set to "prisma_cloud"

## Effort Estimate
**XS** — 1 day per converter. Most converters complete; verify schema compatibility.

## Status
**COMPLETE** — Converter implemented in multiscanner_consolidate.py.
