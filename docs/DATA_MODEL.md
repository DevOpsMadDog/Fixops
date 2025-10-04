# Data Model Reference

The backend works with a handful of lightweight dataclasses that wrap the parsed artefacts. This
section translates those models into plain language and explains key invariants.

## SBOM Normalisation

- **`SBOMComponent`** (`backend/normalizers.py`)
  - Represents a single software component from the SBOM.
  - Fields:
    - `name` (string, required): component identifier.
    - `version` (string, optional): semantic version.
    - `purl` (string, optional): Package URL when provided.
    - `licenses` (list of strings): flattened licence names.
    - `supplier` (string, optional): supplier name; may come from nested dicts.
    - `raw` (dict): full package object for traceability.
  - Invariants: `raw` always contains the original SBOM entry to avoid data loss.

- **`NormalizedSBOM`**
  - Bundles the full parsed SBOM document, component list, relationships, services, vulnerabilities,
    and metadata counters.
  - Metadata includes `component_count`, `relationship_count`, `service_count`, and
    `vulnerability_count` for quick dashboards.

## CVE / KEV Feeds

- **`CVERecordSummary`**
  - Focuses on correlation-friendly fields: `cve_id`, `title`, `severity`, `exploited`, and `raw`.
  - `exploited` is derived from several possible boolean flags for broad feed compatibility.

- **`NormalizedCVEFeed`**
  - Contains the list of `CVERecordSummary` objects, any validation errors, and metadata such as
    `record_count` and optional `validation_errors` counts.
  - Records may include validation issues even if ingestion succeeded; callers should inspect both
    `records` and `errors`.

## SARIF Findings

- **`SarifFinding`**
  - Stores the fields needed for quick inspection: `rule_id`, `message`, `level`, `file`, `line`,
    and the original `raw` SARIF result.

- **`NormalizedSARIF`**
  - Tracks SARIF `version`, optional `$schema` URI, a list of tool names, extracted findings, and
    metadata counters for runs and findings.

## Design Dataset

- Captured as a plain dictionary: `{ "columns": [..], "rows": [ {"component": ...}, ... ] }`.
- Rows can use any of the keys `component`, `Component`, or `service`. The orchestrator trims white
  space and handles case-insensitive matching.

## Crosswalk Output

- Each entry returned by `PipelineOrchestrator.run()` looks like:

```json
{
  "design_row": {"component": "Payment-Service"},
  "sbom_component": {
    "name": "payment-service",
    "version": "1.0.0",
    "licenses": [],
    "supplier": null,
    "purl": null,
    "raw": {"name": "payment-service", "version": "1.0.0"}
  },
  "findings": [{"rule_id": "CWE-79", "message": "…"}],
  "cves": [{"cve_id": "CVE-2023-0001", "severity": "HIGH"}]
}
```

- Summaries in the response provide quick statistics without reprocessing:
  - `design_summary`: total rows and unique component names.
  - `sbom_summary`: SBOM metadata plus source document name.
  - `sarif_summary`: run/finding counts, severity histogram, and tools used.
  - `cve_summary`: record counts and exploited record tally.

