# Data Model

This reference summarises the primary domain models used by the ingestion service and the overlay
configuration. Each description lists core fields, invariants, and persistence notes.

## Overlay Configuration (`fixops.configuration.OverlayConfig`)

- **mode** (`str`): Lower-case identifier for the active profile (`demo` or `enterprise`). Always
  stored in metadata for auditing.
- **jira / confluence / git / ci / auth** (`dict`): Integration payloads keyed by integration name.
  Secrets are masked when exported via `to_sanitised_dict()`.
- **data** (`dict`): Maps logical directories (`design_context_dir`, `evidence_dir`, etc.) to paths.
  `OverlayConfig.data_directories` expands and normalises them to `Path` objects.
- **toggles** (`dict`): Feature flags controlling runtime behaviour. Defaults:
  - `require_design_input` (`bool`): Whether `/pipeline/run` requires a design dataset.
  - `auto_attach_overlay_metadata` (`bool`): Whether pipeline responses include overlay metadata.
  - `enforce_ticket_sync` (`bool`): If `True`, Jira configuration must include `project_key`.
- **guardrails** (`dict`): Maturity-aware policy settings with optional overrides.
  - `maturity` (`str`): One of `foundational`, `scaling`, `advanced`. Defaults to `scaling` when not provided.
  - `fail_on` / `warn_on` (`str`): Optional severity thresholds overriding defaults per maturity.
  - `profiles` (`dict`): Nested overrides keyed by maturity, enabling per-mode tuning.
- **metadata** (`dict`): Loader-supplied diagnostics (source path, applied profile list, etc.).

## Normalisation Models (`backend/normalizers.py`)

- **SBOMComponent**
  - Fields: `name`, `version`, `purl`, `licenses`, `raw` (original package record).
  - Invariants: `name` is preserved as provided; `to_dict()` always includes `raw` for traceability.
- **NormalizedSBOM**
  - Fields: `format`, `document`, `components` (`List[SBOMComponent]`), `metadata` (counts).
  - Invariants: `metadata['component_count']` matches `len(components)`.
- **CVERecordSummary**
  - Fields: `cve_id`, `title`, `severity`, `exploited`, `raw`.
  - Invariants: `severity` normalised to lowercase strings; `exploited` is boolean.
- **NormalizedCVEFeed**
  - Fields: `records` (`List[CVERecordSummary]`), `metadata` (record counts), `errors` (validation
    messages).
  - Invariants: `metadata['record_count']` equals `len(records)`.
- **SarifFinding**
  - Fields: `rule_id`, `level`, `file`, `message`, `raw`.
  - Invariants: `raw` retains the original SARIF result for audit evidence.
- **NormalizedSARIF**
  - Fields: `tool_names`, `metadata` (finding counts), `findings` (`List[SarifFinding]`).
  - Invariants: `metadata['finding_count']` equals `len(findings)`.

## Pipeline Output (`backend/pipeline.py`)

`PipelineOrchestrator.run()` produces a dictionary with:

- `status`: Always `"ok"` on success.
- `design_summary`: `row_count` and `unique_components` (sorted, deduplicated list).
- `sbom_summary`: Source metadata plus SBOM `format` and `document_name` (if present).
- `sarif_summary`: Metadata, severity histogram (`severity_breakdown`), and tool names.
- `cve_summary`: Metadata plus `exploited_count` tally.
- `severity_overview`: Highest severity observed, aggregated counts, and per-source breakdown.
- `guardrail_evaluation`: Resolved maturity tier, thresholds, trigger metadata, and pass/warn/fail status
  derived from the overlay policy.
- `crosswalk`: List of dictionaries, one per design row, containing:
  - `design_row`: Original row values.
  - `sbom_component`: Matched component dictionary (or `None`).
  - `findings`: SARIF findings matched by token.
  - `cves`: CVE summaries matched by token.
- `overlay`: Present when `auto_attach_overlay_metadata` is enabled. Contains sanitized integration
  payloads and `required_inputs` describing the mode-specific prerequisites.

## Persistence Rules

- Artefacts are cached in-memory (`app.state.artifacts`) for the lifetime of the FastAPI process.
- Overlay directories are created on startup but no files are written automatically. Downstream
  evidence exporters should respect `OverlayConfig.data_directories` for durable storage.
- No relational database is used in this demo; persistence responsibilities are intentionally left to
  downstream modules (to be implemented in Enterprise mode).
