# Line-by-Line Commentary

This commentary highlights the meaningful sections of the FixOps ingestion backend. Blank lines and
obvious imports are grouped for readability.

## `backend/app.py`

| Lines | Description |
| ----- | ----------- |
| 1-17 | Imports, logger setup, and overlay loader wiring. |
| 20-42 | `create_app()` initialises FastAPI, configures permissive CORS, instantiates helpers, loads the overlay, and creates any declared data directories. |
| 44-46 | `_store()` helper centralises writing artefacts into `app.state.artifacts` with debug logging. |
| 48-66 | `/inputs/design` endpoint parses the uploaded CSV, rejects empty payloads, stores the dataset, and returns metadata plus raw rows. |
| 68-121 | `/inputs/sbom`, `/inputs/cve`, and `/inputs/sarif` normalise uploads via `InputNormalizer`, wrap parser failures in HTTP 400 responses, and return summaries for UI previews. |
| 123-153 | `/pipeline/run` enforces overlay-driven required inputs, validates Jira configuration when ticket sync is mandatory, runs the orchestrator with the active overlay so guardrail evaluation occurs, and appends sanitised overlay metadata (including required inputs) to the response. |

## `backend/normalizers.py`

| Lines | Description |
| ----- | ----------- |
| 1-27 | Imports, optional dependency guards, and logger configuration. Missing optional libs degrade gracefully except `sarif-om`, which raises immediately. |
| 30-52 | `SBOMComponent` dataclass captures the subset of SBOM component fields used downstream and ensures `to_dict()` preserves the embedded raw package. |
| 55-76 | `NormalizedSBOM` dataclass stores the parsed SBOM document alongside related lists and metadata; `to_dict()` serialises nested components. |
| 79-92 | `CVERecordSummary` dataclass shrinks CVE entries to key attributes plus raw payload. |
| 95-108 | `NormalizedCVEFeed` dataclass provides a uniform structure for CVE data and validation errors. |
| 111-125 | `SarifFinding` dataclass represents an extracted SARIF result. |
| 128-143 | `NormalizedSARIF` dataclass encapsulates SARIF metadata and findings with serialisation support. |
| 146-158 | `InputNormalizer.__init__` captures SBOM type preferences and `_ensure_text` converts any raw input (bytes, file-like, str) into UTF-8 strings. |
| 160-215 | `load_sbom` leverages `lib4sbom` to parse the document, builds `SBOMComponent` objects with defensive defaults, caches supplier extraction, and stores relationship/service/vulnerability lists once to avoid repeated parser calls. |
| 217-281 | `load_cve_feed` decodes JSON feeds that may be dicts or lists, validates entries with `cvelib` when available, normalises identifiers/title/severity, and records validation errors. |
| 283-335 | `load_sarif` parses JSON, optionally converts Snyk payloads to SARIF, instantiates `SarifLog`, reuses the parsed runs list, extracts tool names/findings, and builds metadata counts. |

## `backend/pipeline.py`

| Lines | Description |
| ----- | ----------- |
| 1-32 | Imports, severity constants, and class docstring. |
| 35-73 | `_extract_component_name`, `_build_finding_search_text`, `_build_record_search_text`, and `_match_components` construct design tokens and component lookups. |
| 75-133 | Severity helpers normalise SARIF levels and CVE severities, resolve threshold rankings, and prepare guardrail evaluation utilities. |
| 135-229 | `run()` builds the design list, precomputes lowercase tokens, indexes SBOM components, aggregates severity/exploitation statistics (including per-source counts), computes the maturity-aware guardrail evaluation when an overlay is provided, and precomputes finding/CVE matches per token using `defaultdict` caches to avoid redundant scans. |
| 231-263 | Crosswalk assembly attaches matches to each design row and prepares the final response with summaries, severity overview, guardrail evaluation, and per-artefact breakdowns. |

## `fixops/configuration.py`

| Lines | Description |
| ----- | ----------- |
| 1-14 | Module docstring, future import, and path constants (`DEFAULT_OVERLAY_PATH`, env override key). |
| 17-33 | `_read_text` and `_parse_overlay` helpers read the file and parse YAML/JSON with graceful fallbacks when PyYAML is absent. |
| 36-44 | `_deep_merge` recursively merges nested dictionaries so profile overrides can target specific keys. |
| 47-115 | `OverlayConfig` dataclass defines integration payloads, toggle defaults, guardrail defaults (including maturity/threshold helpers), helper properties for required inputs/data directories, and `to_sanitised_dict()` masking logic that now exports guardrail policy. |
| 118-158 | `load_overlay()` resolves the path (including environment override), merges profile-specific data, applies default toggles/metadata, instantiates `OverlayConfig`, and annotates metadata with resolved guardrail maturity and thresholds before returning the configuration. |
| 161 | `__all__` exposes the loader and dataclass for importers. |

## `simulations/cve_scenario/runner.py`

| Lines | Description |
| ----- | ----------- |
| 1-75 | Imports, risk-scorer resolver, CVE source constant, and `RunResult` dataclass exposing file paths, adjustment metadata, and guardrail status. |
| 77-139 | `_load_contexts()` reads business-context fixtures and `_build_artifacts()` constructs synthetic SBOM/SARIF/CVE inputs for CVE-2021-44228. |
| 142-196 | `_ensure_overlay_for_mode()` replays the overlay merge logic so the runner can switch between Demo and Enterprise profiles without mutating the source file. |
| 198-209 | `_write_design_context()` exports a CSV of the scenario-specific design rows into the overlay’s `design_context_dir`. |
| 212-321 | `run_simulation()` loads the overlay, executes the pipeline orchestrator (capturing guardrail evaluations), applies contextual risk scoring (with per-mode scanner severities), and writes score/evidence JSON bundles annotated with guardrail and severity overviews. |
| 324-352 | CLI helpers parse `--mode`/`--overlay` flags and allow manual execution with structured JSON output. |
