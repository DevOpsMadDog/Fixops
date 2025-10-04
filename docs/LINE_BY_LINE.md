# Line-by-Line Commentary

This commentary highlights the meaningful sections of the FixOps ingestion backend. Blank lines and
obvious imports are grouped for readability.

## `backend/app.py`

| Lines | Description |
| ----- | ----------- |
| 1-16 | Imports, logger setup, and overlay loader wiring. |
| 19-41 | `create_app()` initialises FastAPI, configures permissive CORS, instantiates helpers, loads the overlay, and creates any declared data directories. |
| 43-45 | `_store()` helper centralises writing artefacts into `app.state.artifacts` with debug logging. |
| 47-65 | `/inputs/design` endpoint parses the uploaded CSV, rejects empty payloads, stores the dataset, and returns metadata plus raw rows. |
| 67-118 | `/inputs/sbom`, `/inputs/cve`, and `/inputs/sarif` normalise uploads via `InputNormalizer`, wrap parser failures in HTTP 400 responses, and return summaries for UI previews. |
| 120-149 | `/pipeline/run` enforces overlay-driven required inputs, validates Jira configuration when ticket sync is mandatory, runs the orchestrator, and appends sanitised overlay metadata (including required inputs) to the response. |

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
| 1-18 | Imports, shared `_lower` helper, and class docstring. |
| 21-36 | `_extract_component_name` trims design row values across canonical keys. |
| 38-58 | `_build_finding_search_text` assembles a searchable string once per SARIF finding, handling non-serialisable targets gracefully. |
| 60-69 | `_build_record_search_text` mirrors the search-text logic for CVE records. |
| 71-79 | `_match_components` constructs a lowercase index of SBOM components for constant-time lookups. |
| 81-141 | `run()` builds the design list, precomputes lowercase tokens, indexes SBOM components, aggregates severity/exploitation statistics, and precomputes finding/CVE matches per token using `defaultdict` caches to avoid redundant scans. |
| 143-162 | Crosswalk assembly attaches matches to each design row and prepares the final response with summaries for every artefact. |

## `fixops/configuration.py`

| Lines | Description |
| ----- | ----------- |
| 1-14 | Module docstring, future import, and path constants (`DEFAULT_OVERLAY_PATH`, env override key). |
| 17-33 | `_read_text` and `_parse_overlay` helpers read the file and parse YAML/JSON with graceful fallbacks when PyYAML is absent. |
| 36-44 | `_deep_merge` recursively merges nested dictionaries so profile overrides can target specific keys. |
| 47-84 | `OverlayConfig` dataclass defines integration payloads, toggle defaults, helper properties for required inputs/data directories, and `to_sanitised_dict()` masking logic. |
| 87-122 | `load_overlay()` resolves the path (including environment override), merges profile-specific data, applies default toggles/metadata, and returns a populated `OverlayConfig` instance. |
| 125 | `__all__` exposes the loader and dataclass for importers. |

## `simulations/cve_scenario/runner.py`

| Lines | Description |
| ----- | ----------- |
| 1-67 | Imports, risk-scorer resolver, CVE source constant, and `RunResult` dataclass exposing file paths and adjustment metadata. |
| 69-131 | `_load_contexts()` reads business-context fixtures and `_build_artifacts()` constructs synthetic SBOM/SARIF/CVE inputs for CVE-2021-44228. |
| 134-188 | `_ensure_overlay_for_mode()` replays the overlay merge logic so the runner can switch between Demo and Enterprise profiles without mutating the source file. |
| 189-200 | `_write_design_context()` exports a CSV of the scenario-specific design rows into the overlay’s `design_context_dir`. |
| 203-301 | `run_simulation()` loads the overlay, executes the pipeline orchestrator, applies contextual risk scoring (with per-mode scanner severities), and writes score/evidence JSON bundles. |
| 304-332 | CLI helpers parse `--mode`/`--overlay` flags and allow manual execution with structured JSON output. |
