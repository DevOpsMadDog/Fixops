# Line-by-Line Commentary

This commentary highlights the meaningful sections of the FixOps ingestion backend. Blank lines and
obvious imports are grouped for readability.

## `apps/api/app.py`

| Lines | Description |
| ----- | ----------- |
| 1-18 | Imports, logger setup, and helper wiring for overlay, feedback recorder, and security utilities. |
| 21-61 | `create_app()` initialises FastAPI, configures CORS, loads the overlay, resolves API-key expectations, and provisions allowlisted data directories (including optional feedback archives). |
| 62-97 | `_read_limited` and `_validate_content_type` enforce per-stage upload caps and reject unsupported MIME types before parsing. `_store()` centralises artefact caching. |
| 102-178 | `/inputs/design`, `/inputs/sbom`, `/inputs/cve`, and `/inputs/sarif` all require the API key, validate content types, stream within overlay byte limits, normalise payloads, and return preview metadata. |
| 179-210 | `/pipeline/run` enforces overlay-required artefacts, validates Jira sync requirements, executes the orchestrator, and appends masked overlay metadata when toggled. |
| 211-220 | `/feedback` honours the `capture_feedback` toggle and persists JSONL decisions via the feedback recorder. |

## `apps/api/normalizers.py`

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

## `apps/api/pipeline.py`

| Lines | Description |
| ----- | ----------- |
| 1-32 | Imports, severity constants, and class docstring. |
| 35-73 | `_extract_component_name`, `_build_finding_search_text`, `_build_record_search_text`, and `_match_components` construct design tokens and component lookups. |
| 75-133 | Severity helpers normalise SARIF levels and CVE severities, resolve threshold rankings, and prepare guardrail evaluation utilities. |
| 135-229 | `run()` builds the design list, precomputes lowercase tokens, indexes SBOM components, aggregates severity/exploitation statistics (including per-source counts), computes the maturity-aware guardrail evaluation when an overlay is provided, and precomputes finding/CVE matches per token using `defaultdict` caches to avoid redundant scans. |
| 231-360 | Crosswalk assembly attaches matches to each design row, prepares summaries, evaluates guardrails, invokes the context engine/onboarding/compliance/policy modules, executes the AI Agent Advisor, persists evidence bundles, and attaches pricing metadata. |

## `core/configuration.py`

| Lines | Description |
| ----- | ----------- |
| 1-58 | Module docstring, imports, constants, YAML/JSON parsing, and deep-merge helper. |
| 61-107 | `_OverlayDocument` Pydantic schema enumerates allowed top-level keys (including limits and AI sections) and rejects unexpected fields; `_resolve_allowlisted_roots` honours `FIXOPS_DATA_ROOT_ALLOWLIST`. |
| 109-143 | `OverlayConfig` dataclass now tracks limits, AI agent settings, allowlisted data roots, and resolved API tokens alongside existing integration metadata. |
| 146-233 | Helper properties compute required inputs, resolve and validate data directories against the allowlist, mask secrets, and derive guardrail/context/evidence/policy/compliance/pricing settings. |
| 234-281 | `upload_limit()` interprets stage-specific caps. `load_overlay()` validates via Pydantic, merges profile overrides, sets defaults (`include_overlay_metadata_in_bundles`), resolves API keys, enforces env-var presence, and validates directories immediately. |
| 283 | `__all__` exposes the loader and dataclass for importers. |

## `core/feedback.py`

| Lines | Description |
| ----- | ----------- |
| 1-21 | Imports and class definition. Constructor resolves the feedback directory (falling back to evidence dir) and ensures it exists. |
| 22-49 | `_validate_payload` enforces required keys (`run_id`, `decision`), normalises optional metadata, and guards against invalid types. |
| 51-61 | `record()` writes validated entries to `<feedback_dir>/<run_id>/feedback.jsonl` and returns a manifest used by the API response. |

## `core/ai_agents.py`

| Lines | Description |
| ----- | ----------- |
| 1-28 | Helper functions and `FrameworkSignature` dataclass capture watchlist entries (name, keywords, optional threat profile). |
| 31-76 | `AIAgentAdvisor.__init__` normalises signatures, control mappings, playbooks, and watchlist version metadata. |
| 78-121 | Private helpers `_match_frameworks`, `_controls_for`, and `_playbooks_for` identify relevant signatures, merge default/specific controls, and select playbooks. |
| 123-162 | `analyse()` scans design crosswalk entries, detects signature hits, aggregates matches, and returns a summary plus per-component recommendations when agents are detected. |

## `simulations/cve_scenario/runner.py`

| Lines | Description |
| ----- | ----------- |
| 1-75 | Imports, risk-scorer resolver, CVE source constant, and `RunResult` dataclass exposing file paths, adjustment metadata, and guardrail status. |
| 77-139 | `_load_contexts()` reads business-context fixtures and `_build_artifacts()` constructs synthetic SBOM/SARIF/CVE inputs for CVE-2021-44228. |
| 142-196 | `_ensure_overlay_for_mode()` replays the overlay merge logic so the runner can switch between Demo and Enterprise profiles without mutating the source file. |
| 198-209 | `_write_design_context()` exports a CSV of the scenario-specific design rows into the overlay’s `design_context_dir`. |
| 212-321 | `run_simulation()` loads the overlay, executes the pipeline orchestrator (capturing guardrail evaluations), applies contextual risk scoring (with per-mode scanner severities), and writes score/evidence JSON bundles annotated with guardrail and severity overviews. |
| 324-352 | CLI helpers parse `--mode`/`--overlay` flags and allow manual execution with structured JSON output. |
