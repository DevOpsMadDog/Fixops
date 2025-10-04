# Line-by-Line Commentary

This document summarises every meaningful line in the FixOps ingestion backend. Blank lines and
obvious imports are grouped for readability.

## `backend/app.py`

| Lines | Description |
| ----- | ----------- |
| 1-15 | Future import, stdlib modules, FastAPI primitives, local dependencies, and logger set-up. |
| 18-31 | `create_app()` initialises FastAPI with permissive CORS, instantiates the normaliser and orchestrator, and prepares `app.state` storage. |
| 33-36 | `_store()` helper centralises writing artefacts to `app.state.artifacts` with debug logging. |
| 38-55 | `/inputs/design` endpoint reads the uploaded CSV, strips empty rows, enforces non-empty payloads, stores the dataset, and returns metadata plus raw rows. |
| 57-74 | `/inputs/sbom` endpoint normalises SBOM bytes through `InputNormalizer.load_sbom`, stores the result, and returns metadata plus a preview of the first five components. Exceptions are wrapped in HTTP 400 responses. |
| 76-91 | `/inputs/cve` endpoint normalises CVE/KEV JSON, stores the canonical feed, and responds with record counts and validation errors. |
| 93-108 | `/inputs/sarif` endpoint loads SARIF JSON (including optional Snyk conversion), stores the result, and returns metadata alongside tool names. |
| 110-126 | `/pipeline/run` validates that all artefacts have been uploaded, invokes the orchestrator, and streams the correlation output. Missing artefacts trigger an HTTP 400 with a structured `missing` list. |

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
| 160-207 | `load_sbom` leverages `lib4sbom` to parse the document, builds `SBOMComponent` objects with defensive defaults, and compiles metadata counts. |
| 209-272 | `load_cve_feed` decodes JSON feeds that may be dicts or lists, validates entries with `cvelib` when available, normalises identifiers/title/severity, and records validation errors. |
| 274-324 | `load_sarif` parses JSON, optionally converts Snyk payloads to SARIF, instantiates `SarifLog`, extracts tool names/findings, and builds metadata counts. |

## `backend/pipeline.py`

| Lines | Description |
| ----- | ----------- |
| 1-18 | Imports, shared `_lower` helper, and class docstring. |
| 21-36 | `_extract_component_name` trims design row values across canonical keys. |
| 38-58 | `_build_finding_search_text` assembles a searchable string once per SARIF finding, handling non-serialisable targets gracefully. |
| 60-69 | `_build_record_search_text` mirrors the search-text logic for CVE records. |
| 71-79 | `_match_components` constructs a lowercase index of SBOM components for constant-time lookups. |
| 81-137 | `run()` builds the design list, precomputes lowercase tokens, indexes SBOM components, aggregates severity/exploitation statistics, and precomputes finding/CVE matches per token to avoid redundant scans. |
| 139-158 | Crosswalk assembly attaches matches to each design row and prepares the final response with summaries for every artefact. |

