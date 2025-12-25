## Enterprise Features

### Feature: Deduplication & Correlation Engine
- **Status**: Implemented
- **Scope**: Deduplicate + correlate findings/events across design/build/deploy/runtime; preserve raw inputs; emit grouped case objects referencing originals.

### API Enhancements / New APIs
- **APIs to enhance**
  - **`POST /pipeline/run`**
    - Adds `deduplication` summary + `cases` (grouped issue/case objects referencing original pipeline findings)
    - Gated by YAML overlay: `modules.correlation_engine.enabled`
  - **`POST /api/v1/analytics/findings`**
    - Computes + stores stable `fingerprint` and `correlation_key`
    - Deduplicates within configured time window (reuses existing finding; updates metadata `dedup.*`)
- **New APIs (only if unavoidable)**
  - **`GET /api/v1/analytics/cases`**
    - Required to retrieve grouped “case” objects from stored findings without re-running pipelines
- **CLI changes**
  - **`python -m core.cli analytics cases`**
    - Flags: `--severity`, `--status`, `--finding-limit`
- **YAML overlay changes**
  - **`modules.correlation_engine.enabled`** (existing)
  - **`modules.correlation_engine.dedup_window_seconds`** (optional)

---

### Feature: Integrations – Audit & Completion
- **Status**: Implemented (minimal skeleton completion)
- **Scope**: Classify existing connectors; complete missing integration types with config validation + API test support.

### API Enhancements / New APIs
- **APIs to enhance**
  - **`POST /api/v1/integrations/{id}/test`**
    - Adds support for `github`, `gitlab`, `pagerduty` integration types (configuration validation + details)
- **New APIs (only if unavoidable)**: None
- **CLI changes**: None
- **YAML overlay changes**
  - **`git.*`**, **`ci.*`** (existing sections; used for connector configuration via integration records)

