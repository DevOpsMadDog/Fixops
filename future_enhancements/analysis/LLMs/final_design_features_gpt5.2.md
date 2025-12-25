# FixOps – Final Feature Design

## 1. Current State Summary
- **Codebase / core pipeline**
  - **Artifact normalization**: `apps/api/normalizers.py` normalizes SBOM/SARIF/CVE (+ VEX, CNAPP, business context). Existing dedup is **local and format-specific**:
    - SBOM: deduplicates vulnerabilities primarily by `id`.
    - CVE feed: deduplicates by `cve_id` and keeps “best” severity/exploited variant.
    - VEX: suppresses SARIF findings for components matching suppressed refs.
  - **Correlation today**: `apps/api/pipeline.py` builds a **design-row “crosswalk”** by substring token matching against SBOM component names, SARIF finding text, and CVE record text (`services/match/*`). This correlates “to design rows”, not “across sources/stages/runs”.
  - **Existing identity/fingerprinting primitives (not wired into main pipeline)**:
    - `core/services/identity.py` computes `correlation_key` and `fingerprint` and resolves `app_id/component_id/asset_id`.
    - `core/services/history.py` stores findings keyed by `correlation_key` for cross-run history/learning.
    - `scripts/demo_orchestrator.py` demonstrates using the above (identity + history), but this is not the canonical runtime path.
  - **Enterprise correlation engine exists but is siloed**:
    - `fixops-enterprise/src/services/correlation_engine.py` provides multi-strategy correlation (fingerprint/location/pattern/root-cause/vulnerability) behind a feature flag. It is not integrated into the `apps/api` pipeline output.
  - **Graph outputs exist**:
    - `apps/api/app.py` builds simplified `/api/v1/graph` and `/api/v1/triage` views from `crosswalk`.
    - `backend/api/graph/router.py` serves a file-backed graph derived from SBOM/risk/provenance sources (separate from the pipeline crosswalk).

- **API surface (relevant to these features)**
  - **Ingestion**: `/inputs/{design|sbom|sarif|cve|vex|cnapp|context}` + chunked upload endpoints in `apps/api/app.py`.
  - **Pipeline execution**: `/pipeline/run` returns `crosswalk`, severity summaries, optional modules outputs (evidence, compliance, analytics, enhanced decision, etc.).
  - **“Triage / graph views”**: `/api/v1/triage`, `/api/v1/graph` are **derived views**, currently without stable dedup/correlation identifiers.
  - **Integrations API**: `apps/api/integrations_router.py` exposes CRUD/test/sync for stored integrations (`core/integration_db.py`, `core/integration_models.py`). “Sync” is currently a stub (updates timestamps/status without real IO).
  - **Legacy bridge**: `apps/api/legacy_bridge_router.py` selectively exposes legacy routers; it explicitly calls out missing/disabled modules due to dependencies, implying intended but incomplete areas (notably CI/CD and scan ingestion in legacy).

- **CLI surface**
  - **Primary CLI**: `core/cli.py` (argparse) is the functional CLI referenced by the repo docs; it loads overlay via `core.overlay_runtime.prepare_overlay` and supports `--overlay` plus runtime env overrides, and `show-overlay`.
  - **Secondary CLI**: `cli/` (click) appears to be a smaller/demo CLI and is not the feature-complete path.
  - **Integrations CLI commands**: `core/cli.py integrations …` stores to a **separate local SQLite** (`.fixops_data/fixops.db`) with default entries and stubby `test/sync` behavior; it is not unified with `apps/api` IntegrationDB nor with `core/connectors.py`.

- **YAML / overlay patterns**
  - **Single canonical overlay**: `config/fixops.overlay.yml` with strict top-level keys validated in `core/configuration.py`.
  - **Profiles**: `mode` selects a profile; profiles are merged via deep-merge at load.
  - **Extensibility point**: `modules.*` is a flexible namespace for new module flags/config without needing new top-level overlay keys (important for adding correlation config safely).
  - **Feature flags**: local overlay-based flag provider exists (`core/flags/*`) and can override module enablement.

- **Existing strengths**
  - Clear ingestion pipeline, normalized artefact models, modular pipeline “modules” pattern, evidence packaging, and a working policy automation connector layer for Jira/Confluence/Slack.
  - Concrete building blocks for correlation already exist (identity resolver + history store + enterprise correlation engine), but are not unified.

- **Existing gaps**
  - No unified, stable **canonical finding/event identity** across sources/stages/runs.
  - Correlation is primarily “design token matching” and does not produce durable dedup clusters, edges, or feedback loops to reduce false positives over time.
  - Integrations are fragmented across (a) overlay-driven policy connectors, (b) IntegrationDB CRUD API, and (c) CLI-local integration table; several integration types are declared but not operational.

## 2. Feature 1: Deduplication & Correlation Engine

### 2.1 Problem Statement
- FixOps currently ingests multiple signal sources but lacks a consistent mechanism to:
  - **Deduplicate** repeated/reformatted findings across runs and tools.
  - **Correlate** related findings/events across **design/build/deploy/runtime** stages.
  - **Explain** why two items were grouped (auditability) and allow safe correction when wrong.

### 2.2 Design Goals
- **Reuse-first**: leverage existing normalized artefact types (`SarifFinding`, `CVERecordSummary`, CNAPP normalized types, Pentagi models) and existing correlation building blocks (`IdentityResolver`, `RunHistoryStore`, enterprise `CorrelationEngine` strategies).
- **Deterministic IDs**: produce stable identifiers for “same issue” across time and sources.
- **Low false-positive rate**: correlation must be conservative by default; allow operator feedback to split/merge.
- **Stage-aware**: represent when a signal was observed (design/build/deploy/runtime) and correlate across stages without collapsing unrelated issues.
- **Explainable**: every dedup/correlation decision records “why” (strategy, fields used, confidence).
- **Backward compatible**: existing `/pipeline/run`, `/api/v1/triage`, `/api/v1/graph` outputs remain usable; new fields are additive and gated by overlay/module flags.

### 2.3 Canonical Finding/Event Model
- **Conceptual split**
  - **Event**: a single observation from a source at a time (scanner record, CNAPP alert, Pentagi result, API-ingested item, CLI-generated item).
  - **Finding Cluster**: a deduplicated “issue identity” aggregating one or more Events; used for triage, history, and integrations.

- **Canonical Event (derived from existing normalized types)**
  - **Identity**
    - `event_id`: unique per ingestion (UUID)
    - `source_type`: one of `sarif|cve|sbom_vuln|cnapp|pentagi|api|cli`
    - `source_tool`: tool/provider name where available (e.g., SARIF tool name, CNAPP vendor)
    - `stage`: `design|build|deploy|runtime` (required; inferred when absent)
    - `observed_at`: timestamp (ingestion time if source time missing)
  - **Asset scope (normalized)**
    - `org_id`, `app_id`, `component_id`, `asset_id` (use `core/services/identity.py` resolution rules; allow mapping overrides)
    - `environment`: `dev|staging|prod|unknown` (esp. runtime/deploy)
  - **Issue signature fields (normalized, sparse)**
    - `category`: high-level category (sast/sca/iac/secrets/runtime/cnapp/pentest/other)
    - `cve_id` (if applicable), `cwe_id` (if available)
    - `rule_id` (SAST/IaC/secrets rules)
    - `package_purl` or `package_name@version` (SCA/SBOM)
    - `resource_id` (CNAPP/runtime cloud resources)
    - `location`: `{path, line_start?, line_end?, function?}` for code-backed signals
  - **Scoring & status (optional on event)**
    - `severity` (normalized `low|medium|high|critical`)
    - `confidence` (0–1 if provided)
    - `exploitability`: fields aligned with Pentagi + EPSS/KEV signals (`verified`, `epss`, `kev`, etc.)
  - **References**
    - `run_id` (pipeline run), `artifact_refs` (evidence bundle id, upload stage record ids)
    - `raw_ref`: pointer to stored raw payload (not embedded), plus minimal display snippet

- **Canonical Finding Cluster**
  - `cluster_id`: stable identifier (see correlation key rules below)
  - `primary_key`: the deterministic correlation key (“what this cluster is”)
  - `summary`: title, normalized severity, first_seen/last_seen, counts by source_type/stage
  - `members`: list of `event_id`s (or a paginated view)
  - `explanation`: why this cluster exists and why members are included (strategy + confidence)

### 2.4 Deduplication Strategy
- **Tier 0: strict normalization**
  - Normalize paths, URLs, resource IDs, package identifiers, rule IDs, and CVE casing.
  - Explicitly ignore “noise fields”: timestamps, scan IDs, transient resource suffixes, line numbers (except as proximity signal), UUID-like fields, ordering differences.

- **Tier 1: deterministic correlation key (primary)**
  - Base design on `core/services/identity.py::compute_correlation_key`, but require stage-aware inputs and source-specific rules.
  - **Key construction (conceptual)**: hash of a canonical tuple:
    - `category`, `stage`, `app_id`, `component_id`, and one of:
      - **SCA/CVE**: `cve_id + package_purl (or component purl/name)`
      - **SAST**: `rule_id + normalized_file_path (+ stable snippet hash if available)`
      - **CNAPP**: `policy_id/rule_id + normalized_resource_id`
      - **Pentagi**: `target + vulnerability_type + (cwe_id|cve_id|rule_id)`
  - **Guardrail**: do not mix different `app_id` (unless explicit mapping says shared service) and do not merge across `stage` unless an explicit cross-stage rule is satisfied (below).

- **Tier 2: fingerprint (secondary, for “same content different location”)**
  - Reuse `core/services/identity.py::compute_fingerprint` but make it source-aware:
    - Prefer `rule_id/cve_id/cwe_id` + stable title/message fragments over full descriptions.
    - Add tool namespace to avoid collisions across scanners.
  - Fingerprints are used to propose merges, not to auto-merge by default.

- **Tier 3: cautious fuzzy merges (opt-in via overlay)**
  - Reuse the enterprise correlation strategies already implemented in `fixops-enterprise/src/services/correlation_engine.py`, but apply strict safety constraints:
    - **Hard constraints**: must share `app_id`, and either share `component_id` or share `package_purl/resource_id`.
    - **Soft constraints**: location proximity and rule pattern may raise confidence but cannot override hard constraints.
  - Output “merge suggestions” with confidence; default action is **no merge** unless above threshold and hard constraints satisfied.

- **Cross-stage dedup rules (design/build/deploy/runtime)**
  - Allowed cross-stage equivalence only when anchored by a stable “thing”:
    - **Dependency** anchored: SBOM vulnerability ↔ CVE feed record ↔ deploy image scan ↔ runtime exploit signal by `cve_id + package_purl`.
    - **Resource** anchored: CNAPP runtime alert ↔ deploy IaC misconfig ↔ runtime telemetry by `resource_id + policy_id`.
    - **Code** anchored: build SAST ↔ deploy SAST rerun ↔ runtime WAF alert by `rule_id + normalized_route/function + service` (requires explicit mapping; default off).

### 2.5 Correlation Strategy
- **Output is a graph of clusters + evidence**
  - Reuse existing knowledge-graph approach in `apps/api/pipeline.py` and extend it with new node/edge types rather than replacing it.

- **Nodes**
  - `service` / `component` (existing concept from design rows + SBOM)
  - `finding_cluster` (new)
  - `event` (optional; include only when requested)
  - `cve` (existing in graph output today as an issue node; can become an attribute or a node depending on UI needs)
  - `evidence_bundle` (existing evidence module output)
  - `pentagi_result` (existing Pentagi DB model output)

- **Edges (minimum set)**
  - `service -> component` (existing)
  - `component -> finding_cluster` (impacted_by / has_issue)
  - `finding_cluster -> event` (observed_as)
  - `finding_cluster -> finding_cluster` (related_to with reason: root_cause, shared_cve, shared_asset, attack_path, etc.)
  - `finding_cluster -> pentagi_result` (verified_by)
  - `finding_cluster -> evidence_bundle` (supported_by)
  - `finding_cluster -> suppression` (suppressed_by via VEX/policy)

- **Correlation confidence**
  - Provide per-edge confidence and strategy metadata.
  - Never hide raw inputs: keep ability to expand from cluster to events.

### 2.6 API Enhancements / New APIs
- **Existing APIs to enhance (path + change)**
  - **`/pipeline/run`** (in `apps/api/app.py` / `apps/api/pipeline.py`)
    - Add `dedup_summary` (counts, noise reduction, top clusters).
    - Add per-item identifiers to `crosswalk[*].findings[*]`, `crosswalk[*].cves[*]`, and CNAPP summaries:
      - `event_id`, `cluster_id`, `correlation_key`, `fingerprint`, `stage`, `source_type`.
    - Add `correlation_graph` (nodes/edges) as an additive section (or embed into `knowledge_graph`).
  - **`/api/v1/triage`**
    - Default remains “one row per raw item” for backward compatibility.
    - Add query mode: `view=clusters|events` (default `events`) to return deduped cluster rows when requested.
  - **`/api/v1/graph`**
    - Add query param `include=clusters|events|both` and return stable IDs for nodes/edges.
  - **`/api/v1/pentagi/*`**
    - When returning pen-test results, include `cluster_id` links where the `finding_id` maps to a cluster (if known).

- **New APIs (only if unavoidable)**
  - **`/api/v1/correlation/clusters`**: list/search clusters (by app/component/cve/rule/severity/status).
  - **`/api/v1/correlation/clusters/{cluster_id}`**: cluster detail + member events (paged).
  - **`/api/v1/correlation/feedback`**: record operator feedback (`merge_allowed`, `merge_blocked`, `split_cluster`) to reduce future false positives.
  - Rationale: current API has no stable surface for cluster lifecycle and feedback without overloading unrelated routers.

### 2.7 CLI Changes
- **Reuse-first**: extend existing `core/cli.py` pipeline commands rather than creating a new CLI entrypoint.
- **`run` / `analyze` / `make-decision`**
  - Add optional flags:
    - `--dedup` / `--no-dedup` (default inherits overlay module enablement)
    - `--triage-view clusters|events` (mirrors API behavior)
    - `--correlation-db PATH` (opt-in persistent store location; defaults to overlay data dir)
    - `--print-clusters` (summary output for CI logs)
- **New command group (minimal)**
  - `correlation clusters list|get`
  - `correlation feedback merge|block|split`
  - `correlation stats`

### 2.8 YAML Overlay Changes
- **Use `modules.correlation_engine` (already present in `config/fixops.overlay.yml`)**
  - Extend it with configuration-only keys (no new top-level overlay keys required):
    - `enabled`: bool (existing)
    - `strategies`: list (existing)
    - `noise_reduction_target`: float (existing)
    - `thresholds`: `{auto_merge: 0.xx, suggest_merge: 0.yy}`
    - `constraints`: `{require_same_app: true, require_same_component_or_anchor: true}`
    - `anchors`: `{allow_cross_stage_by_cve_purl: true, allow_cross_stage_by_resource: false, allow_code_to_runtime: false}`
    - `identity_mappings_path`: path to a mapping file (e.g., `configs/overlay_mappings.yaml`)
    - `storage`: `{provider: sqlite, path: data/correlation.db}`
    - `retention_days`: for event retention vs cluster retention

### 2.9 Risks & Mitigations
- **False-positive correlation (over-merging)**
  - Mitigation: hard constraints on `app_id` + anchor identity, conservative defaults, and explicit feedback endpoints.
- **Scanner drift / message churn**
  - Mitigation: stable key fields (CVE/purl/rule_id/path), normalization rules, and versioned fingerprinting.
- **Performance regression**
  - Mitigation: tiered pipeline (deterministic first), indexed storage, batch operations, and opt-in event expansion.
- **Backward compatibility**
  - Mitigation: additive fields only; default views unchanged unless overlay enables module; keep raw crosswalk arrays.

## 3. Feature 2: Integrations

### 3.1 Integration Inventory (Stub / Partial / Complete)
- **Jira (outbound ticket creation)**
  - **Complete**: `core/connectors.py::JiraConnector` creates issues via REST; used by `core/policy.py` (policy automation).
  - **Partial**: `apps/api/integrations_router.py` can store/test Jira configs, but does not implement real “sync” semantics.
  - **Stub**: `core/cli.py integrations test/sync` are local, non-network stubs.

- **Confluence (outbound documentation)**
  - **Complete**: `core/connectors.py::ConfluenceConnector` creates pages via REST; used by policy automation.
  - **Partial**: stored/tested via integrations API; “sync” stub.
  - **Stub**: CLI integrations flow is local only.

- **Slack (outbound notifications)**
  - **Complete**: `core/connectors.py::SlackConnector` posts webhooks; used by policy automation.
  - **Partial**: stored/tested via integrations API; “sync” stub.
  - **Stub**: CLI integrations flow is local only.

- **Pentagi (micro-pentest platform)**
  - **Partial to Complete (environment-dependent)**:
    - `integrations/pentagi_client.py` + `integrations/pentagi_service.py` provide a real async client/service model.
    - `apps/api/pentagi_router_enhanced.py` persists configs/requests/results in SQLite and can trigger/monitor tests (requires a reachable Pentagi service).
  - **Stub (duplicate legacy)**: `backend/api/pentagi/router.py` is an in-memory demo router; not a real integration.

- **Integration CRUD framework**
  - **Partial**: `core/integration_db.py` + `core/integration_models.py` + `apps/api/integrations_router.py` implement storage + basic operations, but do not provide functional connectors for `github/gitlab/pagerduty` types yet.

- **Other enterprise integration stubs / implied**
  - **Stub/unused**: `apps/api/integrations.py` contains many integration classes (Splunk/QRadar/ServiceNow/GitHub) but is not the active connector path for the running API/pipeline.
  - **Implied but missing**: legacy bridge explicitly lists CI/CD + scan routers as not bridged due to dependencies, suggesting intended CI/CD ingest and scan management are incomplete.

### 3.2 Missing Critical Integrations
Based on declared integration types and repository intent, the minimal “must-have” gaps are:
- **SCM gating + feedback**: GitHub/GitLab (commit/PR status, PR comments with cluster IDs, attach evidence links).
- **CI/CD ingestion**: GitHub Actions / GitLab CI / Jenkins webhook-driven runs that push artifacts to existing `/inputs/*` and trigger `/pipeline/run`.
- **Enterprise ticketing**: ServiceNow (create/update incidents for high-confidence clusters).
- **On-call alerting**: PagerDuty (create incident/trigger event for “block” verdict clusters).
- **SIEM forwarding**: Splunk/QRadar (ship correlated cluster events + decisions, not raw noise).

### 3.3 Design for Completion
- **Unify the “three integration systems” into one conceptual model**
  - **System of record**: `IntegrationDB` records integration instances and status.
  - **Execution layer**: connector implementations (Jira/Confluence/Slack already exist in `core/connectors.py`; extend similarly for GitHub/GitLab/PagerDuty/ServiceNow/Splunk).
  - **Secrets model**: DB stores references (e.g., `token_env`) rather than raw secrets; overlay can provide defaults.

- **Minimum viable connector capabilities (per integration type)**
  - **Test**: validate configuration + auth (no side effects).
  - **Deliver**: send one outbound action (ticket/comment/status/alert) with idempotency keys derived from `cluster_id`.
  - **Sync** (redefined minimally): refresh “last known” metadata (rate limits, project/space existence) and update `last_sync_status` with real results (not a synthetic success).

- **Correlation-first payloads**
  - All outbound integrations should operate on **cluster-level** payloads:
    - stable `cluster_id`, severity, verdict, affected app/component, top evidence refs, and a link back to cluster/event detail endpoints.
  - Raw events are optionally attached as “appendix” only when explicitly requested.

### 3.4 API / CLI / YAML Implications
- **API**
  - Enhance `apps/api/integrations_router.py`:
    - Implement real `test` for `github/gitlab/pagerduty` (auth + basic resource existence).
    - Implement real `sync` semantics (no-op is not acceptable for “complete”).
    - Add “deliver sample payload” endpoint (optional) for operator verification.
  - Add integration-driven ingestion endpoints only if needed:
    - Webhook endpoint that accepts (a) run metadata + stage + artifact URLs, or (b) direct artifact uploads and then triggers `/pipeline/run`.

- **CLI**
  - Keep `core/cli.py integrations …` but make it a thin client over the API or reuse `IntegrationDB` schema to avoid a parallel local DB.
  - Add optional `--cluster-id` targeting for “send to integration” actions (e.g., send Jira issue for a cluster).

- **YAML**
  - Prefer existing allowed top-level sections for provider configuration:
    - `git:` for SCM providers (GitHub/GitLab) and webhook settings.
    - `ci:` for CI/CD provider settings and artifact naming conventions.
    - Keep delivery actions under `policy_automation.actions` (already implemented and validated).
  - For new settings, nest under existing keys or `modules.*` to avoid breaking strict overlay key validation.

### 3.5 Risks & Mitigations
- **Secrets leakage (DB/config)**
  - Mitigation: store only env-var references in DB, keep sanitization on all API responses (already modeled in `Integration.to_dict`).
- **Rate limits / retries**
  - Mitigation: idempotency via `cluster_id`, exponential backoff, and connector-level circuit breakers.
- **Fragmentation between “policy actions” and “integration CRUD”**
  - Mitigation: define a single Integration registry and have policy automation reference integration IDs/types rather than ad-hoc config copies.

## 4. Non-Goals
- Building a full “data lake” or long-term multi-tenant warehouse for all raw events (beyond minimal SQLite persistence).
- Replacing existing pipeline modules (evidence, compliance, probabilistic, enhanced decision); this feature only adds stable identity + correlation outputs that those modules can consume.
- Aggressive ML/LLM-based clustering as the default (allowed only as opt-in suggestions).
- UI redesigns or new micro-frontends.
- Pull-based polling integrations for every vendor; prioritize push-model ingestion and minimal outbound actions.

## 5. Implementation Readiness Checklist
- **Model agreement**
  - Canonical Event + Cluster schemas finalized, including required fields per source_type and stage.
  - Deterministic key rules documented and versioned (so fingerprints can evolve safely).
- **Compatibility**
  - Confirm additive-only changes to `/pipeline/run` and triage/graph outputs; legacy consumers remain functional.
  - Overlay config approach validated: new settings live under `modules.correlation_engine` (no new top-level keys).
- **Storage**
  - Decide persistence target (reuse `core/services/history.py` DB vs a dedicated correlation DB) and index plan.
  - Retention rules and size limits defined for demo vs enterprise modes.
- **Safety**
  - False-positive guardrails and feedback loop semantics defined (merge blocked, split cluster, override mapping).
- **Performance**
  - Budget targets set (e.g., correlation adds < X ms per run for Y events) and batching strategy chosen.
- **Integrations completion**
  - Single integration registry chosen (API IntegrationDB) and CLI alignment plan established.
  - Minimal “test/deliver/sync” semantics defined per critical integration type (GitHub/GitLab/PagerDuty/ServiceNow/SIEM).

