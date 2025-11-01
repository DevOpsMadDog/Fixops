# Architecture Inventory

This document captures the current FixOps repository layout, runtime entrypoints, data
models, automation workflows, and key dependencies. It is derived from a manual crawl of
the entire codebase, including API/CLI surfaces, enterprise services, docs, data, and CI
configuration.

## Runtime entrypoints & services

| Surface | Entrypoint | Purpose | Dependencies |
| --- | --- | --- | --- |
| CLI (demo + enterprise parity) | `core/cli.py` (`main()` via `fixops/__main__.py`) | Loads overlay configuration, normalises local artefacts with `apps.api.normalizers.InputNormalizer`, and executes the pipeline via `PipelineOrchestrator`, `StageRunner`, `ProcessingLayer`, and `EvidenceHub`. | Core modules (`core.configuration`, `core.overlay_runtime`, `core.storage`, `core.probabilistic`, `core.stage_runner`), enterprise services for run IDs/signing (`fixops-enterprise/src/services`). |
| FastAPI ingestion API | `apps/api/app.py:create_app` (re-exported by `backend/app.py`) | Exposes `/inputs/*` upload endpoints, `/pipeline/run`, feedback capture, chunked uploads, and enhanced decision APIs. Configures CORS, JWT/token auth, overlay-controlled data directories, analytics store, and enhanced decision engine. | `fastapi`, `core.analytics`, `core.storage.ArtefactArchive`, `core.enhanced_decision.EnhancedDecisionEngine`, `apps/api/pipeline.PipelineOrchestrator`, `apps/api/upload_manager.ChunkUploadManager`. |
| Enterprise API gateway | `fixops-enterprise/src/main.py:create_app` | Adds enterprise middleware (security headers, rate limiting, performance telemetry), schedules feed refresh jobs, and mounts `/api/v1` routes for evidence, marketplace, CI integrations, and enhanced decision telemetry. | `fastapi`, `structlog`, enterprise settings (`fixops-enterprise/src/config/settings.py`), routers (`fixops-enterprise/src/api/v1/*`), services (`fixops-enterprise/src/services/*`). |
| Enterprise services | `fixops-enterprise/src/services/*` | Hardened implementations for compliance rollups, evidence signing, marketplace recommendations, CI adapters, and enhanced decision orchestration. | `core.configuration`, `core.enhanced_decision`, `structlog`, signing helpers, compliance/marketplace services. |
| Knowledge graph augmentation | `new_apps/api/processing/knowledge_graph.py` | Optional pipeline enrichment that maps entities/relationships for enhanced decisioning. | `networkx`, contextual payloads from pipeline outputs. |
| Integrations toolkit | `integrations/github/adapter.py`, `integrations/jenkins/adapter.py`, `integrations/sonarqube/adapter.py` | Transform CI/SCM payloads into FixOps decision submissions and return verdicts/evidence manifests. | Enterprise decision engine (`fixops-enterprise/src/services/decision_engine.py`), `structlog`. |

## Core module breakdown

- **Configuration & overlays**
  - `core/configuration.py`, `core/overlay_runtime.py` load `config/fixops.overlay.yml`, merge profile overrides, and expose `OverlayConfig` with directory allowlists, auth tokens, feature toggles, enhanced decision settings, and runtime metadata. Data directories such as uploads, archive, analytics, and evidence are created via `core.paths.ensure_secure_directory`.【F:core/overlay_runtime.py†L1-L200】【F:config/fixops.overlay.yml†L1-L120】
  - Overlay metadata drives `core.paths.verify_allowlisted_path` and `core.storage.ArtefactArchive` to enforce secure persistence for evidence bundles and analytics exports.【F:core/paths.py†L1-L200】【F:core/storage.py†L1-L200】

- **Pipeline orchestration**
  - `apps/api/pipeline.py.PipelineOrchestrator` correlates design rows, SBOM components, SARIF findings, CVE summaries, CNAPP/VEX inputs, and optional business context. It invokes guardrail evaluations, compliance checks, SSPLC scoring, policy automation, AI agent analysis, probabilistic forecasts, exploitability insights, vector-store similarity, and custom overlay modules via `core.modules.execute_custom_modules`. Results are persisted to the archive and analytics store when run through the API.【F:apps/api/pipeline.py†L1-L400】【F:core/modules.py†L1-L160】
  - `core/stage_runner.StageRunner` and `core/demo_runner.run_demo_pipeline` orchestrate sequential stage execution for the CLI, coordinating run IDs (`fixops-enterprise/src/services/run_registry.py`), signing (`fixops-enterprise/src/services/signing.py`), and module enablement toggles.【F:core/stage_runner.py†L1-L200】【F:core/demo_runner.py†L1-L200】
  - Probabilistic forecasting lives in `core/probabilistic.py.ProbabilisticForecastEngine`, providing Dirichlet priors, Markov transitions, and entropy metrics over component severity. Exploit intelligence is computed in `core/exploit_signals.py.ExploitSignalEvaluator`. Vector similarity and AI agent analysis are handled by `core/vector_store.py` and `core/ai_agents.py` respectively.【F:core/probabilistic.py†L1-L200】【F:core/exploit_signals.py†L1-L200】【F:core/vector_store.py†L1-L160】【F:core/ai_agents.py†L1-L200】

- **Context, compliance, and policy**
  - `core/context_engine.py`, `core/compliance.py`, `core/policy.py`, `core/evidence.py`, `core/analytics.py`, `core/tenancy.py`, and `core/performance.py` enrich pipeline results with business context, compliance coverage, automation manifests, evidence bundles, telemetry, and ROI metrics. `core/design_context_injector.py` transforms design CSVs into SSVC priors using plugins from `ssvc/plugins`.【F:core/context_engine.py†L1-L200】【F:core/compliance.py†L1-L200】【F:core/design_context_injector.py†L1-L200】
  - SSDLC orchestration and IaC posture live in `core/ssdlc.py` and `core/iac.py`, enabling stage-by-stage assessments referenced by the CLI workflow and enterprise decision engine.【F:core/ssdlc.py†L1-L200】【F:core/iac.py†L1-L200】

- **Enhanced decision engine**
  - `core/enhanced_decision.py.EnhancedDecisionEngine` fuses deterministic guardrails with optional LLM providers, knowledge graph insights, and AI agent signals. Enterprise deployments wrap it via `fixops-enterprise/src/services/enhanced_decision_engine.EnhancedDecisionService` to expose reloadable capabilities, pipeline evaluation, and signal introspection APIs.【F:core/enhanced_decision.py†L1-L200】【F:fixops-enterprise/src/services/enhanced_decision_engine.py†L1-L160】

## Data models & persistence

- Normalised artefact structures (SBOM, SARIF, CVE, VEX, CNAPP, business context) live in
  `apps/api/normalizers.py`, `lib4sbom/parser.py`, and `apps/api/upload_manager.py`. These
  classes enforce deterministic metadata (component counts, severity breakdowns) used by the
  pipeline crosswalk and guardrail evaluations.【F:apps/api/normalizers.py†L1-L320】【F:lib4sbom/parser.py†L1-L160】【F:apps/api/upload_manager.py†L1-L200】
- Evidence manifests are stored by `core/evidence.EvidenceHub` and the enterprise
  `fixops-enterprise/src/services/evidence.EvidenceStore`, which adds signing via
  `fixops-enterprise/src/services/signing.py`. Archives and analytics payloads are persisted to
  overlay-governed directories under `data/` and `artefacts/` using `core/storage.ArtefactArchive`
  and `core/analytics.AnalyticsStore`. Data fixtures and feed snapshots live in `data/feeds/`,
  `simulations/`, and `artefacts/` for deterministic demos.【F:core/evidence.py†L1-L200】【F:fixops-enterprise/src/services/evidence.py†L1-L200】【F:data/FOLDER_README.md†L1-L80】【F:simulations/ssdlc/run.py†L1-L200】
- Knowledge graph and marketplace metadata are stored in `new_apps/api/processing/knowledge_graph.py`
  and `marketplace/docs/*.md`, powering enhanced decision explanations and ROI storytelling.【F:new_apps/api/processing/knowledge_graph.py†L1-L200】【F:marketplace/docs/FOLDER_README.md†L1-L80】

## Supporting infrastructure & tooling

- **Configuration & settings**: `config/fixops.overlay.yml` defines demo/enterprise modes, integration endpoints, policy toggles, AI agent settings, exploit signals, probabilistic priors, SSDLC requirements, and automation directories. Enterprise settings (`fixops-enterprise/src/config/settings.py`) expose environment-driven controls for production deployments.【F:config/fixops.overlay.yml†L1-L120】【F:fixops-enterprise/src/config/settings.py†L1-L200】
- **Scripts & automation**: `scripts/` hosts bootstrap, demo runners, stage workflows, inventory generators, and analysis tooling. Historical workflows and experiments live under `WIP/` and `analysis/`. Auto-generated repo indices sit in `index/`.【F:scripts/run_demo_steps.py†L1-L200】【F:analysis/TRACEABILITY.csv†L1-L1】【F:index/FOLDER_README.md†L1-L80】
- **Docs & reports**: `docs/` collects architecture, data model, configuration, runbooks, and strategy references. `audit/`, `reports/`, `reviews/`, and `analysis/` provide assessments, deep dives, and traceability for governance stakeholders.【F:docs/ARCHITECTURE.md†L1-L80】【F:audit/SECURITY.md†L1-L80】【F:reports/deep_review/gaps.json†L1-L80】
- **Fixtures & simulations**: `fixtures/`, `simulations/`, `artefacts/`, and `data/` offer deterministic datasets for CLI, API, and CI workflows. `simulations/ssdlc/run.py` can regenerate lifecycle artefacts via the Makefile `sim` target.【F:simulations/ssdlc/run.py†L1-L200】【F:Makefile†L1-L120】

## Workflows & quality gates

- GitHub Actions workflows:
  - `.github/workflows/ci.yml` enforces formatting (black/isort), lint (flake8), pytest coverage, and optional demo runs on selected branches. It also uploads decision artefacts on pushes.【F:.github/workflows/ci.yml†L1-L160】
  - `.github/workflows/fixops-ci.yml` provisions a virtualenv, compiles modules, runs API regression flows with curl uploads, executes CLI enterprise runs, operations simulations, and pytest. Secrets provide API tokens and signing keys for integration validation.【F:.github/workflows/fixops-ci.yml†L1-L160】
- Local automation uses the `Makefile` to bootstrap environments, run formatting/lint/test suites, execute demos, regenerate inventories, and clean artefacts. Pytest is configured via `pytest.ini` to target enterprise services, integrations, and simulations with coverage gates. Type checking is configured in `mypy.ini`.【F:Makefile†L1-L160】【F:pytest.ini†L1-L80】【F:mypy.ini†L1-L40】

## Dependencies

- **Core requirements** (`requirements.txt`): `fastapi`, `pydantic`, `PyJWT`, `cryptography`, `structlog`, `pgmpy`, `networkx`, `PyYAML`, and `requests` underpin API routing, configuration, probabilistic modelling, and graph analytics.【F:requirements.txt†L1-L11】
- **Developer tooling** (`requirements.dev.txt`): `black`, `isort`, `flake8`, `mypy`, `pytest-cov`, and `pre-commit` enforce code quality. Git hooks are configured via `.pre-commit-config.yaml`.【F:requirements.dev.txt†L1-L8】【F:.pre-commit-config.yaml†L1-L160】
- **Optional extras**: `apps/api/requirements-optional.txt` (Snyk SARIF converter, ChromaDB, sentence-transformers) and `backend/requirements-optional.txt` (lib4sbom) unlock advanced parsing and vector search capabilities when credentials are available.【F:apps/api/requirements-optional.txt†L1-L80】【F:backend/requirements-optional.txt†L1-L20】
- **Front-end**: The `frontend` symlink targets `/app/fixops-blended-enterprise/frontend` but is currently broken in this workspace; enterprise React assets are expected in downstream deployments. No runtime JavaScript is bundled in the repo snapshot.【F:frontend†L1-L1】

## Testing surface

- Unit and integration tests under `tests/` validate overlay loading, pipeline matching, evidence export, rate limiting, CLI commands, knowledge graph processing, and enterprise enhanced API routes. Supplemental smoke tests (`backend_test.py`, `test_frontend.py`, `real_components_test.py`) provide targeted checks outside the `tests/` package.【F:tests/test_pipeline_matching.py†L1-L200】【F:backend_test.py†L1-L80】【F:real_components_test.py†L1-L200】
- Fixtures for tests reside in `fixtures/` and `simulations/demo_pack/`, while SQLite sample data lives in `fixops_enterprise.db` for enterprise features.【F:fixtures/FOLDER_README.md†L1-L80】【F:fixops_enterprise.db†L1-L1】

## Observations & gaps

- The enterprise React frontend is not present locally (symlink target missing), so front-end changes must be coordinated with the downstream repository.
- Scripts in `WIP/` and legacy enterprise code exist but are not wired into the active pipelines; treat them as references when planning modernization.
- Secrets are expected to be provided via environment variables or GitHub Actions secrets; no secrets are stored in the repo.
