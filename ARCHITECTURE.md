# FixOps Architecture Overview

## High-level layers
- **Apps / API (`apps/api/`)**: FastAPI ingestion service exposing upload and orchestration endpoints.
- **Core (`core/`)**: Reusable analytics, guardrails, compliance, and evidence utilities consumed by the API, CLI, and enterprise stack.
- **Enterprise (`enterprise/`)**: Full reference deployment including React frontend, database migrations, Terraform/IaC, and operational scripts.
- **Prototypes (`prototypes/decider/`)**: Archived decision-engine experiments kept for research purposes.

## Data flow
1. **Uploads** – Clients send design CSV, SBOM, SARIF, and CVE feeds to `/inputs/*` (validated, streamed, and stored).
2. **Pipeline orchestration** – `PipelineOrchestrator` (core modules) correlates artefacts, evaluates guardrails, compliance, SSDLC, policy automation, and analytics.
3. **Evidence & analytics** – Results are persisted via `core.evidence.EvidenceHub` and summarised for ROI dashboards.
4. **Exploit intelligence** – `core.exploit_signals` enriches CVE feeds with KEV/EPSS data, optionally refreshed daily via APScheduler.
5. **Enterprise adapters** – `enterprise/src/services` extend the pipeline with multi-tenant APIs, marketplace integrations, and enhanced dashboards.

## Key decisions
- **Overlay-driven configuration** – `config/fixops.overlay.yml` controls modules, thresholds, and data directories; caching avoids redundant disk reads.
- **Atomic evidence handling** – Evidence bundles are written atomically and can be compressed or encrypted per overlay.
- **Security posture** – CORS origins and JWT secrets are environment-driven, upload size limits enforced per stage, and exploit feeds refresh with retries and logging.
- **Extensibility** – Custom modules integrate via `core.modules.execute_custom_modules`, receiving a `PipelineContext` enriched with compliance results.

## Running modes
- **Demo** – Local fixtures showcase ingestion and pipeline without external dependencies.
- **Enterprise** – Full stack in `enterprise/` supports SQLite/Postgres, React dashboards, and IaC deployments.
- **Simulations** – `simulations/ssdlc/` provides deterministic SSDLC scenarios for workshops and QA.
