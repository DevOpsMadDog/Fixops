# FixOps Contextual Risk & Evidence Platform

FixOps turns raw security artefacts into contextual risk, compliance, and automation outputs in minutes. A lightweight FastAPI service and a parity CLI accept push-style uploads, hydrate an overlay-driven pipeline, and emit guardrail verdicts, context summaries, evidence bundles, pricing signals, and automation manifests that match demo or enterprise guardrails without code changes.

| What it does | One command demo | Where to dig deeper |
| --- | --- | --- |
| **Ingest → Normalise → Correlate → Score → Prove.** Upload design, SBOM, SARIF, and CVE feeds, then let the orchestrator stitch context, guardrails, probabilistic risk, and evidence bundles in a single pass. | ```bash\ndocker compose -f docker-compose.demo.yml up -d\n``` Visit [http://localhost:8000/docs](http://localhost:8000/docs) for the interactive API and use `python -m core.cli demo --mode demo` for the CLI mirror. | - [Architecture (canonical)](docs/ARCHITECTURE.md)  \n- [Developer handbook](readme_updated.md)  \n- [SBOM quality](docs/SBOM-QUALITY.md)  \n- [Risk scoring](docs/RISK-SCORING.md)  \n- [Provenance](docs/PROVENANCE.md)  \n- [Evidence bundles](docs/EVIDENCE-BUNDLES.md) |

> **Canonical docs:** start with [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the platform map, then dive into [`readme_updated.md`](readme_updated.md) for feature-by-feature deep dives.

## Quick start

For a fully reproducible setup run the bootstrap helper (installs runtime + dev tooling, pre-commit, and fixtures) or use the Makefile targets:

```bash
$ cp .env.example .env  # update secrets before running services
$ ./scripts/bootstrap.sh
$ make fmt lint typecheck test
$ make demo
$ make demo-enterprise
```

The repository ships with a pair of curated fixtures and overlay profiles so you can experience the full pipeline without wiring external systems or secrets.

1. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   # Optional: install backend extras when you have access to private repos
   pip install -r apps/api/requirements-optional.txt
   ```

2. **Run the bundled demo experience**

   ```bash
   python -m core.cli demo --mode demo --output out/demo.json --pretty
   ```

   The command seeds deterministic tokens, loads the curated design/SBOM/SARIF/CVE fixtures, and executes the same pipeline that powers the API. The JSON result is saved to `out/demo.json` and the console summary highlights severity, guardrail status, compliance frameworks, executed modules, and the active pricing tier.

3. **Switch to the enterprise overlay**

   ```bash
   python -m core.cli demo --mode enterprise --output out/enterprise.json --pretty
   ```

   Enterprise mode applies the hardened profile from `config/fixops.overlay.yml`, demonstrating how additional guardrails, automation destinations, and evidence retention settings change the output without touching code. Evidence bundles, cache directories, and automation payloads are created under the allow-listed paths declared in the overlay.

4. **Iterate locally**

   You can point the CLI at your own artefacts with `python -m core.cli run` or import `core.demo_runner.run_demo_pipeline` in a notebook for scripted exploration. Use `python -m core.cli show-overlay --pretty` to inspect the merged overlay for each profile. When running the enterprise stack with Docker Compose, copy `enterprise/.env.example` to `.env`, rotate the secrets, and ensure `FIXOPS_AUTH_DISABLED` remains `false`.

5. **Validate with automated tests**

   The repository ships with a pytest suite that exercises the CLI stage runner, ingest API, compliance rollups, and SSDLC orchestrator logic. Re-run it after local changes to confirm the canonical IO contract still holds.

   ```bash
   export PYTHONPATH=.
   pytest
   ```

### Stage-by-stage local workflow

The unified stage runner gives you the same normalisation logic that powers the API while keeping artefacts local. Each invocation calls `core.stage_runner.StageRunner.run_stage`, which coordinates identity minting via `src.services.id_allocator.ensure_ids`, run persistence through `src.services.run_registry.RunRegistry.ensure_run`, and optional manifest signing with `src.services.signing`.

| Stage | Demo input | Command | Processor |
| --- | --- | --- | --- |
| Requirements | `simulations/demo_pack/requirements-input.csv` | `python -m apps.fixops_cli stage-run --stage requirements --input simulations/demo_pack/requirements-input.csv --app life-claims-portal` | `_process_requirements` parses CSV/JSON, mints `Requirement_ID`, and applies SSVC anchoring. |
| Design | `simulations/demo_pack/design-input.json` | `python -m apps.fixops_cli stage-run --stage design --input simulations/demo_pack/design-input.json --app life-claims-portal` | `_process_design` hydrates IDs via `ensure_ids` and annotates component risk. |
| Build | `simulations/demo_pack/sbom.json` | `python -m apps.fixops_cli stage-run --stage build --input simulations/demo_pack/sbom.json --app life-claims-portal` | `_process_build` normalises with `apps.api.normalizers.InputNormalizer` and flags risky components. |
| Test | `simulations/demo_pack/scanner.sarif` | `python -m apps.fixops_cli stage-run --stage test --input simulations/demo_pack/scanner.sarif --app life-claims-portal` | `_process_test` ingests SARIF, folds in coverage, and derives drift metrics. |
| Deploy | `simulations/demo_pack/tfplan.json` | `python -m apps.fixops_cli stage-run --stage deploy --input simulations/demo_pack/tfplan.json --app life-claims-portal` | `_process_deploy` accepts Terraform or Kubernetes manifests and extracts guardrail evidence. |
| Operate | `simulations/demo_pack/ops-telemetry.json` | `python -m apps.fixops_cli stage-run --stage operate --input simulations/demo_pack/ops-telemetry.json --app life-claims-portal` | `_process_operate` blends telemetry with KEV/EPSS feeds to compute pressure. |
| Decision | (auto-discovers prior outputs) | `python -m apps.fixops_cli stage-run --stage decision --app life-claims-portal` | `_process_decision` synthesises stage outputs, bundles evidence, and emits explainable verdicts. |

Run the sequence above to materialise canonical JSON under `artefacts/<app_id>/<run_id>/outputs/`. Each run also records signed manifests (when `FIXOPS_SIGNING_KEY`/`FIXOPS_SIGNING_KID` are configured) and emits a transparency log via `outputs/transparency.index`. After the CLI walkthrough, execute `pytest` to confirm the ingest API and compliance regressions continue to pass end-to-end.


## Why teams adopt FixOps
- **Overlay-governed operating modes** – A single configuration file switches between 30-minute demo onboarding and hardened enterprise guardrails, provisioning directories, tokens, compliance packs, automation connectors, and module toggles on startup (`config/fixops.overlay.yml`).
- **Push ingestion + parity CLI** – Upload design CSV, SBOM, SARIF, and CVE/KEV data through FastAPI endpoints or run the same flow locally via `python -m core.cli`, with API-key enforcement, MIME validation, byte limits, and evidence export controls (`apps/api/app.py`, `core/cli.py`).
- **Context-aware decisioning** – The orchestrator correlates design intent with bill-of-materials, findings, and advisories, then layers the context engine, guardrails, SSDLC scoring, IaC posture, exploit intelligence, AI agent detections, and knowledge graph analytics in a single pass (`apps/api/pipeline.py`, `new_apps/api/processing/knowledge_graph.py`).
- **Probabilistic escalation intelligence** – The `core.probabilistic.ProbabilisticForecastEngine` applies Dirichlet-smoothed calibration, spectral diagnostics, Markov chains, and Bayesian posterior updates to forecast severity drift, quantify stationary risk, and surface explainable escalation pressure for decision makers.
- **Multi-LLM consensus & transparency** – The enhanced decision engine layers deterministic heuristics with optional OpenAI/Anthropic/Gemini calls (when API keys are present), reconciles verdicts, enriches MITRE ATT&CK, compliance, and marketplace intelligence, and emits explainable consensus telemetry for demos or production pipelines (`fixops-enterprise/src/services/enhanced_decision_engine.py`, `fixops-enterprise/src/api/v1/enhanced.py`).
- **Security-as-code provenance & trust** – SLSA v1 attestations, provenance graph relationships, reproducible build attestations, and cosign signing keep releases anchored to verifiable supply-chain evidence (`services/provenance`, `services/graph`, `services/repro`, `scripts/signing`, `services/evidence/packager.py`).
- **Risk-first posture** – Normalised SBOMs, EPSS/KEV feed joins, FixOpsRisk scoring, and anomaly detection correlate exploit probability, exposure, and downgrade drift before pull requests merge (`lib4sbom/normalizer.py`, `risk/scoring.py`, `risk/feeds`, `services/graph/graph.py`).
- **Evidence & automation built-in** – Compliance packs, policy automation (Jira/Confluence/Slack), onboarding guidance, feedback capture, and evidence bundling persist auditable manifests inside overlay-allowlisted directories (`core/compliance.py`, `core/policy.py`, `core/evidence.py`, `core/feedback.py`, `services/evidence/packager.py`).
- **Observability & demo-ready experiences** – Telemetry hooks, dashboards, and docker-compose demos provide investor-ready tours while keeping operators in control of data flow (`telemetry`, `docker-compose.demo.yml`, `ui/dashboard`).

### Architecture overview
```text
┌────────────┐   uploads    ┌───────────────┐   overlay + artefacts   ┌────────────────────────────┐   probabilistic + LLM intelligence   ┌────────────────────┐   evidence + automations   ┌──────────────┐
│  Clients    │ ───────────▶│ FastAPI (ing) │────────────────────────▶│ Pipeline orchestrator     │──────────────────────────────────────▶│ Enhanced decisioning │──────────────────────────▶│ Destinations    │
│ (CLI/API)   │             │  /inputs/*    │                         │ (context, guardrails,     │                                           │ (consensus, MITRE,   │                          │ (Jira, bundle,  │
│             │◀────────────│ /pipeline/run │◀────────────────────────│ SSDLC, IaC, probabilistic)│◀──────────────────────────────────────│ compliance, KG, LLM) │◀──────────────────────────│ Slack, storage) │
└────────────┘  JSON status └───────────────┘  overlay metadata       │ overlay module matrix     │                                           └───────────────────────┘                            └──────────────┘
                                                   │                   └────────────────────────────┘
                                                   ▼
                                   Graph + risk engine, evidence hub, pricing, knowledge graph, feedback, docs
```

### Component interaction diagram
```
             ┌────────────────────┐
             │ Overlay registry   │
             │ config/*.yml       │
             └────────┬───────────┘
                      │
                      ▼ load_overlay()
┌────────────┐   auth/token   ┌───────────────────┐    artefact cache     ┌───────────────────────┐
│ CLI runner │──────────────▶│ FastAPI ingestion │──────────────────────▶│ Storage + evidence    │
│ core.cli │               │  apps/api/app.py   │◀──────────────────────│ data/uploads/*        │
└────────────┘               └────────┬──────────┘     archive bundles    └──────────┬────────────┘
         ▲                             │                                    decrypt/compress │
         │ module toggles              │ orchestrate()                       ▼                │
         │                             ▼                             ┌─────────────┐        │
         │                     ┌───────────────────┐                 │ Destinations│◀───────┘
         ├────────────────────▶│ Pipeline modules  │───────────────▶ │ Jira/Slack │   automation manifests
         │                     │ context/guardrail │  ROI & telemetry │ GRC repos │
         │                     └────────┬──────────┘                 └─────────────┘
         │                              │ enhanced_run()
         │                              ▼
         │                     ┌───────────────────┐
         └────────────────────▶│ Enhanced decision │
                               │ multi-LLM + KG    │
                               │ explanations      │
                               └───────────────────┘
```

The overlay registry feeds both the CLI and FastAPI surfaces with runtime configuration. Artefacts ingested through the API are cached under `data/uploads`, normalised, and handed to modular pipeline stages that emit automation payloads, evidence bundles, and ROI telemetry to downstream destinations.

The enhanced decisioning layer augments the classic pipeline by invoking the multi-LLM ensemble, SentinelGPT explanations, and CTINexus-style knowledge graph analytics before returning consensus decisions and reasoning metadata for executive dashboards.

### Sequence diagram (demo → enterprise hand-off)
```
Client/CLI -> FastAPI ingestion: POST /inputs/* (design, sbom, cve, sarif)
FastAPI ingestion -> Artefact cache: store + normalise artefacts
FastAPI ingestion -> Pipeline orchestrator: invoke /pipeline/run
Pipeline orchestrator -> Module registry: resolve enabled modules
Module registry -> Context engine: enrich with business signals
Module registry -> Guardrails: evaluate maturity thresholds
Module registry -> Automation pack: dispatch Jira/Slack/Confluence
Module registry -> Evidence hub: build encrypted bundle
Module registry -> Analytics: compute ROI + performance profile
Pipeline orchestrator -> Enhanced decisioning: invoke multi-LLM consensus + explanations
Enhanced decisioning -> Knowledge graph processor: map attack paths and entities
Enhanced decisioning -> Explanation engine: craft SentinelGPT executive summary
Enhanced decisioning -> Pipeline orchestrator: return consensus, MITRE, compliance, KG
Pipeline orchestrator -> FastAPI ingestion: return aggregated response
FastAPI ingestion -> Client/CLI: JSON with summaries + bundle paths
```

### UML overview
```
@startuml
class OverlayLoader {
  +load_overlay(path)
  +resolve_tokens()
}

class IngestionService {
  +accept_design()
  +accept_sbom()
  +accept_cve()
  +accept_sarif()
  +run_pipeline()
}

class PipelineOrchestrator {
  +correlate_artefacts()
  +execute_modules()
  +emit_outputs()
}

class ModuleRegistry {
  +enable(name)
  +disable(name)
  +register(hook)
}

class EvidenceHub {
  +archive()
  +encrypt()
  +handoff()
}

OverlayLoader --> IngestionService
IngestionService --> PipelineOrchestrator
PipelineOrchestrator --> ModuleRegistry
ModuleRegistry --> EvidenceHub
PipelineOrchestrator --> Destinations
@enduml
```

The UML block highlights the primary classes composing FixOps: configuration loaders, the ingestion facade, the orchestrator, the modular execution surface, and evidence management.

### Feature mind map
```
FixOps Platform
├── Ingestion
│   ├── FastAPI endpoints (`backend/api/*`)
│   └── CLI parity (`cli/fixops-*`)
├── Normalisation & analytics
│   ├── SBOM normaliser (`lib4sbom/normalizer.py`)
│   ├── Risk scoring + feeds (`risk/scoring.py`, `risk/feeds/*`)
│   └── Provenance graph (`services/graph/graph.py`)
├── Contextual intelligence
│   ├── Context engine & guardrails (`apps/api/pipeline.py`)
│   ├── Probabilistic (Markov/Bayesian) forecasts (`core/probabilistic/*`)
│   └── Multi-LLM consensus (`fixops-enterprise/src/services/enhanced_decision_engine.py`)
├── Evidence & automation
│   ├── Evidence bundling (`services/evidence/packager.py`)
│   ├── Cosign signing & provenance (`scripts/signing/*`, `services/provenance`)
│   └── Reproducible build attestations (`services/repro`)
├── Observability & demo
│   ├── Telemetry (`telemetry/*`)
│   ├── Demo stack (`docker-compose.demo.yml`, `config/otel-collector-demo.yaml`)
│   └── UI dashboards (`ui/dashboard`, `ui/graph-view`)
└── Developer experience
    ├── Playbooks & docs (`docs/*.md`)
    ├── QA automation (`.github/workflows/qa.yml`)
    └── Coverage + reports (`reports/coverage/*`)
```

### Detailed feature list
| Feature | Inputs | Runtime toggles | Outputs | Value delivered |
| --- | --- | --- | --- | --- |
| Context engine | Design CSV, SBOM, CVE, SARIF | `modules.context_engine.enabled` | Enriched component scores, prioritised findings | Correlates business impact with exposure to cut remediation noise. |
| Guardrails | Overlay maturity targets, SSDLC/IaC artefacts | `modules.guardrails.enabled` | Pass/fail gates, downgrade logic | Demonstrates readiness to executives and reduces false positives. |
| SSDLC evaluator | Design CSV, overlay stage metadata | `modules.ssdlc.enabled` | Stage coverage map, control gaps | Shows pipeline health for governance reviews. |
| IaC posture | Terraform/K8s scan results | `modules.iac.enabled` | IaC findings embedded in pipeline report | Connects infrastructure risk to application context. |
| Compliance packs | Overlay compliance packs, evidence hub config | `modules.compliance.enabled` | SOC2/ISO bundles, attestations | Provides audit-ready evidence per run. |
| Policy automation | Automation connectors, Jira/Slack secrets | `modules.policy_automation.enabled` | Tickets, pages, chat receipts | Automates remediation and documentation workflows. |
| Evidence hub | Any uploaded artefact | `modules.evidence.enabled` | Compressed, optionally encrypted bundles | Centralises artefacts for hand-off without manual effort. |
| AI agent advisor | SBOM, SARIF, overlay AI toggles | `modules.ai_agents.enabled` | AI agent detection notes, control guidance
| Highlights autonomous agents requiring new guardrails. |
| Multi-LLM consensus | Enhanced API payloads, CLI overrides, marketplace context | Enhanced decision engine toggles | Consensus verdict, MITRE & compliance overlays, disagreement map | Blends deterministic heuristics with optional OpenAI/Anthropic/Gemini calls when API keys are present. |
| Narrative explanations | Pipeline findings, business context | Enhanced decision engine | Narrative summary, mitigation guidance | Produces Sentinel-style narratives locally; remote providers are optional fallbacks. |
| Knowledge graph analytics | Normalised entities, relationships from scans | Enhanced decision engine | Graph metrics, attack path highlights | Surfaces CTINexus-style attack path intelligence using the bundled overlay graph. |
| Exploit signals | CVE feeds, EPSS/KEV overlays | `modules.exploit_signals.enabled` | Exploitability scores, refresh SLAs
| Keeps remediation focused on weaponised threats. |
| Probabilistic forecasts | Correlated crosswalk, historical refresh | `modules.probabilistic.enabled` | Bayesian/Markov risk projections | Quantifies breach likelihood for planning and VC narratives. |
| ROI analytics | Pipeline telemetry, automation success | `modules.analytics.enabled` | Cost savings, MTTR deltas, executive KPIs | Substantiates FixOps value in investor demos. |
| Tenant lifecycle | Tenant registry, stage definitions | `modules.tenancy.enabled` | Stage transitions, module gaps | Guides shared-service owners through onboarding and renewals. |
| Performance simulation | Overlay latency targets, benchmark profiles | `modules.performance.enabled` | Backlog predictions, throughput advice | Ensures capacity planning for enterprise pilots. |

### CLI/API usage by stage
| Stage | Interface | Command / Endpoint | Required inputs | Primary value |
| --- | --- | --- | --- | --- |
| Demo discovery | CLI | `python -m core.cli run --overlay config/demo.overlay.yml --design samples/design.csv --sbom samples/sbom.json --sarif samples/scan.sarif --cve samples/cve.json --output out/demo.json` | Demo overlay, curated artefacts | Fast investor narrative with contextual scoring and ROI headlines. |
| Demo discovery | API | `POST /inputs/*`, `GET /pipeline/run` | Same artefacts via multipart uploads | Live walkthrough showing ingestion health checks and guardrail outputs. |
| Enterprise onboarding | CLI | `python -m core.cli run --overlay config/fixops.overlay.yml --enable compliance --enable policy_automation --evidence-dir out/evidence` | Enterprise overlay, connector secrets | Proves compliance and automation readiness for procurement teams. |
| Enterprise onboarding | API | `POST /pipeline/run` with `X-API-Key` | Cached artefacts, overlay toggles | Enables integration tests and CI gating. |
| Operations steady state | CLI | `python -m core.cli run --enable exploit_signals --enable analytics --output out/ops.json` | Latest artefacts, exploit feeds | Keeps vuln management prioritised around active threats and ROI metrics. |
| Operations steady state | API | `POST /feedback` (if enabled) | Review payloads linked to run IDs | Captures analyst decisions for continuous improvement. |
| Overlay hardening | CLI | `python -m core.cli run --overlay config/fixops.overlay.yml --enable compliance` | Enterprise overlay, connector secrets | Demonstrates hardened guardrails without additional infrastructure. |

Each row outlines the stage of the customer journey, the surface to invoke, the exact commands or endpoints, the minimal inputs required, and the resulting business value to emphasise during demos or enterprise rollouts.
- **Ingestion service (`apps/api/app.py`)** – Loads the overlay at startup, prepares allowlisted directories, enforces API tokens, validates MIME types, caps uploads, and accepts artefacts at `/inputs/design`, `/inputs/sbom`, `/inputs/cve`, and `/inputs/sarif` before orchestrating `/pipeline/run`.
- **Pipeline orchestrator (`apps/api/pipeline.py`)** – Normalises severities, builds the design ↔ SBOM ↔ findings ↔ CVE crosswalk, evaluates guardrails and contextual modules, executes automation connectors, and emits the module matrix alongside summaries, evidence bundles, pricing, and sanitized overlay metadata.
- **Extension surface (`core/modules.py`)** – Overlay-declared modules and custom hooks allow integrators to disable, enable, or extend behaviour (e.g., IaC posture checks, exploit refresh, probabilistic forecasts) without code changes.

## End-to-end data flow
1. **Load configuration** – `load_overlay()` merges defaults with demo or enterprise overrides, validates directories, registers tokens, and prepares module toggles (`core/configuration.py`).
2. **Upload artefacts** – Push CSV/SBOM/SARIF/CVE data (plain JSON or gzip/zip archives) through FastAPI or point the CLI at local files; the normaliser caches parsers to reuse tokens and reduce I/O (`apps/api/normalizers.py`).
3. **Run the pipeline** – The orchestrator correlates artefacts, executes enabled modules (context engine, compliance packs, policy automation, SSDLC, IaC, AI agents, exploitability, probabilistic forecasts, ROI analytics, tenant lifecycle, performance simulation), invokes the enhanced decision engine for multi-LLM consensus, knowledge graph analytics, and SentinelGPT explanations, and tracks custom module outcomes.
4. **Persist outputs** – Artefact archives capture raw and normalised inputs, evidence hub writes compressed/encrypted bundles, automation connectors dispatch tickets/messages with manifests, exploit feeds refresh against allowlisted directories, and pricing summaries expose plan/limit data. Enhanced responses also persist consensus telemetry, MITRE mapping, and knowledge graph payloads for replay.

### Validation checklist

1. **Stage canonicalisation** – Execute the stage workflow table above (or run `PYTHONPATH=. pytest tests/test_cli_stage_run.py`) to ensure each command writes the canonical artefact into `artefacts/<app_id>/<run_id>/outputs/` and, when signing variables are present, emits manifests plus `outputs/transparency.index`.
2. **API ingest parity** – Launch the FastAPI app (`uvicorn apps.api.app:app --reload`) and post artefacts to `/api/v1/artefacts`; confirm the JSON summary echoes the stage, run ID, canonical output path, and signature state.
3. **Overlay pipeline regression** – `python -m core.cli run --overlay config/fixops.overlay.yml --design simulations/demo_pack/design-input.json --sbom simulations/demo_pack/sbom.json --sarif simulations/demo_pack/scanner.sarif --cve demo/fixtures/sample.cve.json --pretty --output out/pipeline-enterprise.json` should emit the full module matrix, evidence bundle path, and pricing posture for enterprise demos.
4. **Probabilistic calibration** – `python -m core.cli train-forecast --incidents data/examples/incidents.json --pretty --output out/forecast.json` validates spectral gap, stationary distribution, and multi-step projections, guaranteeing the enhanced analytics remain reproducible.
5. **Continuous regression** – `pytest` executes the CLI/API regression suites, stage-run coverage, probabilistic diagnostics, and the import guard that prevents active code from depending on archived `WIP/` modules.
5. **Inspect results** – API/CLI responses include severity overviews, guardrail status, context summaries, compliance coverage, policy execution, SSDLC assessments, IaC posture, AI agent findings, exploitability insights, probabilistic forecasts, ROI dashboards, tenant lifecycle summaries, performance profiles, knowledge graph analytics, SentinelGPT narratives, multi-LLM disagreement matrices, module matrices, feedback endpoints, and sanitized overlay metadata.

## Installation & setup
This repository ships the CLI workflow, the FastAPI ingestion service, and the overlay profiles used to demonstrate demo vs. enterprise behaviour. Container bundles, React front-ends, and Terraform stacks referenced in earlier drafts are **not** included.

### Local CLI & FastAPI workflow
1. Create a virtual environment and install dependencies (see below).
2. Copy `.env.example` to `.env` when running the service locally; for enterprise demos use `enterprise/.env.example` as a reference for additional secrets.
3. Launch the API with `uvicorn apps.api.app:app --reload` and exercise the `/inputs/*` plus `/pipeline/run` endpoints using the bundled fixtures under `simulations/demo_pack/`.
4. Use `python -m core.cli demo --mode demo|enterprise` or `make demo` / `make demo-enterprise` to produce canonical pipeline JSON and evidence bundles without wiring external systems.

### Deployment considerations
- The historical Docker Compose stack has been removed; rely on the CLI or FastAPI app for walkthroughs.
- There is no checked-in Terraform state. If you need infrastructure automation, treat it as a greenfield addition and document it alongside new modules.
- The `frontend/` symlink in this snapshot points to an external package and is left for compatibility; there is no bundled UI.

### Prerequisites
- Python 3.10+ (tested with CPython 3.11)
- `pip` and `virtualenv`
- Optional: `uvicorn` for serving the FastAPI application, `jq` for response inspection
- Optional: `cryptography` if enabling evidence bundle encryption (`limits.evidence.encrypt: true`)

### 1. Install dependencies
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure credentials & overlays
- Copy `config/fixops.overlay.yml` and adjust tokens, directories, module toggles, and pricing tiers as needed.
- Export `FIXOPS_API_TOKEN` (used by API and CLI) and any connector secrets declared in the overlay (e.g., `FIXOPS_JIRA_TOKEN`).

### 3. Launch the API (demo profile)
```bash
export FIXOPS_API_TOKEN="demo-token"
uvicorn backend.app:create_app --factory --reload
```

Upload artefacts and execute the pipeline:
```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" -F "file=@samples/design.csv;type=text/csv" http://127.0.0.1:8000/inputs/design
curl -H "X-API-Key: $FIXOPS_API_TOKEN" -F "file=@samples/sbom.json;type=application/json" http://127.0.0.1:8000/inputs/sbom
curl -H "X-API-Key: $FIXOPS_API_TOKEN" -F "file=@samples/cve.json;type=application/json" http://127.0.0.1:8000/inputs/cve
curl -H "X-API-Key: $FIXOPS_API_TOKEN" -F "file=@samples/scan.sarif;type=application/json" http://127.0.0.1:8000/inputs/sarif
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://127.0.0.1:8000/pipeline/run | jq
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://127.0.0.1:8000/api/v1/enhanced/capabilities | jq
curl -H "X-API-Key: $FIXOPS_API_TOKEN" -X POST \
  -H 'Content-Type: application/json' \
  -d '{\"service_name\":\"demo-app\",\"security_findings\":[{\"rule_id\":\"SAST001\",\"severity\":\"high\",\"description\":\"SQL injection\"}],\"business_context\":{\"environment\":\"demo\",\"criticality\":\"high\"}}' \
  http://127.0.0.1:8000/api/v1/enhanced/compare-llms | jq
```

### 3b. Try the bundled demo & enterprise fixtures
Skip manual artefact preparation and run the overlay-driven demo or
enterprise walkthrough in a single command. The CLI seeds required
environment variables (API token, Jira/Confluence tokens, and an
encryption key) with safe defaults.

```bash
# Demo profile (non-encrypted evidence bundle)
python -m core.cli demo --mode demo --output out/pipeline-demo.json --pretty

# Enterprise profile (encryption enabled when `cryptography` is installed)
python -m core.cli demo --mode enterprise --output out/pipeline-enterprise.json --pretty
```

Both commands emit a short textual summary, persist the full pipeline
response (if `--output` is supplied), and drop evidence bundles inside the
overlay-approved directories under `data/`.

### 4. Run the CLI (enterprise profile + module overrides)
```bash
python -m core.cli run \
  --overlay config/fixops.overlay.yml \
  --enable policy_automation --enable compliance --enable ssdlc --enable probabilistic \
  --design artefacts/design.csv --sbom artefacts/sbom.json \
  --sarif artefacts/scan.sarif --cve artefacts/cve.json \
  --evidence-dir out/evidence --output out/pipeline-enterprise.json
```

Use `python -m core.cli show-overlay --overlay config/fixops.overlay.yml` to inspect sanitized overlay metadata or `python -m core.cli run --offline` to disable automatic exploit feed refresh during air-gapped runs. `python -m core.cli copy-evidence --run out/pipeline-enterprise.json --target ./hand-off` copies bundle archives into hand-off directories for audits.

### 5. Validate the environment
- `pytest` – exercises ingestion, overlay validation, module toggles, connectors, exploit refresh, probabilistic forecasts, CLI parity, simulations, and SSDLC outputs.
- `python -m compileall backend fixops simulations tests` – guards against syntax regressions prior to deployment.

## API reference
| Endpoint | Method | Purpose | Notes |
| --- | --- | --- | --- |
| `/inputs/design` | `POST` | Upload design intent CSV (`component_id`, `service`, `owner`, `criticality`, optional `name`). | Enforces MIME, size, and API key; caches artefacts under overlay-approved directories. |
| `/inputs/sbom` | `POST` | Upload SBOM JSON. | Accepts JSON, gzip, or zip archives; normalises component tokens and retains version metadata. |
| `/inputs/cve` | `POST` | Upload CVE or KEV advisories. | Accepts JSON, gzip, or zip archives; exploit refresh annotates staleness and EPSS scores. |
| `/inputs/sarif` | `POST` | Upload scanner findings (SARIF). | Accepts JSON, gzip, or zip archives; deduplicates rule IDs and severity labels before crosswalk building. |
| `/pipeline/run` | `POST`/`GET` | Execute pipeline using cached artefacts. | Returns guardrails, context summaries, SSDLC/IaC/AI/exploit/probabilistic insights, automation manifests, pricing telemetry, module matrix, sanitized overlay, and evidence bundle paths. |
| `/feedback` | `POST` | (Enterprise toggle) Persist review decisions tied to pipeline runs. | Requires `capture_feedback` enabled; identifiers are sanitized and stored within allowlisted audit directories. |
| `/api/v1/enhanced/capabilities` | `GET` | Discover multi-LLM, MITRE, compliance, and marketplace readiness. | Surfaces enabled LLM providers, ATT&CK coverage, feed status, and consensus telemetry for Enhanced mode. |
| `/api/v1/enhanced/compare-llms` | `POST` | Compare individual model verdicts and consensus reasoning. | Accepts security findings payload, returns disagreement analysis, MITRE/ATT&CK mapping, and expert validation flags. |
| `/api/v1/enhanced/analysis` | `POST` | Retrieve standardised multi-LLM schema for CI/CD gating. | Streams consensus verdict, model rationales, evidence, SSVC label, and timing metadata for automated pipelines. |

All endpoints require the `X-API-Key` header. See `docs/PLATFORM_RUNBOOK.md` for persona-specific examples and `docs/INTEGRATIONS.md` for connector payload details.

## CLI workflows by persona
- **CISO & Executive Reporting** – `python -m core.cli run --overlay config/fixops.overlay.yml --enable probabilistic --enable compliance --enable analytics --output out/ciso.json` surfaces guardrail status, compliance posture, tenant coverage, ROI telemetry, and performance posture for board reporting.
- **CTEM & Vulnerability Ops** – `python -m core.cli run --enable exploit_signals --enable policy_automation --design ... --sbom ... --sarif ... --cve ...` contextualises findings, executes policy automations, and refreshes exploit intelligence.
- **DevSecOps / Platform** – `python -m core.cli run --enable ssdlc --enable iac --custom-module modules/custom.py:main` enforces pipeline gates across IaC scans and SSDLC targets.
- **SIEM & Incident Responders** – `python -m core.cli run --enable ai_agents --enable probabilistic --output out/siem.json` generates AI-agent detections and probabilistic breach forecasts for downstream correlation.
- **Security Testers** – Combine `--offline` with curated artefacts to validate guardrail outcomes pre-deployment.
- **Enterprise Architects & Tenant Ops** – `python -m core.cli run --enable tenancy --enable performance --output out/tenant-summary.json` produces tenant lifecycle health, module coverage gaps, and near real-time performance status for shared platforms.

Use `python -m core.cli help` for the full command reference and flags.

## Feature catalog
| Capability | Description | Overlay toggle |
| --- | --- | --- |
| Context engine | Blends business criticality, exposure, data sensitivity, exploitability, and scanner signals. | `modules.context_engine.enabled`
| Guardrails | Applies maturity thresholds and policy checks; downgrades noisy alerts. | `modules.guardrails.enabled`
| Compliance packs | Generates SOC 2 / ISO evidence bundles per run. | `modules.compliance.enabled`
| Policy automation | Dispatches Jira, Confluence, and Slack actions with manifest receipts. | `modules.policy_automation.enabled`
| SSDLC evaluator | Scores plan→audit stages and flags gaps per component. | `modules.ssdlc.enabled`
| IaC posture | Maps Terraform/Kubernetes findings into guardrail outputs. | `modules.iac.enabled`
| AI agent advisor | Detects agentic frameworks and prescribes controls. | `modules.ai_agents.enabled`
| Multi-LLM consensus | Fuses GPT-5, Claude, Gemini, and vertical models with variance checks and expert escalation. | Enhanced decision engine (`api/v1/enhanced/*`)
| SentinelGPT explanations | Generates natural-language narratives and mitigation guidance from findings. | Enhanced decision engine (`new_apps/api/processing/explanation.py`)
| Knowledge graph analytics | Builds CTINexus graphs to expose attack paths and clustered risk. | Enhanced decision engine (`new_apps/api/processing/knowledge_graph.py`)
| Exploit signals | Merges EPSS, KEV, and overlay refresh schedules to score exploitability. | `modules.exploit_signals.enabled`
| Probabilistic forecasts | Bayesian/Markov projections of breach likelihood based on crosswalk. | `modules.probabilistic.enabled`
| ROI analytics | Computes noise reduction, MTTR deltas, automation savings, and assigns ROI value per module. | `modules.analytics.enabled`
| Tenant lifecycle | Summarises tenant health, stage transitions, and module coverage gaps. | `modules.tenancy.enabled`
| Performance simulation | Estimates near real-time latency, throughput, and backlog recommendations. | `modules.performance.enabled`
| Evidence hub | Compresses artefacts, redacts secrets, persists manifests. | `modules.evidence.enabled`
| Module registry | Supports organisation-specific hooks and toggles. | `modules.custom`

## Analytics, dashboards & ROI storytelling
- Pipeline responses include dedicated `analytics`, `pricing_summary`, `performance_profile`, and `tenant_lifecycle` blocks that feed executive dashboards outlined in `market/DEMO_STORY.md` and `market/ENTERPRISE_READINESS.md`.
- Evidence bundles automatically embed ROI, tenant, and performance sections when the corresponding modules are enabled, giving CISOs auditable proof of value per run.
- Roadmap: extend analytics with historical warehousing, interactive ROI dashboards, and connector-level cost attribution (tracked in `audit/GAPS.md`).

## Multi-tenant lifecycle tooling
- Overlay-driven tenancy settings now define tenant inventories, lifecycle stages, stage defaults, and module expectations (`tenancy` section in `config/fixops.overlay.yml`).
- Pipeline runs emit `tenant_lifecycle` summaries highlighting stage distribution, module gaps, and support/billing metadata for each tenant.
- Roadmap: add overlay versioning, tenant-specific RBAC, and approval workflows for managed multi-tenant environments (tracked in `audit/GAPS.md` and `docs/PR_SUMMARY.md`).

## Performance simulation & observability
- **Pipeline performance module** – The `performance_profile` block computes cumulative latency, throughput, and backlog recommendations based on overlay targets for demo and enterprise runs.
- **Scenario replay** – `python -m simulations.cve_scenario.runner --mode {demo,enterprise}` still mirrors production flows (context, automation, evidence) against CVE-2021-44228, now capturing ROI and performance outputs alongside severity shifts.
- **Benchmarks & profiling** – `perf/BENCHMARKS.csv` captures timing; extend via `python scripts/generate_index.py --bench` to aggregate additional profiles while aligning with overlay thresholds.

## Troubleshooting & support
- Verify artefact cache health with `python -m core.cli show-overlay` and inspect `data/uploads/` for sanitized filenames.
- Review `docs/PLATFORM_RUNBOOK.md` for stage-by-stage troubleshooting, persona runbooks, and escalation paths.
- Consult `audit/SECURITY.md` and `docs/SDLC_SSDLC.md` when integrating FixOps into enterprise governance.


## Configuration overlays
- **Schema** – Authentication, data directories, upload limits, guardrail thresholds, onboarding checklists, compliance packs, policy automation targets, SSDLC objectives, IaC checks, AI agent watchlists, exploit feeds, probabilistic priors, pricing tiers, and module toggles live in `config/fixops.overlay.yml`.
- **Modes** – Profiles labelled `demo` and `enterprise` adjust required artefacts, Jira/Confluence/Slack enforcement, evidence maturity, automation aggressiveness, pricing plans, and module enablement.
- **Customization** – Supply environment overrides (`--env KEY=VALUE` via CLI) or add custom modules under `modules.custom` to execute organisation-specific logic alongside first-party modules.

Refer to `docs/CONFIG_GUIDE.md` for field-level descriptions and overlay extension patterns, and `docs/USAGE_GUIDE.html` for a persona-focused walkthrough.

## Simulations, benchmarks, and testing
- **CVE contextual re-scoring** – `python -m simulations.cve_scenario.runner --mode demo` (or `enterprise`) replays CVE-2021-44228 (Log4Shell) with overlay-governed context, producing severity shifts, evidence bundles, guardrail outcomes, and pricing summaries (`simulations/cve_scenario/runner.py`).
- **Performance telemetry** – `perf/BENCHMARKS.csv` captures representative timings for pipeline crosswalks and probabilistic forecasts; `perf/CHANGES.md` and `perf/BASELINE.md` document optimisation rationale.
- **Automated tests** – `pytest` exercises ingestion endpoints, overlay validation, module toggles, connectors, exploit refresh, probabilistic forecasts, CLI parity, and simulations; `python -m compileall backend fixops simulations tests` guards against syntax regressions.

## Documentation map
- **Market & positioning** – `market/` contains competitive analysis, pricing strategy, GTM plans, and demo storyboards.
- **Architecture & SDLC** – `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/SDLC_SSDLC.md`, and `docs/INTEGRATIONS.md` outline components, data flows, lifecycle coverage, and integration contracts.
- **Architecture inventory & roadmap** – `docs/ARCH-INVENTORY.md` summarises modules/services/data models while `docs/TASK-PLAN.md` maps Phases 2–10 with concrete code touchpoints.
- **Security & audits** – `audit/SECURITY.md`, `audit/GAPS.md`, and `audit/CTEM_ASSESSMENT.md` track mitigations, residual risk, and CTEM readiness.
- **SBOM normalisation & quality** – `docs/SBOM-QUALITY.md` explains deduplication logic, quality scoring metrics, CLI usage, and HTML reporting expectations.
- **Risk scoring & exposure** – `docs/RISK-SCORING.md` documents EPSS/KEV ingestion, FixOpsRisk weighting, CLI usage, and API endpoints for the risk pipeline.
- **Provenance & signing** – `docs/PROVENANCE.md`, `docs/SIGNING.md`, and `docs/CI-SECRETS.md` cover SLSA attestations, cosign signing flows, required secrets, and verification guidance.
- **Provenance graph intelligence** – `docs/PROVENANCE-GRAPH.md` details graph ingestion sources, query surface, anomaly detection, and API integration.
- **Reproducible builds** – `docs/REPRO-BUILDS.md` explains the hermetic verifier, plan structure, CLI usage, and CI workflow outputs.
- **Evidence bundles & policy** – `docs/EVIDENCE-BUNDLES.md` covers policy-driven packaging, manifest signing, API endpoints, and CLI automation.
- **Demo stack & telemetry** – `docs/DEMO.md` walks through the OpenTelemetry-enabled docker-compose demo and dashboard.
- **Runbooks & usage** – `docs/PLATFORM_RUNBOOK.md`, `docs/USAGE_GUIDE.html`, and `docs/PR_SUMMARY.md` provide persona guides, troubleshooting steps, and an executive summary for reviewers.
- **Operational playbooks** – `docs/PLAYBOOK-DEV.md`, `docs/PLAYBOOK-SEC.md`, and `docs/PLAYBOOK-AUDIT.md` equip engineering, security, and audit stakeholders with repeatable workflows.
- **Security posture & audits** – `docs/SECURITY-POSTURE.md`, `audit/SECURITY.md`, `audit/GAPS.md`, and `audit/CTEM_ASSESSMENT.md` capture branch protections, mitigations, residual risk, and CTEM readiness.

Whether you launch the API or the CLI, FixOps now delivers overlay-governed context, compliance, automation, and probabilistic insight with auditable artefacts that keep demo and enterprise buyers on the same code path.

## Local stage workflow commands

Run the bundled stage fixtures end-to-end with a single target:

```bash
make stage-workflow
```

The target seeds deterministic identifiers (`FIXOPS_RUN_ID_SEED=stage-demo`, `FIXOPS_FAKE_NOW=2024-01-01T00:00:00Z`) and calls `scripts/run_stage_workflow.py` to materialise canonical outputs under `artefacts/stage-demo/`. To execute individual stages or capture a JSON summary without Make, invoke the script directly:

```bash
python scripts/run_stage_workflow.py \
  --fixtures fixtures/sample_inputs \
  --artefacts artefacts/stage-demo \
  --summary artefacts/stage-demo/summary.json
```

Refer to `fixtures/stage_runbook.md` for the complete Input → Command → Output matrix.
