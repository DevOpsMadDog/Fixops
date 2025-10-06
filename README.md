# FixOps Contextual Risk & Evidence Platform

FixOps turns raw security artefacts into contextual risk, compliance, and automation outputs in minutes. A lightweight FastAPI service and a parity CLI accept push-style uploads, hydrate an overlay-driven pipeline, and emit guardrail verdicts, context summaries, evidence bundles, pricing signals, and automation manifests that match demo or enterprise guardrails without code changes.

## Quick start

For a fully reproducible setup run the bootstrap helper (installs runtime + dev tooling, pre-commit, and fixtures) or use the Makefile targets:

```bash
$ ./scripts/bootstrap.sh
$ make fmt lint typecheck test
$ make demo
$ make demo-enterprise
```

The repository ships with a pair of curated fixtures and overlay profiles so you can experience the full pipeline without wiring external systems or secrets.

1. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

2. **Run the bundled demo experience**

   ```bash
   python -m fixops.cli demo --mode demo --output out/demo.json --pretty
   ```

   The command seeds deterministic tokens, loads the curated design/SBOM/SARIF/CVE fixtures, and executes the same pipeline that powers the API. The JSON result is saved to `out/demo.json` and the console summary highlights severity, guardrail status, compliance frameworks, executed modules, and the active pricing tier.

3. **Switch to the enterprise overlay**

   ```bash
   python -m fixops.cli demo --mode enterprise --output out/enterprise.json --pretty
   ```

   Enterprise mode applies the hardened profile from `config/fixops.overlay.yml`, demonstrating how additional guardrails, automation destinations, and evidence retention settings change the output without touching code. Evidence bundles, cache directories, and automation payloads are created under the allow-listed paths declared in the overlay.

4. **Iterate locally**

   You can point the CLI at your own artefacts with `python -m fixops.cli run` or import `fixops.demo_runner.run_demo_pipeline` in a notebook for scripted exploration. Use `python -m fixops.cli show-overlay --pretty` to inspect the merged overlay for each profile.

## Why teams adopt FixOps
- **Overlay-governed operating modes** – A single configuration file switches between 30-minute demo onboarding and hardened enterprise guardrails, provisioning directories, tokens, compliance packs, automation connectors, and module toggles on startup (`config/fixops.overlay.yml`).
- **Push ingestion + parity CLI** – Upload design CSV, SBOM, SARIF, and CVE/KEV data through FastAPI endpoints or run the same flow locally via `python -m fixops.cli`, with API-key enforcement, MIME validation, byte limits, and evidence export controls (`backend/app.py`, `fixops/cli.py`).
- **Context-aware decisioning** – The orchestrator correlates design intent with bill-of-materials, findings, and advisories, then layers the context engine, guardrails, SSDLC scoring, IaC posture, exploit intelligence, AI agent detections, Bayesian/Markov forecasts, and knowledge graph analytics in a single pass (`backend/pipeline.py`, `new_backend/processing/knowledge_graph.py`).
- **Multi-LLM consensus & transparency** – The enhanced decision engine fans out to GPT-5, Claude, Gemini, and vertical cyber models, reconciles verdicts, enriches MITRE ATT&CK, compliance, and marketplace intelligence, and emits explainable consensus telemetry for demos or production pipelines (`fixops-blended-enterprise/src/services/enhanced_decision_engine.py`, `fixops-blended-enterprise/src/api/v1/enhanced.py`).
- **Evidence & automation built-in** – Compliance packs, policy automation (Jira/Confluence/Slack), onboarding guidance, feedback capture, and evidence bundling persist auditable manifests inside overlay-allowlisted directories (`fixops/compliance.py`, `fixops/policy.py`, `fixops/evidence.py`, `fixops/feedback.py`).
- **Artefact archiving & regulated storage** – Every upload is normalised, persisted with metadata, and summarised via the artefact archive while secure directory enforcement and optional bundle encryption keep regulated tenants compliant (`fixops/storage.py`, `fixops/paths.py`).
- **Analytics & ROI telemetry** – Pipeline responses surface pricing tiers, guardrail progress, exploit refresh health, and contextual noise-reduction metrics that feed executive dashboards and ROI storytelling (`perf/BENCHMARKS.csv`, `market/ENTERPRISE_READINESS.md`).
- **Tenant lifecycle & performance intelligence** – Overlay-governed ROI dashboards, tenant lifecycle summaries, and near real-time performance simulations help CISOs, CTEM leads, and platform teams prove value and spot bottlenecks without bespoke code (`fixops/analytics.py`, `fixops/tenancy.py`, `fixops/performance.py`).
- **Modular & extensible** – Toggle modules, adjust weights, or register custom hooks without touching code; every run reports configured, enabled, and executed modules plus outcomes to keep integrators in control (`fixops/modules.py`).

## System architecture at a glance
```
┌────────────┐   uploads    ┌───────────────┐   overlay + artefacts   ┌────────────────────────────┐   multi-LLM + context   ┌──────────────────────┐   evidence + automations   ┌──────────────┐
│  Clients    │ ───────────▶│ FastAPI (ing) │────────────────────────▶│ Pipeline orchestrator     │────────────────────────▶│ Enhanced decisioning │──────────────────────────▶│ Destinations    │
│ (CLI/API)   │             │  /inputs/*    │                         │ (context, guardrails,     │                        │ (consensus, MITRE,   │                          │ (Jira, bundle,  │
│             │◀────────────│ /pipeline/run │◀────────────────────────│ SSDLC, IaC, probabilistic)│◀───────────────────────│ compliance, KG, LLM) │◀──────────────────────────│ Slack, storage) │
└────────────┘  JSON status └───────────────┘  overlay metadata       │ overlay module matrix     │                        └──────────────────────┘                            └──────────────┘
                                                   │                   └────────────────────────────┘
                                                   ▼
                                   Evidence hub, pricing, knowledge graph, feedback, docs
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
│ fixops.cli │               │  backend/app.py   │◀──────────────────────│ data/uploads/*        │
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
Client/CLI -> Enterprise Terraform: promote overlay + secrets
Enterprise Terraform -> Kubernetes cluster: deploy services + ingress
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
│   ├── FastAPI endpoints
│   └── CLI parity
├── Contextual intelligence
│   ├── Context engine
│   ├── Guardrails
│   └── SSDLC + IaC posture
├── Automation
│   ├── Policy automation
│   ├── Compliance packs
│   └── Evidence hub
├── Analytics
│   ├── ROI telemetry
│   ├── Tenant lifecycle
│   └── Performance simulation
├── AI & probabilistic
│   ├── AI agent advisor
│   └── Probabilistic forecasts
├── Multi-LLM & knowledge graph
│   ├── Multi-model consensus + MITRE mapping
│   ├── SentinelGPT explanations
│   └── CTINexus knowledge graph analytics
└── Deployment
    ├── Docker demo
    └── Terraform enterprise
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
| Multi-LLM consensus | Enhanced API payloads, CLI overrides, marketplace context | Enhanced decision engine toggles | Consensus verdict, MITRE & compliance overlays, disagreement map
| Provides transparent GPT-5/Claude/Gemini decision audits with reasoning and expert escalation flags. |
| SentinelGPT explanations | Pipeline findings, business context | Enhanced decision engine | Narrative summary, mitigation guidance
| Generates executive-ready narratives from multi-LLM output without manual editing. |
| Knowledge graph analytics | Normalised entities, relationships from scans | Enhanced decision engine | Graph metrics, attack path highlights
| Surfaces CTINexus attack path intelligence and entity clusters for responders. |
| Exploit signals | CVE feeds, EPSS/KEV overlays | `modules.exploit_signals.enabled` | Exploitability scores, refresh SLAs
| Keeps remediation focused on weaponised threats. |
| Probabilistic forecasts | Correlated crosswalk, historical refresh | `modules.probabilistic.enabled` | Bayesian/Markov risk projections | Quantifies breach likelihood for planning and VC narratives. |
| ROI analytics | Pipeline telemetry, automation success | `modules.analytics.enabled` | Cost savings, MTTR deltas, executive KPIs | Substantiates FixOps value in investor demos. |
| Tenant lifecycle | Tenant registry, stage definitions | `modules.tenancy.enabled` | Stage transitions, module gaps | Guides shared-service owners through onboarding and renewals. |
| Performance simulation | Overlay latency targets, benchmark profiles | `modules.performance.enabled` | Backlog predictions, throughput advice | Ensures capacity planning for enterprise pilots. |

### CLI/API usage by stage
| Stage | Interface | Command / Endpoint | Required inputs | Primary value |
| --- | --- | --- | --- | --- |
| Demo discovery | CLI | `python -m fixops.cli run --overlay config/demo.overlay.yml --design samples/design.csv --sbom samples/sbom.json --sarif samples/scan.sarif --cve samples/cve.json --output out/demo.json` | Demo overlay, curated artefacts | Fast investor narrative with contextual scoring and ROI headlines. |
| Demo discovery | API | `POST /inputs/*`, `GET /pipeline/run` | Same artefacts via multipart uploads | Live walkthrough showing ingestion health checks and guardrail outputs. |
| Enterprise onboarding | CLI | `python -m fixops.cli run --overlay config/fixops.overlay.yml --enable compliance --enable policy_automation --evidence-dir out/evidence` | Enterprise overlay, connector secrets | Proves compliance and automation readiness for procurement teams. |
| Enterprise onboarding | API | `POST /pipeline/run` with `X-API-Key` | Cached artefacts, overlay toggles | Enables integration tests and CI gating. |
| Operations steady state | CLI | `python -m fixops.cli run --enable exploit_signals --enable analytics --output out/ops.json` | Latest artefacts, exploit feeds | Keeps vuln management prioritised around active threats and ROI metrics. |
| Operations steady state | API | `POST /feedback` (if enabled) | Review payloads linked to run IDs | Captures analyst decisions for continuous improvement. |
| Scale-out deployment | Terraform | `terraform -chdir=fixops-blended-enterprise/terraform apply` | AWS credentials, S3 backend, overlay secrets | Launches Kubernetes-backed enterprise stack with same overlays. |
| Scale-out deployment | Helm (via Terraform) | Automated by module | Helm charts, Kubernetes context | Ensures parity between local demo and production footprint. |

Each row outlines the stage of the customer journey, the surface to invoke, the exact commands or endpoints, the minimal inputs required, and the resulting business value to emphasise during demos or enterprise rollouts.
- **Ingestion service (`backend/app.py`)** – Loads the overlay at startup, prepares allowlisted directories, enforces API tokens, validates MIME types, caps uploads, and accepts artefacts at `/inputs/design`, `/inputs/sbom`, `/inputs/cve`, and `/inputs/sarif` before orchestrating `/pipeline/run`.
- **Pipeline orchestrator (`backend/pipeline.py`)** – Normalises severities, builds the design ↔ SBOM ↔ findings ↔ CVE crosswalk, evaluates guardrails and contextual modules, executes automation connectors, and emits the module matrix alongside summaries, evidence bundles, pricing, and sanitized overlay metadata.
- **Extension surface (`fixops/modules.py`)** – Overlay-declared modules and custom hooks allow integrators to disable, enable, or extend behaviour (e.g., IaC posture checks, exploit refresh, probabilistic forecasts) without code changes.

## End-to-end data flow
1. **Load configuration** – `load_overlay()` merges defaults with demo or enterprise overrides, validates directories, registers tokens, and prepares module toggles (`fixops/configuration.py`).
2. **Upload artefacts** – Push CSV/SBOM/SARIF/CVE data (plain JSON or gzip/zip archives) through FastAPI or point the CLI at local files; the normaliser caches parsers to reuse tokens and reduce I/O (`backend/normalizers.py`).
3. **Run the pipeline** – The orchestrator correlates artefacts, executes enabled modules (context engine, compliance packs, policy automation, SSDLC, IaC, AI agents, exploitability, probabilistic forecasts, ROI analytics, tenant lifecycle, performance simulation), invokes the enhanced decision engine for multi-LLM consensus, knowledge graph analytics, and SentinelGPT explanations, and tracks custom module outcomes.
4. **Persist outputs** – Artefact archives capture raw and normalised inputs, evidence hub writes compressed/encrypted bundles, automation connectors dispatch tickets/messages with manifests, exploit feeds refresh against allowlisted directories, and pricing summaries expose plan/limit data. Enhanced responses also persist consensus telemetry, MITRE mapping, and knowledge graph payloads for replay.
5. **Inspect results** – API/CLI responses include severity overviews, guardrail status, context summaries, compliance coverage, policy execution, SSDLC assessments, IaC posture, AI agent findings, exploitability insights, probabilistic forecasts, ROI dashboards, tenant lifecycle summaries, performance profiles, knowledge graph analytics, SentinelGPT narratives, multi-LLM disagreement matrices, module matrices, feedback endpoints, and sanitized overlay metadata.

## Installation & setup
### Local Docker demo setup
* The `fixops-blended-enterprise/docker-compose.yml` bundle gives you a three-service stack: MongoDB, the FastAPI backend, and the optional React frontend, each with health checks and environment defaults suitable for a laptop demo. Start it with `docker-compose up -d` to get ports `8001` (API) and `3000` (UI) exposed locally.

* After the containers are up, seed the bundled SQLite database and create a demo admin account by running `python quick_start.py`; it provisions schema and demo credentials (`admin@fixops.com` / `FixOpsAdmin123!`) that you can use in the browser for an investor walkthrough.

* For presentation polish, Option C in the enterprise deployment guide walks through the same docker-compose flow and reminds you to tailor `.env.enterprise` so the UI reflects the buyer’s industry before inviting the VC to visit `http://localhost:3000`. Health checks at `http://localhost:8001/health` let you prove everything is live on the spot.

### Enterprise IaC (Terraform-only)
* The production path is modeled entirely in Terraform under `fixops-blended-enterprise/terraform/`. The root module pins Terraform ≥ 1.5, enables the Kubernetes and Helm providers, and expects an S3 remote state backend—useful if you want to demo an “upgrade from laptop to cluster” story.

* `deployment.tf` composes namespace, RBAC, storage, MongoDB, Redis, backend, frontend, and ingress modules, wiring in replica counts, secrets, health probes, and HA defaults so an enterprise prospect sees bank-grade hardening out of the box.

* Outputs expose URLs, kube commands, and compliance posture, which makes it easy to hand over state or plug the stack into CI/CD during diligence.

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
python -m fixops.cli demo --mode demo --output out/pipeline-demo.json --pretty

# Enterprise profile (encryption enabled when `cryptography` is installed)
python -m fixops.cli demo --mode enterprise --output out/pipeline-enterprise.json --pretty
```

Both commands emit a short textual summary, persist the full pipeline
response (if `--output` is supplied), and drop evidence bundles inside the
overlay-approved directories under `data/`.

### 4. Run the CLI (enterprise profile + module overrides)
```bash
python -m fixops.cli run \
  --overlay config/fixops.overlay.yml \
  --enable policy_automation --enable compliance --enable ssdlc --enable probabilistic \
  --design artefacts/design.csv --sbom artefacts/sbom.json \
  --sarif artefacts/scan.sarif --cve artefacts/cve.json \
  --evidence-dir out/evidence --output out/pipeline-enterprise.json
```

Use `python -m fixops.cli show-overlay --overlay config/fixops.overlay.yml` to inspect sanitized overlay metadata or `python -m fixops.cli run --offline` to disable automatic exploit feed refresh during air-gapped runs. `python -m fixops.cli copy-evidence --run out/pipeline-enterprise.json --target ./hand-off` copies bundle archives into hand-off directories for audits.

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
- **CISO & Executive Reporting** – `python -m fixops.cli run --overlay config/fixops.overlay.yml --enable probabilistic --enable compliance --enable analytics --output out/ciso.json` surfaces guardrail status, compliance posture, tenant coverage, ROI telemetry, and performance posture for board reporting.
- **CTEM & Vulnerability Ops** – `python -m fixops.cli run --enable exploit_signals --enable policy_automation --design ... --sbom ... --sarif ... --cve ...` contextualises findings, executes policy automations, and refreshes exploit intelligence.
- **DevSecOps / Platform** – `python -m fixops.cli run --enable ssdlc --enable iac --custom-module modules/custom.py:main` enforces pipeline gates across IaC scans and SSDLC targets.
- **SIEM & Incident Responders** – `python -m fixops.cli run --enable ai_agents --enable probabilistic --output out/siem.json` generates AI-agent detections and probabilistic breach forecasts for downstream correlation.
- **Security Testers** – Combine `--offline` with curated artefacts to validate guardrail outcomes pre-deployment.
- **Enterprise Architects & Tenant Ops** – `python -m fixops.cli run --enable tenancy --enable performance --output out/tenant-summary.json` produces tenant lifecycle health, module coverage gaps, and near real-time performance status for shared platforms.

Use `python -m fixops.cli help` for the full command reference and flags.

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
| SentinelGPT explanations | Generates natural-language narratives and mitigation guidance from findings. | Enhanced decision engine (`new_backend/processing/explanation.py`)
| Knowledge graph analytics | Builds CTINexus graphs to expose attack paths and clustered risk. | Enhanced decision engine (`new_backend/processing/knowledge_graph.py`)
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
- Verify artefact cache health with `python -m fixops.cli show-overlay` and inspect `data/uploads/` for sanitized filenames.
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
- **Security & audits** – `audit/SECURITY.md`, `audit/GAPS.md`, and `audit/CTEM_ASSESSMENT.md` track mitigations, residual risk, and CTEM readiness.
- **Runbooks & usage** – `docs/PLATFORM_RUNBOOK.md`, `docs/USAGE_GUIDE.html`, and `docs/PR_SUMMARY.md` provide persona guides, troubleshooting steps, and an executive summary for reviewers.

Whether you launch the API or the CLI, FixOps now delivers overlay-governed context, compliance, automation, and probabilistic insight with auditable artefacts that keep demo and enterprise buyers on the same code path.
