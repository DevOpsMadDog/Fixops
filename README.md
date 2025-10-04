# FixOps Contextual Risk & Evidence Platform

FixOps turns raw security artefacts into contextual risk, compliance, and automation outputs in minutes. A lightweight FastAPI service and a parity CLI accept push-style uploads, hydrate an overlay-driven pipeline, and emit guardrail verdicts, context summaries, evidence bundles, pricing signals, and automation manifests that match demo or enterprise guardrails without code changes.

## Why teams adopt FixOps
- **Overlay-governed operating modes** – A single configuration file switches between 30-minute demo onboarding and hardened enterprise guardrails, provisioning directories, tokens, compliance packs, automation connectors, and module toggles on startup (`config/fixops.overlay.yml`).
- **Push ingestion + parity CLI** – Upload design CSV, SBOM, SARIF, and CVE/KEV data through FastAPI endpoints or run the same flow locally via `python -m fixops.cli`, with API-key enforcement, MIME validation, byte limits, and evidence export controls (`backend/app.py`, `fixops/cli.py`).
- **Context-aware decisioning** – The orchestrator correlates design intent with bill-of-materials, findings, and advisories, then layers the context engine, guardrails, SSDLC scoring, IaC posture, exploit intelligence, AI agent detections, and Bayesian/Markov forecasts in a single pass (`backend/pipeline.py`).
- **Evidence & automation built-in** – Compliance packs, policy automation (Jira/Confluence/Slack), onboarding guidance, feedback capture, and evidence bundling persist auditable manifests inside overlay-allowlisted directories (`fixops/compliance.py`, `fixops/policy.py`, `fixops/evidence.py`, `fixops/feedback.py`).
- **Analytics & ROI telemetry** – Pipeline responses surface pricing tiers, guardrail progress, exploit refresh health, and contextual noise-reduction metrics that feed executive dashboards and ROI storytelling (`perf/BENCHMARKS.csv`, `market/ENTERPRISE_READINESS.md`).
- **Modular & extensible** – Toggle modules, adjust weights, or register custom hooks without touching code; every run reports configured, enabled, and executed modules plus outcomes to keep integrators in control (`fixops/modules.py`).

## System architecture at a glance
```
┌────────────┐   uploads    ┌───────────────┐   overlay + artefacts   ┌─────────────────────────┐   evidence + automations   ┌────────────────┐
│  Clients    │ ───────────▶│ FastAPI (ing) │────────────────────────▶│ Pipeline orchestrator   │──────────────────────────▶│ Destinations    │
│ (CLI/API)   │             │  /inputs/*    │                         │ (context, guardrails,   │                          │ (Jira, bundle,  │
│             │◀────────────│ /pipeline/run │◀────────────────────────│ compliance, policies,   │◀──────────────────────────│ Slack, storage) │
└────────────┘  JSON status └───────────────┘  overlay metadata       │ SSDLC, IaC, AI, prob.)  │  overlay module matrix   └────────────────┘
                                                   │                 └─────────────────────────┘
                                                   ▼
                                   Evidence hub, pricing, feedback, docs
```

- **Ingestion service (`backend/app.py`)** – Loads the overlay at startup, prepares allowlisted directories, enforces API tokens, validates MIME types, caps uploads, and accepts artefacts at `/inputs/design`, `/inputs/sbom`, `/inputs/cve`, and `/inputs/sarif` before orchestrating `/pipeline/run`.
- **Pipeline orchestrator (`backend/pipeline.py`)** – Normalises severities, builds the design ↔ SBOM ↔ findings ↔ CVE crosswalk, evaluates guardrails and contextual modules, executes automation connectors, and emits the module matrix alongside summaries, evidence bundles, pricing, and sanitized overlay metadata.
- **Extension surface (`fixops/modules.py`)** – Overlay-declared modules and custom hooks allow integrators to disable, enable, or extend behaviour (e.g., IaC posture checks, exploit refresh, probabilistic forecasts) without code changes.

## End-to-end data flow
1. **Load configuration** – `load_overlay()` merges defaults with demo or enterprise overrides, validates directories, registers tokens, and prepares module toggles (`fixops/configuration.py`).
2. **Upload artefacts** – Push CSV/SBOM/SARIF/CVE data through FastAPI or point the CLI at local files; the normaliser caches parsers to reuse tokens and reduce I/O (`backend/normalizers.py`).
3. **Run the pipeline** – The orchestrator correlates artefacts, executes enabled modules (context engine, compliance packs, policy automation, SSDLC, IaC, AI agents, exploitability, probabilistic forecasts), and tracks custom module outcomes.
4. **Persist outputs** – Evidence hub writes compressed bundles, automation connectors dispatch tickets/messages with manifests, exploit feeds refresh against allowlisted directories, and pricing summaries expose plan/limit data.
5. **Inspect results** – API/CLI responses include severity overviews, guardrail status, context summaries, compliance coverage, policy execution, SSDLC assessments, IaC posture, AI agent findings, exploitability insights, probabilistic forecasts, module matrices, feedback endpoints, and sanitized overlay metadata.

## Installation & setup
### Prerequisites
- Python 3.10+ (tested with CPython 3.11)
- `pip` and `virtualenv`
- Optional: `uvicorn` for serving the FastAPI application, `jq` for response inspection

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
```

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
| `/inputs/sbom` | `POST` | Upload SBOM JSON. | Normalises component tokens and retains version metadata. |
| `/inputs/cve` | `POST` | Upload CVE or KEV advisories. | Accepts NVD-style JSON; exploit refresh annotates staleness and EPSS scores. |
| `/inputs/sarif` | `POST` | Upload scanner findings (SARIF). | Deduplicates rule IDs and severity labels before crosswalk building. |
| `/pipeline/run` | `POST`/`GET` | Execute pipeline using cached artefacts. | Returns guardrails, context summaries, SSDLC/IaC/AI/exploit/probabilistic insights, automation manifests, pricing telemetry, module matrix, sanitized overlay, and evidence bundle paths. |
| `/feedback` | `POST` | (Enterprise toggle) Persist review decisions tied to pipeline runs. | Requires `capture_feedback` enabled; identifiers are sanitized and stored within allowlisted audit directories. |

All endpoints require the `X-API-Key` header. See `docs/PLATFORM_RUNBOOK.md` for persona-specific examples and `docs/INTEGRATIONS.md` for connector payload details.

## CLI workflows by persona
- **CISO & Executive Reporting** – `python -m fixops.cli run --overlay config/fixops.overlay.yml --enable probabilistic --enable compliance --output out/ciso.json` surfaces guardrail status, compliance posture, pricing tier utilisation, and ROI telemetry.
- **CTEM & Vulnerability Ops** – `python -m fixops.cli run --enable exploit_signals --enable policy_automation --design ... --sbom ... --sarif ... --cve ...` contextualises findings, executes policy automations, and refreshes exploit intelligence.
- **DevSecOps / Platform** – `python -m fixops.cli run --enable ssdlc --enable iac --custom-module modules/custom.py:main` enforces pipeline gates across IaC scans and SSDLC targets.
- **SIEM & Incident Responders** – `python -m fixops.cli run --enable ai_agents --enable probabilistic --output out/siem.json` generates AI-agent detections and probabilistic breach forecasts for downstream correlation.
- **Security Testers** – Combine `--offline` with curated artefacts to validate guardrail outcomes pre-deployment.

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
| Exploit signals | Merges EPSS, KEV, and overlay refresh schedules to score exploitability. | `modules.exploit_signals.enabled`
| Probabilistic forecasts | Bayesian/Markov projections of breach likelihood based on crosswalk. | `modules.probabilistic.enabled`
| ROI telemetry | Surfaces pricing tier usage, artefact freshness, and automation savings estimates. | Always on (in pricing schema)
| Evidence hub | Compresses artefacts, redacts secrets, persists manifests. | `modules.evidence.enabled`
| Module registry | Supports organisation-specific hooks and toggles. | `modules.custom`

## Analytics, dashboards & ROI storytelling
- Pipeline responses include `pricing_summary`, `guardrail_overview`, `exploit_refresh`, and `automation_results` blocks that roll into ROI dashboards described in `market/DEMO_STORY.md` and `market/ENTERPRISE_READINESS.md`.
- Evidence bundles carry per-run manifest metadata suitable for executive scorecards.
- Roadmap: historical analytics warehouse and interactive ROI dashboards (noise reduction, MTTR delta, audit hours saved) are slated for implementation per `audit/GAPS.md`.

## Multi-tenant lifecycle tooling
- Current state: overlay loader validates a single profile per deployment, with API-key enforcement and directory allowlists. Operators can maintain separate overlays per tenant and switch via CLI/API flags.
- Roadmap: build overlay versioning, RBAC, and approval workflows for managed multi-tenant environments (tracked in `audit/GAPS.md` and `docs/PR_SUMMARY.md`).

## Performance simulation & observability
- **Near real-time simulation** – `python -m simulations.cve_scenario.runner --mode {demo,enterprise}` mirrors production flows (context engine, automation connectors, evidence bundling) against CVE-2021-44228 to validate severity shifts in seconds.
- **Benchmarks & profiling** – `perf/BENCHMARKS.csv` captures timing; extend via `python scripts/generate_index.py --bench` to aggregate additional profiles.
- **Runtime metrics** – Overlay hooks expose module execution durations and automation manifest status in pipeline responses for lightweight monitoring integrations.

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
