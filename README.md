# FixOps Contextual Risk & Evidence Platform

FixOps turns raw security artefacts into contextual risk, compliance, and automation outputs in minutes. A lightweight FastAPI service and a parity CLI accept push-style uploads, hydrate an overlay-driven pipeline, and emit guardrail verdicts, context summaries, evidence bundles, pricing signals, and automation manifests that match demo or enterprise guardrails without code changes.

## Why teams adopt FixOps
- **Overlay-governed operating modes** – A single configuration file switches between 30-minute demo onboarding and hardened enterprise guardrails, provisioning directories, tokens, compliance packs, automation connectors, and module toggles on startup (`config/fixops.overlay.yml`).
- **Push ingestion + parity CLI** – Upload design CSV, SBOM, SARIF, and CVE/KEV data through FastAPI endpoints or run the same flow locally via `python -m fixops.cli`, with API-key enforcement, MIME validation, byte limits, and evidence export controls (`backend/app.py`, `fixops/cli.py`).
- **Context-aware decisioning** – The orchestrator correlates design intent with bill-of-materials, findings, and advisories, then layers the context engine, guardrails, SSDLC scoring, IaC posture, exploit intelligence, AI agent detections, and Bayesian/Markov forecasts in a single pass (`backend/pipeline.py`).
- **Evidence & automation built-in** – Compliance packs, policy automation (Jira/Confluence/Slack), onboarding guidance, feedback capture, and evidence bundling persist auditable manifests inside overlay-allowlisted directories (`fixops/compliance.py`, `fixops/policy.py`, `fixops/evidence.py`, `fixops/feedback.py`).
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

## Quickstart
### 1. Install dependencies
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the API (demo profile)
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

### 3. Run the CLI (enterprise profile + module overrides)
```bash
python -m fixops.cli run \
  --overlay config/fixops.overlay.yml \
  --enable policy_automation --enable compliance --enable ssdlc --enable probabilistic \
  --design artefacts/design.csv --sbom artefacts/sbom.json \
  --sarif artefacts/scan.sarif --cve artefacts/cve.json \
  --evidence-dir out/evidence --output out/pipeline-enterprise.json
```

Use `python -m fixops.cli show-overlay --overlay config/fixops.overlay.yml` to inspect sanitized overlay metadata or `python -m fixops.cli run --offline` to disable automatic exploit feed refresh during air-gapped runs.

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
