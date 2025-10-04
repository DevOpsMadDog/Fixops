# FixOps Platform Runbook

This runbook summarises the shipped feature set, end-to-end data flow, CLI/API touchpoints, and a comprehensive test plan so teams can exercise every FixOps capability with confidence.

## Feature Overview

| Capability | What It Delivers | Key Modules / Files |
| --- | --- | --- |
| Overlay-driven configuration | Mode-aware guardrails, integrations, pricing, and lifecycle profiles | `fixops/configuration.py`, `config/fixops.overlay.yml` |
| Context engine | Business-aware severity weighting, playbook selection, and summaries | `fixops/context_engine.py` |
| Guardrail maturity & policy automation | Fail/warn thresholds, Jira/Confluence actions, deployment approvals | `backend/pipeline.py`, `fixops/policy.py` |
| Compliance packs | Framework scoring, audit-ready summaries | `fixops/compliance.py` |
| Evidence hub | Persisted bundles, manifests, feedback capture integration | `fixops/evidence.py`, `fixops/feedback.py` |
| AI agent advisor | Framework detection, control recommendations, playbook routing | `fixops/ai_agents.py` |
| SSDLC evaluator | Stage-by-stage lifecycle coverage report | `fixops/ssdlc.py` |
| CVE contextual simulation | Log4Shell demo vs enterprise evidence bundles | `simulations/cve_scenario/runner.py` |

## End-to-End Data Flow

```mermaid
flowchart LR
    A[Client uploads artefacts via CLI/API] -->|Design CSV| B[InputNormalizer]
    A -->|SBOM JSON| B
    A -->|SARIF JSON| B
    A -->|CVE Feed| B
    B --> C[PipelineOrchestrator]
    C -->|Severity overview| D[Guardrail Evaluation]
    C -->|Crosswalk| E[Context Engine]
    C -->|Results| F[Compliance Packs]
    C -->|Results| G[Policy Automation]
    C -->|Results| H[SSDLCEvaluator]
    {D,E,F,G,H} --> I[EvidenceHub]
    I --> J[Evidence bundle & manifest]
    C --> K[Pricing Summary]
    C --> L[AIAgentAdvisor]
    C --> M[Onboarding Guide]
    C --> N[API Response / CLI Output]
```

The FastAPI service wires this chain during startup by loading the overlay, provisioning allowlisted data directories, and enforcing authentication. The orchestrator reuses cached lowercase tokens to avoid repeated SBOM/SARIF scans and passes a single enriched payload through guardrails, context, compliance, policy, AI, SSDLC, and evidence modules before responding.

## CLI & API Touchpoints

### FastAPI ingestion workflow

```bash
export FIXOPS_API_TOKEN="demo-token"
uvicorn backend.app:create_app --factory --reload

# Upload design context
curl -X POST \
  -H "X-API-Key: ${FIXOPS_API_TOKEN}" \
  -F "file=@samples/design.csv;type=text/csv" \
  http://127.0.0.1:8000/inputs/design

# Upload SBOM
curl -X POST \
  -H "X-API-Key: ${FIXOPS_API_TOKEN}" \
  -F "file=@samples/sbom.json;type=application/json" \
  http://127.0.0.1:8000/inputs/sbom

# Upload CVE feed
curl -X POST \
  -H "X-API-Key: ${FIXOPS_API_TOKEN}" \
  -F "file=@samples/kev.json;type=application/json" \
  http://127.0.0.1:8000/inputs/cve

# Upload SARIF
curl -X POST \
  -H "X-API-Key: ${FIXOPS_API_TOKEN}" \
  -F "file=@samples/scan.sarif;type=application/json" \
  http://127.0.0.1:8000/inputs/sarif

# Execute the overlay-aware pipeline
curl -X POST \
  -H "X-API-Key: ${FIXOPS_API_TOKEN}" \
  http://127.0.0.1:8000/pipeline/run | jq
```

Each response includes mode, severity breakdowns, context summaries, AI agent findings, SSDLC assessment, guardrail status, evidence bundle pointers, and pricing plan metadata.

### CVE contextual scoring simulation

```bash
# Demo mode: proves high → medium downgrade with limited blast radius
python -m simulations.cve_scenario.runner --mode demo

# Enterprise mode: proves medium → high escalation with regulated data and production exposure
python -m simulations.cve_scenario.runner --mode enterprise
```

Both runs emit contextual scorecards and evidence bundles in the overlay-configured `evidence_dir`, referencing the bundled guardrail, compliance, policy, AI agent, and SSDLC outputs.

### Real CVE playbook CLI

```bash
python scripts/run_real_cve_playbook.py --context simulations/cve_scenario/contexts.json
```

The script leverages the blended enterprise scorer to contrast scanner severities with FixOps-adjusted tiers and prints compliance alignment via Rich tables.

## Test Strategy ("Best Tester" checklist)

1. **Unit & integration suite**
   ```bash
   pytest
   ```
   Validates overlay parsing, API endpoints, pipeline orchestration, AI agent detection, SSDLC scoring, policy automation, compliance packs, and feedback capture.

2. **Bytecode compilation smoke test**
   ```bash
   python -m compileall backend fixops simulations tests
   ```
   Catches syntax regressions across orchestrator, helpers, simulations, and tests.

3. **CVE scenario verification** – ensures demo vs enterprise guardrails, pricing, compliance, and SSDLC diffs are preserved.
   ```bash
   python -m simulations.cve_scenario.runner --mode demo
   python -m simulations.cve_scenario.runner --mode enterprise
   ```

4. **Manual FastAPI workflow** – exercise the full push-model ingestion using the `curl` steps above, confirm `/pipeline/run` returns:
   - Guardrail status `pass/warn/fail`
   - Context summary with component counts and weighted severities
   - Compliance frameworks with satisfied/in-progress status
   - Policy automation action plans
   - AI agent matches and recommendations
   - SSDLC stage summary and requirement rollups
   - Evidence bundle manifest paths
   - Pricing summary with active plan

5. **Feedback capture** – if `toggles.capture_feedback` is true, post a JSON payload to `/feedback` and verify the JSONL entry appears under the overlay-configured `feedback_dir`.

## Data & Evidence Handling

- Overlay allowlists constrain upload destinations (`FIXOPS_DATA_ROOT_ALLOWLIST`).
- Evidence bundles include manifest + archive paths; the CVE simulation asserts both files exist when guardrails trigger bundling.
- Feedback entries live under `data/feedback/<mode>/<run_id>/feedback.jsonl`, matching SSDLC "feedback_loop" requirements.

## Quick Feature Recap

- **Demo mode** delivers contextual risk summaries, onboarding checklist, AI agent callouts, and lightweight compliance guidance within 30 minutes.
- **Enterprise mode** enforces ticket-sync prerequisites, richer compliance packs, policy automation (Jira/Confluence/change requests), SSDLC depth, pricing disclosures, and comprehensive evidence bundles.
- Both modes share the same push ingestion API and overlay contract, making upgrades configuration-only.

Refer to `docs/CONFIG_GUIDE.md` for deeper configuration examples and `docs/ARCHITECTURE.md` for component boundaries.
