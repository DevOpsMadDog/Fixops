# FixOps Blended Enterprise – Quick Onboarding Guide

This guide orients new contributors to the current repository snapshot. It reflects the checked-in code only—any assets referenced in older decks (front-end bundles, Terraform stacks, Docker Compose files) are out of scope unless you add them back.

## Handover Pack
- [README](README.md) – single source of truth for capabilities, setup, and supported workflows.
- [ROADMAP](ROADMAP.md) – delivery priorities and sequencing.
- [docs/README_GAP_AND_TEST_PLAN.md](docs/README_GAP_AND_TEST_PLAN.md) – gap assessment plus demo/enterprise regression strategy.
- [tests/](tests/) – practical tour of CLI, pipeline, and enhanced API behaviour.

## Repository layout highlights
- **`core/`** – Overlay loader, pipeline orchestrator, and module implementations (context engine, evidence hub, compliance, IaC posture, probabilistic analytics, etc.).【F:core/stage_runner.py†L214-L413】【F:core/iac.py†L18-L134】
- **`apps/api/`** – FastAPI ingestion surface that prepares allowlisted directories, enforces API keys, and invokes the orchestrator.【F:apps/api/app.py†L1-L120】【F:apps/api/pipeline.py†L1-L210】
- **`fixops-enterprise/src/`** – Enhanced decision router and service wrapper used for enterprise overlays.【F:fixops-enterprise/src/api/v1/enhanced.py†L1-L63】【F:fixops-enterprise/src/services/enhanced_decision_engine.py†L1-L92】
- **`config/`** – Overlay definitions and environment defaults (e.g., `config/fixops.overlay.yml` governs enterprise hardening).
- **`simulations/demo_pack/`** – Canonical artefacts (design CSV, SBOM, SARIF, CVE, telemetry) for deterministic demos.
- **`scripts/run_demo_steps.py`** – Helper that drives demo/enterprise pipelines and persists outputs under `artefacts/`.
- **`tests/`** – Coverage for CLI parity, overlay validation, IAС posture, enhanced decision API, and regression guards.

## Enhanced decision surfaces
- `fixops-enterprise/src/api/v1/enhanced.py` exposes `/api/v1/enhanced/*` routes for capabilities discovery, payload analysis, and multi-model comparisons. Routers load lazily from the service singleton to keep startup light.【F:fixops-enterprise/src/api/v1/enhanced.py†L7-L63】
- `fixops-enterprise/src/services/enhanced_decision_engine.py` wraps `core.enhanced_decision.EnhancedDecisionEngine`, lazily loads overlay settings, and offers helpers for pipeline evaluation, ad-hoc payload analysis, and signal export.【F:fixops-enterprise/src/services/enhanced_decision_engine.py†L14-L88】
- `core/enhanced_decision.py` defines the multi-provider consensus engine. Without external API keys it operates deterministically; populate `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GOOGLE_API_KEY` to enable real-time calls.【F:core/enhanced_decision.py†L70-L139】【F:core/llm_providers.py†L44-L118】

## CLI & pipeline essentials
- `python -m core.cli demo --mode demo|enterprise` replays the curated overlay profiles, emitting canonical JSON and evidence bundles. The underlying helper lives in `core/demo_runner.py` and is also exposed via `scripts/run_demo_steps.py` for makefile automation.【F:core/demo_runner.py†L129-L192】【F:scripts/run_demo_steps.py†L19-L61】
- `python -m core.cli run ...` executes the full stage runner, orchestrating ingestion, guardrails, modules, and enhanced decision telemetry. Inspect `core/stage_runner.py` for the execution order and integration points.
- Overlay metadata (`config/*.yml`) toggles modules such as compliance packs, policy automation, IaC posture, exploit signals, and AI agent detection. Use `python -m core.cli show-overlay --mode enterprise` to inspect the resolved config.

## Running the platform locally
1. **Install dependencies**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Seed environment** – Copy `.env.example` to `.env`. For hardened demos review `enterprise/.env.example` and populate provider keys if available.【F:enterprise/.env.example†L1-L31】
3. **Launch FastAPI**
   ```bash
   export PYTHONPATH=.
   export FIXOPS_API_TOKEN="demo-token"
   uvicorn apps.api.app:app --reload
   ```
4. **Exercise endpoints** – Upload fixtures from `simulations/demo_pack/` to `/inputs/*`, then call `/pipeline/run` and `/api/v1/enhanced/capabilities`.
5. **Or run scripted demos**
   ```bash
   make demo            # demo overlay
   make demo-enterprise # enterprise overlay
   ```
   Outputs land under `artefacts/<APP>/<RUN>/` along with evidence bundles and transparency indices.
6. **Regression tests** – Execute `pytest` to cover CLI parity, overlay validation, IaC posture checks, enhanced decision APIs, and deterministic fallbacks.【F:tests/test_enterprise_enhanced_api.py†L1-L96】【F:tests/test_pipeline_matching.py†L497-L560】

## Known gaps & next steps
- The `frontend/` symlink references an external UI bundle and is intentionally left unresolved; ship a new UI or remove the link when ready.
- There is no committed Terraform or Docker Compose automation. Treat infrastructure as a future enhancement and document it alongside the code when implemented.
- Overlay docs and the README now reflect the actual assets. Keep them in sync as you add providers, modules, or automation targets.

Welcome aboard—use this guide alongside the regression suite to understand how demo and enterprise overlays diverge and where to contribute next.
