# README Implementation Gap & Test Strategy Review

## 1. Executive summary
- The root README communicates an ambitious dual-mode (demo/enterprise) platform story. Several elements are well supported by the codebase (e.g., the bundled demo runner, overlay-driven modules, and IaC posture evaluation).
- Critical statements in the README and companion docs reference tooling, directories, or automation that are absent or only partially implemented (e.g., missing `make demo-enterprise` target, absent enhanced decision API module, and stale enterprise front-end/Terraform paths).
- This review enumerates the gaps, prescribes remediation items, and defines an end-to-end regression plan spanning demo and enterprise modes, infrastructure-as-code (IaC), and documentation deliverables.

## 2. Implementation gaps vs. README commitments
| README claim | Observed gap | Evidence | Recommended action |
| --- | --- | --- | --- |
| `make demo-enterprise` exists for full pipeline runs.【F:README.md†L9-L15】 | ✅ Resolved – Makefile now ships a dedicated `demo-enterprise` target invoking `scripts/run_demo_steps.py --mode enterprise` and persisting artefacts under `artefacts/enterprise/demo.json`.|【F:Makefile†L58-L71】【F:scripts/run_demo_steps.py†L1-L61】 | Ensure onboarding docs reference the scripted target when describing enterprise walkthroughs.
| Enterprise stack bootstraps via `enterprise/.env.example`.【F:README.md†L43-L46】 | ✅ Resolved – An enterprise-scoped template now lives at `enterprise/.env.example` with signing, automation, and provider credentials called out explicitly.【F:enterprise/.env.example†L1-L31】 | Keep the template in sync with new environment variables as modules evolve.
| Enhanced decision API served from `enterprise/src/api/v1/enhanced.py` backed by `enterprise/src/services/enhanced_decision_engine.py`.【F:README.md†L72-L78】 | ✅ Resolved – Enterprise services expose `enhanced_decision_service` plus `/api/v1/enhanced/*` routes wired to the consensus engine, matching README claims.【F:fixops-enterprise/src/services/enhanced_decision_engine.py†L1-L92】【F:fixops-enterprise/src/api/v1/enhanced.py†L1-L63】 | Extend regression coverage as new telemetry fields or knowledge graph enrichments ship.
| Enterprise front-end referenced via `enterprise/frontend` (indirectly relied upon in docs).【F:ARCHITECTURE.md†L7-L13】 | `frontend` symlink targets `/app/fixops-blended-enterprise/frontend`, which is unavailable in this repo snapshot, breaking dev UX.【8be9cb†L1-L9】 | Replace the broken symlink with the actual source (or vendor it as a submodule) and adjust onboarding docs to reflect the true path.
| Terraform hand-off implied in the README sequence diagram (`Enterprise Terraform -> Kubernetes cluster`).【F:README.md†L128-L147】 | Only legacy Terraform definitions exist under `WIP/code/enterprise_legacy/terraform`, signalling incomplete IaC automation for the current stack.【282337†L1-L6】 | Promote current IaC modules into the active tree (under `iac/` or `infrastructure/`) and document deployment workflows, or explicitly mark Terraform hand-off as roadmap.
| Multi-LLM ensemble fans out to GPT‑5, Claude, Gemini, etc.【F:README.md†L72-L78】 | The consensus engine defaults to provider labels like `gpt-5`, but OpenAI requests are implemented via `gpt-4o-mini` fallbacks; other providers degrade to deterministic responses when API keys are absent.【F:core/enhanced_decision.py†L117-L140】【F:core/llm_providers.py†L44-L118】【F:core/llm_providers.py†L285-L348】 | Clarify documentation around provider fallbacks (deterministic mode without keys) and expose configuration guidance for swapping in real models.

## 3. Demo vs. enterprise regression strategy
### 3.1 Pipeline execution
1. **CLI smoke tests** – run `python -m core.cli demo --mode demo` and `--mode enterprise` to validate bundled fixtures, summary output, and evidence bundling.【F:core/demo_runner.py†L129-L192】 Existing tests cover both modes but should be extended to assert guardrail and compliance deltas across overlays.【F:tests/test_demo_runner.py†L6-L23】
2. **Stage workflow** – exercise `apps.fixops_cli` for every stage with curated fixtures to verify canonical outputs and signing toggles.【F:apps/fixops_cli/__main__.py†L19-L84】【F:core/stage_runner.py†L214-L413】 Add assertions for transparency logs and bundle verification in enterprise mode.
3. **Overlay validation** – extend `core.cli show-overlay` regression tests to ensure encrypted evidence flags disable gracefully when `Fernet` is unavailable.【F:core/demo_runner.py†L118-L127】【F:core/cli.py†L766-L776】

### 3.2 Module-level checks
- **Enhanced decisioning** – validate telemetry fields (`models_consulted`, marketplace references, knowledge graph summary) under enterprise overlay; current test fixture asserts presence but not value ranges.【F:tests/test_enterprise_paths.py†L88-L125】 Add mocks for remote provider failures to ensure deterministic fallbacks surface provider metadata.
- **IaC posture** – maintain coverage verifying matched targets, missing artefacts, and unmatched components for multi-cloud designs.【F:core/iac.py†L18-L124】【F:tests/test_pipeline_matching.py†L497-L560】 Introduce enterprise-specific fixture covering encryption and automation prerequisites per overlay (`policy_automation` dependencies).
- **Evidence handling** – ensure encrypted bundles are produced when overlay demands it and that retrieval via CLI matches allowed directories.【F:config/fixops.overlay.yml†L18-L55】【F:tests/test_enterprise_paths.py†L81-L109】 Add regression where evidence key is missing to confirm graceful downgrade.

### 3.3 End-to-end enterprise assertions
- Run the pipeline orchestrator with enterprise overlay ensuring module matrix reports all enabled features and consensus telemetry matches overlay provider list.【F:config/fixops.overlay.yml†L34-L194】【F:tests/test_enterprise_paths.py†L88-L137】
- Verify IaC telemetry surfaces in the enterprise JSON payload and intersects with compliance rollups, extending `tests/test_end_to_end.py` to assert `iac_posture` modules execute under enterprise configuration.【3cfe67†L5-L14】【d1f005†L497-L560】

## 4. IaC coverage & required artefacts
- **Overlay targets** – The enterprise overlay enables IaC posture evaluation and defines target metadata (match keywords, required artefacts).【F:config/fixops.overlay.yml†L45-L91】 Ensure documentation reflects how to extend this section for new cloud environments.
- **Evaluator implementation** – `core.iac.IaCPostureEvaluator` normalises tokens, matches design components, and records missing artefacts; unmatched components accumulate into posture analytics.【F:core/iac.py†L18-L134】 Document expected design CSV schema (component, cloud, environment) so integrators can supply compatible inputs.
- **Testing hooks** – Pipeline integration tests already assert IaC coverage and unmatched component reporting.【F:tests/test_pipeline_matching.py†L497-L560】 Add enterprise-mode regression that checks automation prerequisites (e.g., Jira credentials) when IaC targets require policy artefacts.
- **Terraform alignment** – Surface the location and status of legacy Terraform modules (`WIP/code/enterprise_legacy/terraform`) until modernised; include migration guidance once new IaC assets are ready.【282337†L1-L6】

## 5. Supporting documentation backlog
1. **README corrections** – Update quick-start targets, clarify provider fallbacks, and temper claims about non-existent modules or assets (front-end, Terraform, enhanced API).
2. **Enterprise deployment guide** – Add/restore `.env.example` scoped to enterprise services, listing required secrets for signing, automation, and LLM providers.【F:config/fixops.overlay.yml†L17-L194】
3. **Front-end onboarding** – Replace broken symlink with concrete installation instructions or remove front-end references until packaged.【8be9cb†L1-L9】
4. **IaC runbook** – Extend `docs/CONFIG_GUIDE.md` (or create `docs/IAC_RUNBOOK.md`) covering target definitions, Terraform bootstrap (when available), and audit requirements.
5. **Enhanced decision appendix** – Document deterministic fallback behaviour and required environment variables for OpenAI, Anthropic, and Gemini adapters.【F:core/llm_providers.py†L44-L118】【F:core/llm_providers.py†L285-L348】

## 6. Next steps for senior contributors
- **Architecture** – Align system diagrams with actual package layout (rename enterprise modules, flag deprecated paths) before stakeholder demos.
- **Development** – Prioritise restoring enterprise artefacts (Makefile target, API router, env templates) and add regression tests capturing overlay-specific deltas.
- **Testing** – Schedule nightly dual-mode pipeline runs capturing JSON snapshots for drift detection; integrate with existing pytest suite to maintain parity across demo and enterprise outputs.
- **Documentation** – Establish a doc review cadence ensuring README updates remain in lockstep with code changes, preventing future divergence.
