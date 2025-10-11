# README Implementation Gap & Test Strategy Review

## 1. Executive summary
- The root README communicates an ambitious dual-mode (demo/enterprise) platform story. Several elements are well supported by the codebase (e.g., the bundled demo runner, overlay-driven modules, and IaC posture evaluation).
- Runtime safeguards now flag missing automation credentials inside overlay metadata and surface the warnings through CLI summaries, demo walkthroughs, and enterprise API payloads so operators immediately understand automation prerequisites.【F:core/overlay_runtime.py†L34-L102】【F:core/cli.py†L566-L647】【F:core/demo_runner.py†L80-L147】【F:fixops-enterprise/src/services/enhanced_decision_engine.py†L1-L140】【F:tests/test_overlay_runtime.py†L1-L72】【F:tests/test_cli.py†L121-L151】【F:tests/test_demo_runner.py†L1-L62】【F:tests/test_enterprise_enhanced_api.py†L1-L129】
- Previous gaps in the README and companion docs have been closed: `make demo-enterprise`, enhanced decision APIs, and enterprise `.env` templates now exist, and the docs explicitly note that UI/Terraform assets are not bundled.
- This review enumerates the gaps, prescribes remediation items, and defines an end-to-end regression plan spanning demo and enterprise modes, infrastructure-as-code (IaC), and documentation deliverables.

## 2. Implementation gaps vs. README commitments
| README claim | Observed gap | Evidence | Recommended action |
| --- | --- | --- | --- |
| `make demo-enterprise` exists for full pipeline runs.【F:README.md†L9-L15】 | ✅ Resolved – Makefile now ships a dedicated `demo-enterprise` target invoking `scripts/run_demo_steps.py --mode enterprise` and persisting artefacts under `artefacts/enterprise/demo.json`. |【F:Makefile†L58-L71】【F:scripts/run_demo_steps.py†L1-L61】 | Ensure onboarding docs reference the scripted target when describing enterprise walkthroughs.
| Enterprise stack bootstraps via `enterprise/.env.example`.【F:README.md†L43-L46】 | ✅ Resolved – An enterprise-scoped template now lives at `enterprise/.env.example` with signing, automation, and provider credentials called out explicitly.【F:enterprise/.env.example†L1-L31】 | Keep the template in sync with new environment variables as modules evolve.
| Enhanced decision API served from `fixops-enterprise/src/api/v1/enhanced.py` backed by `fixops-enterprise/src/services/enhanced_decision_engine.py`.【F:README.md†L72-L78】 | ✅ Resolved – Enterprise services expose `enhanced_decision_service` plus `/api/v1/enhanced/*` routes wired to the consensus engine, matching README claims.【F:fixops-enterprise/src/services/enhanced_decision_engine.py†L1-L92】【F:fixops-enterprise/src/api/v1/enhanced.py†L1-L63】 | Extend regression coverage as new telemetry fields or knowledge graph enrichments ship.
| Enterprise front-end referenced via `enterprise/frontend` (indirectly relied upon in docs).【F:ARCHITECTURE.md†L7-L13】 | ✅ Resolved – README and onboarding clarify that the symlink targets an external package and no UI ships in this snapshot.【F:README.md†L275-L286】【F:ONBOARDING.md†L1-L25】 | Remove the symlink or vendor a UI when ready; continue flagging the absence until assets land.
| Terraform hand-off implied in the README sequence diagram (`Enterprise Terraform -> Kubernetes cluster`).【F:README.md†L128-L147】 | ✅ Resolved – README now states Terraform automation is not bundled and should be treated as net-new work.【F:README.md†L275-L284】 | When IaC assets are introduced, re-enable deployment documentation and add regression coverage.
| Policy automation connectors execute when enterprise overlay enables them.【F:README.md†L72-L82】 | ✅ Resolved – Runtime overlay helper persists automation readiness, pipeline results downgrade the policy module when prerequisites are missing, CLI/demo summaries echo the warnings, and enterprise APIs attach the same metadata for operators.【F:core/overlay_runtime.py†L34-L102】【F:apps/api/pipeline.py†L700-L846】【F:core/cli.py†L566-L647】【F:core/demo_runner.py†L80-L147】【F:fixops-enterprise/src/services/enhanced_decision_engine.py†L1-L140】 | Continue Phase 3 work to integrate warnings with analytics dashboards and operator runbooks.
| Multi-LLM ensemble fans out to GPT‑5, Claude, Gemini, etc.【F:README.md†L72-L78】 | ✅ Resolved – README and onboarding explain deterministic fallbacks with optional OpenAI/Anthropic/Gemini providers driven by environment variables.【F:README.md†L72-L82】【F:ONBOARDING.md†L26-L44】【F:core/llm_providers.py†L44-L118】 | Keep provider guidance in sync as new adapters or credentials are supported.

## 3. Phased remediation plan
| Phase | Scope | Est. build & regression effort | Status | Notes |
| --- | --- | --- | --- | --- |
| Phase 1 – Runtime prerequisites instrumentation | Detect missing Jira/Confluence automation credentials during overlay preparation and persist operator-visible warnings; add pytest coverage that enforces the metadata contract.【F:core/overlay_runtime.py†L34-L86】【F:tests/test_overlay_runtime.py†L45-L67】 | ~70 LOC (helper + 2 tests) | ✅ Complete | Runtime metadata now advertises automation readiness without breaking local demo runs.
| Phase 2 – Surface automation readiness to operators | Bubble `runtime_warnings` through `core.cli show-overlay`, demo runner output, and enterprise API payloads; extend regression tests to assert warning propagation and automation status downgrades.【F:core/cli.py†L566-L647】【F:core/demo_runner.py†L80-L147】【F:apps/api/pipeline.py†L700-L846】【F:fixops-enterprise/src/services/enhanced_decision_engine.py†L1-L140】【F:tests/test_cli.py†L121-L151】【F:tests/test_demo_runner.py†L1-L62】【F:tests/test_enterprise_enhanced_api.py†L1-L129】 | ~110 LOC plus fixture updates | ✅ Complete | CLI, demo, and enterprise responses now echo automation warnings and downgrade policy automation status when credentials are missing.
| Phase 3 – Observability & documentation hardening | Persist automation warnings into analytics dashboards and update onboarding/docs with prerequisite checklists and troubleshooting. | ~60 LOC + doc revisions | ⏳ Planned | Closes the loop between runtime checks, dashboards, and operator runbooks.

## 4. Demo vs. enterprise regression strategy
### 4.1 Pipeline execution
1. **CLI smoke tests** – run `python -m core.cli demo --mode demo` and `--mode enterprise` to validate bundled fixtures, summary output, and evidence bundling.【F:core/demo_runner.py†L129-L192】 Regression coverage now asserts evidence bundles materialise on disk for both overlays and that encryption downgrades when optional crypto dependencies are absent.【F:tests/test_demo_runner.py†L6-L36】 Continue extending assertions for guardrail and compliance deltas across overlays.
2. **Stage workflow** – exercise `apps.fixops_cli` for every stage with curated fixtures to verify canonical outputs and signing toggles.【F:apps/fixops_cli/__main__.py†L19-L84】【F:core/stage_runner.py†L214-L413】 Add assertions for transparency logs and bundle verification in enterprise mode.
3. **Overlay validation** – extend `core.cli show-overlay` regression tests to ensure encrypted evidence flags disable gracefully when `Fernet` is unavailable.【F:core/overlay_runtime.py†L1-L102】【F:core/cli.py†L566-L647】 Runtime helpers and CLI coverage now coerce encryption off when crypto support or keys are missing, preventing sample runs from failing while surfacing runtime warnings when automation credentials are absent.【F:tests/test_cli.py†L121-L151】【F:tests/test_overlay_runtime.py†L1-L72】

### 4.2 Module-level checks
- **Enhanced decisioning** – validate telemetry fields (`models_consulted`, marketplace references, knowledge graph summary) under enterprise overlay; current test fixture asserts presence but not value ranges.【F:tests/test_enterprise_paths.py†L88-L125】 Add mocks for remote provider failures to ensure deterministic fallbacks surface provider metadata.
- **IaC posture** – maintain coverage verifying matched targets, missing artefacts, and unmatched components for multi-cloud designs.【F:core/iac.py†L18-L124】【F:tests/test_pipeline_matching.py†L497-L560】 Introduce enterprise-specific fixture covering encryption and automation prerequisites per overlay (`policy_automation` dependencies).
- **Evidence handling** – ensure encrypted bundles are produced when overlay demands it and that retrieval via CLI matches allowed directories.【F:config/fixops.overlay.yml†L18-L55】【F:tests/test_enterprise_paths.py†L81-L109】 Add regression where evidence key is missing to confirm graceful downgrade.

### 4.3 End-to-end enterprise assertions
- Run the pipeline orchestrator with enterprise overlay ensuring module matrix reports all enabled features and consensus telemetry matches overlay provider list.【F:config/fixops.overlay.yml†L34-L194】【F:tests/test_enterprise_paths.py†L88-L137】
- Verify IaC telemetry surfaces in the enterprise JSON payload and intersects with compliance rollups, extending `tests/test_end_to_end.py` to assert `iac_posture` modules execute under enterprise configuration.【3cfe67†L5-L14】【d1f005†L497-L560】

## 5. IaC coverage & required artefacts
- **Overlay targets** – The enterprise overlay enables IaC posture evaluation and defines target metadata (match keywords, required artefacts).【F:config/fixops.overlay.yml†L45-L91】 Ensure documentation reflects how to extend this section for new cloud environments.
- **Evaluator implementation** – `core.iac.IaCPostureEvaluator` normalises tokens, matches design components, and records missing artefacts; unmatched components accumulate into posture analytics.【F:core/iac.py†L18-L134】 Document expected design CSV schema (component, cloud, environment) so integrators can supply compatible inputs.
- **Testing hooks** – Pipeline integration tests already assert IaC coverage and unmatched component reporting.【F:tests/test_pipeline_matching.py†L497-L560】 Add enterprise-mode regression that checks automation prerequisites (e.g., Jira credentials) when IaC targets require policy artefacts.
- **Terraform alignment** – Terraform is not bundled in this snapshot; treat infrastructure automation as net-new work and document modules when they land.

## 6. Supporting documentation backlog
1. **Documentation hygiene** – Keep README and onboarding in sync with new modules, overlays, or service entry points as they land.
2. **Enterprise deployment guide** – When infrastructure automation exists, document secrets, overlays, and rollout steps alongside `.env` templates.【F:enterprise/.env.example†L1-L31】
3. **Front-end onboarding** – Either vendor the UI package or remove the symlink once a replacement exists; document setup when assets become available.
4. **IaC runbook** – Author guidance for new Terraform/Helm modules if introduced, covering target definitions, bootstrap steps, and audit requirements.
5. **Enhanced decision appendix** – Expand provider documentation (e.g., additional environment variables, telemetry fields) as new adapters are added.【F:core/llm_providers.py†L44-L118】

## 7. Next steps for senior contributors
- **Architecture** – Align system diagrams with actual package layout (rename enterprise modules, flag deprecated paths) before stakeholder demos.
- **Development** – Focus on net-new assets (UI bundle, Terraform modules, additional automation connectors) and extend regression tests as they appear.
- **Testing** – Schedule nightly dual-mode pipeline runs capturing JSON snapshots for drift detection; integrate with existing pytest suite to maintain parity across demo and enterprise outputs.
- **Documentation** – Establish a doc review cadence ensuring README updates remain in lockstep with code changes, preventing future divergence.
