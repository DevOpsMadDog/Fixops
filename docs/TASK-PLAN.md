# Multi-Phase Execution Plan

Phase 1 established the authoritative architecture inventory (see `docs/ARCH-INVENTORY.md`).
Phases 2–10 focus on incremental hardening of the ingestion pipeline, enterprise services,
and integration adapters. Each phase lists the exact code touchpoints and validation steps.

| Phase | Objective | Code touchpoints (file → function/class) | Validation & docs |
| --- | --- | --- | --- |
| 2 | Harden overlay loading and path safety | `core/overlay_runtime.py` → `prepare_overlay`; `core/paths.py` → `verify_allowlisted_path`; `config/fixops.overlay.yml` (add explicit directory schema comments) | Extend `tests/test_overlay_runtime.py::test_prepare_overlay_*` fixtures and update `docs/CONFIG_GUIDE.md` with new validation notes. |
| 3 | Tighten chunked upload handling & API auth ergonomics | `apps/api/upload_manager.py` → `ChunkUploadManager._persist_chunk`; `apps/api/app.py` → `_verify_api_key` inner dependency; `apps/api/routes/enhanced.py` (propagate auth errors) | Add regression cases in `tests/test_api_dependencies.py::test_upload_manager_*` and document auth flows in `docs/PLATFORM_RUNBOOK.md`. |
| 4 | Improve guardrail + policy explainability in pipeline responses | `apps/api/pipeline.py` → `_evaluate_guardrails`, `_build_policy_summary`; `core/policy.py` → `build_policy_summary`; `core/modules.py` → `PipelineContext` (add policy field metadata) | Update `tests/test_pipeline_matching.py::test_guardrail_rollup` and enhance `docs/ARCHITECTURE.md` guardrail narrative. |
| 5 | Stabilise enhanced decision provider fallbacks | `core/enhanced_decision.py` → `EnhancedDecisionEngine.evaluate_pipeline`; `fixops-enterprise/src/services/enhanced_decision_engine.py` → `EnhancedDecisionService.reload`; `new_apps/api/processing/knowledge_graph.py` (optional provider hints) | Extend `tests/test_enterprise_enhanced_api.py::test_enhanced_capabilities` and capture provider fallback guidance in `docs/PLATFORM_RUNBOOK.md`. |
| 6 | Streamline CLI stage execution & evidence persistence | `core/stage_runner.py` → `StageRunner.run_stage`; `core/storage.py` → `ArtefactArchive.register_run`; `fixops-enterprise/src/services/run_registry.py` → `RunRegistry.ensure_run` | Enhance `tests/test_cli_commands.py::test_stage_run_sequence` and document run lifecycle in `docs/USAGE_GUIDE.html` (CLI section). |
| 7 | Strengthen enterprise evidence signing & retention | `fixops-enterprise/src/services/evidence.py` → `EvidenceStore.attach_signature`; `fixops-enterprise/src/services/signing.py` → `sign_manifest`; `fixops-enterprise/src/services/compliance.py` → `ComplianceEngine.evaluate` (attach retention metadata) | Expand `tests/test_ci_adapters.py::test_jenkins_signed_response` and update `docs/SECURITY.md` with signing/retention controls. |
| 8 | Unify CI adapter telemetry & marketplace hooks | `integrations/github/adapter.py` → `GitHubCIAdapter.handle_webhook`; `integrations/jenkins/adapter.py` → `JenkinsCIAdapter.ingest`; `integrations/sonarqube/adapter.py` → `SonarQubeAdapter.ingest`; ensure shared helpers in `fixops-enterprise/src/services/decision_engine.py` | Broaden `tests/test_ci_adapters.py` coverage (new telemetry assertions) and record adapter usage in `docs/INTEGRATIONS.md`. |
| 9 | Bolster enterprise observability & rate limiting defaults | `fixops-enterprise/src/core/middleware.py` → `PerformanceMiddleware.dispatch`, `RateLimitMiddleware._consume_token`; `fixops-enterprise/src/services/metrics.py` → aggregation helpers; `apps/api/app.py` → analytics instrumentation wiring | Add `tests/test_rate_limit.py` assertions plus new metrics snapshot tests, and update `docs/OBSERVABILITY.md`. |
| 10 | Close documentation & onboarding gaps | `docs/PLATFORM_RUNBOOK.md` (new operational checklist); `docs/USAGE_GUIDE.html` (CLI/API walkthrough); `ONBOARDING.md` (phase summary appendix); `README.md` (final capability matrix) | Run `scripts/generate_analysis.py` for traceability refresh and ensure `docs/PR_SUMMARY.md` captures the completed phases. |

Dependencies between phases are linear: hardening the overlay (Phase 2) precedes API
adjustments (Phase 3); pipeline explainability (Phase 4) underpins enhanced decision
telemetry (Phase 5); CLI and evidence improvements (Phases 6–7) provide the data consumed by
adapter and observability upgrades (Phases 8–9) before documentation closure (Phase 10).
