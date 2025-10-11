# FixOps feature call tree

This guide maps the "Why teams adopt FixOps" features from the README to the concrete files and call flows that implement them. It highlights how inputs travel through the system and where each feature is enforced so that you can trace behaviour from artefact ingestion to final outputs.

## Overview tree

```text
FixOps Feature Map
├── Overlay-governed operating modes
│   ├── config/fixops.overlay.yml
│   └── core.configuration.load_overlay()
│       └── StageRunner.run_stage() → RunRegistry.ensure_run()
├── Push ingestion + parity CLI
│   ├── apps.api.app.create_app()
│   │   └── InputNormalizer → PipelineOrchestrator.run()
│   └── core.cli._handle_stage_run() → StageRunner.run_stage()
├── Context-aware decisioning
│   ├── apps.api.pipeline.PipelineOrchestrator.run()
│   └── apps.api.knowledge_graph.KnowledgeGraphService.build()
├── Probabilistic escalation intelligence
│   └── core.probabilistic.ProbabilisticForecastEngine.evaluate()
├── Multi-LLM consensus & transparency
│   └── core.enhanced_decision.MultiLLMConsensusEngine.evaluate()
├── Evidence & automation built-in
│   ├── core.compliance.ComplianceEvaluator.evaluate()
│   ├── core.policy.PolicyAutomation.plan()/execute()
│   ├── core.evidence.EvidenceHub.persist()
│   └── core.feedback.FeedbackRecorder.record()
├── Artefact archiving & regulated storage
│   └── core.storage.ArtefactArchive.persist()
├── Analytics & ROI telemetry
│   └── core.analytics.AnalyticsStore / ROIDashboard
├── Tenant lifecycle & performance intelligence
│   ├── core.tenancy.TenantLifecycleManager.evaluate()
│   └── core.performance.PerformanceSimulator.simulate()
└── Modular & extensible pipeline
    └── core.modules.execute_custom_modules()
```

## Feature walkthroughs

### Overlay-governed operating modes
* **Input → overlay config:** The repository ships with overlay profiles (demo/enterprise) that declare guardrails, directories, module toggles, and size limits in `config/fixops.overlay.yml`. 【F:config/fixops.overlay.yml†L1-L66】
* **Overlay loader:** `core.configuration.load_overlay()` parses the YAML/JSON, merges profile overrides, normalises auth/signing/compliance sections, and materialises an `OverlayConfig`. 【F:core/configuration.py†L1213-L1379】
* **Runtime consumers:** The CLI and API both call `load_overlay()` to seed shared runtime state (`core.cli._handle_stage_run()` and `apps.api.app.create_app()`). Stage execution then uses the overlay to provision run directories (`RunRegistry.ensure_run()`), toggle modules, and enforce upload limits. 【F:core/cli.py†L460-L488】【F:apps/api/app.py†L71-L200】【F:fixops-enterprise/src/services/run_registry.py†L56-L200】

### Push ingestion + parity CLI
* **API flow:** `apps.api.app.create_app()` wires authentication, upload size enforcement, and persistence. Upload handlers stream files through `InputNormalizer`, archive the normalised payloads, and call `PipelineOrchestrator.run()` for unified processing. 【F:apps/api/app.py†L71-L240】【F:apps/api/pipeline.py†L438-L520】
* **CLI flow:** `core.cli._handle_stage_run()` drives the same artefact handling locally by instantiating `StageRunner`, which normalises inputs, persists them through `RunRegistry`, and emits canonical outputs. 【F:core/cli.py†L460-L508】【F:core/stage_runner.py†L215-L466】
* **Identity + storage:** The stage runner hydrates design artefacts with deterministic IDs (`id_allocator.ensure_ids`) and records all artefacts through the run registry so parity is maintained between push uploads and local runs. 【F:fixops-enterprise/src/services/id_allocator.py†L13-L40】【F:fixops-enterprise/src/services/run_registry.py†L67-L200】

### Context-aware decisioning
* **Pipeline orchestration:** `PipelineOrchestrator.run()` correlates design rows, SBOM components, SARIF findings, CVE records, optional VEX/CNAPP/context payloads, and builds a crosswalk that underpins guardrails, compliance, analytics, and decisioning. 【F:apps/api/pipeline.py†L438-L640】
* **Module fan-out:** Depending on overlay toggles, the orchestrator invokes context engine, onboarding, compliance, policy automation, knowledge graph, SSDLC, AI agents, exploit intelligence, probabilistic forecasting, analytics, tenancy, performance, IaC, evidence bundling, and custom modules in sequence. 【F:apps/api/pipeline.py†L717-L1004】【F:core/modules.py†L20-L126】
* **Knowledge graph:** Pipeline outputs feed the `KnowledgeGraphService.build()` wrapper, which assembles CTINexus-style entities/relationships before the enhanced decision engine consumes them. 【F:apps/api/knowledge_graph.py†L1-L200】【F:new_apps/api/processing/knowledge_graph.py†L1-L120】

### Probabilistic escalation intelligence
* **Input → forecast:** When enabled, `ProbabilisticForecastEngine.evaluate()` ingests severity histograms, crosswalk context, and exploited CVEs to generate calibrated priors, transition matrices, and escalation probabilities for each component. 【F:apps/api/pipeline.py†L870-L880】【F:core/probabilistic.py†L1-L199】
* **Output:** The resulting forecast is persisted to analytics storage and surfaced alongside the pipeline response so operators can spot drift risk early. 【F:apps/api/pipeline.py†L870-L904】【F:core/analytics.py†L136-L190】

### Multi-LLM consensus & transparency
* **Ensemble orchestration:** `EnhancedDecisionEngine` constructs a multi-provider consensus workflow using `MultiLLMConsensusEngine.evaluate()`, weighting GPT-5/Claude/Gemini/Sentinel models, injecting knowledge graph context, and returning disagreement telemetry. 【F:core/enhanced_decision.py†L1-L190】
* **Pipeline integration:** The pipeline hands severity, guardrail, compliance, CNAPP, exploitability, AI agent, marketplace, and knowledge-graph signals into the enhanced engine so the final decision bundle includes explainable multi-LLM insights. 【F:apps/api/pipeline.py†L920-L936】

### Evidence & automation built-in
* **Compliance packs:** The pipeline hydrates `ComplianceEvaluator` so every run maps requirements, guardrail status, and evidence coverage to framework controls before policy or automation logic fires. 【F:apps/api/pipeline.py†L717-L804】【F:core/compliance.py†L1-L120】
* **Policy automation:** `PolicyAutomation.plan()` inspects guardrail outcomes, context scores, and compliance gaps to queue Jira/Confluence actions; `PolicyAutomation.execute()` then dispatches them via connectors for auditing. 【F:apps/api/pipeline.py†L764-L804】【F:core/policy.py†L83-L200】
* **Evidence hub:** After the decision stage, `EvidenceHub.persist()` bundles overlay metadata, guardrail/compliance summaries, analytics, tenancy telemetry, and probabilistic outputs into compressed/encrypted archives with retention tracking. 【F:apps/api/pipeline.py†L953-L1004】【F:core/evidence.py†L1-L200】
* **Feedback capture:** When overlays enable capture, `FeedbackRecorder.record()` writes secure JSONL evidence, forwards to Jira/Confluence, and updates analytics stores so remediation decisions remain auditable. 【F:apps/api/app.py†L135-L155】【F:core/feedback.py†L1-L140】

### Artefact archiving & regulated storage
* **Secure persistence:** `ArtefactArchive.persist()` saves raw uploads and normalised artefacts under allow-listed directories with per-stage manifests, ensuring regulated tenants retain evidence without leaving permitted paths. 【F:apps/api/app.py†L214-L240】【F:core/storage.py†L1-L96】

### Analytics & ROI telemetry
* **Ingestion + persistence:** API startup provisions an `AnalyticsStore` under overlay-allowlisted directories so forecasts, exploit snapshots, policy delivery metrics, and feedback outcomes persist per run. 【F:apps/api/app.py†L122-L155】【F:core/analytics.py†L1-L200】
* **ROI computation:** When the analytics module is toggled on, `ROIDashboard.evaluate()` translates severity counts, automation outputs, and module execution mixes into hours saved, monetary value, and module-level contribution. 【F:apps/api/pipeline.py†L885-L897】【F:core/analytics.py†L415-L520】
* **Dashboards:** Stored artefacts roll up via `AnalyticsStore.load_dashboard()` to power README-referenced ROI storytelling and executive reporting. 【F:core/analytics.py†L288-L413】

### Tenant lifecycle & performance intelligence
* **Tenant lifecycle:** `TenantLifecycleManager.evaluate()` compares executed modules against tenant expectations to surface lifecycle gaps and operations metadata for CISO-facing dashboards. 【F:apps/api/pipeline.py†L900-L906】【F:core/tenancy.py†L11-L136】
* **Performance simulations:** `PerformanceSimulator.simulate()` turns module latency profiles, severity mix, and throughput targets into SLA recommendations and capacity plans. 【F:apps/api/pipeline.py†L909-L919】【F:core/performance.py†L10-L123】

### Modular & extensible pipeline
* **Module matrix:** Overlay flags determine which modules execute, and the pipeline records configured/enabled/executed modules for transparency. Custom entrypoints declared in the overlay run via `execute_custom_modules()`, receiving the full pipeline context and the ability to mutate results. 【F:apps/api/pipeline.py†L717-L1004】【F:core/modules.py†L20-L126】

## Stage input → output map

Each stage in the CLI/API pipeline follows a deterministic input/function/output chain:

| Stage | Input artefact | Core calls | Output payload |
| --- | --- | --- | --- |
| Requirements | CSV/JSON requirements | `_parse_requirements()` → `_assign_requirement_ids()` → `_derive_ssvc_anchor()` | Requirement list with SSVC anchor | 【F:core/stage_runner.py†L215-L234】【F:core/stage_runner.py†L484-L552】
| Design | Design manifest/CSV | `_load_design_payload()` → `id_allocator.ensure_ids()` → `_design_risk_score()` | Design manifest with minted IDs and risk score | 【F:core/stage_runner.py†L236-L255】【F:fixops-enterprise/src/services/id_allocator.py†L13-L40】
| Build | SBOM + extras | `InputNormalizer.load_sbom()` → risk flag scan → `_read_optional_json()` | Component index, risk flags, provenance links, build risk score | 【F:core/stage_runner.py†L257-L306】
| Test | SARIF/tests JSON | `_load_test_inputs()` → severity summarisation → drift/coverage calc | Severity histogram, drift metrics, coverage snapshot | 【F:core/stage_runner.py†L308-L341】【F:core/stage_runner.py†L570-L611】
| Deploy | Terraform/K8s plan | `_load_deploy_payload()` → `_analyse_posture()` → `_control_evidence()` | Posture findings, control evidence, deploy risk score | 【F:core/stage_runner.py†L343-L370】【F:core/stage_runner.py†L613-L639】
| Operate | Ops telemetry | JSON merge with KEV/EPSS feeds → pressure computation | Pressure snapshot with KEV/EPSS hits and operate risk score | 【F:core/stage_runner.py†L372-L413】
| Decision | Prior stage outputs | `_collect_documents()` → `_decision_factors()` → `_write_evidence_bundle()` | Allow/Defer verdict, confidence, factors, bundled manifest | 【F:core/stage_runner.py†L415-L466】

This table shows how every artefact flows through deterministic helper functions before being written back via `RunRegistry.write_output()` so that demo, CLI, and API invocations share the same guardrails and evidence trail. 【F:fixops-enterprise/src/services/run_registry.py†L167-L200】
