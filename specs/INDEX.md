# Spec Index

> Status is authoritative here, sourced from each spec file's header (synced 2026-06-03).
> Ordered by spec ID. This table is the Augment Code intent-IDE governance map — every
> spec file in `specs/` must have a row so the whole API surface is spec-governed.

| ID | Title | Family | Status | Routers/Engines |
|----|-------|--------|--------|-----------------|
| [SPEC-001](SPEC-001-trustgraph-correlation.md) | TrustGraph Correlation Bridge (council enrichment) | TrustGraph | IMPLEMENTING | llm_council, trustgraph_integrations, knowledge_brain |
| [SPEC-002](SPEC-002-nuclei-pentest.md) | Local Nuclei Pen-Test Connector (real exploitability, no SaaS) | Pentest | IMPLEMENTED | openclaw_router (/api/v1/openclaw), openclaw_engine, pentest_connectors/nuclei_connector |
| [SPEC-003](SPEC-003-local-council.md) | Local LLM Council (real air-gap inference) | Council/Learning | IMPLEMENTED | llm_council, llm_providers (AirGapLLMProvider), airgap_config, llm_learning_loop, llm_distill_train |
| [SPEC-004](SPEC-004-reachability-multilang.md) | Multi-language Reachability (TS/Java/Go) + auto-run | ASPM/Reachability | IMPLEMENTED | function_reachability_engine, brain_pipeline |
| [SPEC-005](SPEC-005-airgap-enforced-default.md) | Air-Gap Enforced By Default (SCIF safe boot) | Air-Gap/Platform | IMPLEMENTED | app.py boot, observability, airgap_config, airgap_deployment (TelemetryKillSwitch), llm_providers, suite-feeds |
| [SPEC-005b](SPEC-005b-graph-populate.md) | Auto-populate TrustGraph + Attack-Path from scans (blast_radius≠0) | TrustGraph/Pipeline | IMPLEMENTED | brain_pipeline (_step_build_graph/_correlate_and_emit), attack_path_engine, knowledge_brain, trustgraph_backbone |
| [SPEC-006](SPEC-006-honest-compliance-reporting.md) | Honest Compliance Reporting (no simulated passes) | Compliance/Accreditation | IMPLEMENTED | compliance_engine |
| [SPEC-006b](SPEC-006b-crypto-hardening.md) | Crypto Hardening — key-at-rest, immutable audit, at-rest DB | Accreditation/Crypto | IMPLEMENTED | crypto, evidence_chain, key_manager, audit, at-rest DB |
| [SPEC-007](SPEC-007-systemic-tenancy.md) | Systemic Tenancy (TenantContext + ContextVar + CI lint) | Platform/Tenancy | IMPLEMENTED | tenant_isolation (TenantContext), org_middleware (get_org_id), CI gate |
| [SPEC-008](SPEC-008-ha-durability.md) | HA / Durability — SQLite WAL + Litestream replication + restore | Platform/Ops | IMPLEMENTED | docker/litestream.yml, db_durability, backup_verify, restore_runbook |
| [SPEC-009](SPEC-009-supplychain-lockfile.md) | Reproducible Build — lockfile + dependabot + SBOM | Supply Chain/Build | IMPLEMENTED | requirements.lock, .github/dependabot.yml, CI pip-audit gate, docs/sbom |
| [SPEC-010](SPEC-010-maintainability.md) | Maintainability — dead-router inventory + CI gate + schema registry | Platform/Maintainability | IMPLEMENTED | router_inventory.py, test_router_inventory_gate.py, schema_registry, dead_router_allowlist.txt |
| [SPEC-011](SPEC-011-aspm.md) | ASPM — Scanner Ingest, Findings, SmartDedup, Reachability | ASPM | BACKFILL | scanner_ingest_router, findings_routes, security_findings_router, findings_lifecycle_router, function_reachability_router, SecurityFindingsEngine, SmartDedup |
| [SPEC-012](SPEC-012-ctem.md) | CTEM — Continuous Threat Exposure Management surface | CTEM/ASPM | BACKFILL | ctem_router, ctem_engine_router (/api/v1/ctem) |
| [SPEC-013](SPEC-013-cspm.md) | CSPM — Cloud Security Posture Management | CSPM/Cloud | BACKFILL | cloud_posture_router (/api/v1/cloud-posture), cspm_connector_router (/api/v1/connectors/cspm) |
| [SPEC-014](SPEC-014-auth-tenancy.md) | Auth + Tenancy | Platform/Auth/Tenancy | BACKFILL | auth_router (/api/v1/auth), auth0_router, org_middleware |
| [SPEC-015](SPEC-015-connectors.md) | Connector Framework (Pull / Push / Scanner) | Connectors | BACKFILL | connectors_router (/api/v1/connectors), connectors.py, pull_connector, connector_ingestion_scheduler, github_api_engine, scanner_parsers, universal_connector, connector_registry |
| [SPEC-016](SPEC-016-scif-stack-fit.md) | SCIF Stack-Fit — correlate existing tools + close the loop | Connectors/TrustGraph/Orchestration | IMPLEMENTED | wiz_router, prisma_router, blackduck_router, closed_loop_router, design_context_router, connectors.py:Confluence, jira_cloud_router, servicenow_router, splunk_router, _index_findings_into_brain |
| [SPEC-017](SPEC-017-full-pipeline-on-ingest.md) | Full Brain-Pipeline on ingest — config-gated, non-blocking, bounded, air-gap-safe | ASPM/BrainPipeline | IMPLEMENTED | pipeline_on_ingest, scanner_ingest_router, wiz_router, prisma_router, blackduck_router |
| [SPEC-018](SPEC-018-risk-aggregator.md) | Risk Aggregator — composite org risk score (0-100) + heatmap + thresholds | Risk/CTEM | BACKFILL | risk_aggregator_router, RiskAggregatorEngine |
| [SPEC-019](SPEC-019-evidence-chain-of-custody.md) | Evidence Chain-of-Custody — cases/custody/seal + REAL re-hash integrity | Evidence/Forensics | BACKFILL | evidence_chain_router, EvidenceChainEngine |
| [SPEC-020](SPEC-020-council-verdict.md) | Council Verdict API — multi-LLM 3-stage decision + honest cost/escalation | Council/Decision | BACKFILL | council_router, LLMCouncilEngine, CouncilVerdict |
| [SPEC-021](SPEC-021-mpte.md) | MPTE — Multi-Phase Test & Exploitability Validation (FP-reduction moat) | Pentest/Offensive Validation | BACKFILL | mpte_router (/api/v1/mpte), mpte_orchestrator_router (/api/v1/mpte-orchestrator), mpte_advanced, mpte_models (ExploitabilityLevel), mpte_db |
| [SPEC-022](SPEC-022-threat-intel.md) | Threat Intelligence Layer — feeds + actors + IOC enrichment (ingest-first, honest-empty) | Threat Intelligence | BACKFILL | threat_intel_router (/api/v1/threat-intel), feeds_router (/api/v1/feeds, 28+ sources), ioc_enrichment_router (/api/v1/ioc-enrichment), suite-feeds/* |

## Backfill backlog (existing API groups needing specs — extend over time)
DONE (2026-06-03): the original backlog is fully authored — ASPM ingest+findings (SPEC-011),
CTEM exposure (SPEC-012), CSPM posture+compliance (SPEC-013), Auth/tenancy (SPEC-014),
Connectors (SPEC-015), Evidence/SOC2 (SPEC-019), Risk-aggregator (SPEC-018), Council verdict
(SPEC-020). All registered in the table above.

Next candidate groups (not yet spec-governed — author one per group as touched, so the whole
surface stays spec-governed for the Augment Code intent IDE): SOAR / playbooks, deception,
forensics, exec-reporting / evidence-export.
(MPTE / attack-simulation → SPEC-021; threat-intel feeds + IOC → SPEC-022; both 2026-06-03.)

## Pre-mortem-driven de-risk specs (SCIF $100K, added 2026-06-01)
| ID | Title | Priority | Effort | Kills failure |
|----|-------|----------|--------|---------------|
| SPEC-002 | Local Nuclei pen-test connector (real exploitability, no SaaS) | P1 | 2-3wk | intelligence value |
| SPEC-003 | Local Qwen council (distill + AirGapLLMProvider) | P1 | 1.5wk | intelligence value |
| SPEC-004 | Multi-language reachability (tree-sitter TS/Java/Go + auto-run) | P2 | 1wk | FP-reduction breadth |
| SPEC-005 | Air-gap enforced-by-default (telemetry kill-switch, OFFLINE env) | P0 | days | day-1 air-gap leak |
| SPEC-005b | Auto-populate TrustGraph + attack-path from scans (blast-radius≠0) | P1 | 1wk | intelligence value |
| SPEC-006 | FIPS-validated crypto + at-rest encryption + immutable audit + PIV-CAC | P2 | months | accreditation/ATO |
| SPEC-007 | Systemic tenancy (TenantScopedEngine + ContextVar + CI lint) | P1 | 1-2wk | spillage |
| SPEC-008 | HA / Litestream replication (1s RPO) | P1 | 1wk | data loss |
| SPEC-009 | Python lockfile + dependabot + SBOM'd reproducible build | P0 | 1day | procurement disqual |
| SPEC-010 | Dead-router purge (686) + SQLite migration registry + CI gate | P2 | 1wk | 5-yr maintainability |

Pre-mortem evidence: docs/premortem/PM-1..PM-5 + PREMORTEM_SCIF_2026-06-01.md
