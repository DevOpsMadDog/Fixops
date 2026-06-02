# Spec Index

| ID | Title | Family | Status | Routers/Engines |
|----|-------|--------|--------|-----------------|
| [SPEC-001](SPEC-001-trustgraph-correlation.md) | TrustGraph Correlation Bridge (council enrichment) | TrustGraph | DRAFT→IMPLEMENTING | llm_council, trustgraph_integrations, knowledge_brain |
| SPEC-002 | Automated Pen-Test Execution (real runner) | Pentest | PLANNED | openclaw_engine, pentest connector |
| SPEC-003 | Per-customer Local LLM (distillation run) | Council/Learning | PLANNED | llm_learning_loop, llm_distill_train |
| SPEC-004 | Multi-language Reachability (TS/Java/Go) | ASPM | PLANNED | function_reachability_engine |
| [SPEC-011](SPEC-011-aspm.md) | ASPM — Scanner Ingest, Findings, SmartDedup, Reachability | ASPM | BACKFILL | scanner_ingest_router, findings_routes, security_findings_router, findings_lifecycle_router, function_reachability_router, SecurityFindingsEngine, SmartDedup |
| [SPEC-019](SPEC-019-evidence-chain-of-custody.md) | Evidence Chain-of-Custody — cases/custody/seal + REAL re-hash integrity | Evidence/Forensics | BACKFILL | evidence_chain_router, EvidenceChainEngine |
| [SPEC-018](SPEC-018-risk-aggregator.md) | Risk Aggregator — composite org risk score (0-100) + heatmap + thresholds | Risk/CTEM | BACKFILL | risk_aggregator_router, RiskAggregatorEngine |
| [SPEC-017](SPEC-017-full-pipeline-on-ingest.md) | Full Brain-Pipeline on ingest — config-gated, non-blocking, bounded, air-gap-safe | ASPM/BrainPipeline | IMPLEMENTED | pipeline_on_ingest, scanner_ingest_router, wiz_router, prisma_router, blackduck_router |
| [SPEC-016](SPEC-016-scif-stack-fit.md) | SCIF Stack-Fit — correlate existing tools (WIZ/Prisma/BlackDuck/Confluence/Splunk/Jira/ServiceNow/GitHub) + close the loop | Connectors/TrustGraph/Orchestration | IMPLEMENTED | wiz_router, prisma_router, blackduck_router, closed_loop_router, design_context_router, connectors.py:Confluence, jira_cloud_router, servicenow_router, splunk_router, _index_findings_into_brain |

## Backfill backlog (existing API groups needing specs — extend over time)
ASPM ingest+findings · CTEM exposure-cases+prioritization · CSPM posture+compliance · Auth/tenancy ·
Connectors · Evidence/SOC2 · Risk-aggregator · Council verdict. One spec per group, authored as we
touch each, so the whole surface becomes spec-governed for Augment Code intent IDE.

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
