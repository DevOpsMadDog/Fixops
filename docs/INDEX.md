# ALdeci Documentation Index

> **Generated:** 2026-04-26 | **Branch:** `features/intermediate-stage`
> **Total docs catalogued:** 108 (markdown) + 3 JSON schemas + image/HTML assets
> **Rule:** No docs were deleted. All consolidation notes are advisory.

---

## READ THESE FIRST (New LLM Onboarding — ordered)

A new LLM picking up this codebase should read these five docs before anything else:

| # | File | Why |
|---|------|-----|
| 1 | [`docs/HANDOFF_2026-04-26-evening.md`](HANDOFF_2026-04-26-evening.md) | Full day recap: what shipped, what is in-flight, exact branch tip SHA, board state. Start here. |
| 2 | [`docs/CTEM_PLUS_IDENTITY.md`](CTEM_PLUS_IDENTITY.md) | Canonical platform identity: 8 native engines, 12-step Brain Pipeline, moats, positioning. All docs must agree with this. |
| 3 | [`docs/CEO_VISION.md`](CEO_VISION.md) | North-star: 10 strategic pillars V1–V10, market problem, architecture overview. |
| 4 | [`docs/ALDECI_REARCHITECTURE.md`](ALDECI_REARCHITECTURE.md) | Source-of-truth architecture: component map, data flow, deployment options. |
| 5 | [`docs/competitive_validation_2026-04-26.md`](competitive_validation_2026-04-26.md) | 149 capability × 7 competitor scoring. 83% WIN/MATCH. Identifies the 4 gap clusters to close. |

---

## Duplicate / Near-Duplicate Consolidation Candidates

> These should be merged in a future session. Do NOT delete — preserve git history.

| Group | Files | Recommendation |
|-------|-------|----------------|
| **Architecture** | `ALDECI_REARCHITECTURE.md`, `ARCHITECTURE_CURRENT.md`, `ARCHITECTURE_v3.md`, `ARCHITECTURE_CHEATSHEET.md`, `BEAST_MODE_ARCHITECTURE.md` | Keep `ALDECI_REARCHITECTURE.md` as canonical; fold cheatsheet content as an appendix section; deprecate the rest with a redirect header. |
| **SCIF docs** | `scif_readiness_2026-04-26.md` (engineering scorecard) + `scif/SSP_aldeci_2026-04-26.md` + `scif/POAM_aldeci_2026-04-26.md` + `scif/SCIF_PILOT_BUNDLE_README.md` | These are complementary, not duplicates, but `scif_readiness_2026-04-26.md` should be the entry-point index linking into the `scif/` sub-folder. |
| **Handoffs** | `HANDOFF_2026-04-26.md` (morning) + `HANDOFF_2026-04-26-evening.md` (final) | Evening supersedes morning. Morning should get a one-line header: `> SUPERSEDED — see HANDOFF_2026-04-26-evening.md`. |
| **LLM training** | `self_learning_llm_scope_2026-04-26.md` (scope/decision), `LLM_TRAINING_ROADMAP_2026-04-26.md` (8-week plan), `llm_learning_phase1_runlog_2026-04-26.md` (run log) | Three distinct documents but could share a single `docs/llm/` sub-folder for navigability. |
| **Investor / Pitch** | `INVESTOR_PITCH.md`, `investor/INVESTOR_PACK_2026-04-26.md`, `investor/data_room_index.md`, `pitch/ALDECI_PITCH_DECK_2026-04-26.md`, `pitch/ONE_PAGER_2026-04-26.md` | `INVESTOR_PITCH.md` is the legacy version; `investor/INVESTOR_PACK_2026-04-26.md` is the current. Redirect old doc to new. |
| **API reference** | `API_REFERENCE.md`, `API_REFERENCE_v2.md`, `API_QUICKSTART.md`, `api-reference/README.md` + wave_a/b/c/d docs | `API_REFERENCE_v2.md` is the living doc; legacy `API_REFERENCE.md` should link to v2 and the `api-reference/` sub-folder. |
| **Demo scripts** | `DEMO_SCRIPT.md`, `sales/demo_script_30min.md`, `sales/video/5min_demo_script.md` | Three different formats/lengths — legitimately distinct, but should be cross-linked. |

---

## Full Catalogue

### Core Platform Identity

| File | Description | Audience |
|------|-------------|----------|
| [`CTEM_PLUS_IDENTITY.md`](CTEM_PLUS_IDENTITY.md) | Canonical: 8 native engines, 12-step Brain Pipeline, MPTE, FAIL, air-gap, moat table | CTO / next-LLM / customer |
| [`CEO_VISION.md`](CEO_VISION.md) | North-star vision, 10 pillars V1–V10, market sizing, strategic positioning | CTO / investor |
| [`ALDECI_BUILD_STATUS.md`](ALDECI_BUILD_STATUS.md) | Current build health: test counts, engine counts, router counts | next-LLM / engineer |

### Architecture

| File | Description | Audience |
|------|-------------|----------|
| [`ALDECI_REARCHITECTURE.md`](ALDECI_REARCHITECTURE.md) | Primary architecture doc v2.5: component map, data flow, deployment | next-LLM / engineer / CTO |
| [`ARCHITECTURE_CURRENT.md`](ARCHITECTURE_CURRENT.md) | Current-state architecture snapshot (may lag rearchitecture doc) | engineer |
| [`ARCHITECTURE_v3.md`](ARCHITECTURE_v3.md) | v3 architecture proposal | CTO / engineer |
| [`ARCHITECTURE_CHEATSHEET.md`](ARCHITECTURE_CHEATSHEET.md) | Quick-reference: key paths, port map, import conventions | engineer |
| [`BEAST_MODE_ARCHITECTURE.md`](BEAST_MODE_ARCHITECTURE.md) | Beast Mode v6 tool stack architecture (OMC, SwarmClaw, TrustGraph, code-review-graph) | CTO / next-LLM |

### Handoffs (Session State)

| File | Description | Audience |
|------|-------------|----------|
| [`HANDOFF_2026-04-26-evening.md`](HANDOFF_2026-04-26-evening.md) | **CANONICAL for 2026-04-26.** 50-commit megasession: TrustGraph 24%→38%, LLM Phase 1 live, 703 DPO pairs, P0 6/6 UX heroes, SCIF 3 stages, sales pack | next-LLM / CTO |
| [`HANDOFF_2026-04-26.md`](HANDOFF_2026-04-26.md) | Morning handoff (superseded by evening version above) | next-LLM |
| [`SESSION_HISTORY.md`](SESSION_HISTORY.md) | Full per-wave history Wave 6 → Wave 60+, 76 KB | CTO / next-LLM |

### Competitive Intelligence

| File | Description | Audience |
|------|-------------|----------|
| [`competitive_validation_2026-04-26.md`](competitive_validation_2026-04-26.md) | 149 caps × 7 competitors: 83% WIN/MATCH, 4 gap clusters, moats reaffirmed | CTO / analyst |
| [`COMPETITIVE_ANALYSIS.md`](COMPETITIVE_ANALYSIS.md) | Evergreen competitor overview (Snyk, Apiiro, Wiz, Tenable, XM Cyber) | CTO / sales |
| [`gap-analysis-refresh-2026-04-26.md`](gap-analysis-refresh-2026-04-26.md) | 71-row gap matrix: 50 DONE, 12 IP, 6 NS, 2 PD | CTO / next-LLM |

### UX Consolidation

| File | Description | Audience |
|------|-------------|----------|
| [`UX_CONSOLIDATION_PLAN_2026-04-26.md`](UX_CONSOLIDATION_PLAN_2026-04-26.md) | 89→30 screen collapse plan: P0/P1/P2 split, target nav, mapping table | CTO / engineer |
| [`UI_OVERHAUL_DISPATCH_2026-04-22.md`](UI_OVERHAUL_DISPATCH_2026-04-22.md) | 22-unit UI overhaul plan, NEW-G071, 216 no-fetch pages | CTO / engineer |
| [`onboarding_ux_bugs_2026-04-24.md`](onboarding_ux_bugs_2026-04-24.md) | UX bugs found during 15-tenant onboarding | engineer |

### LLM Self-Learning

| File | Description | Audience |
|------|-------------|----------|
| [`self_learning_llm_scope_2026-04-26.md`](self_learning_llm_scope_2026-04-26.md) | Scope decision: RAG + DPO path chosen (6–8 weeks), full fine-tune deferred | CTO / engineer |
| [`LLM_TRAINING_ROADMAP_2026-04-26.md`](LLM_TRAINING_ROADMAP_2026-04-26.md) | 8-week Phase 1 gantt, milestones, air-gap constraints | CTO / engineer |
| [`llm_learning_phase1_runlog_2026-04-26.md`](llm_learning_phase1_runlog_2026-04-26.md) | Run log: 703 council_verdicts + 703 DPO pairs produced today; Phase 2 dry-run validated | engineer / next-LLM |

### TrustGraph Coverage

| File | Description | Audience |
|------|-------------|----------|
| [`trustgraph_coverage_2026-04-26.md`](trustgraph_coverage_2026-04-26.md) | Coverage scorecard: engines 99.1%, routers 3.9%, connectors 0% — ordered fix list | engineer / CTO |
| [`integration_topology_2026-04-25.md`](integration_topology_2026-04-25.md) | Integration topology HTML + narrative | engineer |

### SCIF / Federal Compliance

| File | Description | Audience |
|------|-------------|----------|
| [`scif_readiness_2026-04-26.md`](scif_readiness_2026-04-26.md) | Engineering scorecard: 3 MET / 7 PARTIAL / 5 MISSING, ~35% maturity overall | CTO / auditor |
| [`scif/SCIF_PILOT_BUNDLE_README.md`](scif/SCIF_PILOT_BUNDLE_README.md) | ISSO-facing: bundle contents, deploy steps, ATO inheritance guidance | auditor / customer |
| [`scif/SSP_aldeci_2026-04-26.md`](scif/SSP_aldeci_2026-04-26.md) | System Security Plan (NIST 800-53 Rev 5) | auditor |
| [`scif/POAM_aldeci_2026-04-26.md`](scif/POAM_aldeci_2026-04-26.md) | Plan of Action and Milestones | auditor |
| [`scif/nist_800-53_control_matrix_2026-04-26.csv`](scif/nist_800-53_control_matrix_2026-04-26.csv) | 95% of in-scope NIST controls mapped | auditor |
| [`scif/threat_model_aldeci_2026-04-26.md`](scif/threat_model_aldeci_2026-04-26.md) | STRIDE threat model for air-gapped deployment | auditor / engineer |
| [`scif/crypto_module_datasheet_2026-04-26.md`](scif/crypto_module_datasheet_2026-04-26.md) | FIPS 204 ML-DSA hybrid, SoftHSM PKCS#11, crypto inventory | auditor |
| [`scif/auditor_quick_reference_2026-04-26.md`](scif/auditor_quick_reference_2026-04-26.md) | One-page auditor cheat-sheet: control families, evidence locations | auditor |
| [`scif/llm_air_gap_setup_2026-04-26.md`](scif/llm_air_gap_setup_2026-04-26.md) | Step-by-step: run LLM council fully offline (Ollama + Gemma 4 + Qwen) | engineer / auditor |
| [`scif/stig_hardening_checklist_2026-04-26.md`](scif/stig_hardening_checklist_2026-04-26.md) | STIG hardening checklist for ALDECI host OS + container | auditor / engineer |

### Sales & Go-to-Market

| File | Description | Audience |
|------|-------------|----------|
| [`sales/demo_script_30min.md`](sales/demo_script_30min.md) | 30-min Command→Brain→Compliance demo arc | sales |
| [`sales/video/5min_demo_script.md`](sales/video/5min_demo_script.md) | 5-min video demo script | sales |
| [`sales/demo_run_evidence_2026-04-26.md`](sales/demo_run_evidence_2026-04-26.md) | Proof-of-demo screenshots and network traces from 2026-04-26 run | sales / CTO |
| [`sales/poc_template.md`](sales/poc_template.md) | POC engagement template (success criteria, timeline, sign-off) | sales / customer |
| [`sales/customer_onboarding_playbook.md`](sales/customer_onboarding_playbook.md) | Step-by-step customer onboarding: org create → connector → Brain Pipeline | sales / customer |
| [`sales/win_loss_analysis_template.md`](sales/win_loss_analysis_template.md) | Win/loss debrief template | sales |
| [`GO_TO_MARKET.md`](GO_TO_MARKET.md) | GTM strategy: ICP, pricing tiers, channel motion | CTO / investor |
| [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md) | Legacy demo script (see sales/ for current versions) | sales |

### Battle Cards

| File | Description | Audience |
|------|-------------|----------|
| [`sales/battle_cards/aikido.md`](sales/battle_cards/aikido.md) | vs Aikido Security | sales |
| [`sales/battle_cards/apiiro.md`](sales/battle_cards/apiiro.md) | vs Apiiro | sales |
| [`sales/battle_cards/snyk.md`](sales/battle_cards/snyk.md) | vs Snyk AppRisk | sales |
| [`sales/battle_cards/sonatype.md`](sales/battle_cards/sonatype.md) | vs Sonatype Lifecycle | sales |
| [`sales/battle_cards/tenable.md`](sales/battle_cards/tenable.md) | vs Tenable One | sales |
| [`sales/battle_cards/wiz.md`](sales/battle_cards/wiz.md) | vs Wiz | sales |
| [`sales/battle_cards/xm_cyber.md`](sales/battle_cards/xm_cyber.md) | vs XM Cyber | sales |

### SCIF Sales Pipeline

| File | Description | Audience |
|------|-------------|----------|
| [`sales/scif/target_list_2026-04-26.md`](sales/scif/target_list_2026-04-26.md) | 36 federal sponsor targets with tier and entry strategy | sales |
| [`sales/scif/cold_outreach_templates_2026-04-26.md`](sales/scif/cold_outreach_templates_2026-04-26.md) | 4 cold outreach email templates for federal/SCIF personas | sales |
| [`sales/scif/discovery_playbook_2026-04-26.md`](sales/scif/discovery_playbook_2026-04-26.md) | Federal discovery call playbook | sales |
| [`sales/scif/pilot_sow_template_2026-04-26.md`](sales/scif/pilot_sow_template_2026-04-26.md) | 20-day pilot SOW template | sales / customer |
| [`sales/scif/reference_arch_scif_2026-04-26.md`](sales/scif/reference_arch_scif_2026-04-26.md) | Reference architecture for SCIF deployment | sales / auditor |

### Analyst Relations

| File | Description | Audience |
|------|-------------|----------|
| [`sales/analyst/analyst_one_pager_2026-04-26.md`](sales/analyst/analyst_one_pager_2026-04-26.md) | One-pager for Gartner/Forrester briefings | analyst |
| [`sales/analyst/mq_wave_submission_2026-04-26.md`](sales/analyst/mq_wave_submission_2026-04-26.md) | MQ / Wave submission brief | analyst |
| [`sales/analyst/reference_architecture_whitepaper.md`](sales/analyst/reference_architecture_whitepaper.md) | Technical reference architecture whitepaper | analyst / customer |
| [`sales/analyst/case_study_template.md`](sales/analyst/case_study_template.md) | Customer case study template | sales / analyst |
| [`sales/analyst/anti_customer_profile.md`](sales/analyst/anti_customer_profile.md) | Anti-ICP: who NOT to sell to | sales |

### Investor Materials

| File | Description | Audience |
|------|-------------|----------|
| [`investor/INVESTOR_PACK_2026-04-26.md`](investor/INVESTOR_PACK_2026-04-26.md) | Current Series A pack: moats, traction, team, ask (pre-revenue, design-partner stage) | investor |
| [`investor/data_room_index.md`](investor/data_room_index.md) | Data room index: what exists, what is still needed | investor / CTO |
| [`investor/TRACTION_METRICS_2026-04-26.md`](investor/TRACTION_METRICS_2026-04-26.md) | Traction metrics: commit velocity, test counts, feature surface | investor |
| [`pitch/ALDECI_PITCH_DECK_2026-04-26.md`](pitch/ALDECI_PITCH_DECK_2026-04-26.md) | 12-slide pitch deck (narrative format) | investor |
| [`pitch/ONE_PAGER_2026-04-26.md`](pitch/ONE_PAGER_2026-04-26.md) | One-pager summary | investor / analyst |
| [`pitch/objection_handling_2026-04-26.md`](pitch/objection_handling_2026-04-26.md) | Investor / enterprise objection handling guide | sales / CTO |
| [`INVESTOR_PITCH.md`](INVESTOR_PITCH.md) | Legacy investor pitch (superseded by investor/INVESTOR_PACK_2026-04-26.md) | investor |

### API Reference

| File | Description | Audience |
|------|-------------|----------|
| [`API_REFERENCE.md`](API_REFERENCE.md) | Legacy API reference (pre-wave-router expansion) | engineer |
| [`API_REFERENCE_v2.md`](API_REFERENCE_v2.md) | Current v2 API reference (living doc) | engineer / customer |
| [`API_QUICKSTART.md`](API_QUICKSTART.md) | 3-step API quickstart with curl examples | engineer / customer |
| [`ALDECI_Postman_Collection.json`](ALDECI_Postman_Collection.json) | Importable Postman collection | engineer |
| [`api-reference/README.md`](api-reference/README.md) | Index of wave-router API docs (124 endpoints documented) | engineer |
| [`api-reference/wave_a.md`](api-reference/wave_a.md) | Wave A: Code & Architecture Intelligence (17 endpoints) | engineer |
| [`api-reference/wave_b.md`](api-reference/wave_b.md) | Wave B: Supply Chain & Runtime (endpoints) | engineer |
| [`api-reference/wave_c.md`](api-reference/wave_c.md) | Wave C: Identity & Access (endpoints) | engineer |
| [`api-reference/wave_d.md`](api-reference/wave_d.md) | Wave D: Governance & Compliance (endpoints) | engineer |
| [`api-reference/context_engine.md`](api-reference/context_engine.md) | Context Engine router API | engineer |
| [`api-reference/duckdb_analytics.md`](api-reference/duckdb_analytics.md) | DuckDB Analytics router API | engineer |
| [`api-reference/graphrag.md`](api-reference/graphrag.md) | GraphRAG router API | engineer |
| [`api-reference/intelligent_security.md`](api-reference/intelligent_security.md) | Intelligent Security router API | engineer |
| [`api-reference/mitre_attack_coverage.md`](api-reference/mitre_attack_coverage.md) | MITRE ATT&CK coverage router API | engineer |
| [`api-reference/privilege_escalation_detector.md`](api-reference/privilege_escalation_detector.md) | Privilege Escalation Detector router API | engineer |
| [`api-reference/verification.md`](api-reference/verification.md) | Verification router API | engineer |

### Engineering Audits (2026-04-26 session)

| File | Description | Audience |
|------|-------------|----------|
| [`board_audit_2026-04-26.md`](board_audit_2026-04-26.md) | Multica board audit: 247 todos scanned, 89 closed, 158 remain (77 endpoint + 81 frontend) | next-LLM / engineer |
| [`schema_migration_audit_2026-04-26.md`](schema_migration_audit_2026-04-26.md) | 65 schema-migration todos: 2 auto-closed as stale placeholders | next-LLM / engineer |
| [`empty_endpoints_triage_2026-04-26.md`](empty_endpoints_triage_2026-04-26.md) | 30 empty endpoints: 1 fixed (actor-tracking, 2,805 MITRE ATT&CK records), 29 classified/deferred | next-LLM / engineer |
| [`dependabot_triage_2026-04-26.md`](dependabot_triage_2026-04-26.md) | 140 Dependabot alerts triaged: 2 Critical, 55 High. Disposition matrix with fix plan | engineer / CTO |

### Multi-Tenant Onboarding & Testing

| File | Description | Audience |
|------|-------------|----------|
| [`multi_tenant_onboarding_results_2026-04-24.md`](multi_tenant_onboarding_results_2026-04-24.md) | 15 GitHub apps onboarded as real tenants; finding counts per tenant per scanner | next-LLM / engineer |
| [`REAL_PRODUCT_VALIDATION_MASTER_RUNBOOK.md`](REAL_PRODUCT_VALIDATION_MASTER_RUNBOOK.md) | Master runbook for real-data E2E validation | engineer |
| [`ORG_WIDE_PERSONA_TRIAL_RUNBOOK.md`](ORG_WIDE_PERSONA_TRIAL_RUNBOOK.md) | 30-persona trial runbook: role matrix, test scenarios | engineer / CTO |
| [`persona_coverage_after_seed.md`](persona_coverage_after_seed.md) | 30-persona × UI-page coverage map | CTO / engineer |

### Deployment & Operations

| File | Description | Audience |
|------|-------------|----------|
| [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) | Primary deployment guide: Docker, K8s/Helm, air-gap | engineer / customer |
| [`DEPLOYMENT_HA.md`](DEPLOYMENT_HA.md) | High-availability deployment addendum | engineer |
| [`deployment/on-prem-ha.md`](deployment/on-prem-ha.md) | On-premises HA reference architecture | engineer / customer |
| [`ADMIN_GUIDE.md`](ADMIN_GUIDE.md) | Platform admin guide: RBAC, org management, connectors | engineer / customer |
| [`SECURITY_WHITEPAPER.md`](SECURITY_WHITEPAPER.md) | Security posture of the platform itself: crypto, isolation, audit trail | customer / auditor |

### Sprint & Backlog Docs

| File | Description | Audience |
|------|-------------|----------|
| [`SPRINT_2_DEMO_BACKLOG_2026-04-22.md`](SPRINT_2_DEMO_BACKLOG_2026-04-22.md) | DEMO-001..005 P0 demo items — mostly shipped | CTO / next-LLM |
| [`GAP_PRD_RECONCILE_2026-04-22.md`](GAP_PRD_RECONCILE_2026-04-22.md) | 48-row MERGE/KEEP/KILL/UNCLEAR reconcile table | CTO / next-LLM |

### Release & Changelog

| File | Description | Audience |
|------|-------------|----------|
| [`CHANGELOG.md`](CHANGELOG.md) | Running changelog | engineer / customer |
| [`RELEASE_NOTES_BEAST_MODE_v6.md`](RELEASE_NOTES_BEAST_MODE_v6.md) | Beast Mode v6 release notes | CTO / engineer |
| [`RELEASE_NOTES_v1.0.md`](RELEASE_NOTES_v1.0.md) | v1.0 platform release notes | customer / investor |

### Audit & Compliance Reports

| File | Description | Audience |
|------|-------------|----------|
| [`AUDIT_REPORT_2026-03-30.md`](AUDIT_REPORT_2026-03-30.md) | March 2026 internal audit report | CTO / auditor |
| [`ENTERPRISE_SIMULATION_DESIGN.md`](ENTERPRISE_SIMULATION_DESIGN.md) | Enterprise simulation design doc | CTO / engineer |

### Tooling & Templates

| File | Description | Audience |
|------|-------------|----------|
| [`ruflo_claude_md_template_2026-04-26.md`](ruflo_claude_md_template_2026-04-26.md) | RuFlo v3 (claude-flow) CLAUDE.md template — installed today; behavioral rules | CTO / next-LLM |
| [`templates/DAILY_REALTIME_E2E_REPORT_TEMPLATE.md`](templates/DAILY_REALTIME_E2E_REPORT_TEMPLATE.md) | Daily E2E report template | engineer |
| [`templates/WEEKLY_REALTIME_E2E_EXECUTIVE_TEMPLATE.md`](templates/WEEKLY_REALTIME_E2E_EXECUTIVE_TEMPLATE.md) | Weekly executive E2E report template | CTO |

### JSON Schemas

| File | Description | Audience |
|------|-------------|----------|
| [`schemas/facts.cve.json`](schemas/facts.cve.json) | CVE fact schema (TrustGraph ingest format) | engineer |
| [`schemas/facts.sarif.json`](schemas/facts.sarif.json) | SARIF fact schema | engineer |
| [`schemas/facts.sbom.json`](schemas/facts.sbom.json) | SBOM fact schema | engineer |

### UI Snapshots

| Directory | Description | Audience |
|-----------|-------------|----------|
| [`ui-snapshots/demo_2026-04-26/`](ui-snapshots/demo_2026-04-26/) | 7 demo screenshots + network trace from live demo run | sales / CTO |
| [`ui-snapshots/proof-2026-04-26/`](ui-snapshots/proof-2026-04-26/) | 30 proof screenshots across 3 tenants (juice-shop, vulnado, webgoat) × 10 UI surfaces | engineer / sales |
| [`ui-snapshots/visual-verify-2026-04-24/`](ui-snapshots/visual-verify-2026-04-24/) | 165 route screenshots from automated visual-verify run (2026-04-24) | engineer |
| [`ui-snapshots/` (root)`](ui-snapshots/) | Misc earlier snapshots (security-findings, violation-lifecycle, DCA, agentless) | engineer |
