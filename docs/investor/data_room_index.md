# ALDECI Data Room — Investor Index

**Date:** 2026-04-26 · **Branch:** `features/intermediate-stage`

> Single-page index pointing to every supporting artefact for the Series A diligence. One-line description per doc. Read against `docs/investor/INVESTOR_PACK_2026-04-26.md`.

---

## 1. Master Pitch & Narrative

| Doc | One-liner |
|---|---|
| `docs/investor/INVESTOR_PACK_2026-04-26.md` | This Series A master pack — synthesizes everything below into one investor narrative. |
| `docs/investor/TRACTION_METRICS_2026-04-26.md` | Numbers-only fact sheet — DPO pairs, commits, NIST coverage, federal pipeline depth. |
| `docs/pitch/ALDECI_PITCH_DECK_2026-04-26.md` | 12-slide pitch deck — federal SCIF + enterprise + reseller; every claim cited. |
| `docs/pitch/ONE_PAGER_2026-04-26.md` | One-paragraph elevator narrative + the 3-intro ask. |
| `docs/pitch/objection_handling_2026-04-26.md` | Top investor & buyer objections with citation-backed answers. |
| `docs/INVESTOR_PITCH.md` | Legacy pitch (superseded by the 2026-04-26 pack — kept for context). |

## 2. Competitive & Market Position

| Doc | One-liner |
|---|---|
| `docs/competitive_validation_2026-04-26.md` | 149 capabilities × 7 competitors scorecard — 83% WIN-or-MATCH; "ship the consolidation" verdict. |
| `docs/CTEM_PLUS_IDENTITY.md` | Canonical product identity — 8 native engines + 12-step Brain Pipeline + MPTE + FAIL + AI consensus. |
| `raw/competitive/gap-matrix-2026-04-26.md` | 71-row competitive gap matrix — 50 DONE / 12 IP / 6 NS / 2 PD. |
| `raw/competitive/truecourse-vs-fixops-comparison.md` | 40-cap side-by-side vs the closest indie comparable. |
| `raw/competitive/competitor-aspm.md` | Snyk / Checkmarx / Veracode / Apiiro deep-dive. |
| `raw/competitive/competitor-cspm.md` | Wiz / Prisma / Orca / Lacework deep-dive. |
| `raw/competitive/competitor-ctem.md` | Tenable / XM Cyber / Balbix / Falcon Surface deep-dive. |
| `raw/competitive/competitor-emerging.md` | Apiiro / Endor / Cycode / Legit / OX / Arnica deep-dive. |
| `raw/competitive/competitor-sonatype.md` | Sonatype Lifecycle / SAGE deep-dive. |
| `docs/sales/battle_cards/snyk.md` | Win/loss battle card vs Snyk. |
| `docs/sales/battle_cards/wiz.md` | Win/loss battle card vs Wiz. |
| `docs/sales/battle_cards/tenable.md` | Win/loss battle card vs Tenable. |
| `docs/sales/battle_cards/apiiro.md` | Win/loss battle card vs Apiiro. |
| `docs/sales/battle_cards/aikido.md` | Win/loss battle card vs Aikido. |
| `docs/sales/battle_cards/sonatype.md` | Win/loss battle card vs Sonatype. |
| `docs/sales/battle_cards/xm_cyber.md` | Win/loss battle card vs XM Cyber. |

## 3. Product & Architecture

| Doc | One-liner |
|---|---|
| `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` | 89 → 30 screens consolidation plan, 8 top-level nav items, 25-persona zero-regression map. |
| `docs/ALDECI_REARCHITECTURE_v2.md` | Master architecture doc (v2.5) — source of truth for layout. |
| `docs/api-reference/README.md` | API surface reference for Wave A/B/C/D + 7 engine routers (~80 endpoints). |
| `docs/SESSION_HISTORY.md` | Full per-wave DONE history (Wave 6 → Wave 60+). |
| `docs/HANDOFF_2026-04-26-evening.md` | Today's session handoff — what shipped, what's in flight, where to read state. |

## 4. AI / LLM Roadmap

| Doc | One-liner |
|---|---|
| `docs/LLM_TRAINING_ROADMAP_2026-04-26.md` | Phase 1 closed-loop (live) + Phase 2 distillation (scaffolded) + Phase 3 per-customer continued-pretrain. |
| `docs/self_learning_llm_scope_2026-04-26.md` | Scope of "self-learning" — honest bounds on what Phase 1 actually changes. |
| `scripts/llm_training_phase1_skeleton.py` | Executable scaffold for the Phase 1 RAG + DPO loop. |
| `scripts/llm_distill_dataset_curator.py` | Phase 2 dataset curator — emits `data/distill_train.jsonl`, signed manifest. |
| `scripts/llm_distill_train.py` | Phase 2 training scaffold — Qwen 2.5 7B + LoRA r=16, dry-run validated. |
| `suite-core/core/llm_distill_router.py` | Phase 2 inference router — student-first, council fall-through, signal capture. |
| `data/learning_signals.db` | Live DPO preference-pair store (703 pairs as of 2026-04-26). |

## 5. SCIF / Federal Compliance

| Doc | One-liner |
|---|---|
| `docs/scif_readiness_2026-04-26.md` | 15-requirement scorecard — 3 MET / 7 PARTIAL / 5 MISSING; 12–18 months to FedRAMP High *In Process*. |
| `docs/scif/SSP_aldeci_2026-04-26.md` | System Security Plan v0 — FedRAMP High baseline mapping. |
| `docs/scif/POAM_aldeci_2026-04-26.md` | Plan of Actions & Milestones — gap closure schedule. |
| `docs/scif/nist_800-53_control_matrix_2026-04-26.csv` | NIST SP 800-53 Rev 5 control-by-control implementation matrix (~95% coverage). |
| `docs/scif/threat_model_aldeci_2026-04-26.md` | STRIDE threat model. |
| `docs/scif/crypto_module_datasheet_2026-04-26.md` | FIPS 203/204/205 + ML-DSA + AES-256-GCM crypto datasheet. |
| `docs/scif/auditor_quick_reference_2026-04-26.md` | 40-minute ATO walk-through for an inheriting auditor. |
| `docs/scif/stig_hardening_checklist_2026-04-26.md` | DISA STIG compliance posture checklist. |
| `docs/scif/llm_air_gap_setup_2026-04-26.md` | LLM Council air-gap deployment runbook. |
| `docs/scif/SCIF_PILOT_BUNDLE_README.md` | The thing we're trying to land in a sponsor's SCIF. |

## 6. Federal Sales Motion

| Doc | One-liner |
|---|---|
| `docs/sales/scif/target_list_2026-04-26.md` | 36 prioritized federal sponsors (P1 12 / P2 16 / P3 8) — DoD, IC, federal civilian. |
| `docs/sales/scif/cold_outreach_templates_2026-04-26.md` | Personalized cold-email + LinkedIn templates by persona (AO, ISSO, ISSM, PM). |
| `docs/sales/scif/discovery_playbook_2026-04-26.md` | 30-min discovery cadence; question script; disqualification triggers. |
| `docs/sales/scif/pilot_sow_template_2026-04-26.md` | 20-day pilot Statement of Work with hard deliverables and success criteria. |
| `docs/sales/scif/reference_arch_scif_2026-04-26.md` | Single-tenant air-gap reference architecture for sponsor-side review. |

## 7. Sales Playbook & Analyst Pack

| Doc | One-liner |
|---|---|
| `docs/sales/demo_script_30min.md` | 30-minute demo script across the 6 hero screens. |
| `docs/sales/poc_template.md` | 2-week POC template against buyer's real repos. |
| `docs/sales/customer_onboarding_playbook.md` | Day 0–30 customer onboarding flow. |
| `docs/sales/win_loss_analysis_template.md` | Win/loss interview template + scoring rubric. |
| `docs/sales/analyst/analyst_one_pager_2026-04-26.md` | One-page brief for industry analysts (Gartner / Forrester / IDC). |
| `docs/sales/analyst/anti_customer_profile.md` | Who we deliberately don't sell to (and why that's a moat). |
| `docs/sales/analyst/case_study_template.md` | Reference case-study template for first 5 design partners. |
| `docs/sales/analyst/mq_wave_submission_2026-04-26.md` | Magic Quadrant / Wave submission packet. |
| `docs/sales/analyst/reference_architecture_whitepaper.md` | Reference-architecture whitepaper for analyst & buyer technical reviewers. |

## 8. Multi-Tenant & Onboarding Validation

| Doc | One-liner |
|---|---|
| `docs/multi_tenant_onboarding_results_2026-04-24.md` | 15-tenant real-customer onboarding flow + UX bug surface. |
| `docs/persona_coverage_after_seed.md` | 30-persona × UI-page coverage map. |
| `docs/ORG_WIDE_PERSONA_TRIAL_RUNBOOK.md` | 25-persona enterprise trial runbook. |

## 9. Engineering Quality & Repo Health

| Doc | One-liner |
|---|---|
| `docs/board_audit_2026-04-26.md` | Multica board audit — what's done vs todo, justifications. |
| `docs/schema_migration_audit_2026-04-26.md` | DB schema migration audit — 63 todos held against parent USes. |
| `docs/dependabot_triage_2026-04-26.md` | Today's Dependabot triage; npm audit clean post-fixes. |
| `tests/test_phase*.py` + `tests/test_connector_framework.py` + `tests/test_trustgraph.py` + `tests/test_pipeline_api.py` + `tests/test_persona_workflows.py` | The 806 Beast Mode tests — run all green. |

---

*Index complete. To stand up a clean room: clone `features/intermediate-stage`, read `docs/investor/INVESTOR_PACK_2026-04-26.md` first, walk this index in numeric order.*
