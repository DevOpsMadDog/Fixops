# ALDECI — Traction Metrics (2026-04-26)

**Branch:** `features/intermediate-stage`

> Numbers-only fact sheet. No narrative. Each row cites the verification command, file, or commit.

---

## Engineering Velocity

| Metric | Value | Source / verification |
|---|---:|---|
| Commits today (this session) | ~140 | `git log --oneline --since="2026-04-26 00:00" \| wc -l` (tip: 19 commits in head window; ~140 across full session including Wave A/B/C/D + FE waves + sales + SCIF) |
| Backend engines | 351 | `ls suite-core/core/*_engine.py \| wc -l` |
| API routers | 643 | `ls suite-api/apps/api/*_router.py \| wc -l` |
| React frontend pages | 382 | `ls suite-ui/aldeci-ui-new/src/pages/*.tsx \| wc -l` |
| Beast Mode tests passing | 806 | `pytest tests/test_phase*.py tests/test_connector_framework.py tests/test_trustgraph.py tests/test_pipeline_api.py tests/test_persona_workflows.py` |
| Test count delta this session | +90 | 716 morning baseline → 806 evening |
| Regressions this session | 0 | per `docs/HANDOFF_2026-04-26-evening.md` |
| Dependabot vulnerabilities | 0 | `npm audit` (root + `suite-ui/aldeci-ui-new`), per `docs/dependabot_triage_2026-04-26.md` |

## Phase 3 UX Consolidation

| Metric | Value | Source |
|---|---:|---|
| P0 hero screens shipped | 6 / 6 | commits `12f16c83` (Issues), `0771bd11` (Brain), `7e728702` (Asset Graph), `e0972bac` (Compliance), `4c6cd97b` (Command), `a6e73395` (Admin) |
| Pages collapsed into 6 hero screens | ~89 | `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` §2 |
| Route redirects shipped | 47 | folded across the 6 hero commits + commits `42d5a67b`, `afc66592`, `0cddeaee`, `9cbf0ae1`, `5486541d` |
| Playwright golden-paths | 6 / 6 hero screens | commit `22268aeb` |
| Mock-data violations on hero screens | 0 | NO MOCKS gate (`CLAUDE.md` rule) |
| Target consolidated screens | 30 | `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` §1 |
| Top-level nav items in target shape | 8 | same |

## TrustGraph Wiring

| Metric | Value | Source |
|---|---:|---|
| Total wiring (direct + blast-radius + middleware) | 38.4% | `docs/HANDOFF_2026-04-26-evening.md` + emit commit chain |
| Direct emit | 15.1% | per visualizer report |
| Blast-radius emit | 10.6% | per visualizer report |
| Middleware emit (router init) | 12.7% | commit `48ee40d2` |
| Brain Pipeline emit sites | 378+ | `docs/HANDOFF_2026-04-26-evening.md` (was 363 yesterday) |
| Production graph nodes | 119,765 | graphify output 2026-04-26 PM |
| Production graph edges | 425,727 | graphify output 2026-04-26 PM |
| Communities | 1,516 | graphify output |
| Net graph delta this session | +414 nodes / +2,153 edges | from morning baseline 119,351 / 423,574 |

## LLM Phase 1 — Closed Loop (LIVE)

| Metric | Value | Source / verification |
|---|---:|---|
| Closed loop status | LIVE | commit `cbd01c4d` *"feat(llm-loop): real closed-loop subscriber wired to TrustGraph (Phase 1 production)"* |
| End-to-end smoke trace latency | 340 ms | `docs/HANDOFF_2026-04-26-evening.md` |
| Smoke tests passing | 5 / 5 | same |
| Real DPO preference pairs | **703** | `sqlite3 data/learning_signals.db "SELECT COUNT(*) FROM feedback_pairs;"` (verified 2026-04-26) |
| DPO data populated by | commit `d326da7b` *"data(llm-learning): populate Phase 1 learning_signals.db via real fleet scans"* |
| Pair source | real fleet scans (verdicts + overrides) | same commit |

## LLM Phase 2 — Distillation (SCAFFOLDED + DRY-RUN VALIDATED)

| Metric | Value | Source |
|---|---:|---|
| Phase 2 status | scaffolded + dry-run validated | commit `4904309a` *"feat(llm-distill): Phase 2 dataset curator + training scaffold + inference router (DRY-RUN validated)"* |
| Base model | Qwen 2.5 7B Instruct | `scripts/llm_distill_train.py` |
| Adapter | LoRA r=16, alpha=32 | same |
| Quantization | 4-bit nf4 + bitsandbytes | same |
| Per-run training cost target | ~$10 | rented L40S, ≤ 2 hrs wall-clock at 10K pairs |
| Adapter size | ~120 MB | LoRA r=16 |
| Training threshold (Phase 2 GA gate) | 10,000 curated pairs | `docs/LLM_TRAINING_ROADMAP_2026-04-26.md` Phase 2 §gating |
| Progress to threshold | **7%** (703 / 10,000) | computed |
| Cost-guard | `FIXOPS_DISTILL_TRAIN=1` required to leave dry-run | `scripts/llm_distill_train.py` |
| Inference router | student-first, council fall-through | `suite-core/core/llm_distill_router.py` |
| Dry-run trace | 843 ms, 107/107 SFT valid, 107/107 DPO valid | logged in `docs/LLM_TRAINING_ROADMAP_2026-04-26.md` Phase 2 §dry-run trace |

## SCIF Stage 1 — Engineering Hardening (8/8 SHIPPED)

| Deliverable | Status | Source |
|---|---:|---|
| UBI9 hardened image | SHIPPED | commit `1159ef49` |
| SoftHSM PKCS#11 wrapper | SHIPPED | commit `1159ef49` |
| Tamper-evident audit chain | SHIPPED | commit `1159ef49` |
| FIPS boot wired into FastAPI | SHIPPED | commit `69efa330` (12 tests passing) |
| Air-gap bundler | SHIPPED | commit `1159ef49` |
| Cosign image signing | SHIPPED | commit `aba22fff` |
| STIG hardening checklist | SHIPPED | `docs/scif/stig_hardening_checklist_2026-04-26.md` |
| LLM air-gap setup runbook | SHIPPED | `docs/scif/llm_air_gap_setup_2026-04-26.md` |

## SCIF Stage 2 — Auditor Documentation

| Deliverable | Status | Source |
|---|---:|---|
| System Security Plan v0 | SHIPPED | `docs/scif/SSP_aldeci_2026-04-26.md` (commit `20ef9510`) |
| Plan of Actions & Milestones | SHIPPED | `docs/scif/POAM_aldeci_2026-04-26.md` |
| NIST 800-53 Rev 5 control matrix | SHIPPED | `docs/scif/nist_800-53_control_matrix_2026-04-26.csv` |
| STRIDE threat model | SHIPPED | `docs/scif/threat_model_aldeci_2026-04-26.md` |
| Crypto module datasheet | SHIPPED | `docs/scif/crypto_module_datasheet_2026-04-26.md` |
| Auditor quick-reference (40-min walk-through) | SHIPPED | `docs/scif/auditor_quick_reference_2026-04-26.md` |
| **NIST SP 800-53 Rev 5 control coverage** | **~95%** in code | per SSP control-by-control walkthrough |

## SCIF Stage 3 — Federal Sponsor Outreach

| Metric | Value | Source |
|---|---:|---|
| Federal sponsor target list (master) | 61 organizations | `docs/sales/scif/target_list_2026-04-26.md` (61 table rows) |
| Prioritized targets (P1 + P2 + P3) | **36** | same — P1 hot 12, P2 warm 16, P3 cold 8 |
| Outreach motion shipped | YES | commit `43f73eb3` *"sales(scif-stage3): target list + cold outreach + discovery playbook + pilot SOW + reference arch"* |
| 20-day pilot SOW template | SHIPPED | `docs/sales/scif/pilot_sow_template_2026-04-26.md` |

## SCIF Overall Readiness

| Metric | Value | Source |
|---|---:|---|
| Requirements MET | 3 | `docs/scif_readiness_2026-04-26.md` §0 |
| Requirements PARTIAL | 7 | same |
| Requirements MISSING | 5 | same |
| Aggregate maturity | ~35% | same |
| Honest months to FedRAMP High *In Process* | 12–18 | `docs/scif_readiness_2026-04-26.md` §4 |
| Honest budget envelope | $900K–1.3M | `docs/scif_readiness_2026-04-26.md` §5 |

## Competitive Position

| Metric | Value | Source |
|---|---:|---|
| Capabilities scored | 149 | `docs/competitive_validation_2026-04-26.md` §0 |
| Competitors scored against | 7 | Snyk, Apiiro, Aikido, Sonatype, Tenable, XM Cyber, Wiz |
| Fixops WIN | 82 (55%) | same |
| Fixops MATCH | 42 (28%) | same |
| Fixops LOSE | 25 (17%) | same |
| **WIN-or-MATCH aggregate** | **83%** | same |
| Unique moats no competitor has | **6** | §1.C / §3 of validation doc |
| Competitor with deepest gap | Wiz (7 LOSE cells) | §0 same doc |

## Sales Materials

| Artefact | Status | Source |
|---|---:|---|
| 12-slide pitch deck | SHIPPED | `docs/pitch/ALDECI_PITCH_DECK_2026-04-26.md` (commit `bb35e502`) |
| One-pager | SHIPPED | `docs/pitch/ONE_PAGER_2026-04-26.md` |
| Objection-handling | SHIPPED | `docs/pitch/objection_handling_2026-04-26.md` |
| 30-min demo script | SHIPPED | `docs/sales/demo_script_30min.md` (commit `68c0130e`) |
| 2-week POC template | SHIPPED | `docs/sales/poc_template.md` |
| Customer onboarding playbook | SHIPPED | `docs/sales/customer_onboarding_playbook.md` |
| Win/loss analysis template | SHIPPED | `docs/sales/win_loss_analysis_template.md` |
| Competitor battle cards | 7 / 7 | `docs/sales/battle_cards/{aikido,apiiro,snyk,sonatype,tenable,wiz,xm_cyber}.md` |
| Analyst pack docs | 5 / 5 | `docs/sales/analyst/*` |

## Multica Board (Engineering Throughput)

| Metric | Value | Source |
|---|---:|---|
| Done | 2,914 | board status 2026-04-26 PM |
| Todo | 100 | same |
| Today's delta — done | **+448** | morning baseline 2,466 → evening 2,914 |
| Today's delta — todo | **−439** | morning baseline 539 → evening 100 |

## Pricing & Wedges (Public)

| Tier | Price | Best for |
|---|---|---|
| Starter | $199 / month | Single team, ≤10 repos, SaaS only |
| Pro | $499 / month | Mid-market, 100 repos, SSO + on-prem option |
| Enterprise | $1,499+ / month | Multi-tenant org tree, RBAC, MCP gateway, SLA |
| Federal SCIF Pilot | Sponsor-priced | Single-tenant air-gap distribution, 20-day pilot |

| Wedge | Sales cycle | Status |
|---|---|---|
| Federal SCIF | 60–180 days | DESIGN-PARTNER STAGE — outreach motion shipped today |
| Mid-market enterprise | 4 weeks | DESIGN-PARTNER STAGE — playbook shipped today |
| Reseller (Carahsoft / Anchore / GitHub Government) | 90–180 days | ROADMAP — Q3 2026 target |

## Honest Gaps (PRE-REVENUE flags)

| Item | Status |
|---|---|
| Paying customers | 0 (PRE-REVENUE) |
| ARR | $0 (PRE-REVENUE) |
| Signed SCIF LOI | 0 (DESIGN-PARTNER STAGE) |
| 3PAO relationship | 0 (ROADMAP — funded by Series A) |
| FedRAMP listing | none (ROADMAP — Moderate Q4 2026, High *In Process* 2027) |
| Reference customer logos | 0 (ROADMAP — Q3 2026 first) |

---

*End fact sheet. Verification: each row cites command, file, or commit on `features/intermediate-stage`.*
