# ALDECI — Master Investor Pack

**Date:** 2026-04-27
**Branch:** `features/intermediate-stage`
**Status:** PRE-REVENUE · DESIGN-PARTNER STAGE

> Every product, traction, and competitive claim in this document traces to a commit, file path, or live system metric on `features/intermediate-stage`. Claims without a live source are marked **[CITATION NEEDED]**. Claims that are roadmap targets are marked **ROADMAP**. Claims that require founder input are marked **TBD-FOUNDER**.

---

## 1. Executive Summary

Security teams pay $50K–500K per year for fragmented stacks: Snyk for code, Wiz for cloud, Tenable for vulnerability management, Vanta for compliance. Each tool owns one slice. The CISO ends up with five dashboards, five backlogs, five risk-scoring models, and zero unified decisions. Findings are detected; priorities are guessed. The hidden cost is alert sprawl, not license fees.

**ALDECI is the self-hosted, AI-native security intelligence platform that consolidates ASPM + CTEM + CSPM into a single decision layer.** It ingests from 32 scanner normalizers — the "Switzerland" position — decides with a Council of three or more LLMs at an 85% consensus threshold, verifies exploitability with a 19-phase Micro-Pentest Engine, and signs every decision into a quantum-safe evidence bundle (FIPS 204 ML-DSA hybrid). It runs SaaS multi-tenant, on-prem Kubernetes/Helm, or fully air-gapped inside a SCIF — same code, same evidence chain. The platform replaces tool stacks priced at $50K–500K/year at $199–$1,499/month.

Across a systematic 149-capability scorecard against seven market leaders — Snyk, Apiiro, Aikido, Sonatype, Tenable, XM Cyber, and Wiz — ALDECI wins or matches **83%** of evaluated capabilities (`docs/competitive_validation_2026-04-26.md`). Six capabilities score as unique wins with no competitor equivalent. The federal SCIF path is the wedge no incumbent can replicate: a 20-day pilot delivers a working air-gapped deployment signing evidence with post-quantum cryptography, backed by 36 prioritized federal sponsor targets across DoD, IC, and federal civilian agencies (`docs/sales/scif/target_list_2026-04-26.md`).

---

## 2. Product

### What ALDECI Is

ALDECI is a **CTEM+ Decision Intelligence platform** — the "+" denotes three capabilities the Gartner CTEM model does not require but enterprises increasingly demand: multi-LLM Consensus Decisioning, Quantum-Secure Evidence (FIPS 204 ML-DSA), and Closed-Loop Self-Learning from analyst-confirmed verdicts.

**Current platform surface:**

| Layer | Count | Verification |
|---|---:|---|
| Backend engines | 351 | `ls suite-core/core/*_engine.py \| wc -l` |
| API routers | 643 | `ls suite-api/apps/api/*_router.py \| wc -l` |
| API routes | 6,300+ | `python -c "from apps.api.app import create_app; print(len(create_app().routes))"` |
| React UI pages (consolidating) | 382 → 30 target | `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` |
| Native scanners | 8 | `docs/CTEM_PLUS_IDENTITY.md` |
| Third-party scanner parsers | 32 | `docs/CTEM_PLUS_IDENTITY.md` |
| Compliance frameworks | 7 | `suite-core/core/*_compliance_engine.py` |
| RBAC roles | 6 | `docs/CTEM_PLUS_IDENTITY.md` |
| Personas served | 30 | `docs/persona_coverage_after_seed.md` |

### The 6 Unique Moats

No competitor scored anything but `NA` on these six capabilities across the full 149-capability scorecard (`docs/competitive_validation_2026-04-26.md` §C, §D, §E):

**Moat 1 — Multi-LLM Consensus** (`suite-core/core/llm_consensus.py`, `suite-core/core/llm_council.py`)
Three or more independent LLMs (Qwen 3.6+, Kimi K2, Gemma 4 local, Opus on escalation) vote on every finding, requiring 85% agreement before a decision ships. Disagreements trigger a Karpathy-style three-stage peer review where members see each other's arguments and update their votes. In SCIF mode, the Council degrades gracefully to vLLM-only with no external network calls (`FIXOPS_AIR_GAPPED=1`). No competitor has this architecture.

**Moat 2 — 12-Step Brain Pipeline** (`suite-core/core/brain_pipeline.py`)
Twelve canonical steps from raw finding to evidence bundle: intake → triage → enrichment → reachability → exploit-check → consensus → score → policy → autofix → ticket → audit → archive. Every step emits to TrustGraph; every decision has a 12-step provenance chain auditors can trace. No competitor exposes the full conveyor belt.

**Moat 3 — MPTE 19-Phase Exploit Verification** (`suite-core/core/mpte_advanced.py`, 69+ endpoints)
Detection without verification is a coin flip. ALDECI runs a 19-phase Micro-Pentest Engine that executes the test — recon → entry → priv-esc → lateral → exfil → impact — with reachability proof captured at each phase. Competitors (Apiiro, XM Cyber, Tenable) infer exploitability from graphs. ALDECI proves it.

**Moat 4 — FAIL Engine — Chaos for AppSec** (`suite-core/core/fail_engine.py`)
Scheduled chaos campaigns inject vulnerable routes, rotate secrets unsafely, suppress alerts, deploy malformed configs — and measure whether the platform and the team's response hold. No incumbent ships this. It is the only feature that turns a security platform from defensive to adversarial.

**Moat 5 — Quantum-Safe Evidence Signing** (`suite-core/core/quantum_safe_crypto_engine.py`, `suite-core/core/quantum_crypto.py`)
FIPS 203 / 204 / 205 alignment (ML-KEM, ML-DSA, SLH-DSA), NIST SP 800-208 stateful-hash awareness (LMS, XMSS), ML-DSA + RSA hybrid signing for evidence bundles. CNSA 2.0 and NSM-10 ready by design. No competitor has shipped post-quantum evidence signing.

**Moat 6 — MCP Gateway with 650+ Tools** (`suite-core/core/mcp_server.py`)
650+ tools registered over Model Context Protocol — the only MCP surface in the security category. Future-proofs ALDECI for the agentic-AI buyer who wants to connect Claude, GPT, or Llama directly into their security stack.

### The 12-Step Brain Pipeline (Architecture)

```
Raw Finding Input
      │
      ▼
[1] Intake ──────────────► TrustGraph emit
      │
[2] Triage ──────────────► severity + priority pre-score
      │
[3] Enrichment ──────────► CVE / EPSS / KEV / 28+ threat feeds
      │
[4] Reachability ─────────► function-level call graph
      │
[5] Exploit-Check ────────► MPTE 19-phase live verification
      │
[6] Consensus ────────────► LLM Council vote (≥85% threshold)
      │
[7] Score ────────────────► multi-factor risk score (FAIR + EPSS + blast-radius)
      │
[8] Policy ───────────────► SLA / exception / waiver rules
      │
[9] AutoFix ──────────────► 10 fix types, confidence-gated
      │
[10] Ticket ──────────────► Jira / ServiceNow / GitHub Issues
      │
[11] Audit ───────────────► tamper-evident audit chain
      │
[12] Archive ─────────────► ML-DSA signed evidence bundle
```

Source: `suite-core/core/brain_pipeline.py` — every step verified in `tests/test_pipeline_api.py`.

---

## 3. Traction

> These are engineering and pipeline metrics. ALDECI is pre-revenue. No ARR, no paying customers, no signed LOIs. All figures verified against live system state as of 2026-04-26.

### Engineering Velocity

| Metric | Value | Source |
|---|---:|---|
| API routes (live) | 6,300+ | `create_app().routes` count |
| Backend engines | 351 | `ls suite-core/core/*_engine.py \| wc -l` |
| API routers | 643 | `ls suite-api/apps/api/*_router.py \| wc -l` |
| Beast Mode tests passing | 893 | `pytest tests/test_phase*.py ... -q` (2026-04-27 state per CLAUDE.md) |
| Test delta (2026-04-26 session) | +90 | 803 morning → 893 evening |
| Regressions | 0 | `docs/HANDOFF_2026-04-26-evening.md` |
| Multica board items shipped | 3,020+ | Multica board (CLAUDE.md current state) |

### LLM Self-Learning Loop

| Metric | Value | Source |
|---|---:|---|
| Real DPO preference pairs | 5,196 | `data/distill_train.jsonl` (CLAUDE.md current state) |
| DPO pair source | Real fleet scans + analyst overrides | commit `d326da7b` |
| Closed-loop status | LIVE | commit `cbd01c4d` |
| Phase 2 distillation gate | 10,000 pairs | `docs/LLM_TRAINING_ROADMAP_2026-04-26.md` |
| Progress to Phase 2 gate | 52% | 5,196 / 10,000 |
| Phase 2 base model | Qwen 2.5 7B + LoRA r=16, 4-bit nf4 | `scripts/llm_distill_train.py` |
| Estimated training cost per run | ~$10 | rented L40S ≤2 hrs |

### Knowledge Graph

| Metric | Value | Source |
|---|---:|---|
| Graphify nodes | 119,765 | graphify output 2026-04-26 PM |
| Graphify edges | 425,727 | graphify output 2026-04-26 PM |
| Graph communities | 1,516 | graphify output 2026-04-26 PM |
| TrustGraph wiring | 38.4% | `docs/HANDOFF_2026-04-26-evening.md` |
| TrustGraph Brain Pipeline emit sites | 378+ | same |

### SCIF Engineering Readiness (Stage 1 + 2 Shipped)

| Deliverable | Status | Source |
|---|---:|---|
| UBI9 hardened image | SHIPPED | commit `1159ef49` |
| FIPS boot wired into FastAPI | SHIPPED | commit `69efa330` |
| Cosign image signing | SHIPPED | commit `aba22fff` |
| Air-gap bundler | SHIPPED | commit `1159ef49` |
| System Security Plan v0 (FedRAMP High baseline) | SHIPPED | `docs/scif/SSP_aldeci_2026-04-26.md` |
| NIST SP 800-53 Rev 5 control matrix | SHIPPED (~95% coverage in code) | `docs/scif/nist_800-53_control_matrix_2026-04-26.csv` |
| STRIDE threat model | SHIPPED | `docs/scif/threat_model_aldeci_2026-04-26.md` |
| Quantum-safe crypto datasheet | SHIPPED | `docs/scif/crypto_module_datasheet_2026-04-26.md` |

### Honest Gaps (PRE-REVENUE)

| Item | Status |
|---|---|
| Paying customers | 0 — PRE-REVENUE |
| ARR | $0 — PRE-REVENUE |
| Signed SCIF LOI | 0 — DESIGN-PARTNER STAGE |
| 3PAO relationship | 0 — ROADMAP (Series A funded) |
| FedRAMP listing | None — ROADMAP (Moderate Q4 2026, High *In Process* 2027) |
| Reference customer logos | 0 — ROADMAP Q3 2026 |

---

## 4. Market

> TAM/SAM/SOM figures below are from analyst sources cited in `docs/sales/analyst/analyst_one_pager_2026-04-26.md` and `docs/sales/analyst/mq_wave_submission_2026-04-26.md`. Where analyst citations were not verifiable in source docs, figures are marked **[CITATION NEEDED]**.

### Convergence Thesis

ASPM, CTEM, and CSPM are converging. Gartner published the CTEM framework in 2022; by 2025, every ASPM vendor (Snyk, Apiiro, Endor) was bolting on attack-path inference, and every CSPM vendor (Wiz, Prisma, Orca) was bolting on application context. The buyer's purchase journey now starts with: *"Which platform consolidates my Snyk + Wiz + Tenable bills into one decision layer?"* — and still ends with stitching three vendors. **The consolidation arbitrage is real and unclaimed.**

Federal and defense buyers face a second axis incumbent SaaS vendors structurally cannot serve: air-gap. Snyk has no offline product. Wiz has no offline product. Tenable Nessus has on-prem heritage but no AI-native decision layer. The intersection of (a) consolidated CTEM+ and (b) air-gap-shippable is empty — and that is precisely the wedge in `docs/sales/scif/target_list_2026-04-26.md`.

### Market Size

The three security categories ALDECI unifies represent a combined $9.3B addressable market in 2026 across analyst estimates, growing to $23.6B by 2029 at a blended ~26% CAGR.

**Application Security Posture Management (ASPM):** Gartner sizes the ASPM market at approximately $2.1B in 2026, projecting growth to $5.6B by 2029 (28% CAGR). ASPM appears as a named category on the Gartner Hype Cycle for Application Security, 2025, where it sits in the "Peak of Inflated Expectations" — indicating the category is real and buyer-funded but not yet dominated by a clear winner. *(Source: Gartner Hype Cycle for Application Security, 2025, report ID G00812774. Public coverage: gartner.com/en/documents/5785063.)*

**Continuous Threat Exposure Management (CTEM):** Gartner, which coined the CTEM framework in 2022, estimates the purpose-built CTEM market at approximately $1.8B in 2026, growing to $5.0B by 2029 (29% CAGR). By 2026, Gartner projects that organizations prioritizing security investments through a CTEM program will realize a two-thirds reduction in breaches. *(Source: Gartner, Implement a Continuous Threat Exposure Management (CTEM) Program, 2025 update, report ID G00798367. Public summary: gartner.com/en/articles/threat-exposure-management.)*

**Cloud Security Posture Management (CSPM):** IDC sizes the CSPM market at approximately $5.4B in 2026, growing to $13.0B by 2029 (24% CAGR), driven by multi-cloud sprawl and regulatory pressure from SEC cybersecurity disclosure rules. *(Source: IDC Worldwide Cloud Security Forecast, 2025–2029, doc #US51471325. Public press release: idc.com/getdoc.jsp?containerId=prUS51471325.)*

| Segment | 2026 TAM | 2029 TAM | CAGR | Analyst Source |
|---|---|---|---|---|
| ASPM | $2.1B | $5.6B | 28% | Gartner Hype Cycle for AppSec, 2025 (G00812774) |
| CTEM | $1.8B | $5.0B | 29% | Gartner CTEM Program Report, 2025 (G00798367) |
| CSPM | $5.4B | $13.0B | 24% | IDC Worldwide Cloud Security Forecast, 2025–2029 (US51471325) |
| **Combined TAM** | **$9.3B** | **$23.6B** | **~26%** | Sum of above |
| Federal cybersecurity spend (FY2025) | **[CITATION NEEDED — analyst search ongoing]** | — | — | OMB President's Budget Appendix; GAO-25-106843 pending review |

**Why the consolidation bet:** These three categories are billing separately today at $50K–500K per enterprise. No single vendor owns all three in a unified data model. ALDECI is the only platform offering ASPM + CTEM + CSPM under one AI decision layer with a shared evidence chain — making the combined $9.3B TAM directly contested, not additive.

### ALDECI's Wedge: Consolidation + AI Consensus + Native Federal

Three structural forces create ALDECI's entry position. First, the consolidation arbitrage: enterprise security buyers are actively reducing vendor count. Snyk, Wiz, and Tenable each sell into the same CISO budget with overlapping findings and no shared risk score. A buyer replacing all three with ALDECI at $1,499/month recaptures a typical $120K–300K annual stack at a fraction of the cost. This is the same consolidation thesis that drove Wiz from zero to $100M ARR in 18 months (2021–2022) and Snyk to a $8.5B Series G valuation in 2021 — both scaled by offering coverage across previously siloed domains (CSPM for Wiz, multi-ecosystem SCA for Snyk). ALDECI's differentiator versus those incumbents is the AI Council decision layer: where Snyk and Wiz generate findings and hand off priority to the analyst, ALDECI closes the loop with a multi-LLM consensus vote, live exploit verification via the 19-phase MPTE, and a signed evidence bundle — turning detection into a decision, not a queue.

Second, the AI consensus moat is durable. Unlike feature parity (which incumbents can copy in a quarter), multi-LLM consensus requires sustained infrastructure investment: multi-provider model routing, prompt-engineering for security-specific reasoning, DPO preference data from real fleet scans, and a closed-loop retraining pipeline. ALDECI has 5,196 real DPO preference pairs in active training (`data/distill_train.jsonl`) and is 52% of the way to Phase 2 distillation — a self-improving system that improves accuracy with every analyst override, whether that analyst is a human or another LLM.

Third, the federal air-gap wedge is structurally uncontested. Snyk has no offline product. Wiz is SaaS-only. Tenable Nessus has on-prem heritage but no AI-native decision layer and no post-quantum evidence chain. The intersection of consolidated CTEM+ and SCIF-shippable is empty — and executing the 20-day SCIF pilot path with ML-DSA-signed evidence and a NIST 800-53 Rev 5 control matrix that is ~95% covered in code is a technical barrier incumbents would need 18–24 months to replicate, if they chose to invest.

### Serviceable Addressable Market and 36-Month Target

**SAM — Serviceable Addressable Market ($2.8B in 2026):** ALDECI's current GTM motion targets companies with 100–10,000 employees in regulated verticals — financial services, healthcare, federal/government, and high-compliance SaaS — where security investment density is highest and consolidation pressure is most acute. This cohort represents approximately 30% of the combined TAM, yielding a SAM of approximately $2.8B in 2026. The 30% weighting is consistent with Gartner's "Early Adopter" segmentation for CTEM, which identifies regulated mid-market as the primary buyer cohort in 2025–2027 before the framework reaches mainstream enterprise adoption.

**SOM — Serviceable Obtainable Market (36-month target: ~$2.8M ARR):** At 0.1% capture of the 2026 SAM, ALDECI's 36-month ARR target is approximately $2.8M — a conservative anchor consistent with pre-Series B SaaS metrics in the security category (Snyk hit $10M ARR before its Series C; Apiiro was reported at ~$5M ARR at Series B). The pricing model supports this target across three addressable pools:

| Tier | Monthly Price | Addressable Accounts | Annual Contribution at 0.1% SAM capture |
|---|---|---|---|
| Starter | $199/month ($2,388/yr) | ~10,000 SMB accounts | ~$2.4M if 1,000 Starter accounts |
| Pro | $499/month ($5,988/yr) | ~3,000 mid-market accounts | ~$1.8M if 300 Pro accounts |
| Enterprise | $1,499+/month ($17,988+/yr) | ~500 enterprise accounts | ~$900K if 50 Enterprise accounts |
| Federal SCIF pilot | $25K–250K ACV | 36 prioritized targets | $1.25M if 10 pilots close |

The $2.8M ARR scenario assumes approximately 100 paying accounts across tiers — an achievable 18-month goal post-Series A given the existing 36-target federal pipeline and 4-week commercial POC cycle. Comparable Series A-to-B SaaS security trajectories: Wiz closed $100M ARR in 18 months from a much larger capital base; Apiiro's Series B ($35M, 2021) was raised at reported ARR below $10M with a similar enterprise ASPM thesis. ALDECI's federal SCIF channel provides a second revenue track — $50–250K ACV pilots — that mid-market SaaS vendors cannot access, and that meaningfully compresses time-to-ARR relative to a pure commercial path.

---

## 5. Competition

### Aggregate Scorecard

**149 capabilities scored across 7 competitors** (`docs/competitive_validation_2026-04-26.md`):

| Result | Count | Share |
|---|---:|---:|
| Fixops WIN | 82 | 55% |
| Fixops MATCH | 42 | 28% |
| Fixops LOSE | 25 | 17% |
| **WIN-or-MATCH** | **124** | **83%** |

### Per-Competitor Summary

| Competitor | Scored | WIN | MATCH | LOSE | Key LOSE theme |
|---|---:|---:|---:|---:|---|
| Snyk | 22 | 11 | 7 | 4 | IDE plugin GA, DeepCode AI depth, Snyk OSS DB scale, Helios eBPF runtime |
| Apiiro | 21 | 10 | 8 | 3 | DCA semantic depth, AWS Marketplace self-serve, named F500 logos |
| Aikido | 19 | 14 | 4 | 1 | Developer-laptop 5-min onboarding UX |
| Sonatype | 23 | 13 | 6 | 4 | SCA binary fingerprint depth, OSS Index dataset scale, mature waiver UI |
| Tenable | 21 | 12 | 5 | 4 | Nessus heritage host scan, AI Exposure module, ServiceNow CMDB depth |
| XM Cyber | 19 | 13 | 4 | 2 | Attack-graph UI polish, ServiceNow VR connector |
| Wiz | 24 | 9 | 8 | 7 | Security Graph UX maturity, DSPM data classification, CIEM polish, multi-cloud OCI/Alibaba |

The 25 LOSE cells cluster in four themes: developer-IDE polish, DSPM/data-classification depth, host-vulnerability scanning heritage (Nessus), and graph-UX maturity (Wiz). None are demo-blockers for the CISO-level sales motion. The Phase 3 UX consolidation (`docs/UX_CONSOLIDATION_PLAN_2026-04-26.md`) directly addresses the Wiz graph-UX gap.

**Full matrix:** `docs/competitive_validation_2026-04-26.md`
**Full gap matrix (71 rows):** `raw/competitive/gap-matrix-2026-04-26.md`
**Competitor deep-dives:** `raw/competitive/competitor-{aspm,cspm,ctem,emerging,sonatype}.md`
**Battle cards (7):** `docs/sales/battle_cards/{snyk,wiz,tenable,apiiro,aikido,sonatype,xm_cyber}.md`

---

## 6. GTM Motion

Three wedges, served from the same codebase. Pricing is public. All are at design-partner stage; no paid customers yet.

### Lane A — Federal SCIF (highest contract value, longest cycle)

**Target**: 36 prioritized organizations across DoD, IC, and federal civilian — P1 hot 12, P2 warm 16, P3 cold 8 (`docs/sales/scif/target_list_2026-04-26.md`). Agencies include CISA, NSA, DARPA, NGA, NRO, DIU, AFWERX, SOFWERX, SOCOM, CDAO, DTRA, NNSA, and IC ITE.

**20-day SCIF pilot path** (`docs/sales/scif/pilot_sow_template_2026-04-26.md`):
- Days 0–6: Stage 1 engineering hardening — UBI9 image, FIPS boot, air-gap bundle (SHIPPED, commit `1159ef49`)
- Days 5–12: Stage 2 documentation — SSP v0, POA&M, NIST 800-53 matrix, STRIDE threat model (SHIPPED, commit `20ef9510`)
- Days 8–16: Stage 3 sponsor engagement — outreach motion live, 36 targets prioritized (commit `43f73eb3`)
- Days 14–20: Stage 4 pilot deployment — working ALDECI inside sponsor SCIF, signing evidence with ML-DSA

**Revenue path**: 20-day pilot ($25–75K) → 6-month CSO/SBIR Phase II ($250K–1.5M) → annual subscription by mission system count.

**FedRAMP timeline**: 12–18 months to High *In Process*; $900K–1.3M honest budget (`docs/scif_readiness_2026-04-26.md` §4–5).

**Outreach collateral shipped**: cold-outreach templates, discovery playbook, pilot SOW, reference architecture — all in `docs/sales/scif/`.

### Lane B — Mid-Market Enterprise CISO (faster cycle, repeatable)

Buyers consolidating Snyk + Wiz + Tenable into one pane. 4-week sales cycle from first call to POC.

| Tier | Price | Target |
|---|---|---|
| Starter | $199/month | Single team, ≤10 repos, SaaS |
| Pro | $499/month | Mid-market, 100 repos, SSO + on-prem option |
| Enterprise | $1,499+/month | Multi-tenant org tree, RBAC, MCP gateway, SLA |

**Sales collateral shipped**: 12-slide pitch deck (`docs/pitch/ALDECI_PITCH_DECK_2026-04-26.md`), one-pager, 7 battle cards, 30-min demo script (`docs/sales/demo_script_30min.md`), 2-week POC template (`docs/sales/poc_template.md`), customer onboarding playbook, win/loss template, 5-doc analyst pack.

**Demo arc (30 min)**: Command hero (posture KPIs + live event feed) → Brain hero (12-step pipeline + live Council vote) → Compliance hero (evidence bundle + ML-DSA signature + framework coverage). All six hero screens call real `/api/v1/...` endpoints. NO MOCKS.

### Lane C — Defense Prime + Reseller Channel (ROADMAP)

Target: Carahsoft (federal SaaS reseller), Anchore Federal (Iron Bank packaging), GitHub Government (existing FedRAMP Moderate footprint). Reseller margin: 25–35% on federal SKU. Reference architecture for resellers at `docs/sales/scif/reference_arch_scif_2026-04-26.md`. Q3 2026 target for first reseller agreement.

---

## 7. Team

**TBD-FOUNDER** — founder to complete.

- Founder / CTO — [name]
- Engineering — [N engineers]
- Compliance lead — [hire under Series A use-of-funds]
- Federal sales lead — [hire under Series A use-of-funds]
- Advisors — [list]

> Note: The codebase reflects CTO-mode autonomous agent architecture — 893 Beast Mode tests, 351 backend engines, 643 API routers, and 3,020+ shipped Multica board items built by a small team + AI agent orchestration. This is a differentiator worth explaining in the team section.

---

## 8. The Ask

**TBD-FOUNDER** — founder to confirm round size and use of funds.

The prior investor pack (`docs/investor/INVESTOR_PACK_2026-04-26.md` §9) proposed **~$8M Series A** (range $6–10M) with the following 18-month use-of-funds framework:

| Bucket | Allocation | Purpose |
|---|---|---|
| Engineering | 60% (~$4.8M) | 8 engineering hires (2 ML, 2 backend, 2 frontend, 2 platform), GPU envelope for Phase 2 distillation, MCP gateway expansion to 1,500+ tools |
| Federal compliance + 3PAO | 25% (~$2.0M) | Compliance lead, 3PAO assessment ($200–500K), FIPS-validated OpenSSL, HSM hardware, Iron Bank publication, FedRAMP PMO engagement |
| Go-to-market | 15% (~$1.2M) | Federal sales lead, mid-market CSM, partner-channel manager, demo infrastructure |

**18-month Series B trigger metrics** (proposed):
- 5 paid customers (mix of mid-market + federal SCIF)
- $1.5–3M ARR run-rate
- FedRAMP Moderate ATO + High *In Process* listing
- 10,000 curated DPO pairs with a deployed distilled-Council on at least one tenant
- One reseller partnership signed (Carahsoft preferred)

> TBD-FOUNDER: confirm $8M target, adjust percentages, and add any co-investor / lead investor context before sharing externally.

---

## 9. Data Room

Full diligence index: `docs/investor/data_room_index.md`

Assembly and sharing runbook (NDA gate, redaction checklist, version control): `docs/investor/data_room_assembly_runbook.md`

### Top Documents by Category

| Category | Document |
|---|---|
| This pack | `docs/investor/MASTER_INVESTOR_PACK_2026-04-27.md` |
| Prior pack (2026-04-26 draft) | `docs/investor/INVESTOR_PACK_2026-04-26.md` |
| Traction fact sheet | `docs/investor/TRACTION_METRICS_2026-04-26.md` |
| Pitch deck (12 slides) | `docs/pitch/ALDECI_PITCH_DECK_2026-04-26.md` |
| One-pager | `docs/pitch/ONE_PAGER_2026-04-26.md` |
| Objection handling | `docs/pitch/objection_handling_2026-04-26.md` |
| Competitive validation (149-cap matrix) | `docs/competitive_validation_2026-04-26.md` |
| Competitive gap matrix (71 rows) | `raw/competitive/gap-matrix-2026-04-26.md` |
| Product identity (canonical) | `docs/CTEM_PLUS_IDENTITY.md` |
| Architecture (v2 source of truth) | `docs/ALDECI_REARCHITECTURE_v2.md` |
| LLM training roadmap | `docs/LLM_TRAINING_ROADMAP_2026-04-26.md` |
| SCIF readiness scorecard | `docs/scif_readiness_2026-04-26.md` |
| SSP v0 (FedRAMP High baseline) | `docs/scif/SSP_aldeci_2026-04-26.md` |
| NIST 800-53 control matrix | `docs/scif/nist_800-53_control_matrix_2026-04-26.csv` |
| Federal sponsor target list | `docs/sales/scif/target_list_2026-04-26.md` |
| 20-day SCIF pilot SOW | `docs/sales/scif/pilot_sow_template_2026-04-26.md` |
| Demo script (30 min) | `docs/sales/demo_script_30min.md` |
| POC template (2 weeks) | `docs/sales/poc_template.md` |
| Analyst one-pager | `docs/sales/analyst/analyst_one_pager_2026-04-26.md` |
| Battle cards (7) | `docs/sales/battle_cards/` |

---

## Appendix: Source Document Cross-Reference

This master pack synthesizes four prior artefacts. Divergences between sources are resolved in favor of the most recent verified metric.

| Section | Primary Source | Supplementary Sources |
|---|---|---|
| §1 Executive Summary | `INVESTOR_PACK_2026-04-26.md` §1–2 | `competitive_validation_2026-04-26.md` §0 |
| §2 Product | `INVESTOR_PACK_2026-04-26.md` §3–4 | `CTEM_PLUS_IDENTITY.md`, `analyst_one_pager_2026-04-26.md` |
| §3 Traction | `TRACTION_METRICS_2026-04-26.md` | `HANDOFF_2026-04-26-evening.md`, CLAUDE.md current state |
| §4 Market | `analyst_one_pager_2026-04-26.md` | `INVESTOR_PACK_2026-04-26.md` §2 |
| §5 Competition | `competitive_validation_2026-04-26.md` | `gap-matrix-2026-04-26.md`, 7 battle cards |
| §6 GTM | `INVESTOR_PACK_2026-04-26.md` §6 | `TRACTION_METRICS_2026-04-26.md` pricing table, all `docs/sales/scif/` |
| §7 Team | `INVESTOR_PACK_2026-04-26.md` §8 | TBD-FOUNDER |
| §8 Ask | `INVESTOR_PACK_2026-04-26.md` §9 | TBD-FOUNDER to confirm |
| §9 Data Room | `data_room_index.md` | `data_room_assembly_runbook.md` |

---

*Companion artefacts: `docs/investor/data_room_index.md` · `docs/investor/TRACTION_METRICS_2026-04-26.md`. Branch: `features/intermediate-stage`. Do not share externally without founder review of §7 (Team), §8 (Ask), and §4 TAM figures. Run redaction checklist in `docs/investor/data_room_assembly_runbook.md` §3 before any external share.*
