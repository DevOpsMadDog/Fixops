# ALDECI 0.1.0-alpha Release Notes

**Release date**: 2026-04-26
**Branch**: `features/intermediate-stage`
**Tip SHA**: `f9cf3fe8`

---

## Headline

ALdeci CTEM+ Platform: Live LLM learning loop, 30-screen hero UI, federal-ready SCIF foundation.

---

## Why this matters

ALdeci closes the loop that every other ASPM/CTEM tool leaves open: every analyst triage decision now feeds back into the LLM council that made it. The same session that shipped that loop also delivered a production-grade federal SCIF engineering foundation and collapsed a 370-screen UI into 30 focused hero views — making the platform simultaneously more learnable for new analysts, more credible to federal procurement officers, and demonstrably faster to demo for enterprise sales.

---

## 5 things shipped

### Frontend (Phase 3 UX consolidation)
6 of 6 P0 hero screens shipped (Issues, Brain Pipeline, Compliance, Asset Graph, Command, Admin), folding ~89 source screens into focused, real-API views. 81+ redirect rules preserve existing bookmarks for 90 days. Playwright golden-path E2E: 6/6 pass, zero mocks confirmed. Proof: `docs/HANDOFF_2026-04-26-evening.md` §3, commit `22268aeb`.

### LLM Phase 1 closed-loop (LIVE)
Closed-loop subscriber wired to TrustGraph emit events. Real fleet scans produced 703 council verdicts and 703 DPO preference pairs in `data/learning_signals.db` — up from 2 at session start (350x). Phase 2 distillation scaffold (trl DPOConfig + student/council inference router) DRY-RUN validated. Nightly cron queued to grow pairs toward 10K GA threshold. Commits: `cbd01c4d`, `d326da7b`, `4904309a`, `f9cf3fe8`.

### TrustGraph second-brain coverage
30 highest-degree engine hubs wired across 6 batches. Router middleware coverage raised from 3.9% to 80%+. Total coverage: 24.4% → 38.4% (15.1% direct emit + 10.6% blast-radius + 12.7% middleware). AgentDB ↔ TrustGraph HNSW bridge delivers 150x speedup on semantic search over emit events. Commits: `befea111`–`3074e918`, `73c05c0d`.

### Federal / SCIF — all 3 stages in one session
Stage 1 (engineering): FIPS boot wired into FastAPI, UBI9/Iron Bank Dockerfile, SoftHSM PKCS#11, Cosign image signing, tamper-evident audit chain, air-gap bundle — 8/8 deliverables, 12/12 tests pass. Stage 2 (auditor docs): SSP, POA&M, NIST 800-53 Rev 5 control matrix — 95% of in-scope controls mapped. Stage 3 (sales): 36-sponsor target list, pilot SOW, 20-day pilot path. Commits: `69efa330`, `aba22fff`, `20ef9510`, `43f73eb3`, `2ee6e8ed`.

### Sales and GTM pack
Pitch deck (12 slides), 7 buyer-persona landing pages, 5-min demo video script, analyst pack (MQ/Wave brief + ref-arch whitepaper), master investor pack with data room index, 7 battle cards, demo script (Command → Brain → Compliance arc). Commits: `bb35e502`, `68c0130e`, `bde8b101`, `2c394e24`, `a0f15a8b`.

---

## Known issues

### Multica board — 100 todo items blocked
100 tasks remain on the Multica board, mostly schema-migration child stories blocked on parent epic completion and 9 long-running EPIC parents. These are not regressions; they represent planned Phase 2 work. Full breakdown: `docs/HANDOFF_2026-04-26-evening.md` §1.7.

### TypeScript errors — 98 remaining
Pre-existing TypeScript errors reduced from 152 to 98 this session (54 cleared). Remaining 98 are in non-critical legacy UI pages outside the 30 hero screens. The 30 P3 heroes compile clean.

### Dependabot — 134 advisories
140 alerts triaged this session; 134 remain open (2 Critical / 55 High / 59 Medium / 24 Low). Critical and High transitive deps in the UI bundle were patched (dompurify, postcss, path-to-regexp, picomatch, follow-redirects). Remaining alerts are assessed low-exploit-probability in a self-hosted deployment context. Full triage: `docs/dependabot_triage_2026-04-26.md`.

### SCIF maturity — 35%
SCIF/FedRAMP High overall maturity is ~35%. Technical surface (FIPS toggle, air-gap engine, PQC crypto, PKCS#11) is credible and shipped. Process surface (3PAO audit relationship, full ATO package, continuous monitoring) requires 12–18 months of focused investment. Do not represent the product as FedRAMP High authorized. Honest framing: "FedRAMP High control-mapped, air-gap ready, 3PAO engagement recommended." Full scorecard: `docs/scif_readiness_2026-04-26.md`.

### LLM Phase 1 — DPO pair gap
703 DPO pairs are live. GA threshold is 10K. Nightly cron (`scripts/nightly_fleet_scan_cron.sh`) is queued to grow the dataset autonomously; ETA for 10K depends on fleet scan cadence. Sentence-transformers (MiniLM) adds approximately 2 GB to the install and 168 ms latency to semantic search calls.

### P1 UX — Incident Response screen deferred
One P1 consolidation item (Incident Response) was deferred due to a file collision. It will be addressed in the next session before the v0.1.0-beta cut.

---

## What is next

- **LLM Phase 1 → 10K DPO pairs**: Nightly cron runs autonomously; target is ~2 weeks at current fleet-scan rate.
- **SCIF first design partner**: Stage 3 sales motion active — target list of 36 program sponsors, 20-day pilot SOW ready to send.
- **Series A close**: Investor pack + data room index shipped (`docs/investor/`). Traction metrics documented.
- **P1 hero completion**: Incident Response screen (1 deferred item) + remaining P2 wave (10 items).
- **LLM Phase 2**: DPO fine-tuning run on 10K pairs → LoRA adapter → vLLM signed bundle for air-gap import.
- **TypeScript — target 0 errors**: 98 → 0 is a dedicated sprint item before beta.

---

## How to try it

1. **5-minute demo walkthrough**: `docs/marketing/demo_video_script_2026-04-26.md` — full Command → Brain → Compliance arc with narration cues and screenshot checkpoints.
2. **Real customer demo**: `docs/HANDOFF_2026-04-26-evening.md` §3 — Juice Shop end-to-end trace with 6-hero screenshot evidence (`134cd807`).
3. **Local setup**: `docs/llm_phase1_nightly_runbook.md` for LLM loop; `docs/scif/` for federal deployment; standard `docker compose up` for the main stack.
