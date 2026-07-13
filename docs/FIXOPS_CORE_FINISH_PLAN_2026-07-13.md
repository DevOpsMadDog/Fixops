# FixOps-Core — Finish Plan (enterprise security buyer)

> Goal: a FINISHED, demoable, onboardable product IN HAND *before* a client — so we
> deliver, not develop, when one appears. Scoped, real, no mocks. Honest DoD below.

## The key realization
**The core value path is already REAL and passes end-to-end** (verified 2026-07-13:
`test_customer_journey_e2e` + `test_real_moat_e2e`, 11/11 — SARIF ingest → location-aware
dedup → 5-member real LLM council (cost>0, never fabricates) → evidence). So "finish" is
**NOT building the core** — it works. Finishing = **package it + hide the bloat**.

## The value path (the ONLY thing we sell)
```
customer scanner output (SARIF / 61 normalizers)
   → normalized findings
   → SmartDedup (location-aware) + TrustGraph correlation
   → 5-member LLM council verdict (real, cost>0, never fabricates)
   → signed, tamper-evident evidence bundle mapped to compliance controls
   → the ~10 UI screens that show this
```
Everything outside this path is **quarantined**, not perfected.

## Definition of Done (6 gates — all real, zero mocks)
| # | Gate | State |
|---|------|-------|
| 1 | Value path works end-to-end with REAL data, no stubs on it | ✅ verified (11/11 E2E) |
| 2 | A repeatable **scripted demo** (real scan → dedup → verdict → evidence) that never breaks | ⬜ |
| 3 | Real **onboarding**: new tenant → API key → upload scan → get verdict+evidence (no seed data) | ⬜ |
| 4 | **Quarantine the bloat**: core surface only (not 800 routes / 299 pages); non-core hidden behind a flag | ⬜ |
| 5 | **Deployed + stable** on fly with the core (canary the dedup+NAC branch) | ⬜ |
| 6 | **Buyer collateral**: one-pager + demo walkthrough | ⬜ |

## Tasks (drive to done, in order)
1. **DEMO SCRIPT** — a single `scripts/demo_core.sh` (or py) that: creates a tenant, ingests a
   realistic SARIF, shows findings→dedup delta, runs the council verdict, emits the signed evidence
   bundle, and prints a clean narrative. Idempotent, reliable, no mocks. + a recorded walkthrough.
2. **ONBOARDING FLOW** — verify + document the real path (org create → connector/API-key → upload →
   pipeline → verdict+evidence). One command / one page a customer follows. Test it.
3. **CORE-MODE QUARANTINE** — a `FIXOPS_CORE_MODE` flag that mounts ONLY the value-path routers + the
   ~10 core UI screens; everything else unmounted/hidden. The product must *feel* finished.
4. **CANARY DEPLOY** — merge the verified dedup+NAC branch, fly canary, confirm the core journey live.
5. **COLLATERAL** — one-pager (problem → the ingest-first + real-council + evidence moat → self-hosted/
   air-gap) + the demo walkthrough doc.

## Non-goals (explicitly NOT finishing)
The 800→25 router consolidation, the 129 handler collisions, the honest-stub non-core engines, the
broad UI. Quarantined, not perfected. They don't block a first-customer demo/pilot.

## The honest bar
"Finished" = a client can be shown the demo (gate 2), onboarded on their own scanner data (gate 3),
against a product whose surface is the real core (gate 4), deployed (gate 5), with collateral (gate 6).
Not "every route perfect." When all 6 are green, we can truthfully say: ready to put in front of a client.
