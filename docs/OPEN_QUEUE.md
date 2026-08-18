# Open queue — single source of truth

Everything still owed, in one place, so no thread goes stale. Updated 2026-08-18.

Closed work lives in `SELLABLE_BACKLOG_2026-08-17.md` (20 of 28 done) and in the ADRs.
This file is only what remains. **Nothing here is abandoned; it is queued.**

Ordered by what unblocks a sale, not by effort.

---

## P0 — a customer sees this and stops trusting the product

| # | Item | Evidence | Closes when |
|---|---|---|---|
| Q1 | **80 human screens are reachable and return nothing or fail** — `asset-inventory`, `audit`, `certificates`, `ciso-report`, … | measured across 745 domains | each is wired, or dormant; a reachable menu item never dead-ends |
| Q2 | **Redeploy** — 8 commits since fly v80, including every action-button and finding-identity fix | `git log 2dcfa843..HEAD` | fly serves the current build, verified live |
| Q3 | **Click the remaining screens** — Respond, Evidence, Onboarding | every defect so far only appeared when something was pressed | each action verified to persist, same method as Triage |

## P1 — the product thesis (ADR-010 / ADR-011)

| # | Item | Why it matters | Closes when |
|---|---|---|---|
| Q4 | **Wire exploit analysis into the pipeline** | `exploit_signals.py` + `exploit_generator.py` exist; `brain_pipeline` imports neither. It is the missing half of the reachability pair, and both are static | exploit signal runs beside reachability at every stage |
| Q5 | **Per-stage verdict history** | a finding needs *many* verdicts over time, not one overwritten field — this is what makes prediction→confirmation measurable | `(finding, stage, verdict, timestamp)` is stored and queryable |
| Q6 | **Forecasting at plan/design** | the honest question where there is no target: how likely is this to *become* exploitable (EPSS trajectory, KEV-addition likelihood) | a design-stage finding carries a forecast, labelled predicted |
| Q7 | **MPTE target providers** | one engine, five providers: nothing at design, ephemeral container at build/test (`sandbox_verifier.py`), staging at release, production at operate | MPTE reports "no target at this stage" rather than silently skipping |
| Q8 | **Measure reachability's filtering value** | mechanism proven (42,796 edges, 6.2s) — noise reduction on a *customer* repo is still unmeasured | a real repo, a published percentage, not an assumption |
| Q9 | **Customer-declarable graph** — the anti-Apiiro differentiator | `entity_type`/`rel_type` are already free strings; the openness is latent and unexposed | a tenant declares a type and a rule via API and a pipeline run correlates using it |

## P2 — surface and shape (the eight flows)

| # | Item | Detail | Closes when |
|---|---|---|---|
| Q10 | **Decide the 183 unassigned domains** | 44 carry real tenant data — fold into a flow, demote to API-only, or retire. Not a blanket switch | each has a decision recorded |
| Q11 | **Build flow 02 (Work the queue) properly** | the spine, and what a customer pays for | ingest→triage→case completes without a dead end |
| Q12 | **Build flow 04 (Prove it to the auditor)** | the commercial wedge | an assessor can open one screen and get a signed, provenanced bundle |
| Q13 | **D2 — core membership by evidence** | membership generated from (tenant-varying data ∧ UI callsite), not curated by hand | list is generated |
| Q14 | **D3 — execute dormancy** | ~290 engine-domain orphans, in verified batches | route count drops by the expected delta each batch, gates stay green |

## P3 — debt with a ratchet already on it

| # | Item | Current | Closes when |
|---|---|---|---|
| Q15 | **E2 — relative DB paths** | 155 files hardcode them and ignore `FIXOPS_DATA_DIR`; ratchet in `test_no_relative_db_paths.py` | count reaches 0 |
| Q16 | **B4 — duplicated contract models** | `CapabilityResponse` ×46, `ScanRequest` ×24 re-declared per router | shared, and duplicate class-name count materially below 4,213 |
| Q17 | **F1 — rename Families 1–2** | we call it SAST/DAST; we normalise other tools' output. 2 of 15 and 1 of 13 domains carry data | no surface claims a scan a normalizer merely ingests |
| Q18 | **F4 — offline bundle verifier** | a customer must verify a bundle without us | third party verifies on a machine with no network and no FixOps |

## P4 — blocked on hardware or a decision only the founder makes

| # | Item | Blocker |
|---|---|---|
| Q19 | **C4 — air-gapped council proof, green** | needs inference-sized hardware. Mechanic proven (2 local models, independent reasoning, **zero egress**); laptop CPU exceeds 10 min on the six-key verdict prompt and falls back to labelled heuristics |
| Q20 | **C2 — vendor-free council member set** | partly present: `_enforce_air_gap_providers()` already swaps providers and fails closed. Needs the member set driven by profile |
| Q21 | **Authenticated verification against fly** | the deployed `FIXOPS_API_TOKEN` was rotated in an earlier session and is unreadable; rotating it is a live change I will not make unasked |

---

## Standing rules this session established

These are not tasks; they are how the work is judged, and they caught every defect above.

1. **Click it, then read the data back.** Triage returned `{"processed": 1}` and changed
   nothing. AutoFix generated a fix and then threw it away on an audit call. Neither was
   visible from code review.
2. **A number nobody measured must not be displayed.** `0ms` health tiles, `"< 24h"` MTTD,
   controls asserting "effective" on a run that did nothing.
3. **Absence is a fact worth stating.** "not configured", "not assessed", "no bundle
   imported" — never an invented substitute.
4. **Two components can each be correct while the product lies.** Split stores, wrong
   identifier space, field-name mismatch. Check the join.
