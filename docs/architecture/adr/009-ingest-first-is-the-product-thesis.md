# ADR-009 — Ingest-first is the product thesis

**Status:** Proposed
**Date:** 2026-08-17

---

## Context

Our own documentation describes families called "SAST / SCA / Secret Scanning" and
"DAST / API Security". Probed live, those two families are the weakest on the entire
surface:

| Family | Domains | Carrying tenant data |
|---|---:|---:|
| SAST / SCA / Secrets | 15 | **2** |
| DAST / API Security | 13 | **1** |
| Vulnerability Mgmt / Risk Scoring | 59 | **25** |

That is not a defect to fix — it is a **mislabel**. We do not run static analysis; we
consume its output. What exists behind those names is 34 scanner normalizers turning
other tools' findings into a unified model. Calling it "SAST" invites a comparison with
Semgrep and Checkmarx that we lose on their terms, while hiding the thing we are actually
good at.

The strength is unambiguous in the same data. The one path where a customer's data flows
end to end — ingest → dedup → enrich → score → triage → decide → evidence — is where
every leading number sits: 59 domains, 25 carrying real data, 39 with UI, backed by 45
connector classes and enrichment from 1,665 KEV CVEs, 360,142 EPSS scores and 2,000 NVD
CVEs.

Deduplication is the proof this thesis is real rather than aspirational. Dogfooding
caught it collapsing 1,636 findings into 8 by merging on title alone; made location-aware
it resolved to 1,318 — a correlation problem no individual scanner can solve, because no
scanner sees the others' output. **That is the value only an ingest-first product can
create.**

It is also what makes one product serve both profiles (ADR-001): an air-gapped
organisation cannot use SaaS scanners, runs its own tools on its own metal, and has no
way to correlate the output. Ingest-first is *more* valuable there, not less.

## Decision

**State plainly that FixOps ingests and correlates security findings; it does not
scan. Position, price, and prioritise on that basis.**

1. Product language stops claiming scanning. Families 1 and 2 are renamed to describe
   ingestion and normalisation ("Semgrep results, normalised") rather than the activity
   the customer's own tools perform.
2. Breadth of *ingestion* is a headline claim and must be kept honest: the supported-tool
   list is generated from the normalizers that pass a round-trip test, not maintained by
   hand in marketing copy.
3. Correlation is the differentiator we invest in — deduplication, exposure-case
   grouping, attack-path linking, TrustGraph. These get engineering priority over
   anything that duplicates a scanner.
4. We do not build first-party scanning. Where a gap exists, we add a normalizer for the
   tool customers already run.
5. The MicroPenTest engine is the deliberate exception — it validates *exploitability* of
   an already-ingested finding, which is correlation, not scanning. It stays opt-in
   (`run_pentest=False`) because live exploitation must be a choice.

## Consequences

- We lose head-to-head "do you have SAST?" checkboxes. We accept that; answering "we
  normalise the SAST you already own, and correlate it with everything else" is a better
  conversation and an honest one.
- Onboarding becomes the critical path: the product is worthless until a customer's tools
  are connected. Connector UX therefore outranks new engines (and see ADR-007 — an
  unconfigured connector must never look broken).
- Our roadmap gets a clear filter: a proposal that duplicates something a customer's
  existing scanner does is out of scope by default.
- The claim survives air-gapped deployment intact, which very few competitors can say.

## Verification

- A test round-trips a real fixture through each advertised normalizer into the unified
  model, and the supported-tool list is generated from the passing set.
- A test asserts deduplication is location-aware — two findings with the same title at
  different `file:line` must not merge.
- No product surface claims to perform a scan that a normalizer merely ingests.
