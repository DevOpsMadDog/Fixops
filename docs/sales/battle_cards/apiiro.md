# Battle Card — Apiiro

> Source: `docs/competitive_validation_2026-04-26.md` (21 caps scored: WIN 10, MATCH 8, LOSE 3)

## When they'll bring it up
- Enterprise ASPM RFPs ("Risk Graph" is their hero)
- Material-Change-Detection-driven shops ("we want to catch when a PR changes the threat model")
- F500 procurement with named-logo bias (they have aggressive logo placement)

## Concede (don't fight what they actually do better)
1. **DCA (Deep Code Analysis) semantic depth** — their architecture-aware code understanding is more mature than our `architecture_aware_kg_engine` (GAP-065 done but Python-only).
2. **Enterprise logo deck** — they have named F500 customer placements that take years to accumulate. We don't yet. Don't fake it.

## Reframe (3 things WE do better — cited from competitive validation)
1. **Brain Pipeline + Multi-LLM Consensus + MPTE** — Apiiro has none of these (3 unique moats; cited §C — 0/10 to Apiiro, 9/10 to us). Apiiro orchestrates findings; we orchestrate AND verify exploitability AND vote on decisions.
2. **Native scanner mode (dual-mode)** — Apiiro is orchestration-only; they cannot run a single native scan. We run 8 native engines AND ingest 200+ scanners. Cited: §H row 5 — Apiiro LOSE on dual-mode.
3. **Quantum-safe evidence + Air-gap deployment** — Apiiro is SaaS-only with RSA evidence. We ship FIPS 204 ML-DSA signed evidence + signed offline air-gap bundle. Cited: §E + §H rows 3-4.

## Deal-killer question to ask
> "If your existing scanners go down or your team gets a directive to go air-gap, what does Apiiro do? (Answer: nothing — they have no native scanners and no air-gap mode.) When that happens to you, would you rather have a tool that fails open or one that runs eight native scanners offline?"

## Reference ammo
- Apiiro's published "Risk Graph" patent — public docs admit it's an orchestration layer, not a scanner. Use this to anchor "they need vendors A+B+C+D to work; we work alone."
- Apiiro pricing is opaque — no public tier list. We publish $199/$499/$1499 transparently. Procurement loves transparency.
- Their PR-scan capability is weak (no first-party GitHub App with HMAC webhook — gap-matrix `competitive_validation_2026-04-26.md` §F row 2).

## Where we'd rather not fight
- DCA semantic depth — note GAP-065 is parity-only and Python-only. If they're a polyglot enterprise, Apiiro will out-position on architecture-aware analysis. Pivot to MPTE + consensus.
