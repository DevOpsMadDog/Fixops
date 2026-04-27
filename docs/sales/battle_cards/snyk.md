# Battle Card — Snyk

> Source: `docs/competitive_validation_2026-04-26.md` (22 caps scored: WIN 11, MATCH 7, LOSE 4)

## When they'll bring it up
- Mid-market dev-tool RFPs (Snyk dominates developer-shopped procurement)
- Any GitHub-native shop (their PR check is muscle memory)
- "We already have Snyk Open Source for SCA"
- Free-tier comparison ("Snyk has a free dev SKU, you don't yet")

## Concede (don't fight what they actually do better)
1. **Snyk Code DeepCode AI** — their SAST AI autofix on PR is GA, polished, and battle-tested. Our `autofix_engine.py` exists with 10 fix types but isn't as deeply integrated into the PR experience yet.
2. **Snyk Vulnerability DB scale** — 12+ years of curated OSS vuln data, exclusive feeds. We use OSV/GHSA which is broader but less curated.

## Reframe (3 things WE do better — cited from competitive validation)
1. **Multi-LLM Consensus + 12-step Brain Pipeline** — Snyk has none of this (we WIN both, they NA on both). Their AutoFix is single-model; ours is 3+ model vote with 85% agreement gate. Cited: `competitive_validation_2026-04-26.md` §C "Decision Intelligence & AI" — 0/10 caps to Snyk, 9/10 to us.
2. **MPTE 19-phase exploit verification** — Snyk tells you a CVE exists. We prove it's exploitable in your runtime with a 19-phase deterministic verification. Cited: §C row 3 — Snyk NA.
3. **Switzerland positioning (orchestrate + native)** — We ingest Snyk's findings AND run our own 8 native engines. Buying us doesn't kill your Snyk investment; it makes it 10x more useful. Snyk only ingests Snyk. Cited: §H row 5 — we WIN dual-mode.

## Deal-killer question to ask
> "When Snyk's AutoFix opens a PR, how many models reviewed that fix before it landed in your repo? And what happens if Snyk's single model is wrong?"

(Answer: one model, no consensus, no rollback hooks. We have 3-model consensus + confidence gating + auto-rollback.)

## Reference ammo
- Snyk pricing page (Team $25/dev/mo) — they price per-developer, we price per-tenant. For a 200-dev team Snyk costs $5K/mo just for Snyk Code; ALdeci Pro is $499/mo flat.
- Snyk State of Open Source Security report — they admit OSS findings are "noisy" — we use that to position our reachability filter (`function_reachability_engine.py` GAP-010).
- Their G2 reviews: search "Snyk false positive" — top complaint, we lead with our 40% noise-reduction POC threshold.

## Where we'd rather not fight
- Pure dev-laptop CLI experience (`snyk monitor` is one-line). Don't anchor on this; pivot to consensus + MPTE.
- IDE plugins (GAP-014 unshipped). If they're an IDE-native shop, position as "we live in the PR + console; your IDE keeps Snyk for now."
