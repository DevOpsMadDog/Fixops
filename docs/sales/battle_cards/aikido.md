# Battle Card — Aikido

> Source: `docs/competitive_validation_2026-04-26.md` (19 caps scored: WIN 14, MATCH 4, LOSE 1)

## When they'll bring it up
- Startup / SMB segment ("we just need something that works in 5 minutes")
- Bootstrapped or PLG-driven security buyers
- "Unified scanner UX" pitch (their core differentiator)
- Anyone who saw Aikido's wedge into the dev-tool category

## Concede (don't fight what they actually do better)
1. **5-minute developer-laptop onboarding UX** — their ICP is "deploy without a sales call." We require a docker-compose minimum and a 14-day POC. They beat us on ZTV (zero-touch value) for SMB.

## Reframe (3 things WE do better — cited from competitive validation)
1. **Brain Pipeline + Multi-LLM Consensus + MPTE + FAIL** — Aikido has none of these unique moats (cited §C — 0/10 to Aikido, 9/10 to us). Aikido is "scanner UX"; we are "decision intelligence."
2. **Compliance + Quantum-safe evidence + 100+ frameworks** — Aikido lists basic compliance; we ship 7 framework engines + quantum-safe ML-DSA evidence chain (§E rows 1, 5, 6 — Aikido LOSE).
3. **Choke-point + attack-path + toxic-combo** — Aikido has no graph layer. We have TrustGraph + Edmonds-Karp choke point + toxic-combo correlator. (§B rows 2-3, 12 — Aikido NA.)

## Deal-killer question to ask
> "When you have a critical-severity finding in a system that's air-gapped from production, how does Aikido know it's not actually exploitable? (Answer: it doesn't — it has no reachability or graph context.) How many engineering hours do you spend per week chasing findings that turn out to be unreachable?"

(We answer with `function_reachability_engine.py` + MPTE + 40% POC noise-reduction threshold.)

## Reference ammo
- Aikido's pricing page (transparent, ~$300-500/mo SMB tier) — directly compare to our Pro $499/mo. We MATCH on price and CRUSH on capability.
- Aikido marketing leans heavily on "we replace 9 tools" — we go further: "we ingest from your 9 tools AND replace them when you're ready, AND add 4 things they all lack" (consensus, MPTE, FAIL, quantum evidence).
- They have no on-prem story. Enterprises with data residency requirements cannot deploy Aikido. We ship on-prem + air-gap (cited §H rows 2-3).

## Where we'd rather not fight
- 5-minute laptop install (not our market). If buyer is SMB-bootstrapped and won't do a 14-day POC, gracefully refer them to Aikido — and add them to a "graduate to ALdeci when you scale" list.
