# Battle Card — Wiz

> Source: `docs/competitive_validation_2026-04-26.md` (24 caps scored: WIN 9, MATCH 8, LOSE 7 — **WORST gap of any competitor**)

## When they'll bring it up
- Cloud-first / cloud-native shops (Wiz is THE cloud-security category leader)
- Multi-cloud AWS + GCP + Azure + OCI environments
- DSPM-driven evaluations (data classification is their hero)
- Anyone post-Google-acquisition aware (massive enterprise air cover)
- "We need the Wiz Security Graph" RFPs

## Concede (don't fight what they actually do better)
1. **Security Graph UX maturity** — Wiz's graph is THE polished gold standard. Our render is functional, not yet beautiful.
2. **Agentless snapshot scale** — Wiz's SideScanning is mature; our `agentless_snapshot_scan_engine` (GAP-020 done) currently uses a mock cloud SDK pending production boto3/Azure SDK wiring.
3. **DSPM (data classification)** — Wiz's data PII detection + lineage is far ahead of our basic `data_governance_engine`.
4. **CIEM polish** — Wiz CIEM > our `ciem_engine` for visual analysis & remediation.
5. **Multi-cloud depth** — Wiz covers OCI + Alibaba + IBM Cloud. We focus AWS + GCP + Azure.
6. **100+ compliance frameworks UI** — Wiz has more polished framework views than us today (we have the engines, working on UI placement).
7. **Post-Google ecosystem** — they have GCP-native distribution we cannot match.

## Reframe (3 things WE do better — cited from competitive validation)
1. **Brain Pipeline + Multi-LLM Consensus + MPTE + FAIL + Self-learning DPO loop** — Wiz has none of these (cited §C — 0/10 to Wiz, 9/10 to us). Wiz tells you about cloud risks; we prove which are exploitable, vote on remediation, and improve overnight from your analyst's choices.
2. **Native code-side scanning (SAST/DAST/SCA/Secrets/Container/IaC/API/LLM)** — Wiz is cloud-side only. They have NO native SAST, NO native DAST, NO native SCA, NO API testing. They added some via acquisition (Dazz) but it's bolt-on. We have all 8 engines integrated through one Brain Pipeline. Cited §A.
3. **Quantum-safe evidence + Air-gap deployment + dual-mode** — Wiz is SaaS-only; cannot run air-gapped, has no FIPS 204 ML-DSA evidence, has no on-prem K8s/Helm story. For federal / regulated / sovereign-cloud customers, Wiz simply cannot deploy. Cited §H rows 2-5.

## Deal-killer question to ask
> "When your developer commits a SQL injection into a microservice, does Wiz catch it in the PR and AutoFix it before merge? Or does it only see the issue after it's deployed and a runtime scanner flags it? Because pre-deployment is 100x cheaper to fix than post-deployment — and that's the half of the lifecycle Wiz doesn't own."

(We answer: Brain Pipeline step 11 AutoFix triggered by SAST step 1, multi-LLM consensus at step 9, PR opens before merge.)

## Reference ammo
- Wiz pricing — opaque, expensive (typically $150K-500K+/yr). Our tiered pricing is 1/10 to 1/100 the cost for equivalent CTEM+ surface.
- Wiz acquisition of Dazz (Apr 2024) — public admission they had no code-side story until then. Use this: "Wiz didn't have SAST until 14 months ago; we've had 8 native engines from day one."
- Wiz cannot deploy air-gapped. Any federal, defense, intelligence, sovereign-cloud, or regulated-bank evaluator with an air-gap requirement = our deal to lose.
- DSPM is their hero in marketing, but for buyers whose primary concern is code + runtime + compliance (not data classification), it's not the wedge they think it is. Reframe.

## Where we'd rather not fight
- Pure cloud-graph visualization. If buyer's #1 gut-check is "show me the prettiest cloud graph," concede Wiz wins today and pivot to the four things they cannot do (native code scanning, MPTE, air-gap, on-prem). For a pure cloud-only PaaS shop with no air-gap need and no compliance pressure, Wiz is genuinely a good fit — recommend coexistence (we ingest Wiz findings, layer Brain Pipeline + MPTE + compliance on top). Don't try to displace; expand around them.
