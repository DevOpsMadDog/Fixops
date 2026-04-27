# Battle Card — Sonatype (Lifecycle / SAGE / Nexus IQ)

> Source: `docs/competitive_validation_2026-04-26.md` (23 caps scored: WIN 13, MATCH 6, LOSE 4)

## When they'll bring it up
- Java / Maven shops (Nexus is their incumbent registry; Lifecycle is the upsell)
- Enterprise SCA-first procurement ("we need the deepest dep analysis")
- Air-gapped + on-prem requirements (SAGE has a real on-prem story)
- IntelliJ-heavy dev orgs (Sonatype's IntelliJ plugin is best-in-class)

## Concede (don't fight what they actually do better)
1. **SCA depth + Advanced Binary Fingerprint** — Sonatype's component intelligence is 18+ years deep. Their 870K malware/typosquat catalog dwarfs our `supply_chain_intel`.
2. **IntelliJ-grade IDE plugin** — Nexus IQ for IntelliJ is mature. Our IDE story is GAP-014 unshipped.
3. **Mature waiver workflow UI** — Sonatype's waiver explorer is polished. Our backend is done (GAP-006) but UI is a placement gap.
4. **OSS Index dataset scale** — they own a curated OSS data feed at industrial scale.

## Reframe (3 things WE do better — cited from competitive validation)
1. **Brain Pipeline + Multi-LLM Consensus + MPTE** — Sonatype has none (cited §C 0/10 to Sonatype). They tell you a dependency is vulnerable; we prove it's exploitable AND vote on the fix.
2. **Switzerland positioning (orchestrate + native, all categories)** — Sonatype is SCA-only natively. We do SAST + DAST + SCA + IaC + Secrets + Container + API + Malware + LLM (8 engines). Cited: §A "Native Scanning" — 16 capabilities, we cover all 16; Sonatype covers 4.
3. **Quantum-safe evidence + 100+ compliance frameworks** — Sonatype has solid compliance for SCA-licensing but not security frameworks at our breadth. We WIN §E quantum-safe (FIPS 204) which Sonatype LOSEs.

## Deal-killer question to ask
> "When you find a vulnerable dependency, how does Sonatype tell you whether the vulnerable function is reachable in YOUR code, or whether your runtime is actually exposing it? (Answer: it doesn't — Sonatype is component-level, not function-level + runtime.) How much engineering time do you waste fixing components whose vulnerable code path you don't even invoke?"

(We answer: `function_reachability_engine.py` GAP-010 done + `auto_waiver` tied to reachability GAP-006 done.)

## Reference ammo
- Sonatype Lifecycle pricing — opaque, enterprise-only, typically $50K-150K/yr for mid-market Java shop. Our Pro $499/mo + Enterprise $1,499/mo is 1/8 the cost.
- Sonatype's own marketing emphasizes "open-source supply chain" — narrow framing. We frame as "complete CTEM+ across code, cloud, runtime, AI" — much broader buyer narrative.
- SAGE air-gap story is real but installation is painful. Our `airgap_router.py` (1427 LOC) + signed bundle is documented in `core/airgap_deployment.py`.

## Where we'd rather not fight
- Pure SCA depth on Java/Maven — their dataset wins. If buyer's #1 criterion is SCA-only Java SCA, recommend they keep Sonatype Nexus IQ AND ingest its findings into ALdeci for the consensus + MPTE + compliance layer. Don't try to displace.
