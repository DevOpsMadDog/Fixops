# Battle Card — Tenable (Tenable One / ExposureAI / Nessus)

> Source: `docs/competitive_validation_2026-04-26.md` (21 caps scored: WIN 12, MATCH 5, LOSE 4)

## When they'll bring it up
- Enterprise host-vuln-management shops (Nessus is the 25-year incumbent)
- CTEM-category RFPs (Tenable owns the analyst-defined "CTEM" term in many shops)
- ServiceNow CMDB-integrated environments (Tenable has deep SN connector)
- "Lumin Exposure View" and "ExposureAI" pitches (their hero AI surface)

## Concede (don't fight what they actually do better)
1. **Nessus host-vuln scanning heritage** — 25 years of host-OS scanning. We don't ship a host vuln scanner; we wrap OSS equivalents.
2. **AI Exposure module** — their shadow-AI inventory is mature. Our `ai_governance + cmdb` (GAP-059 done) is parity-only and needs UI placement.
3. **ServiceNow CMDB ingest depth** — Tenable's SN connector is bidirectional and asset-class-rich.
4. **ACR (Asset Criticality Rating) auto-derivation** — Tenable's auto-tagging maturity is ahead of our `asset_tagging_engine`.

## Reframe (3 things WE do better — cited from competitive validation)
1. **Brain Pipeline + Multi-LLM Consensus + MPTE + FAIL** — Tenable has none (cited §C — 0/10 to Tenable, 9/10 to us). Their ExposureAI is single-model NL; ours is 3+ model consensus with vote audit.
2. **CTEM+ moat: continuous exploit verification** — Tenable infers exploitability from Lumin scoring. We PROVE it via 19-phase MPTE verification, every cycle, with chain-of-custody evidence. Cited §C row 3.
3. **Quantum-safe evidence + WORM audit chain** — Tenable has compliance but not FIPS 204 PQC + Merkle-chained audit log. Cited §E rows 6, 11.

## Deal-killer question to ask
> "When ExposureAI tells you a finding is exploitable, what's its evidence? Is it model inference, or is it a 19-phase verification with safe rollback and an attached chain-of-custody evidence bundle? Because your auditor will ask."

(We answer: MPTE 19-phase + signed evidence bundles + 365 verifications/year vs 1 annual pentest.)

## Reference ammo
- Tenable's "CTEM" framing — concede the term, then differentiate with **CTEM+**. Reference: `docs/CTEM_PLUS_IDENTITY.md`. The "+" is consensus + MPTE + FAIL + quantum evidence + dual-mode native scanning.
- Tenable's air-gap story is weak; their ConMon and ATO maturity exists but for VM/scanning. We ship `airgap_router.py` for the entire CTEM lifecycle.
- Tenable per-asset pricing scales painfully for cloud-native shops. We ship per-tenant tiers.

## Where we'd rather not fight
- Host vuln scanning heritage. If buyer's primary need is patch management for 50K endpoints, Tenable wins — recommend coexistence: keep Nessus, ingest findings into ALdeci for consensus + MPTE + compliance. Don't try to displace Nessus.
