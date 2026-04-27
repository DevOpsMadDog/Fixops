# Battle Card — XM Cyber

> Source: `docs/competitive_validation_2026-04-26.md` (19 caps scored: WIN 13, MATCH 4, LOSE 2)

## When they'll bring it up
- Attack-path-graph / choke-point category buyers (XM owns this term in many shops)
- Red-team-aware enterprise security teams
- ServiceNow VR-native shops (XM's SN-VR connector is deep)

## Concede (don't fight what they actually do better)
1. **Attack-graph polish + Choke Point UX** — XM's visualization is genuinely the gold standard. Our `attack_path_engine.py` + Edmonds-Karp min-cut is real (GAP-026 done) but UI polish lags. (We're closing this gap during current consolidation per `competitive_validation_2026-04-26.md` action item #9.)
2. **ServiceNow VR native connector polish** — XM's bidirectional SN-VR integration is more mature than our generic ServiceNow connector.

## Reframe (3 things WE do better — cited from competitive validation)
1. **Brain Pipeline + Multi-LLM Consensus + MPTE + FAIL** — XM has none of these (cited §C — 0/10 to XM, 9/10 to us). XM infers exploitability from graph traversal; we PROVE it with 19-phase MPTE verification with rollback.
2. **Native scanning across 8 categories + dual-mode** — XM is a graph + breach-path platform; it doesn't ship native SAST/DAST/SCA/Container/IaC/Secrets/API/LLM scanners. We do all 8. Cited §A — XM has only 1 of 16 native scanning caps.
3. **Quantum-safe evidence + 100+ compliance frameworks + air-gap** — XM has compliance hooks but not FIPS 204 + WORM Merkle chain + signed offline bundle. Cited §E + §H.

## Deal-killer question to ask
> "When XM Cyber identifies a choke point, can it then patch the choke point AND verify the patch worked AND generate signed compliance evidence AND fine-tune your private model on your analyst's override? Because that's the closed loop your CISO actually needs — and that's what we deliver in 12 steps."

## Reference ammo
- XM Cyber acquisition by Schwarz Group (2021) — they're a portfolio asset, not an aggressive growth product. Roadmap velocity is a concern for evaluators.
- XM positions exclusively as "attack path." We position as "complete CTEM+ with attack-path as one of 12 pipeline steps." Bigger surface, more buyer value.
- XM's pricing is enterprise-only opaque. Our $1,499/mo Enterprise tier is transparent; for a comparable XM deployment expect $80K-200K/yr.
- Their published demo videos all show graph traversal — never show a closed remediation loop. We close the loop (Brain Pipeline step 11 AutoFix + step 12 evidence).

## Where we'd rather not fight
- Pure attack-graph visual polish. If buyer's #1 demo gut-check is graph beauty, acknowledge XM's edge and pivot to the closed loop. "Their graph is prettier today; ours has the next 9 steps after the graph."
