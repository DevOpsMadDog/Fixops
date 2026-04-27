# SCIF Discovery Call Playbook (30 min)

**Date:** 2026-04-26
**Companion docs to have open during the call:**
- `docs/pitch/ALDECI_PITCH_DECK_2026-04-26.md` — primary screen-share
- `docs/scif_readiness_2026-04-26.md` — the honest scorecard
- `docs/scif/SSP_aldeci_2026-04-26.md` — SSP draft
- `docs/scif/POAM_aldeci_2026-04-26.md` — POA&M
- `docs/scif/SCIF_PILOT_BUNDLE_README.md` — bundle README
- `docs/sales/scif/pilot_sow_template_2026-04-26.md` — SOW (do NOT share until next-step)

---

## 0. Pre-Call (T-15 min)

- [ ] Re-read prospect's LinkedIn + the public program/RFI you cited in cold email
- [ ] Have screen-share ready, deck pre-loaded to Slide 1, scorecard tab open
- [ ] Confirm `docs/sales/scif/scif-outreach-log.json` is updated with the call
- [ ] Mute Slack/email — federal calls do not get rescheduled
- [ ] Have water; speak slowly; AOs and ISSOs hate fast-talkers

---

## 1. Agenda (share verbally in first 60 sec)

```
"[First name], thanks for the time. Here's how I'd like to use the 30 min
if it works for you:
  - 2 min: super quick context on what ALDECI is and isn't
  - 5 min: I'd love to ask you about your current pain — classification level,
           toolchain, ATO posture, deadlines
  - 10 min: walk you through our 4-stage SCIF pilot path — Stages 1 and 2 are
            already done, this call is Stage 3, Stage 4 is the install
  - 8 min: your questions
  - 5 min: agree on next step

Sound right?"
```

If they push back ("I only have 20 min"), compress sections 4 and 5 by half. Never cut the qualifying questions (section 3) — that's where the deal is made or lost.

---

## 2. Context-Setting (2 min) — Slides 1–2

- "ALDECI is a self-hosted, AI-native CTEM platform — Continuous Threat Exposure Management."
- "Built specifically for SCIF, IL5, FedRAMP High class deployments. Zero outbound network, FIPS 140-3 boundary, on-prem LLM inference, HSM-backed tamper-evident audit chain, CRYSTALS-Kyber and Dilithium inventory aligned to CNSA 2.0."
- "Honest status: we're ~35% of full FedRAMP High maturity. The technical surface is real and shipped. The compliance paperwork is in draft. We're not selling you authorization — we're selling you a pilot under your existing ATO inheritance pattern."
- "Today is Stage 3 of our 4-stage pilot motion. I'll get to that in 8 min."

**Tone:** measured, honest, no superlatives. AOs respect candor; they punish hype.

---

## 3. Their Pain — Qualifying Questions (5 min)

Ask in order. Take notes. Do **not** pitch in this section.

### 3a. Mission classification & deployment surface
- "What's the classification ceiling of the systems you'd want CTEM coverage for? UNCLASS, CUI, SECRET, TS, TS/SCI?"
- "Are these systems on a network — NIPR, SIPR, JWICS — or true SCIF air-gap?"
- "How many distinct enclaves / SCIFs would the pilot scope cover?"

### 3b. Current toolchain & gap
- "What's in your CTEM/ASPM stack today? Snyk? Wiz? Veracode? Tenable? Custom?"
- "Of those, which can run inside your SCIF without a phone-home?"
- "Where does the workflow break — what's the painful part?"

### 3c. ATO inheritance & authority
- "What's your ATO inheritance model — package-of-package, control inheritance, or stand-alone?"
- "Who's your AO, and who'd own the ISSO seat for this pilot?"
- "Is there a 3PAO already in flight, or would this be a fresh assessment?"

### 3d. Compliance deadlines & forcing functions
- "Any specific deadline driving this — FedRAMP High In-Process target, IL5 PA, CNSA 2.0 migration milestone, or a program ATO renewal?"
- "Any board / IG / GAO findings that this would help close?"

### 3e. Budget & vehicle
- "How does cyber tooling typically buy at [org] — direct procurement, OTA via DIU/AFWERX/SOFWERX, SBIR, or through a SI/reseller like Carahsoft?"
- "Is there discretionary $ this fiscal cycle, or do we need to shape next-year POM?"

**Critical:** if answers reveal it's a *bad* fit (e.g., commercial-only, no clearances, no air-gap need), say so and end the call gracefully at 12 min. Don't waste their time. They'll respect you and refer.

---

## 4. The 4-Stage Pilot Overview (10 min) — Slides 5, 7, 8

Frame: **"You're meeting us at Stage 3. The first two are done. The fourth is the install."**

### Stage 1 — Engineering Hardening — DONE (show)
- Cite commits: `1159ef49` (HSM PKCS#11), `69efa330` (Merkle audit chain), `aba22fff` (cosign image signing), Wave C `8e9e573d` (FIPS 140-3 NIST KAT), Iron Bank UBI9 base
- Open `docs/scif/SCIF_PILOT_BUNDLE_README.md` § 9 "Honest Status" — read aloud:
  - "Bundle contents: complete and reproducible from git sha"
  - "Hardening checklist: 23/30 STIG controls met in code (77%)"
  - "HSM functional with SoftHSM, production swap config-only"
  - "Audit chain: tamper-evidence verified"
  - "Air-gap: FIPS boot + telemetry kill-switch + active probe"
- Show the bundle artefact name pattern: `dist/aldeci-scif-<git_sha>-<utc_date>.tar.gz`
- **Pause** — invite questions on Stage 1 specifically.

### Stage 2 — Compliance Documentation — DONE (show)
- Open `docs/scif/SSP_aldeci_2026-04-26.md` — show table of contents, 1 paragraph
- Open `docs/scif/nist_800-53_control_matrix_2026-04-26.csv` — show 5 rows
- Open `docs/scif/POAM_aldeci_2026-04-26.md` — show open POA-001..POA-006 with severity (all LOW/MED, none blocking pilot)
- Open `docs/scif/threat_model_aldeci_2026-04-26.md` — show STRIDE entry
- Open `docs/scif/crypto_module_datasheet_2026-04-26.md` — show FIPS module boundary diagram
- Open `docs/scif/auditor_quick_reference_2026-04-26.md` — "this is the 40-min ATO walk-through your ISSO will use"
- **Pause** — invite questions on Stage 2.

### Stage 3 — Sponsor Engagement — IN PROGRESS (this call)
- "This call is Stage 3 — we identify the right pilot fit, agree the scope, and decide if there's mutual interest."
- "If there is, the next step is a 1-page pilot SOW your contracting officer can sign within 7 days."
- "If there isn't, we both walk away with no obligation — and I appreciate the honest read."

### Stage 4 — Pilot Deployment — T+5 from sponsor sign, full install by T+20
- "Day 0 — SOW signed."
- "Day +5 — bundle hand-off via your approved data-transfer mechanism (sneakernet/cross-domain solution/encrypted media — your call)."
- "Day +6 — bundle integrity verification by your ISSO (sha256, GPG signature, manifest reconciliation)."
- "Day +7 — install on the SCIF host, smoke tests pass, FIPS_STRICT_BOOT=1, HSM_ENABLED=1."
- "Day +8 to +14 — 1 real workflow demo end-to-end, your ISSO walks through `auditor_quick_reference` doc."
- "Day +15 to +20 — formal acceptance, ConMon evidence baseline captured, weekly POA&M cadence agreed."

**Critical:** show timeline as a Gantt-style table. AOs/PMs love clear date math.

---

## 5. Q&A (8 min) — anticipated objections

| Q | A (≤45 sec each) |
|---|---|
| "How are you different from Snyk / Veracode / Wiz?" | "We're not a replacement. We ingest their outputs and add the SCIF-grade controls they don't ship — air-gap appliance with active outbound-blocking, HSM-backed Merkle audit, CRYSTALS-Kyber/Dilithium inventory. Slide 4 has the scorecard." |
| "Why should I pilot a 35%-mature platform?" | "Because the 35% is the part that's hardest to retrofit — air-gap, FIPS, HSM, PQC. The other 65% is paperwork and process, which is faster to add than to invent the technical foundation. The pilot lets us co-design the remaining 65% around your real needs." |
| "What's your FedRAMP High status?" | "FedRAMP High *aware*, not authorized. 12–18 months out under a sponsor co-sponsorship pattern. Slide 7 is the honest scorecard. We are NOT marketing FedRAMP High today." |
| "How does your audit chain compare to AWS CloudTrail Lake / Azure Sentinel?" | "We hash-chain every entry with prev_hash + canonical-JSON + timestamp; checkpoint every 100 entries with HSM RSA signature. Tamper to any row breaks the chain at the exact mutated row. Cloud audit is point-in-time signed; ours is continuously verifiable. Both are valid — ours is purpose-built for offline." |
| "Who else is using ALDECI?" | "We're at design-partner stage. The pilot you're considering is itself a co-design opportunity — we'd happily reference you on outcomes, not features. Slide 12 is our three-category design partner ask." |
| "Why not just buy Anchore Enterprise + Sigstore + open-source CTEM?" | "You can. You'd be integrating 6 tools and writing the air-gap glue + audit chain + DPO loop yourself. We've already built that integration with shared evidence/control plane. Slide 3 has the moats." |
| "What about telemetry / phone-home?" | "Zero. `FIXOPS_DISABLE_TELEMETRY=1` is the default in the SCIF SKU. The container actively probes 8 known internet endpoints during boot; if any are reachable, it refuses to claim air-gap status." |
| "Who owns the data?" | "You do. Pilot SOW says: no exfil, customer owns all DPO learning data, ALDECI may use anonymized telemetry for product (opt-in only). Pilot SOW template is 1 page." |
| "Pricing post-pilot?" | "Pilot is $0 (design-partner) or $25K all-inclusive. Post-pilot pricing depends on scale, but ballpark: $50K-150K/yr per SCIF, replaces $250K-500K of current tool spend." |

If a question is one we can't answer honestly: **say so and commit to a 24-hour written follow-up.** Never bluff in front of an AO.

---

## 6. Next Step (5 min)

Three possible exits — pick one with the prospect:

### Exit A — Hot ("Let's do this")
- Confirm: "Great — I'll send the 1-page pilot SOW within 24h. Your contracting officer reviews; aim is signature within 7 days."
- Confirm cost choice: "$0 pre-revenue design-partner OR $25K all-inclusive — I'll send both options."
- Confirm tech POC: "Who's the ISSO who'll own day-to-day during pilot?"
- Confirm hand-off mechanism: "What's your approved data-transfer for the bundle — sneakernet/CDS/encrypted media?"
- Set the install date: T+5 working days from signature.

### Exit B — Warm ("Need to socialize internally")
- Confirm: "Totally fair. What would help — should I send a tailored 1-pager for [their AO/CIO/PM]?"
- Set follow-up: "Can we calendar a check-in for [+10 working days]?"
- Send within 24h: tailored 1-pager with their org name, their program, the specific controls/POA&Ms most relevant.

### Exit C — Cold ("Not right now / not the right fit")
- Confirm: "Understood — appreciate the honest read."
- Ask the referral: "Is there someone in your network who'd be a better fit for an air-gap CTEM pilot? OK if I cite you on the intro?"
- Set a quarterly nurture: add to P3 list, ping at next quarterly cadence with product update.

---

## 7. Post-Call (T+15 min)

- [ ] Update `.claude/team-state/sales/scif-outreach-log.json` — call date, outcome (A/B/C), commitments made, next-step date
- [ ] Send same-day follow-up email (within 2 hours):
  ```
  Subject: ALDECI — follow-up + docs as discussed

  [First name],

  Thanks for the 30 min today. As discussed:
   - Attaching: pitch deck, SCIF Pilot Bundle README, auditor quick-reference
   - [If Exit A: pilot SOW under separate cover within 24h]
   - [If Exit B: tailored 1-pager for [their AO] in next 24h, check-in calendared for [date]]
   - [If Exit C: thanks + quarterly nurture]

  Two action items I owe you by [date]:
   1. [...]
   2. [...]

  Open question I'll answer in writing within 24h:
   - [...]

  Best,
  [Sender]
  ```
- [ ] If commitments include written answers: deliver in <24h, no exceptions
- [ ] If Exit A: trigger pilot SOW from `docs/sales/scif/pilot_sow_template_2026-04-26.md` and `docs/sales/scif/reference_arch_scif_2026-04-26.md` (send both)
- [ ] Update sales-engineer status: `.claude/team-state/sales-engineer-status.md`

---

## 8. Things To Avoid

- **Never** describe the platform as "the most advanced" / "AI-powered" / "industry-leading" — federal AOs auto-discount hyperbole
- **Never** promise FedRAMP High *Authorization* — only *In-Process candidate with sponsor*
- **Never** promise zero POA&M items — show the open ones; transparency wins
- **Never** quote competitor pricing or claim "10× cheaper" — agencies have tool-budget visibility we don't
- **Never** demo live in a discovery call — book a separate technical deep-dive (Stage 4 prep)
- **Never** offer to "white-label" or "co-brand" with a prime in the discovery call without legal review

*End playbook.*
