# SCIF Cold Outreach Templates

**Date:** 2026-04-26
**Companion:** `docs/sales/scif/target_list_2026-04-26.md`, `docs/pitch/ALDECI_PITCH_DECK_2026-04-26.md`, `docs/scif/SCIF_PILOT_BUNDLE_README.md`

> **Use rules**
> - Personalize the **first sentence** every time. Reference one specific program, RFI, or public statement from the recipient. Generic openings get archived.
> - **Word counts are caps, not targets.** Less is better.
> - **Never attach files** in the cold message. Reference the deck slide # and offer to share on accept.
> - **One ask per message.** A 30-min discovery call is the only ask. Not a demo, not a meeting with the CTO.
> - **Deck slide refs:** Slide 5 = Architecture, Slide 6 = Self-learning DPO, Slide 7 = SCIF scorecard, Slide 8 = 20-day pilot path, Slide 12 = Three categories of design partner.

---

## Template 1 — LinkedIn DM (200-word cap)

**Use for:** Federal IC contacts (NGA, NRO, NSA, CIA), DARPA PMs, FFRDC senior staff. Anyone who reads LinkedIn before email.

```
Subject (auto): Connect

Hi [First name],

I'm reaching out because of [specific program / publication — e.g., "your team's Apr 2025 talk at ShmooCon on offline SBOM mirrors" or "the CISA AI Roadmap CTEM line item you co-authored"].

I'm building ALDECI — a self-hosted, air-gap CTEM platform that ships today with FIPS 140-3 mode, on-prem LLM inference (vLLM), CRYSTALS-Kyber/Dilithium inventory, and a tamper-evident HSM-backed audit chain. Think CTEM with the controls a SCIF will actually authorize.

Honest status: ~35% of full FedRAMP High maturity (12–18 months out), but technical surface is ready for a 20-day pilot under your existing ATO inheritance pattern. SSP draft, POA&M, NIST 800-53 control matrix, threat model, and crypto datasheet are all written and ready to share.

Would a 30-min discovery call make sense in the next 2 weeks? I'd like to walk you through our SCIF readiness scorecard (the honest one) and see if there's a fit with [their program].

Happy to send the pilot bundle README ahead of time.

— [Sender]
ALDECI / DevOpsAI
```

**Why it works:** opens with proof you read their work; sets honest expectations (35%, 12–18 months) which AOs respect; offers the doc bundle on response, not in DM; one ask.

---

## Template 2 — Cold Email v1 — Federal Sponsor (150-word cap)

**Use for:** CISA, DIU, AFWERX, SOCOM SOFWERX, NavalX, ARCYBER, CDAO, agency CISO offices.

```
Subject: 20-day SCIF pilot — air-gap CTEM with FIPS 140-3 + ML-DSA evidence signing

Hi [First name],

[Specific reference — e.g., "Saw the DIU Cyber Portfolio's Mar 2026 CSO topic on offline vulnerability management"].

ALDECI is a self-hosted CTEM platform built for SCIF-class deployments: zero outbound network, FIPS 140-3 boundary (Slide 7), on-prem LLM inference, HSM-backed tamper-evident audit chain, and CRYSTALS-Kyber/Dilithium inventory aligned to CNSA 2.0.

We've packaged a SCIF Pilot Bundle that an ISSO can authorize under your existing ATO inheritance pattern in ~20 working days from contract sign (Slide 8). SSP draft, POA&M, NIST 800-53 control matrix, threat model, crypto datasheet, and 40-min auditor walk-through are all written.

Pilot is $0 (pre-revenue design-partner) or $25K all-inclusive — your choice.

Would 30 min in the next 2 weeks work to walk through the scorecard and see if there's program fit?

— [Sender] | DevOpsAI / ALDECI
```

---

## Template 3 — Cold Email v2 — Defense Prime CISO (150-word cap)

**Use for:** Lockheed Martin, Northrop Grumman, RTX I&S, GD Mission Systems, Booz Allen, Leidos, L3Harris.

```
Subject: ALDECI — air-gap CTEM your SCIF dev teams can run TODAY

Hi [First name],

Your engineers in [SCIF-resident program, e.g., "Skunk Works Fort Worth" or "Sentinel Cyber"] almost certainly run scans on a connected jump-box and sneakernet outputs into the SCIF — because no commercial CTEM works inside the fence.

ALDECI does. Self-hosted, zero outbound network, FIPS 140-3 boundary, on-prem vLLM inference, PKCS#11 HSM-backed audit chain, CycloneDX SBOM at install (Slide 5).

Two motions:
1. **Internal use** — deploy in your own cleared dev environments
2. **Customer-embed** — re-deploy unmodified in your customer's SCIF, under their ATO

Pilot bundle is signed, reproducible, with SSP draft + POA&M + NIST 800-53 control matrix ready for inheritance. ~20 working days from sign to install (Slide 8).

30-min discovery to see if it lands in [program]?

— [Sender] | DevOpsAI / ALDECI
```

---

## Template 4 — Cold Email v3 — Reseller Intro (150-word cap)

**Use for:** Carahsoft, Anchore Federal, GitHub Government, Second Front, Rebellion Defense, DLT, Immix.

```
Subject: ALDECI partnership — air-gap CTEM, federal SCIF-ready, no fed reseller yet

Hi [First name],

Quick intro — ALDECI is a self-hosted, AI-native CTEM platform built for SCIF-class deployments. We just shipped the SCIF Pilot Bundle: FIPS 140-3 mode, on-prem LLM inference, HSM-backed audit chain, CRYSTALS-Kyber/Dilithium inventory, signed reproducible build (Slide 5).

Three current motions where a fed channel partner accelerates everything:
1. P1 federal sponsors in motion (CISA, DIU, SOCOM, AFWERX, NGA) — each could hit a vehicle you already hold
2. Defense primes (LM, NG, RTX) for internal + customer-embed use
3. FFRDCs (MITRE NCF, APL, Sandia) as evaluators

Pilot SOW is one page; SSP/POA&M/NIST 800-53 matrix already written. 20-day install path post-sign (Slide 8).

Worth a 30-min call to see if there's a SEWP/GSA/CSO play here?

— [Sender] | DevOpsAI / ALDECI
```

---

## Send Hygiene

| Item | Rule |
|---|---|
| Send window | Tue–Thu, 7:30–9:30 AM recipient local time. Avoid Mon AM (inbox overload) and Fri PM (lost). |
| Follow-up cadence | Day +4 (gentle nudge, 50-word reply-on-thread), Day +11 (final, "closing the loop"). Never more than 3 touches without a response. |
| A/B subject lines | Run 50/50 on first 20 sends. Track open + reply rates in `.claude/team-state/sales/scif-outreach-log.json`. |
| Personalization marker | Every send must have one specific reference (program, paper, talk, RFI, public statement). If you can't find one in 5 minutes, drop the target. |
| Calendar link | Use a Calendly-style link ONLY in template 4 (resellers). Federal sponsors prefer "send 3 times that work." |
| Disclaimers | None. Do NOT add "confidential" or compliance footers — looks corporate-sales-y. |
| Attachments | Never on first touch. Send the SCIF Pilot Bundle README + pitch deck only after a "yes, send more." |

---

## Reply Triage Playbook

| Reply type | Response template (≤80 words) |
|---|---|
| **"Send more info"** | "Thanks [name] — attaching: (1) `ALDECI_PITCH_DECK_2026-04-26.md` (12 slides), (2) `SCIF_PILOT_BUNDLE_README.md` (the technical pilot doc), (3) `auditor_quick_reference_2026-04-26.md` (the 40-min ATO walk-through). Slide 7 is the honest readiness scorecard; Slide 8 is the 20-day pilot path. Happy to walk through any of these — what 3 times work next week?" |
| **"Not the right person — try X"** | "Thanks [name], much appreciated. Mind if I cite you when I reach out to [X]? — and would 5 min later in the quarter make sense to keep you in the loop?" |
| **"Interesting but no budget"** | "Totally understood. The pilot can run at $0 (pre-revenue design-partner posture) — we trade engineering hours for case-study rights and product feedback. Worth a 15-min chat on whether that model fits your authority?" |
| **"We already use [Snyk/Wiz/Veracode]"** | "We're not a replacement — we ingest [tool] outputs alongside our own scanners and add the SCIF-grade controls (air-gap, FIPS 140-3, HSM audit, PQC inventory) those tools don't ship. The pilot installs alongside, not instead-of." |
| **"How is this different from [competitor]?"** | "Three honest differentiators: (1) air-gap appliance with active outbound-blocking probe, (2) HSM-backed Merkle audit chain with HSM-signed checkpoints, (3) CRYSTALS-Kyber/Dilithium inventory aligned to CNSA 2.0 — none of which our peers ship today. Slide 4 has the scorecard. 30 min to walk through?" |
| **No response after 3 touches** | Mark target dormant in log; revisit at quarterly cadence. |

*End templates.*
