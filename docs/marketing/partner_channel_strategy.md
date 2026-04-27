# ALdeci Partner Channel Strategy

**Date:** 2026-04-26
**Owner:** Marketing Head / VP Marketing
**Horizon:** 90 days (through 2026-07-26) with 12-month buildout
**Starting state:** No reseller agreements signed, no channel pipeline
**End-state target:** Carahsoft listing live, 2 SI referral agreements signed, 1 technology co-sell active

---

## Strategic Premise

ALdeci's route-to-market has two parallel lanes:
1. **Direct** — founder-led outbound to CISOs and ISSOs (covered in `90day_gtm_plan.md`)
2. **Channel** — leverage existing federal distribution (Carahsoft) and SI delivery capacity (Booz Allen, SAIC) to reach buyers we cannot cold-email directly

The channel is not a replacement for direct. It is a force multiplier for the federal wedge specifically. Commercial channel (Snyk/GitHub resellers) is a 6–12 month build; do not invest in it before Series A closes.

---

## Tier 1 — Carahsoft Technology Corp (Federal Distribution)

**Role:** Master reseller for federal IT. Carahsoft holds GSA Schedule vehicles (IT 70, Schedule 70) and contracts (NASA SEWP, NIH CIO-CS, ITES-SW2) that government agencies use for procurement. Being on Carahsoft's catalog removes procurement friction from every federal deal.

**Why Carahsoft first:**
- Every serious federal software vendor runs through Carahsoft or Immixgroup. Carahsoft's federal buyer list includes procurement officers at every agency on our `target_list_2026-04-26.md`.
- Federal buyers can't easily sole-source an unknown vendor. Carahsoft's contract vehicles give them a clean procurement path.
- Carahsoft actively markets its portfolio to agency buyers — co-marketing emails, webinars, presence at AFCEA/ACT-IAC events.

**Onboarding timeline:** 6 weeks (submit Week 3, live Week 9)

**Required to apply:**
- Company overview and product description (1 page)
- GSA Schedule eligibility: SAM.gov registration (obtain CAGE code + DUNS/UEI if not already registered)
- Pricing sheet — public list prices in USD, matching `pricing_architecture.md` federal tier
- Product datasheet: technical spec, FIPS 140-3/204 callouts, air-gap capability statement
- Compliance documentation: FIPS validation certs, FedRAMP In Process acknowledgment (if applicable)
- References: at least 1 federal agency pilot reference (design partner from weeks 7–8 can serve as reference)

**Contact protocol:**
- Primary: Carahsoft Federal Cyber/DevSecOps team
- Entry point: `federalcyber@carahsoft.com` or via their vendor portal at carahsoft.com/vendors
- Reference competitors on their roster: Snyk (they distribute Snyk Federal), Lacework, Prisma Cloud — we sit adjacent

**Compensation model:**
- Standard Carahsoft reseller margin: 10–18% off list price for federal deals they source
- For deals we source and Carahsoft simply processes (using their contract vehicle): 5–8% fee
- No exclusivity — Carahsoft is non-exclusive by default

**MDF (Market Development Funds) ask:**
- Year 1: Request $15K MDF for joint federal webinar (target: 100 ISSO/ISSM attendees) + AFCEA TechNet Cyber booth co-presence
- Year 2 (post-Series A, post-FedRAMP IP): Request $50K for federal demand-gen campaign

**Joint webinar plan:**
- Carahsoft hosts a federal CTEM/ASPM webinar under their brand
- ALdeci presents 20-minute product demo (federal variant from `content_calendar_q2_2026.md` Week 7)
- Carahsoft promotes to their existing federal agency buyer list (typically 500–2,000 registrants for cyber topics)
- Timing: 8 weeks after listing is live (Week 17 of plan)

**Week-by-week milestones:**
| Week | Action |
|---|---|
| Week 3 | Submit vendor application, initiate SAM.gov registration if not already done |
| Week 4 | Carahsoft intake call — present product, pricing, federal use case |
| Week 5–7 | Contract and paperwork (standard Carahsoft VAR agreement) |
| Week 8 | Pricing and catalog entry review |
| Week 9 | Catalog listing LIVE |
| Week 10 | First co-marketing email to Carahsoft federal buyer list |
| Week 13 | Propose joint webinar date (post-Series A for credibility) |

---

## Tier 2A — Anchore Federal (Technology Co-Sell)

**Role:** Container and SBOM security for federal markets. Anchore Enterprise is deployed in classified environments; their customers have the exact air-gap constraint we address.

**Co-sell thesis:**
Anchore handles SBOM generation and container provenance. ALdeci handles CTEM orchestration, exploit verification, and compliance evidence. Neither replaces the other — they compose cleanly:
- Anchore generates the SBOM → ALdeci ingests it via `suite-core/core/scanner_parsers.py` (CycloneDX/SPDX parsers already built) → Brain Pipeline prioritizes findings → MPTE verifies exploitability → Evidence bundle signed.
- Joint pitch: "Anchore proves what's in your container. ALdeci proves what's exploitable and fixes it."

**Contact protocol:**
- Target: Anchore Federal VP of Sales or Federal Partnerships lead
- Entry: LinkedIn cold outreach or warm intro via SCIF community (DIU, NavalX, AFWERX contacts overlap)
- Reference: Anchore is already on Carahsoft — Carahsoft can make the introduction once we're listed

**Compensation model:**
- Referral fee: 15% of first-year ACV for deals Anchore sources to ALdeci
- Reciprocal: ALdeci pays same rate for Anchore deals we source
- Technology integration: free mutual integration, listed on both partner pages

**Timeline:** Begin outreach Week 5. Goal: signed referral agreement by Week 10.

---

## Tier 2B — GitHub Government (Technology Co-Sell)

**Role:** GitHub Advanced Security (GHAS) is the default AppSec tooling for .gov and .mil developers. GHAS produces CodeQL SARIF output. ALdeci ingests SARIF natively (scanner parser already built in `suite-core/core/scanner_parsers.py`).

**Co-sell thesis:**
GHAS detects. ALdeci decides, verifies, and remediates. Customer already paying for GHAS; ALdeci adds the AI decision layer on top — no rip-and-replace.
- Joint pitch: "You have GHAS for detection. ALdeci turns GHAS output into a prioritized, verified, remediated backlog with a compliance evidence bundle. Same findings, 90% less triage work."

**Contact protocol:**
- Target: GitHub Government Partner Manager (Microsoft Federal structure)
- Entry: GitHub Partner Network application + direct outreach to GitHub .gov/mil sales team
- Reference point: GitHub and Carahsoft have an existing relationship — cross-reference

**Compensation model:**
- Technology partnership (no reseller margin) — mutual listing on GitHub Marketplace and ALdeci integrations page
- Referral: GitHub sales reps refer GHAS customers who ask "what do I do with all these findings" — ALdeci pays 10% referral on closed ARR

**Timeline:** Begin outreach Week 6. Goal: GitHub Marketplace listing application submitted by Week 12.

---

## Tier 2C — Snyk Federal (Technology Co-Sell / Competitor-Adjacent)

**Strategic nuance:** Snyk is a competitor in ASPM but a feeder for ALdeci in the CTEM layer. Many federal customers have Snyk licenses they cannot cancel (3-year ELAs). They need ALdeci on top of Snyk, not instead of it.

**Co-sell thesis:**
"ALdeci is the brain that sits above your Snyk instance. Snyk detects in code; ALdeci verifies in runtime, correlates across your cloud posture, and generates the compliance evidence Snyk cannot."
- Technical proof: `suite-core/core/scanner_parsers.py` ingests Snyk JSON output natively — Day 1 value with zero Snyk configuration change.

**Contact protocol:**
- This is a sensitive conversation. Do not approach Snyk corporate BD — they will block.
- Target: Snyk Federal SE team individually. Federal SEs are often frustrated that Snyk can't serve the SCIF/air-gap use case; they will refer customers rather than lose the deal.
- Entry: Individual LinkedIn outreach to Snyk Federal SEs: "We ingest your output natively, run in SCIFs they can't access, and we are not competing for your license renewal. Let's co-sell."

**Compensation:** Referral fee 15% to individual Snyk SEs where their company allows it, or channel through Carahsoft jointly.

**Timeline:** Begin individual outreach Week 8 (after Carahsoft listing established — we need credibility first).

---

## Tier 3 — SI Partners (System Integrators — Referral Fee Model)

SI partners do not resell software. They embed ALdeci in their professional services engagements — assessments, ATO packages, DevSecOps modernization programs. The SI gets paid for the services; ALdeci gets a license referral fee.

### Booz Allen Hamilton

**Why:** Booz Allen has the largest federal cyber practice in the US. Their DarkLabs team does advanced threat research. Their DevSecOps modernization engagements at DoD and IC agencies are exactly the context where ALdeci gets deployed.

**Angle:** "ALdeci as the assessment platform for your DevSecOps engagements. Your cleared consultants run the platform; the client buys the license. You get the referral fee and a better deliverable."

**Contact protocol:**
- Target: VP, Cyber Innovation Practice OR Principal, DarkLabs
- Entry: Warm intro preferred (DIU/DARPA/CDAO contacts often know BAH leadership). Cold: LinkedIn + reference a specific BAH case study where CTEM was the gap.
- Key proof point: BAH clients frequently have CMMC, FedRAMP, and NIST SP 800-53 requirements — ALdeci addresses all three with automated evidence.

**Compensation model:**
- Referral fee: 12% of first-year ACV for licenses BAH's engagement sources
- Joint deliverable: BAH can white-label ALdeci's compliance report output as part of their ATO package (requires agreement)
- No MDF — BAH has its own marketing budget

### SAIC

**Why:** SAIC's cyber division runs managed security services for DoD and IC. They have long-term program contracts where they need CTEM tooling. An embedded ALdeci deployment is a program deliverable, not a standalone license.

**Angle:** "Embed ALdeci in your managed security service as the CTEM engine. Your SOC team uses our platform; the program pays the license as an ODC (other direct cost)."

**Contact protocol:**
- Target: VP Cybersecurity Solutions or Director, Managed Security Services
- Entry: AFCEA events (SAIC is a perennial sponsor — meet in person at AFCEA TechNet Cyber Jun 17–19)

**Compensation model:**
- OEM/embedded: SAIC pays ALdeci a per-program fee (negotiated per engagement, typically $X/seat/year at volume discount)
- Referral alternative: 12% of first-year ACV for deals they source

### Mandiant Federal (Google Cloud)

**Why:** Mandiant Federal does incident response and red team assessments for federal agencies. Post-incident, they recommend tooling. ALdeci's MPTE + FAIL Engine directly addresses the gaps Mandiant finds in IR engagements.

**Angle:** "After Mandiant finds the gaps in an IR engagement, ALdeci continuously monitors them. Recommend ALdeci as the tool your clients deploy to prevent the next incident."

**Contact protocol:**
- Target: Mandiant Federal VP or Practice Lead, Threat Intelligence
- Entry: Post-Series A, Google Cloud partner program (Mandiant is Google Cloud) — apply for Google Cloud ISV partner status; Mandiant Federal is accessible through that channel.

**Compensation model:** Referral fee 12%. No volume commitment required — pure referral relationship.

**Timeline:** Begin SI outreach at AFCEA TechNet Cyber (Jun 17–19). Goal: verbal referral agreement with 1 SI by Week 13.

---

## Channel Readiness Checklist

Before activating any channel partner, ALdeci must have:

| Requirement | Status | Owner | Target date |
|---|---|---|---|
| SAM.gov registration (CAGE + UEI) | PENDING | Founder | Week 3 |
| GSA Schedule pricing documentation | PENDING | Marketing Head | Week 3 |
| Partner one-pager (co-branded template) | PENDING | Marketing Head | Week 3 |
| Integration documentation (API, SARIF/CycloneDX ingest) | EXISTS | Engineering | Ongoing |
| Partner portal / deal registration system | PENDING | Founder | Week 6 (Carahsoft requires this) |
| Referral agreement template (legal) | PENDING | Legal / Founder | Week 4 |
| Co-marketing asset library | PENDING | Marketing Head | Week 4 |
| Channel manager contact (internal) | Founder (initially) | — | Now |

---

## 12-Month Channel Revenue Forecast

| Partner | Deal type | Expected deals (12 mo) | Avg ACV | Expected ARR contribution |
|---|---|---|---|---|
| Carahsoft (direct federal) | Reseller | 3 | $80K | $240K |
| Carahsoft (ALdeci-sourced, processed) | Admin fee | 5 | $80K | $400K ($32K fee income) |
| Anchore Federal | Referral | 2 | $60K | $120K |
| GitHub Government | Referral | 3 | $40K | $120K |
| Booz Allen / SAIC / Mandiant | Referral | 2 | $120K | $240K |
| **Total channel ARR** | | | | **~$720K (conservative)** |

Note: These are design-partner-stage projections. They are not ARR commitments. Actual conversion will depend on Carahsoft listing timing and Series A close credibility signal.
