# ALdeci — 90-Day Go-To-Market Plan

**Period:** 2026-04-28 through 2026-07-26
**Starting state:** Design-partner stage, pre-revenue, $0 ARR
**End-state target:** 5 paid customers (≥2 federal SCIF) + Series A $8M closed
**Owner:** Marketing Head / VP Marketing
**Input artifacts:**
- `docs/competitive_validation_2026-04-26.md` — 149 caps × 7 competitors, 83% W/M
- `docs/sales/scif/target_list_2026-04-26.md` — 36 federal sponsors, 12 P1-Hot
- `docs/investor/INVESTOR_PACK_2026-04-26.md` — $8M Series A data room
- `docs/sales/demo_script_30min.md` — 30-min hero arc, 6 screens, NO MOCKS
- `docs/sales/poc_template.md` — 14-day POC SOW
- `docs/sales/analyst/mq_wave_submission_2026-04-26.md` — Forrester Wave RFI draft

---

## Phase 1 — Federal Blitz (Weeks 1–2: 2026-04-28 → 2026-05-08)

**Objective:** Book 8+ discovery calls with P1-Hot targets. Publish demo video. Seed LinkedIn presence.

### Week 1 (Apr 28 – May 2): Cold Outreach Blitz, Day 1

**Day 1 — Monday Apr 28: Email blast to all 12 P1-Hot targets**

Send personalized cold emails to every P1-Hot contact in `docs/sales/scif/target_list_2026-04-26.md`.
Prioritized send order (most time-sensitive acquisition signals first):

| Send order | Target | Title | Primary angle |
|---|---|---|---|
| 1 | CISA — JCDC | Branch Chief, VM Sub-Coordination Group | 20-day SCIF pilot inheriting SBOM/VEX feeds offline; CISA AI Roadmap CTEM alignment |
| 2 | DIU — Cyber Portfolio | Director, Cyber Portfolio | CSO-shaped pilot, OTA-ready, 20-day SOW pre-written |
| 3 | NSA — CCC | Technical Director, CCC | ML-DSA/FIPS 204 + CNSA 2.0 alignment — quantum-safe by default |
| 4 | DARPA — I2O | PM, AIxCC follow-on | AutoFix + LLM Council; same problem as AIxCC, production-ready + air-gap |
| 5 | SOCOM — SOFWERX | SOFWERX Cyber Lead | Operator-grade air-gap: day-1 SCIF install, day-20 demonstrable workflow |
| 6 | CDAO — AI Red Team | Director, AI Assurance | 703 DPO pairs = auditable AI provenance; pre-built for AI red-team review |
| 7 | AFWERX — Spark Cell | AFWERX Cyber Lead | SBIR Phase II direct candidate; pilot SOW maps to AF Form 1419 |
| 8 | NGA — Office of CIO | ISSM, GEOINT Services | Single-tenant SCIF SKU; existing ATO inheritance pattern works day 1 |
| 9 | NRO — GED | ISSM, Mission Ground Systems | Air-gap appliance under existing GED ATO; no internet plumbing |
| 10 | ARCYBER — CSDD | Chief Engineer, CSDD | PCTE-compatible CTEM tenant; training/operational SCIF ready |
| 11 | NavalX — Tech Bridges | Tech Bridge Director, Crane | NIWC/NSWC-deployable; FIPS-validated OpenSSL distribution |
| 12 | DCSA — NBIS | NBIS Cyber/IA Lead | Classification-level + clearance-attribute pass-through on Phase 2 roadmap |

**Email template structure** (personalize rows 1–3 per target):
```
Subject: 20-day air-gap CTEM pilot for [ORG] — [specific program hook]

[First name],

[1 sentence: their specific acquisition signal or program pain — cite the actual program name]

ALdeci is the only CTEM+ platform that runs fully air-gapped inside a SCIF on commodity
hardware (<1 GB/year storage), signs every decision into a FIPS 204 ML-DSA evidence bundle,
and ships with 8 native scanners so no external tools are required.

We've pre-written a 20-day pilot SOW with measurable success criteria. No procurement
gymnastics — OTA/CSO-compatible.

Specific to [ORG]: [1 sentence on their exact alignment from target_list, e.g. "CNSA 2.0
alignment for your vendor engagement program" for NSA CCC].

15-minute call this week or next?

[Name]
```

**Day 1 — Monday Apr 28: LinkedIn DMs to same 12 contacts**

Send connection request + note simultaneously with email. Note template (150 chars max):
```
[First name] — building air-gap CTEM+ for SCIF environments. Sent you an email.
Would value 15 min on [specific program]. — [Name]
```

**Day 4 — Thursday May 1: First follow-up (email)**

Subject: `Re: 20-day SCIF pilot — quick follow-up`
Body: one paragraph. Attach the 1-page `docs/sales/analyst/analyst_one_pager_2026-04-26.md` as PDF.
New hook: reference the competitive validation — "83% WIN-or-MATCH across 149 capabilities vs Snyk, Wiz, Tenable, XM Cyber, Apiiro, Sonatype, Aikido."

**Day 7 — Sunday May 4: Demo video published**

Publish the 5-minute YouTube/Loom demo (see `content_calendar_q2_2026.md` — Week 1 video).
Update all outreach templates to include the video URL.

**Day 7 — Sunday May 4: Second follow-up (LinkedIn)**

Short DM: "Published our 5-min demo — [URL] — min 2:30 is the MPTE exploit-verification step most relevant to [their program]. Happy to walk through it live."

**Day 12 — Friday May 9: Third follow-up (email)**

Final touch before moving to P2 cadence. Offer a 30-min live demo slot with specific calendar link.
Subject: `ALdeci — one more try before I stop bugging you`
Tone: direct, not apologetic.

### Week 2 (May 5–9): P2-Warm Outreach + Federal Primes

**Day 8 — Monday May 5: Email blast to 16 P2-Warm targets**

Same personalized template cadence. P2 targets include FFRDCs, defense labs, IC components listed in `target_list_2026-04-26.md` §2.

**Day 8 — Monday May 5: Begin defense primes outreach**

Target CISOs at Booz Allen, SAIC, Leidos, MITRE, Palantir Federal:

| Prime | Target title | Angle |
|---|---|---|
| Booz Allen Hamilton | VP Cyber, Federal Practice | "Referral reseller channel — your SCIF-cleared consultants deploy ALdeci as the assessment platform" |
| SAIC | CISO / VP Cybersecurity Solutions | "White-label or co-sell for DevSecOps modernization engagements" |
| Leidos | VP, Cyber & SIGINT | "Same air-gap constraint your teams face in classified programs" |
| MITRE | Principal, Cyber Operations | "MITRE ATT&CK alignment built in; 19-phase MPTE maps to ATT&CK TTP chain" |

**Day 9 – 12 (May 6–9): Discovery calls**

Target: 4+ calls booked from week-1 outreach. Run 30-min demo arc from `docs/sales/demo_script_30min.md`. Hero arc: Command → Brain (LLM Council vote live) → Compliance (ML-DSA evidence bundle).

**Metrics to track at end of Week 2:**
- Emails sent: 28 (12 P1 + 16 P2)
- Reply rate target: ≥25% (7+ replies)
- Discovery calls booked: ≥4
- Demo video views: ≥200
- LinkedIn connection accepts: ≥15

---

## Phase 2 — Mid-Market Discovery (Weeks 3–4: May 12–23)

**Objective:** Identify 10 logo-ready commercial prospects. Begin reseller channel activation.

### Week 3 (May 12–16)

**Monday May 12: Carahsoft onboarding initiated**

Submit ALdeci vendor application to Carahsoft Technology Corp (see `partner_channel_strategy.md`).
Carahsoft onboarding is 6 weeks — start immediately. Required artifacts:
- Company overview + GSA Schedule eligibility questionnaire
- Product datasheet (use `analyst_one_pager_2026-04-26.md` as base)
- FIPS 140-3 validation documentation
- Pricing sheet (use `pricing_architecture.md` public tiers)

**Monday May 12: Outbound to 10 commercial prospects**

Target profile: Series B+ SaaS / fintech / healthcare companies with 500–5,000 employees, known DevSecOps teams, Snyk or Wiz already in stack (they understand ASPM/CSPM; we're the consolidation story).

Sourcing: LinkedIn Sales Navigator filter — Title: CISO OR "VP Security" OR "Head of AppSec", Company size: 500–5,000, Industry: Fintech/Healthcare/SaaS, Technologies: Snyk OR Wiz.

| # | Company profile | Angle |
|---|---|---|
| 1–3 | Series C fintech (Plaid-tier) | "You're paying Snyk + Wiz + Tenable separately. ALdeci consolidates all three for less." |
| 4–6 | HIPAA-scope healthcare SaaS | "Compliance evidence on autopilot — SOC 2 + HIPAA proof bundle, signed with quantum-safe crypto" |
| 7–9 | Defense-adjacent SaaS (ITAR, CMMC) | "CMMC Level 2 coverage built in; air-gap option for CUI-scope systems" |
| 10 | Large fintech (Stripe/Brex-tier) | "Design partner slot — $0 + co-marketing, 90 days, your logo on our Series A deck" |

**Wednesday May 14 — Friday May 16: Discovery calls from weeks 1–2**

Run all booked federal discovery calls. Outcome goal per call: agree on 14-day POC terms using `docs/sales/poc_template.md`. POC success criteria must be quantifiable (e.g., "reduce critical backlog from 38 to ≤12 in 20 days").

### Week 4 (May 19–23)

**Follow-up cadence on all 28 P1+P2 federal contacts (Day 4 equivalent for P2 targets).**

**Mid-market discovery calls (target: 3+ commercial prospects).**

**Begin Forrester Wave RFI draft review** — `docs/sales/analyst/mq_wave_submission_2026-04-26.md` already drafted. Finalize and identify submission window.

**Metrics at end of Week 4:**
- Federal discovery calls completed: ≥6
- Federal POC agreements in discussion: ≥2
- Commercial discovery calls: ≥3
- Carahsoft application submitted: YES
- Design partner pipeline: ≥3 conversations in flight

---

## Phase 3 — Analyst Engagement (Weeks 5–6: May 26 – Jun 6)

**Objective:** Submit Forrester Wave RFI. Book Gartner pre-Q1 briefing. Get on analyst radar before Magic Quadrant research cycle opens.

### Week 5 (May 26–30)

**Monday May 26: Forrester Wave RFI submission**

Use `docs/sales/analyst/mq_wave_submission_2026-04-26.md` as the draft. Submission target: Forrester CTEM or Application Security Posture Management Wave (research cycle opens Q2 2026).

RFI sections to complete before submission:
- Company financials (use Series A metrics from INVESTOR_PACK)
- Customer references (design partners — confirm two will provide reference by this date)
- Product demo slot scheduling

**Tuesday May 27: Gartner briefing request submitted**

Target analyst: Patrick Hevesi (AppSec / ASPM coverage) or Neil MacDonald (CTEM).
Briefing request via Gartner Research Inquiry portal or direct analyst email.

Briefing deck structure (30 min):
1. Market problem (2 min) — alert sprawl, fragmented stacks
2. CTEM+ category definition (5 min) — how ALdeci extends Gartner's 5-step CTEM framework
3. 6 unique moats (10 min) — LLM Council, MPTE, FAIL Engine, quantum-safe evidence, MCP Gateway, 12-step Brain Pipeline
4. Competitive matrix (5 min) — cite `competitive_validation_2026-04-26.md`, 83% W/M
5. Federal wedge (5 min) — air-gap + SCIF readiness, why incumbents can't serve this
6. Ask (3 min) — Gartner Innovation Insight or CTEM Guidance mention

**Week 5: IDC and Omdia outreach**

Submit briefing requests to IDC (AppSec / DevSecOps coverage) and Omdia (CSPM / cloud security).

### Week 6 (Jun 2–6)

**Gartner briefing (if accepted) — run the deck above.**

**Forrester analyst briefing (independent of RFI) — request inquiry call.**

**CISA JCDC follow-up — check status of week-1 outreach. If no reply, escalate via CISA's public industry partnership form.**

**Metrics at end of Week 6:**
- Forrester RFI submitted: YES
- Gartner briefing requested: YES (accepted: bonus)
- Analyst conversations: ≥1
- Federal pipeline: ≥8 conversations in flight

---

## Phase 4 — First Design Partner Signatures (Weeks 7–8: Jun 9–20)

**Objective:** Convert 2 federal prospects to signed design-partner agreements. 1 commercial design partner signed.

### Week 7 (Jun 9–13)

**Design partner agreement execution**

Target: CISA JCDC and DIU Cyber Portfolio (highest conversion probability from P1 list).

Design partner terms (from `pricing_architecture.md`):
- $0 license for 90 days
- Co-marketing rights (logo, case study, joint press release)
- Weekly feedback sessions (1 hour)
- ALdeci provides dedicated onboarding engineer for first 30 days
- Customer provides: access to 1 non-production SCIF environment, 2 named contacts (ISSO + technical lead), written feedback at 30/60/90 days

Legal: use the pre-written POC agreement in `docs/sales/poc_template.md` as base. Add co-marketing rider.

**Commercial design partner #1 signed**

Target: the Series C fintech or HIPAA-scope healthcare company most advanced in discovery (weeks 3–4 pipeline). Same $0 + co-marketing terms.

### Week 8 (Jun 16–20)

**Onboarding design partners**

Follow `docs/sales/customer_onboarding_playbook.md`. Week-1 milestones:
- Day 1: tenant provisioned, API key delivered, 1 scanner connected
- Day 3: first findings ingested, Brain Pipeline running
- Day 7: first dashboard review call

**First demo video (federal variant) published** — see `content_calendar_q2_2026.md`.

**Investor pipeline: begin Series A LP outreach**

Use `docs/investor/INVESTOR_PACK_2026-04-26.md` data room. Target tier-1 investors with federal/defense portfolio:
- In-Q-Tel (CIA venture arm — direct fit; SCIF-capable portfolio companies)
- Paladin Capital (defense tech focus)
- Shield Capital (DoD tech)
- Two general-purpose tier-1s (a16z Growth, Bessemer) for validation / co-lead

First LP outreach: warm intro preferred. Cold email if no warm path.

**Metrics at end of Week 8:**
- Design partners signed: ≥3 (2 federal + 1 commercial)
- Onboarding started: ≥2
- Investor deck sent: ≥5 VCs
- Investor calls booked: ≥2

---

## Phase 5 — Mid-Market POCs in Flight (Weeks 9–10: Jun 23 – Jul 4)

**Objective:** 3 commercial POCs running simultaneously. Reseller pipeline confirmed. First federal pilot midpoint review.

### Week 9 (Jun 23–27)

**3 commercial POCs active**

Convert 3 commercial prospects from weeks 3–4 pipeline to 14-day paid POCs.
POC pricing: $0 for design partners; $2,500 for non-design-partner POC (proof of commitment, fully credited toward subscription).

Success metrics per POC (from `docs/sales/poc_template.md`):
- Findings ingested from existing tools (Snyk, Wiz output) within 48h
- Brain Pipeline producing prioritized backlog within 72h
- At least 1 critical finding verified by MPTE within 5 days
- Compliance report generated (SOC 2 or HIPAA) within 7 days

**Carahsoft onboarding complete** (started Week 3 — 6-week process concludes)
ALdeci listed on Carahsoft's federal catalog. First co-marketing email to Carahsoft's federal buyer list.

**Reseller pipeline: Anchore Federal + GitHub Government**

Initiate co-sell conversations:
- Anchore Federal: ALdeci as the CTEM orchestration layer on top of Anchore's SBOM engine
- GitHub Government: ALdeci as the AppSec decision layer for GitHub Advanced Security customers in .gov

### Week 10 (Jun 30 – Jul 4)

**Design partner midpoint reviews (Day 30 check-ins)**

For all signed design partners — run the 30-day review call. Capture:
- Quantified findings reduction (target: critical backlog reduced ≥50%)
- Time-to-triage improvement (target: ≥70% reduction vs manual)
- Any POA&M gaps identified

This data feeds the Series A close deck in weeks 11–13.

**Investor pipeline: second-round calls**

VCs who received the deck in week 8 should have reviewed it. Push for partner meetings (Series A is partner-level decision at most funds).

**Metrics at end of Week 10:**
- Commercial POCs active: ≥3
- Carahsoft listing: LIVE
- Federal design partner 30-day reviews: ≥2 completed
- Investor partner meetings: ≥2 scheduled
- ARR pipeline (LOI-stage): ≥$100K

---

## Phase 6 — Series A Close + First Paid LOI (Weeks 11–13: Jul 7–26)

**Objective:** Series A term sheet signed. First paid customer LOI (federal or commercial). 5 customers in pipeline at some deal stage.

### Week 11 (Jul 7–11)

**Series A: partner meetings at target funds**

Present the full 45-min investor narrative. Key proof points by this date:
- 3 signed design partners (≥2 federal)
- 30-day metrics from design partners (critical backlog reduction %)
- 703 DPO pairs → LLM self-improvement loop live
- Carahsoft on authorized vendor list (federal distribution channel de-risked)
- Forrester RFI submitted (analyst awareness established)

**Commercial POC Day 14 reviews**

Convert POC completions to paid LOIs. Target: 2 of 3 POCs convert.
First paid deal: $199/mo Starter or $499/mo Pro depending on org size.

### Week 12 (Jul 14–18)

**Series A: term sheet negotiation**

Target lead investor: In-Q-Tel or Paladin Capital (federal focus = strategic fit).
Target close: $8M, 18-month runway, primary milestones: FedRAMP High In Process + 5 paid SCIF customers.

**Federal design partner → paid conversion**

Design partner 90-day window ends ~Sep. Begin conversion conversation at Day 45 (around Week 12).
Federal pricing: see `pricing_architecture.md` — GSA Schedule pricing or OTA direct.

**Press release drafted: "ALdeci Closes $8M Series A"**

Draft now; publish on close. Distribution: Business Wire + PR Newswire federal tech vertical + direct to analyst contacts at Gartner/Forrester.

### Week 13 (Jul 21–26)

**Series A close (wire)**

**First paid customer LOI signed**

**5-customer pipeline state at Day 90:**

| Customer | Type | Stage | Target ARR |
|---|---|---|---|
| Federal Partner 1 (CISA or DIU) | Federal / SCIF | Design partner → paid | $180K/yr (Enterprise) |
| Federal Partner 2 (NSA or SOCOM) | Federal / SCIF | Design partner → paid | $180K/yr (Enterprise) |
| Commercial 1 (Series C fintech) | Commercial | POC → paid | $60K/yr (Pro) |
| Commercial 2 (Healthcare SaaS) | Commercial | POC → paid | $60K/yr (Pro) |
| Commercial 3 (Defense-adjacent SaaS) | Commercial | Discovery → POC | $60K/yr (Pro) |

**Total ARR pipeline at Day 90:** ~$540K (if 5 convert); **First confirmed ARR (LOI):** ≥$60K.

---

## Conference & Event Calendar (Weeks 1–13)

| Event | Date | Action | Priority |
|---|---|---|---|
| **BlackHat USA 2026** | Aug 2–7 Las Vegas | Submit speaking proposal (CFP deadline ~Mar 2026 — MISSED; target 2027). Book 10x10 booth ($15K). Demo pod. | HIGH — book now |
| **AFCEA TechNet Cyber** | Jun 17–19 Baltimore | Exhibit + speaking submission. Federal buyer density is highest here for CTEM. | HIGH |
| **DEF CON 34 — Aerospace Village** | Aug 8–11 Las Vegas | Submit talk: "19-Phase MPTE: How We Prove Exploitability in Air-Gapped Classified Environments." No cost to present. | MEDIUM |
| **RSA Conference 2027** | Apr 2027 | Begin sponsorship pitch for Innovation Sandbox (pre-revenue companies eligible). Apply in Q4 2026. | FUTURE — log now |
| **SOFWERX Tech Tuesday** | Monthly | Apply for virtual demo slot. Low friction, direct SOCOM access. | HIGH |
| **CISA ICS/OT Summit** | Oct 2026 | Submit for 2026 agenda. Pipeline builder for civilian federal. | MEDIUM |

---

## Weekly Rhythm (All 13 Weeks)

| Day | Standing action |
|---|---|
| Monday | Review pipeline CRM (HubSpot or Notion). Log all status changes. |
| Tuesday | Outreach batch (new prospects OR follow-ups per sequence). |
| Wednesday | Content publish (per `content_calendar_q2_2026.md`). |
| Thursday | Demo / discovery calls (batch same day). |
| Friday | Metrics review. Investor/analyst follow-ups. Week-ahead prep. |

---

## North-Star Metrics (Track Weekly)

| Metric | Week 2 target | Week 6 target | Week 13 target |
|---|---|---|---|
| Emails sent | 28 | 80 | 200 |
| Discovery calls completed | 4 | 15 | 40 |
| Design partners signed | 0 | 2 | 5 |
| POCs active | 0 | 1 | 3 |
| Analyst briefings | 0 | 2 | 4 |
| Investor deck sent | 0 | 5 | 20 |
| Investor partner meetings | 0 | 1 | 8 |
| Confirmed ARR (LOI) | $0 | $0 | ≥$60K |
| Series A status | Not started | Data room open | Term sheet signed |
