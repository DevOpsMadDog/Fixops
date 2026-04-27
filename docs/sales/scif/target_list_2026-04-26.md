# SCIF Pilot Target List — Federal Sponsor Motion

**Date:** 2026-04-26
**Branch:** `features/intermediate-stage`
**Author:** sales-engineer
**Owning artefact:** `docs/scif/SCIF_PILOT_BUNDLE_README.md` (the thing we're trying to land)
**Companion docs:** `docs/pitch/ALDECI_PITCH_DECK_2026-04-26.md` (Slide 8 = 20-day pilot path), `docs/scif_readiness_2026-04-26.md` (honest scorecard), `docs/scif/SSP_aldeci_2026-04-26.md` (SSP draft for inheritance), `docs/scif/auditor_quick_reference_2026-04-26.md` (40-min ATO walk-through)

---

## 0. How To Read This List

| Priority | Definition | Outreach posture |
|---|---|---|
| **P1 — Hot (12)** | Active CTEM/ASPM RFI/RFQ in last 12 months OR known SBIR/CSO topic alignment OR known air-gap pain. Send within 48h. | Personalized cold email + LinkedIn DM, cite Slide 8 (20-day pilot) and Slide 7 (SCIF scorecard). Aim: 30-min discovery within 10 days. |
| **P2 — Warm (16)** | Mission fit + budget cycle but no active acquisition signal. Send week 2. | Same templates, lighter personalization, cite POA&M to show transparency. |
| **P3 — Cold (8)** | Strategic for 12-month horizon (FedRAMP PMO sponsor candidates, IL6 partners). Nurture, not chase. | LinkedIn-only first touch; warm intro preferred. |

**Title taxonomy** (use the right one — addressing AOs as CISOs is a known disqualifier):

- **AO** — Authorizing Official (signs the ATO; usually 2-star or SES)
- **ISSO** — Information System Security Officer (operates the controls daily — the actual day-to-day buyer for our pilot)
- **ISSM** — Information System Security Manager (the ISSO's boss; multi-system view)
- **CISO/CSO** — agency-level; sets policy, not pilots
- **CTO/CIO** — agency-level; budget owner
- **Innovation Cell head** — DIU/AFWERX/SOFWERX/NavalX; runs CSO/SBIR fast-track
- **PEO/PM** — Program Executive Office / Program Manager; owns mission systems and discretionary modernization $$
- **CDAO** — Chief Digital and AI Officer (DoD); owns AI/ML controls and AI red-team programs

---

## 1. P1 — HOT (12) — Send within 48 hours

### Federal Civilian / IC

| # | Org | Why-fit (acquisition signal + program) | Title to target | Angle (≤1 sentence) |
|---:|---|---|---|---|
| 1 | **CISA — JCDC / Cyber Innovation** | JCDC SBOM + vulnerability transparency push 2025; CISA AI Roadmap Apr 2025 names CTEM as a priority | Branch Chief, Vulnerability Management Sub-Coordination Group; Senior Advisor, JCDC | "20-day SCIF pilot of an air-gap CTEM with FIPS 140-3 + ML-DSA evidence signing — built to inherit your SBOM/VEX feeds offline" (Slide 8) |
| 2 | **NSA — Cybersecurity Directorate (CCC)** | NSA Cybersecurity Collaboration Center actively partners with vendors on CNSA 2.0 implementations; published CNSA 2.0 roadmap | Technical Director, CCC; Chief of Vendor Engagement | "Quantum-safe by default — ML-KEM/ML-DSA/SLH-DSA inventory shipped today, FIPS 203/204/205 alignment for CNSA 2.0" (Slide 7 row 8) |
| 3 | **DARPA — I2O (Information Innovation Office)** | DARPA AIxCC just wrapped (Aug 2024); follow-on programs need autonomous patching benches | Program Manager, AI Cyber Challenge; PM, AIxCC follow-on | "AutoFix engine + LLM Council — same problem space as AIxCC, but production-ready and air-gap shippable" |
| 4 | **NGA — Office of the CIO (Springfield)** | GEOINT mission system modernization 2024–2026; Cardillo's Ozone arch refresh; SCIF-native by default | ISSM, GEOINT Services; Deputy CIO | "Single-tenant SCIF SKU + classification-level model on roadmap — your existing ATO inheritance pattern works on day one" |
| 5 | **NRO — Ground Enterprise Directorate (GED)** | GED actively buys commercial CTEM/CDR for ground systems; cleared-vendor friendly | Chief Engineer, GED; ISSM, Mission Ground Systems | "Air-gap appliance under your existing GED ATO, no internet plumbing required" (Slide 5) |

### DoD

| # | Org | Why-fit | Title to target | Angle |
|---:|---|---|---|---|
| 6 | **DIU — Cyber Portfolio (Mountain View / DC)** | DIU Cyber portfolio runs CSO (Commercial Solutions Opening) — fastest-path federal $; CTEM/ASPM is an active 2025 area | Director, Cyber Portfolio; Project Manager, Cyber | "CSO-shaped 20-day pilot, OTA-friendly, deliverables and success criteria pre-written" (cite pilot SOW template) |
| 7 | **AFWERX — Spark Cell (Wright-Patt)** | SBIR Phase II open topics for cyber resilience + air-gap operations; AFRL 711HPW SCIF pilots | Spark Cell Director, AFLCMC; AFWERX Cyber Lead | "SBIR Phase II direct-to-Phase-II candidate — pilot SOW maps to AF Form 1419 cleanly" |
| 8 | **SOCOM — SOFWERX (Tampa)** | SOFWERX runs rapid 30/60/90-day pilots; SOCOM SO/LIC mission systems are SCIF-bound | SOFWERX Cyber Lead; J6 SOCOM (Cyber) | "Operator-grade air-gap: install in your SCIF on day 1, demonstrable workflow by day 20" |
| 9 | **ARCYBER — Cyber Solutions Development Detachment (Augusta)** | CSDD/2nd Army owns persistent-cyber-training and operates Persistent Cyber Training Environment (PCTE) air-gap | Chief Engineer, CSDD; Technical Director, ARCYBER G-3/5/7 | "PCTE-compatible — air-gap CTEM as a tenant in your training/operational SCIFs" |
| 10 | **NavalX — Tech Bridges (DC, Crane, San Diego)** | NavalX Tech Bridges run CSO + SBIR; NIWC Atlantic and NSWC Crane both have SCIF programs | Tech Bridge Director (Crane preferred); NIWC Atlantic Cyber PM | "NIWC- and NSWC-deployable air-gap appliance with FIPS-validated OpenSSL distribution" |
| 11 | **CDAO — AI Red Team (Pentagon)** | CDAO chartered AI red-team capability 2024; needs auditable AI-decision provenance | Director, AI Assurance; CDAO AI Red Team Lead | "Council-DPO loop = auditable AI decision trail for every finding — pre-built provenance for AI red-team review" (Slide 6) |
| 12 | **DCSA — NBIS Program** | National Background Investigation Services (NBIS) is the IC personnel-security replacement; classification-level data model directly aligned | NBIS Cyber/IA Lead; DCSA CIO | "Classification-level + clearance-attribute pass-through is on Phase 2 roadmap (POA-004) — pilot lets us co-design the model around NBIS schema" |

---

## 2. P2 — WARM (16) — Send week 2

### FFRDCs (no procurement, but they sponsor + influence)

| # | Org | Why-fit | Title to target | Angle |
|---:|---|---|---|---|
| 13 | **MITRE — National Cybersecurity FFRDC (NCF) (McLean)** | NCF sponsors CTEM-adjacent research (D3FEND, ATT&CK) and runs NIST evaluation infrastructure | Director, NCF; Principal, ATT&CK Evaluations | "Evaluator-friendly: every finding ships with ATT&CK technique mapping + DPO consensus trail" |
| 14 | **CMU SEI / CERT Coordination Center** | CERT/CC runs vulnerability disclosure and SBOM research; long-running DoD relationship | CERT/CC Technical Manager; SEI CSED Director | "Vulnerability + SBOM correlation with offline KEV/EPSS mirror — co-evaluation candidate" |
| 15 | **APL — Johns Hopkins (Laurel)** | APL builds cyber tooling for IC and DoD mission systems; cleared engineers | Cyber Resilience Group Supervisor, APL | "Air-gap CTEM as a building block in mission-system ATOs — APL is exactly the right integrator" |
| 16 | **Sandia National Labs — Cyber Resiliency Center** | Sandia runs critical-infrastructure ICS/OT cyber programs in air-gap | Cyber Resiliency Center Manager | "OT/ICS air-gap with no telemetry kill-switch — fits your test ranges" |
| 17 | **MIT Lincoln Labs — Cyber Operations and Analysis** | LL Cyber Ops builds DoD evaluation and adversary emulation; SCIF-native | Group Leader, Cyber Operations and Analysis | "Adversary-emulation-friendly: MPTE engine + AutoFix in a closed-loop bench" |

### Defense Primes (cleared CISO orgs — they buy for their own corp networks AND embed in customer programs)

| # | Org | Why-fit | Title to target | Angle |
|---:|---|---|---|---|
| 18 | **Lockheed Martin — Skunk Works / Aero (Fort Worth + Palmdale)** | Cleared mission-system development; SCIF-resident dev environments | VP, Cyber & Intelligence Systems; CISO, LM Aeronautics | "Air-gap CTEM for your SCIF-resident dev environments — your engineers stop sneakernet'ing scan results" |
| 19 | **Northrop Grumman — Mission Systems Sector** | Owns cyber for ICBM modernization (Sentinel) + mission systems; SCIF-heavy | CISO, Mission Systems; Sector CTO | "FIPS 140-3 + PQC inventory ready today — same controls you owe Sentinel program" |
| 20 | **Raytheon (RTX) — Intelligence & Space** | Cleared programs need internal CTEM that operates inside SCIF customer fences | CISO, RTX I&S; Director, Mission Cyber | "Customer-deployable — pilot inside your fence, then re-deploy in your customer's SCIF unmodified" |
| 21 | **General Dynamics — Mission Systems (Fairfax + Scottsdale)** | GDMS runs IL5/IL6 enclaves; cleared CISO buyer | CISO, GDMS; PM, Cleared IT Programs | "Single-tenant SCIF SKU = no multi-tenant blast-radius questions in your IL6 enclave" |
| 22 | **Booz Allen Hamilton — Defense / Cyber** | BAH integrates a lot in SCIFs; could be channel partner OR buyer | Senior VP, Cyber; Director, Federal Markets | "Channel + use: deploy in BAH's own clearances, then resell as part of your CTEM offering" |
| 23 | **Leidos — Defense Group (Reston)** | Cleared engineering services + mission systems; large CTEM gap | VP, Cyber Solutions; CTO, Defense Group | "OT/IT converged air-gap CTEM — fits your DoE + DoD mix" |
| 24 | **L3Harris — Communication Systems / SAS** | SAS division builds SCIF-resident comms; tight ATO inheritance constraints | CISO, SAS; Director, Cyber Engineering | "ATO inheritance designed-in — SSP draft is ready (`docs/scif/SSP_aldeci_2026-04-26.md`)" |

### IC / Civ Mission Owners (specific PEOs)

| # | Org | Why-fit | Title to target | Angle |
|---:|---|---|---|---|
| 25 | **Army PEO IEW&S — Cyber Portfolio** | Intelligence Electronic Warfare & Sensors; runs SCIF-resident PMs | PM, Cyber; PEO IEW&S Chief Engineer | "SCIF-resident, no telemetry, no internet — drops into your PM-owned ATO" |
| 26 | **Navy PEO Digital — Information Warfare** | Owns Navy's ASPM/CTEM modernization; recent CSO awards in space | PM, Information Warfare; Chief Digital Officer, PEO Digital | "Replaces 5-tool stack with one offline appliance — fits your CSO acquisition path" |
| 27 | **Air Force LCMC — Strategic Systems / Sentinel** | Sentinel program is the largest USAF cyber-enabled modernization | CIO, Sentinel; Cyber PM, AFLCMC Strategic Systems | "Quantum-safe-by-default = future-proof for Sentinel's 50-year operational life" |
| 28 | **DoE — NNSA / Y-12 + Pantex** | Nuclear security air-gap is the gold standard; DoE-NA/CIO buys cyber tooling | DoE NNSA CIO; Y-12 Cyber Operations Lead | "True air-gap, FIPS, HSM-backed audit chain — exactly what NNSA M&O contractors need" |

---

## 3. P3 — COLD (8) — 12-month nurture (FedRAMP/IL6 sponsorship horizon)

| # | Org | Why-fit | Title to target | Angle |
|---:|---|---|---|---|
| 29 | **GSA — FedRAMP PMO** | The PMO sponsor needed for FedRAMP High In-Process | Director, FedRAMP PMO; Authorization Branch Chief | LinkedIn-only first touch; will be relevant once a federal customer co-sponsors |
| 30 | **DISA — Mission Owners / Cloud Computing PMO** | DoD IL5/IL6 PA sponsor | Cloud Computing PMO Director; Mission Owner Liaison | Wait until P1 customer signs — DISA reacts to demand, not pitches |
| 31 | **NSA — Trusted Engineering Solutions Office (TESO)** | Cleared-product evaluation channel | TESO Director | Warm intro only; via a cleared-prime referral |
| 32 | **State Department — Diplomatic Security / IRM Cyber** | SCIF-resident, post-network-isolated, classification-level model fits | DS/CTI Director; IRM Cyber Director | LinkedIn nurture |
| 33 | **Treasury — OCCIP (Office of Cybersecurity)** | Critical financial infrastructure, partial SCIF posture | OCCIP Director | Email + LinkedIn |
| 34 | **DHS S&T — Cyber Security Division** | SBIR-friendly, but timeline is slow | CSD Program Manager | SBIR-only path |
| 35 | **OUSD(R&E) — Defense Innovation Marketplace** | Strategic visibility for DoD-wide modernization | DIM lead, OUSD(R&E) | LinkedIn nurture; via DIU referral |
| 36 | **DoT — FAA NextGen / Air Traffic** | OT/safety critical, partial air-gap posture | FAA Cybersecurity Architect | Long-cycle; plant seed |

---

## 4. Reseller / Channel Targets (parallel motion)

These are not end-buyers but the *fastest* federal procurement vehicles. Send the reseller email template (template #4) in week 2.

| # | Reseller | Why-fit | Title to target |
|---|---|---|---|
| R1 | **Carahsoft** | Largest fed reseller; runs SEWP, ITES-SW2, GSA contracts | Federal Cybersecurity Account Manager |
| R2 | **Anchore Federal** | Iron Bank + STIG specialists; perfect technical match | Federal Sales Director |
| R3 | **GitHub Government / Microsoft Federal** | Owns DevSecOps in GovCloud + IL5; complementary to ALDECI's air-gap | GitHub Federal Sales Engineering Lead |
| R4 | **Second Front Systems** | "FedRAMP-in-a-box" and IL5 hosting; could shortcut compliance | Director, Compliance-as-a-Service |
| R5 | **Rebellion Defense** | DoD-native, cleared engineers, buys CTEM upstream | VP, Engineering |
| R6 | **DLT Solutions (a Tech Data company)** | Federal reseller, GSA + SEWP V | Federal Cybersecurity BD |
| R7 | **Immix Group / Arrow Electronics Federal** | Tier 1 fed distributor | Cyber Practice Lead |

---

## 5. Recommended First-Send Order (today + tomorrow)

| Day | Send to | Channel | Template | Reason |
|---|---|---|---|---|
| **2026-04-26 (today, EOD)** | #1 CISA JCDC, #6 DIU Cyber, #8 SOCOM SOFWERX | Cold email v1 | template #2 | Friday-EOD lands in their Monday inbox first; all three are CSO/CSO-adjacent and fastest-path |
| **2026-04-26 (today)** | #4 NGA, #5 NRO | LinkedIn DM | template #1 | Federal IC moves on relationships; LinkedIn-first is the norm |
| **2026-04-27 (tomorrow AM)** | #7 AFWERX, #9 ARCYBER, #10 NavalX, #11 CDAO | Cold email v1 | template #2 | DoD innovation cells; Monday morning is best |
| **2026-04-27 (tomorrow)** | #2 NSA CCC, #3 DARPA I2O | LinkedIn DM only first | template #1 | Higher-bar orgs; DM-first to gauge interest before email |
| **2026-04-28 (Tue)** | #18 Lockheed, #19 Northrop, #20 RTX | Cold email v2 (defense prime) | template #3 | Mid-week is best for prime CISO orgs |
| **2026-04-29 (Wed)** | R1 Carahsoft, R2 Anchore Federal, R3 GitHub Federal | Cold email v3 (reseller) | template #4 | Resellers move fastest mid-week |

---

## 6. Disqualifiers (do NOT send to)

- Any org currently inside a 3PAO assessment for a competing CTEM (would create COI for them)
- Foreign government addresses (export control: ALDECI's PQC inventory may be ITAR/EAR-touching once we ship the bundle internationally — pending counsel review)
- Cold-cold orgs without a public security program signal (waste of P1 send budget)

---

## 7. Tracking (for sales-engineer-status update)

- Sends to log: `.claude/team-state/sales/scif-outreach-log.json` (one row per send: target, channel, template, date, response status)
- Discovery calls booked: target ≥3 by 2026-05-10
- Pilot SOWs out: target ≥1 by 2026-05-17
- Pilot signature: target ≥1 by 2026-05-24 → triggers T+20 install (commit `aba22fff` cosign + `1159ef49`/`69efa330` Stage 1 hardening already in place)

*End target list.*
