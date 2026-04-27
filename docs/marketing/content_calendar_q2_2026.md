# ALdeci Content Calendar — Q2 2026 (12 Weeks)

**Period:** 2026-04-28 through 2026-07-26
**Owner:** Marketing Head
**Publishing channels:** Twitter/X (@aldeci), LinkedIn (founder page), YouTube/Loom, aldeci.com/blog
**Voice:** Technical founder — direct, specific numbers, no fluff, cite real commits and data

---

## Publishing Rules

1. Every Twitter/X thread must cite a real data point: commit hash, file path, or measured metric.
2. Every LinkedIn post must be ≥400 words with a concrete technical claim.
3. Every blog post must have a real H1 + 3–5 subheadings (H2). No SEO filler.
4. Video scripts live in `docs/sales/video/`. Publish YouTube first, then embed in blog.
5. No vendor-bashing by name in public content. Use "leading ASPM vendors" or describe the gap technically.
6. Federal-specific variants of all major content — separate post, same week.

---

## Week 1 (Apr 28 – May 2)

### Twitter/X Thread — Monday Apr 28
**Title:** "We scored ALdeci against 149 capabilities across 7 leading security vendors. Here's what we found."
**Data hook:** 83% WIN-or-MATCH. Source: `docs/competitive_validation_2026-04-26.md`
**Thread structure (8 tweets):**
1. Hook: "149 capabilities. 7 vendors (Snyk, Wiz, Tenable, Apiiro, Aikido, Sonatype, XM Cyber). We scored every one. Thread:"
2. Overall: "WIN=82 (55%), MATCH=42 (28%), LOSE=25 (17%). 83% WIN or MATCH. Here's what that means."
3. Where we win clearly: LLM Council (unique), MPTE 19-phase exploit verification (unique), FAIL Engine (unique), MCP Gateway 650+ tools (unique).
4. Where we lose honestly: IDE plugin polish (Snyk wins), DSPM/data classification (Wiz wins), Nessus host-scan heritage (Tenable wins).
5. Why the losses don't matter for the buyer profile we're targeting (CISO with multi-tool stack vs developer-first buyer).
6. The federal gap: "Snyk: no offline product. Wiz: no offline product. Tenable: on-prem heritage but no AI-native decision layer. The intersection of CTEM+ + air-gap is empty." — `docs/competitive_validation_2026-04-26.md` §2
7. Our moat: "Multi-LLM Consensus. 85% threshold. 703 preference pairs in the self-improvement loop today. This isn't a prompt chain — it's a decision architecture."
8. CTA: "We're opening 5 design partner slots. Air-gap, SCIF-ready, $0 for 90 days. DM or link in bio."

### YouTube/Loom Demo Video — Friday May 2 (PUBLISH)
**Title:** "ALdeci 5-Minute Product Demo — From 1,247 Findings to 12 Verified Exploitable"
**Talk track:** Follows `docs/sales/demo_script_30min.md` hero arc, compressed to 5 min.
**Sections:**
- 0:00–0:45: Command hero — KPI strip (1,247 findings → 38 critical → 12 MPTE-verified)
- 0:45–2:00: Brain Pipeline — 12-step animated flow, LLM Council vote panel (Qwen/Kimi/Gemma/Opus, 87% agreement)
- 2:00–3:15: MPTE exploit verification — single finding drilled, real reachability proof
- 3:15–4:15: Compliance hero — evidence bundle, ML-DSA signature, SOC 2 coverage bar
- 4:15–5:00: AutoFix — PR generated, diff shown, confidence score HIGH → auto-apply
**Thumbnail:** Split screen — "10,000 alerts" (red stack) vs "12 verified exploitable" (green checkmarks)
**YouTube description:** Include links to `docs/sales/poc_template.md` (design partner CTA) and Series A data room (investor CTA).

---

## Week 2 (May 5–9)

### LinkedIn Long-Form — Tuesday May 6
**Title:** "Why Multi-LLM Consensus Changes Everything in Security Triage"
**Length:** 600–800 words
**H1:** Why Multi-LLM Consensus Changes Everything in Security Triage
**H2 subheadings:**
- The Single-Model Problem: Confident and Wrong
- How the Council Works: 85% Threshold, Not 51%
- 703 DPO Preference Pairs: The Self-Improvement Loop
- What This Means for Alert Fatigue
**Key claims to include:**
- "Average enterprise receives 10,000+ findings per quarter. 90% are noise." — cite general industry stat
- "ALdeci's LLM Council requires 85% consensus threshold across 3+ models (Qwen, Kimi, Gemma, escalation to Opus). A single overconfident model gets outvoted."
- "703 real DPO preference pairs in `data/learning_signals.db` — 7% toward the 10K-pair distillation gate. The platform is already teaching itself which decisions were correct." — cite `docs/investor/INVESTOR_PACK_2026-04-26.md` §3
- Tiered cost-gating: simple findings route to local Ollama/vLLM; contested findings escalate to Opus. SCIF-clean when `FIXOPS_AIR_GAPPED=1`.
**CTA:** Design partner program link.

### Twitter/X Thread — Thursday May 8
**Title:** "The SCIF problem no security vendor will talk about."
**Data hook:** Snyk/Wiz/Tenable have no offline product. Source: competitive validation §2.
**Thread (6 tweets):**
1. "US classified environments (SCIFs, SAPs, IL5/IL6) collectively run thousands of applications. Most have no CTEM coverage. Here's why — and what we built."
2. "Snyk's scanner phones home. Wiz requires cloud API access. Tenable Nessus has on-prem, but no AI-native decision layer. None of them run in a SCIF without severe capability reduction."
3. "ALdeci: 8 native scanners. Zero external dependencies. FIPS 203/204/205 crypto. ML-DSA evidence signing. Runs on commodity hardware, <1 GB/year storage."
4. "Air-gap guarantee: if you can't reach Snyk or ZAP, ALdeci's SAST (110+ rules), DAST, Secrets (200+ patterns), Container, IaC, API Fuzzer, Malware, and LLM Monitor all work offline."
5. "20-day pilot SOW, pre-written. OTA/CSO-compatible. ATO inheritance path documented." — cite `docs/sales/scif/`
6. CTA: "We have 5 federal design partner slots open. Targeting CISA, DIU, NSA, SOCOM, DARPA as first cohort."

---

## Week 3 (May 12–16)

### Blog Post — Wednesday May 14
**Title:** "CTEM+: Why Gartner's 5-Step Framework Is Necessary but Not Sufficient"
**URL slug:** `/blog/ctem-plus-beyond-gartner`
**H1:** CTEM+: Why Gartner's 5-Step Framework Is Necessary but Not Sufficient
**H2 subheadings:**
- What Gartner's CTEM Framework Gets Right
- The Three Gaps Gartner Left Open (Scanning, AI Decision, Autonomous Remediation)
- The CTEM+ Extension: What "Plus" Actually Means
- Why Air-Gap Is the Fourth Gap Nobody Mentions
- What a Complete CTEM+ Platform Looks Like in Practice
**Key claims:** Reference `docs/CTEM_PLUS_IDENTITY.md`. Gartner's 5 steps (Scoping, Discovery, Prioritization, Validation, Mobilization) vs ALdeci's 12-step Brain Pipeline.
**SEO target keyword:** "CTEM platform" / "continuous threat exposure management"
**Length:** 1,200 words

---

## Week 4 (May 19–23)

### Twitter/X Thread — Monday May 19
**Title:** "The 12-step Brain Pipeline: what happens between 'finding detected' and 'PR merged.'"
**Data hook:** `suite-core/core/brain_pipeline.py` — 12 steps, every finding flows the same path.
**Thread (10 tweets):** Walk through each step with a one-sentence explanation. End with: "Every step emits to TrustGraph. Every decision is signed. Nothing is a guess."

### LinkedIn Long-Form — Wednesday May 21
**Title:** "The Federal Security Gap: What Happens When Your CTEM Tool Needs the Internet"
**Length:** 700 words
**H2 subheadings:**
- Classification-Level Environments Have a Different Set of Constraints
- What "Air-Gap Capable" Actually Requires (It's Not Just On-Prem)
- FIPS 204 ML-DSA: Why Quantum-Safe Signing Matters Now
- The 20-Day SCIF Pilot Design
**Key claims:** Cite `docs/sales/scif/target_list_2026-04-26.md` for federal acquisition context. Reference NSA CNSA 2.0 roadmap alignment.

---

## Week 5 (May 26–30)

### Blog Post — Wednesday May 28
**Title:** "MPTE: Why We Prove Exploitability Instead of Inferring It"
**URL slug:** `/blog/mpte-exploit-verification`
**H1:** MPTE: Why We Prove Exploitability Instead of Inferring It
**H2 subheadings:**
- The Inference Problem: How CVSS Scores Lead to Wasted Work
- What a 19-Phase Micro-Pentest Engine Actually Does
- Real Reachability vs Theoretical Reachability
- Evidence Chain: From Detection to Cryptographic Proof
- What This Means for Your Mean Time to Remediate
**Key claims:** 19-phase MPTE, 69+ endpoints (`docs/competitive_validation_2026-04-26.md` Fixops evidence column). Compare to competitors' "inferred exploitability" approaches.

### Twitter/X Thread — Friday May 30
**Title:** "19 phases of exploit verification. Here's what happens in each one."
**Data hook:** MPTE, `suite-attack/` codebase. 69+ endpoints.
**Thread (9 tweets):** One phase per tweet for phases 1–8, then final tweet: "The output: not 'probably exploitable.' A signed evidence bundle proving it."

---

## Week 6 (Jun 2–6)

### LinkedIn Long-Form — Tuesday Jun 3
**Title:** "The FAIL Engine: Chaos Engineering for Application Security"
**Length:** 600 words
**H2 subheadings:**
- Why Static Security Testing Misses Runtime Blast Radius
- What Chaos Engineering Looks Like in AppSec
- The Four Drill Types: Vulnerable Route, Secret Rotation, Alert Suppression, Recovery
- Measuring What Matters: Real Blast Radius and Recovery Time
**Key claims:** `suite-core/core/fail_engine.py` — industry first. Cite no competitor offering this. Source: `docs/competitive_validation_2026-04-26.md`.

---

## Week 7 (Jun 9–13)

### YouTube/Loom Demo Video — Federal Variant — Thursday Jun 12 (PUBLISH)
**Title:** "ALdeci Federal Demo: SCIF-Ready CTEM+ in 7 Minutes"
**Audience:** ISSO, ISSM, CISO at federal agencies. Not a commercial demo.
**Sections:**
- 0:00–1:00: Air-gap deployment — commodity hardware, <1 GB/year, no internet plumbing
- 1:00–2:30: 8 native scanners — all running offline, FIPS-validated
- 2:30–4:00: MPTE in classified env — exploit verification without external network calls
- 4:00–5:30: Evidence bundle — ML-DSA signature, FIPS 204, 7-year WORM retention
- 5:30–7:00: POA&M integration, NIST SP 800-53 Rev 5 mapping, ~95% controls in code
**Distribution:** Send direct link to all 36 federal targets in `target_list_2026-04-26.md`.

### Blog Post — Wednesday Jun 11
**Title:** "Quantum-Safe Evidence Bundles: Why Security Audit Trails Need to Survive 2040"
**URL slug:** `/blog/quantum-safe-evidence-signing`
**H2 subheadings:**
- The Harvest-Now-Decrypt-Later Threat
- FIPS 203/204/205: What the Standards Actually Require
- ML-DSA Hybrid Signing in Practice
- 7-Year WORM Retention: What That Means for Compliance Audits
- Why This Matters More in Federal Environments

---

## Week 8 (Jun 16–20)

### Twitter/X Thread — Monday Jun 16
**Title:** "MCP Gateway: 650+ security tools exposed over Model Context Protocol."
**Data hook:** `suite-core/core/mcp_server.py`. No competitor offers an MCP surface (cite `competitive_validation_2026-04-26.md`).
**Thread (7 tweets):** What MCP is → why it matters for agentic security → what 650+ tools enables → the competitive moat angle.

### LinkedIn Long-Form — Wednesday Jun 18
**Title:** "Why the Consolidation Arbitrage in Security Is Real and Still Unclaimed"
**Length:** 700 words
**H2 subheadings:**
- The $50K–$500K Stack Problem: Five Dashboards, Zero Unified Decisions
- ASPM + CTEM + CSPM Converging: What Gartner's Research Cycle Is Telling Us
- The Switzerland Position: Ingest Everything, Replace Nothing
- Where Every Incumbent Has a Structural Gap
- The Window: Why This Moment Favors a New Platform

---

## Week 9 (Jun 23–27)

### Blog Post — Wednesday Jun 25
**Title:** "TrustGraph: Building a Second Brain for Security Intelligence"
**URL slug:** `/blog/trustgraph-security-knowledge-graph`
**H2 subheadings:**
- Why a Graph Database Changes How You Think About Vulnerabilities
- Five Knowledge Cores: Findings, Assets, Threats, Compliance, Decisions
- 119,765 Nodes, 425,727 Edges: What the Numbers Mean
- GraphRAG vs Traditional Search in Security Context
- The Closed-Loop: When the Platform Learns from Its Own Decisions
**Key claims:** 119k nodes / 425k edges, 38.4% of platform emitting to TrustGraph. Source: `docs/investor/INVESTOR_PACK_2026-04-26.md` §3.

---

## Week 10 (Jun 30 – Jul 4)

### Twitter/X Thread — Monday Jun 30
**Title:** "30-day update: what our design partners measured."
**Data hook:** Actual 30-day review metrics from design partners (critical backlog reduction %, MTTR improvement).
**Thread (6 tweets):** Anonymized results, no customer names without permission. Focus on the numbers.

### LinkedIn Long-Form — Wednesday Jul 2
**Title:** "What 'Design Partner' Actually Means (And What We Ask In Return)"
**Length:** 500 words. Transparent post about the design partner program: what we give ($0, onboarding engineer, co-marketing), what we ask (access, feedback, reference).
**CTA:** 2 remaining design partner slots open.

---

## Week 11 (Jul 7–11)

### Blog Post — Wednesday Jul 9
**Title:** "30 Personas, One Platform: How ALdeci Serves Every Security Stakeholder"
**URL slug:** `/blog/30-personas-security-platform`
**H2 subheadings:**
- Why Security Tools Usually Serve One Persona at the Expense of Others
- The CISO View: Unified Posture, Zero Dashboard Switching
- The DevSecOps Lead View: Findings in the PR, Not the Email Inbox
- The Compliance Officer View: Evidence Generated Automatically
- The Pen Tester View: MPTE as a Force Multiplier

---

## Week 12 (Jul 14–18)

### YouTube/Loom Demo Video — Compliance Focus — Thursday Jul 17 (PUBLISH)
**Title:** "ALdeci SOC 2 + HIPAA in 6 Minutes: Automated Evidence, Zero Manual Screenshots"
**Audience:** Compliance officers, VP Engineering at regulated companies.
**Sections:**
- 0:00–1:30: Compliance hero screen — frameworks coverage bar, evidence vault
- 1:30–3:00: Evidence bundle generation — ML-DSA signature, audit-ready PDF
- 3:00–4:30: Continuous monitoring — findings linked to controls automatically
- 4:30–6:00: 7-year WORM retention, FedRAMP alignment, NIST SP 800-53

### Twitter/X Thread — Monday Jul 14
**Title:** "We submitted an RFI to the Forrester CTEM Wave. Here's what we wrote."
**Data hook:** RFI submission confirms Forrester is evaluating the CTEM category formally.
**Thread (5 tweets):** What the Wave evaluates → the 6 moats we highlighted → the federal differentiation → what inclusion in a Forrester Wave means for a buyer's procurement process.

---

## Week 13 (Jul 21–25)

### Blog Post — Wednesday Jul 22
**Title:** "Series A Lessons: What Investors Actually Asked About Our Security Platform"
**URL slug:** `/blog/series-a-fundraising-security-platform`
**Note:** Publish after Series A close (Week 13). Founder-voice, honest, technical.
**H2 subheadings:**
- The Question Every Investor Asked First
- Why "83% WIN-or-MATCH" Is the Wrong Way to Present Competitive Data
- What Federal Wedge Means to a VC Who's Never Heard of a SCIF
- The Product Metric That Mattered Most: 703 DPO Pairs
- What We'd Do Differently in the Deck

### LinkedIn Long-Form — Wednesday Jul 23
**Title:** "ALdeci Closes $8M Series A — What's Next"
**Length:** 400 words. Announcement post. Tag lead investor. Mention design partners (with permission).
**CTA:** We're hiring. Link to jobs page.

---

## Evergreen Assets (Produce in Weeks 1–4, Reuse Throughout)

| Asset | Format | Purpose | Status |
|---|---|---|---|
| 1-page product brief | PDF | Attach to all outreach emails | Derive from `analyst_one_pager_2026-04-26.md` |
| Competitive matrix (public version) | PNG infographic | LinkedIn, blog embeds | Derive from `competitive_validation_2026-04-26.md` §0 — redact the LOSE column for public version |
| 12-step Brain Pipeline diagram | SVG/PNG | All content pieces | Derive from `docs/sales/demo_script_30min.md` hero arc |
| CTEM+ definition explainer | 300-word insert | Reuse in every blog post intro | Write once in Week 1 |
| Federal pitch one-pager | PDF | Federal outreach only | Derive from SCIF target list angles |

---

## Content Metrics (Track Weekly)

| Metric | Week 4 target | Week 8 target | Week 13 target |
|---|---|---|---|
| Twitter/X impressions | 5,000 | 20,000 | 60,000 |
| LinkedIn followers | +100 | +500 | +1,500 |
| Blog sessions (aldeci.com) | 200 | 1,000 | 5,000 |
| YouTube video views | 200 | 800 | 3,000 |
| Demo video requests (inbound) | 2 | 10 | 30 |
| Design partner inquiries from content | 1 | 3 | 8 |
