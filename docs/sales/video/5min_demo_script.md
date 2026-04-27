# ALdeci — 5-Minute Demo Video Script

**Format:** Loom-style solo recording, sales engineer narrates live UI
**Target runtime:** 5:00–5:30 (edit to max 5:45; anything over 6 minutes gets skipped by champions)
**Tenant:** `juice-shop-corp` — real OWASP Juice Shop onboarded as a live ALdeci customer
**Arc:** Command (substrate) → Brain Pipeline (moat) → Compliance (federal close) → Asset Graph (teaser) → CTA

---

## 0:00–0:30 — Hook

**Screen:** Command hero at `http://localhost:5173/command`
**Show:** KPI strip fully loaded — Findings: 1,247 | Open Critical: 38 | MPTE-verified exploitable: 12 | AutoFix queue: 67

**Say verbatim:**
> "Last week your team triaged 1,247 findings. Watch ALdeci do this in 2 minutes."

> "38 were flagged critical by your scanners. ALdeci has already proved that only 12 are actually exploitable — the other 26 are unreachable in code, blocked by compensating controls, or proven safe by our pen-test engine. That's not a filter. That's proof."

**Pause 1 second. Let the KPI numbers land.**

---

## 0:30–1:30 — Command Hero: The Dollar Number and the Drawer

**Screen:** Still on Command — hover the "Open Critical: 38" KPI tile

**Say:**
> "Click into critical. Every finding has a FAIL score — Frequency times Asset value times Impact times Likelihood — dollarized. This one: $147,000 expected loss. EPSS exploitation probability: 87% in 30 days. CISA KEV: yes, actively exploited in the wild."

**Click:** First critical finding row — `CVE-2024-XXXXX — eval() in juice-shop /rest/products`
**Screen:** Drawer opens, Score Breakdown tab visible

**Say:**
> "The score-breakdown tab shows you exactly why this finding ranked first — not because CVSS said 9.8, but because the graph traced a live call path from the HTTP handler all the way down to the eval(). This is function-level reachability, not heuristics."

**Click:** Multi-LLM Consensus tab in the drawer

**Say:**
> "Three independent AI models voted: GPT-4 scored severity 9.2, Claude 9.1, Gemini 9.4. Agreement: 94%. If they'd disagreed below our 85% threshold, this would have escalated to a human analyst automatically. That is the consensus rule — hardcoded."

---

## 1:30–2:45 — Brain Pipeline Hero: The 12-Step Engine

**Navigate:** Top nav → Brain → `http://localhost:5173/brain`
**Screen:** 12-step pipeline grid fully rendered

**Say:**
> "Every finding — from your Snyk, your Wiz, your Semgrep, our 8 native scanners — flows through these same 12 steps. Deterministic. Auditable. Reproducible."

**Click:** Step 10 — Consensus

**Say:**
> "Step 10 is the Multi-LLM Council. Watch as 5 models converge on a verdict. Each model votes independently — we require an 85% agreement threshold before a severity or remediation decision is emitted downstream."

**Screen:** Consensus pane with Active Providers / Total Decisions / Consensus Rate / Avg Latency KPIs visible

**Say:**
> "703 Direct Preference Optimization pairs already learned from this tenant's analyst overrides. Every time your analyst accepts or rejects a recommendation, that decision becomes training data for tonight's fine-tune run. Tomorrow, your private model is sharper. Your data trains your model. It never trains anyone else's."

**Click:** Step 11 — Remediate/AutoFix

**Say:**
> "Step 11: AutoFix. Confidence above 85% — we ship the PR automatically. Below 85%, your developer reviews it. 10 fix types: code patches, dependency updates, secret rotation, IaC hardening. The diff is in your PR. Nothing touches production without a human in the loop unless you authorize it."

---

## 2:45–4:00 — Compliance Hero: SCIF Posture and Quantum-Secure Evidence

**Navigate:** Top nav → Compliance → `http://localhost:5173/compliance`
**Screen:** Compliance hero — 7 framework cards (NIST 800-53, FedRAMP, SOC 2, PCI-DSS, HIPAA, ISO 27001, CIS), SCIF LIVE panel in corner with FIPS 140 Mode = ENABLED

**Say:**
> "Seven compliance frameworks. Evidence is auto-generated as findings flow through the pipeline — not assembled at audit time."

**Click:** NIST 800-53 → AC-2 control

**Say:**
> "412 timestamped evidence events for this one control. Each event is cryptographically signed with post-quantum ML-DSA — that's FIPS 204, Dilithium lattice signatures. Stored WORM. 7-year retention. This is the slide your auditor wants."

**Click:** SCIF Posture LIVE panel

**Say:**
> "SCIF mode: FIPS 140-3 active, air-gap deployment, all 8 native scanners run with zero external dependencies. This is why we win the federal customer that Snyk and Wiz lose every time. No cloud egress. No external API calls. Everything on your hardware."

**Briefly show:** Audit chain tab — Merkle-chained immutable log

**Say:**
> "Append-only. Cryptographically chained. Tamper-evident. SOC 2 Type II ready out of the box."

---

## 4:00–4:45 — Asset Graph Teaser: Chokepoint Drill-In

**Navigate:** Top nav → Assets → `http://localhost:5173/assets`
**Screen:** Asset graph — 1,221 nodes / 3,054 edges, Choke Points filter active, 3 red nodes highlighted

**Say:**
> "1,200 assets. We computed the minimum cut using Edmonds-Karp — fix any one of these three nodes and you sever the attack path to 47 crown-jewel systems downstream."

**Click:** Top choke point — "shared-auth-svc"

**Say:**
> "Blast radius: 47 assets, dollar-weighted to $4.2 million. And here is the toxic combination — over-permissive IAM plus reachable RCE plus crown-jewel-tagged data. This is XM Cyber-class chokepoint analysis. It is part of the platform. No extra license."

---

## 4:45–5:00 — Close

**Screen:** Return to Command — full KPI strip visible as visual anchor

**Say:**
> "To recap: 1,247 findings ingested, triaged by AI consensus, verified by 19-phase pen-test, evidence cryptographically signed, compliance mapped, attack graph computed. All in one platform. Air-gapped."

> "If you are a federal SCIF customer: 20-day pilot path, hardware ships pre-configured. Mid-market: you are live today — connect your first scanner in under 10 minutes. And if you are evaluating us for an investment conversation — book 30 minutes, we will show you the full 12-step pipeline live on your own repos."

**Fade to ALdeci logo + booking link.**

---

## Contingency Lines (do not cut — read before recording)

| Scenario | Fallback |
|----------|----------|
| Assets page crashes (DEMO-BUG-001) | Say "Asset Graph is in active development — here is the pre-rendered chokepoint from our last clean run" and show `docs/ui-snapshots/demo_2026-04-26/04-assets-chokepoint.png` on screen |
| Brain consensus shows "No consensus yet" | Say "This tenant is freshly deployed — on a production tenant with active analyst overrides, you see live vote breakdowns. The council infrastructure is wired; it fires when LLM provider keys are configured." |
| KPI strip shows zeros | Switch to backup tenant `node-goat-inc` — same script, same beats |
| Compliance SCIF panel not live | Fall back to screenshot `05-compliance-posture.png` — narrate the same points |
