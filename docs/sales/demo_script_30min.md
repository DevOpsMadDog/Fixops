# ALdeci 30-Minute Demo Script

> **Audience:** Mixed-technical buyer (CISO + DevSecOps lead + 1 technical evaluator)
> **Outcome:** Buyer agrees to a 14-day POC by minute 28
> **Pre-flight:** Tenant `juice-shop-corp` seeded with 1,247 findings via `scripts/onboard_real_apps.sh`. Self-learning loop is LIVE (DPO pair captured this morning). Verify `curl -s http://localhost:8000/api/v1/health` returns 200.
> **Hero arc:** Command (substrate) → Brain (moat) → Asset Graph (chokepoint) → Compliance (federal close)

---

## 0:00–2:00 — Open at Command Hero (the substrate)

**URL:** `http://localhost:5173/command`

**Click path:**
1. Land on `/command` — KPI strip should show `Findings: 1,247`, `Open critical: 38`, `MPTE-verified exploitable: 12`, `AutoFix queue: 67`.
2. Hover the "Findings (7d)" sparkline to show real-time tick.

**Say verbatim:**
> "Last week your SOC triaged 1,247 findings. 38 were marked critical by your scanners. **In ALdeci, only 12 are actually exploitable** — the other 26 we proved unreachable in code, in runtime, or behind compensating controls. That's the headline. Let me show you how."

**Watch out for:**
- If KPI strip shows zeros → tenant not seeded. Switch to backup tenant `node-goat-inc`.
- If sparkline is flat → ingestion stalled. Trigger `POST /api/v1/scanner-ingest/upload` from terminal in side panel.

---

## 2:00–6:00 — Drill into a critical finding (score-breakdown reveal)

**Click path:**
1. From Command, click the "Open critical: 38" tile → routes to `/issues?severity=critical`.
2. Click first row labeled `CVE-2024-XXXXX — eval() in juice-shop /rest/products` → drawer opens.
3. Drawer tab: **Score breakdown**.

**Say verbatim:**
> "This is one finding. Notice we don't show you a CVSS number and walk away. We show you the **FAIL score** — Frequency × Asset value × Impact × Likelihood — dollarized to $147K expected loss. EPSS says 87% chance of exploitation in the next 30 days. CISA KEV: yes, actively exploited. **And here's the proof it's reachable** — function-level call graph from the HTTP handler down to the eval()."

**Click:**
4. Drawer tab: **Reachability proof** → shows function call chain rendered from `function_reachability_engine.py`.
5. Drawer tab: **Multi-LLM consensus** → shows 3-model vote: GPT-4 (severity 9.2), Claude (9.1), Gemini (9.4). Agreement: 94%.

**Say:**
> "Three independent AI models voted. 94% agreement. If they'd disagreed below 85%, this would have been escalated to a human analyst — that's the consensus rule."

**Watch out for:**
- If reachability tab shows "no proof available" → fall back to a different finding. Pre-stage `juice-shop-corp` finding ID `f-7831` which has full reachability.
- If consensus tab shows only 1 model → LLM provider config issue. Skip and pivot to next beat.

---

## 6:00–13:00 — Pivot to Brain Hero (the moat — 12-step pipeline)

**URL:** `http://localhost:5173/brain`

**Click path:**
1. Top nav → Brain.
2. Pipeline visualization shows 12 steps as horizontal flow with live throughput counters.
3. Click step 9 (**AI Consensus**) → side panel shows last 10 votes with model, confidence, latency.
4. Click step 10 (**MPTE Verify Exploitability**) → shows last 5 verifications, each with 19-phase status badges.
5. Click step 11 (**Remediate / AutoFix**) → shows AutoFix queue + last 3 generated patches with confidence scores.

**Say verbatim:**
> "Every finding from every source — your Snyk, your Wiz, your Semgrep, our 8 native engines — flows through these same 12 steps. **Deterministic, auditable, reproducible.** Step 9 is the multi-LLM vote you just saw. Step 10 is MPTE — 19-phase exploit verification. Continuous, not annual. Step 11 generates the fix. **Confidence above 85%, we ship the PR automatically. Below, your developer reviews it.**"

**Click (the self-learning reveal — this is the wow moment):**
6. Side panel → "Self-learning telemetry" tab.
7. Show: "Last DPO pair captured: 11 minutes ago. Total pairs this week: 847. Next vLLM fine-tune scheduled: tonight 02:00 UTC."

**Say:**
> "Here's what no other vendor does. Every time your analyst overrides one of our recommendations, we capture a Direct Preference Optimization pair — preferred decision vs. rejected. **That pair becomes training data tonight.** Tomorrow morning your private model is sharper. Your data trains your model. It never trains anyone else's."

**Watch out for:**
- If the live pipeline visualization stalls → degrade to a screenshot of the same view in `docs/ui-snapshots/brain-pipeline-2026-04-26.png`. Don't apologize, keep narrating.
- If self-learning panel shows 0 pairs → likely fresh tenant. Switch narrative: "On a busy tenant we capture ~120 pairs/day. We're showing you a fresh deployment."

---

## 13:00–20:00 — Land at Asset Graph (chokepoint + attack path)

**URL:** `http://localhost:5173/asset-graph`

**Click path:**
1. Top nav → Asset Graph.
2. Render: 1,221 nodes / 3,054 edges. Largest component 95.8%.
3. Filter chip: **Choke Points** → highlights 3 red nodes (min-cut from Edmonds-Karp).
4. Click the top choke point — labeled "shared-auth-svc".
5. Right panel: **Attack path traversal** → animates path from internet-facing edge → choke point → 47 downstream assets.

**Say verbatim:**
> "This is your security graph. 1,200 assets. We computed the minimum cut — **fix any one of these three nodes and you sever the attack path to 47 crown-jewel systems.** This isn't a CVSS list. This is XM Cyber-class choke-point analysis, and it's part of the platform — no extra license."

**Click:**
6. Right panel → **Blast radius** tab → shows 47 downstream assets dollar-weighted to $4.2M.
7. Right panel → **Toxic combo** tab → highlights the over-permissive IAM + reachable RCE + crown-jewel data combo.

**Say:**
> "And here's the toxic combination — over-permissive IAM PLUS reachable RCE PLUS crown-jewel-tagged data. Wiz calls these Issues. We do too — and we tell you the dollar exposure if you ignore them."

**Watch out for:**
- If graph fails to render >500 nodes → the GAP-047 10k benchmark is in-progress. Fall back to filtered view (top 100 nodes) — still shows the choke point pattern.
- If Edmonds-Karp computation hangs >5 sec → it's pre-computed nightly; explain that and click pre-rendered overlay.

---

## 20:00–26:00 — Close at Compliance Hero (federal-grade evidence)

**URL:** `http://localhost:5173/compliance`

**Click path:**
1. Top nav → Compliance.
2. Framework grid: NIST 800-53 / FedRAMP High / SOC 2 / PCI-DSS / HIPAA / ISO 27001 / CIS — all show coverage %.
3. Click **NIST 800-53 → AC-2 control** → shows automated evidence chain with 412 timestamped events.
4. Toggle **SCIF mode** flag → banner appears: "FIPS 140-3 mode active · Air-gap deployment · ML-DSA quantum-safe signing".
5. Click any evidence item → shows ML-DSA (Dilithium FIPS 204) signature + WORM retention badge + chain hash.

**Say verbatim:**
> "Seven frameworks mapped. Evidence is auto-generated, cryptographically signed with **post-quantum ML-DSA** — that's FIPS 204. Stored WORM. This is the slide your auditor wants. **And here's the SCIF-ready toggle** — air-gapped operation, FIPS 140-3, all eight scanners run with zero external dependencies. This is why we win the federal customer Snyk and Wiz lose every time."

**Click:**
6. Audit log tab → tail the immutable Merkle-chained log showing the 412 events.

**Say:**
> "Append-only. Cryptographically chained. Tamper-evident. SOC 2 Type II ready out of the box."

**Watch out for:**
- SCIF readiness is 35% per `docs/scif_readiness_2026-04-26.md`. If asked about FedRAMP authorization timeline, answer honestly: "12–18 months to ATO. We have the technical surface — FIPS, air-gap, PQC — shipped today. The 3PAO engagement is the critical path."
- If they ask about FedRAMP **today** → "We are FedRAMP-Ready, not FedRAMP-Authorized. Authorization is on roadmap."

---

## 26:00–30:00 — POC ask (the close)

**Click path:** Stay on Compliance hero or return to Command for visual anchor.

**Say verbatim:**
> "Here's what I'd like to do next. **14-day POC.** Connect to one of your repos, one of your scanners, one of your clouds. Day 7, you've ingested real findings, seen real consensus votes, captured your first DPO pair. Day 14, we measure: how much noise we cut, how many MPTE-verified exploitables we surfaced, how many AutoFix patches you accepted. If those numbers don't beat what you have today, we shake hands and you walk away. If they do, we move to commercial."

**Hand them:** `docs/sales/poc_template.md` (printed or shared link).

**Stop talking. Wait for objection.**

---

## Things to AVOID during this demo

- **DO NOT** open Admin or Settings — pages are real but visually rough; not a hero surface.
- **DO NOT** mention IDE plugin (GAP-014 unshipped — competitor question, not our story).
- **DO NOT** go deeper than 1 click in any drawer — buyer attention is shallow at minute 20.
- **DO NOT** show DSPM/data-classification — Wiz wins this surface, no reason to fight there.
- **DO NOT** quote test counts (806 passing) — sounds like engineering, not value.
- **DO NOT** apologize for any UI rough edge — narrate through it.

## Recovery if API dies mid-demo

1. Switch to `docs/ui-snapshots/` — pre-staged screenshots of every beat above.
2. Say: "We have a live environment, but for the next 60 seconds let me walk you through a recorded path so I don't waste your time."
3. Continue narrating. Do NOT debug live.

## Post-demo follow-up email template

Subject: ALdeci POC kickoff — 14 days from your go-ahead

Body:
- Re-state the 3 numbers we'll measure (noise reduction, MPTE exploitables, AutoFix acceptance)
- Attach `docs/sales/poc_template.md`
- Propose 3 calendar slots for kickoff
- CC: their CISO + DevSecOps lead + your sales engineer
