# ALdeci 5-Min Demo — Storyboard

**One row per scene. Screenshot column references `docs/ui-snapshots/demo_2026-04-26/`.**

---

## Scene 1 — Hook (0:00–0:30)

| Field | Detail |
|-------|--------|
| **Screenshot** | `01-command.png` |
| **Duration** | 30 sec |
| **Visual overlay** | Top-left corner: white title card fades in — "1,247 findings. 2 minutes." in 36px bold. Bottom-right: ALdeci logo lockup. |
| **Annotation arrows** | Red arrow pointing at "Open Critical: 38" KPI tile. Green arrow pointing at "MPTE-verified exploitable: 12" KPI tile. Arrow label: "26 proved safe — not guessed." |
| **Callout box** | Yellow callout over the KPI strip: "Real tenant data — juice-shop-corp. No mock data." |
| **Audio cue** | Voice-over begins immediately. No intro music. Background: silent or very low ambient tone (-30 dB). |

---

## Scene 2 — Command: Score Breakdown and Dollar Number (0:30–1:00)

| Field | Detail |
|-------|--------|
| **Screenshot** | `01-command.png` (hover state on Critical tile — record live, not screenshot) |
| **Duration** | 30 sec |
| **Visual overlay** | Animated cursor highlight circling the "Open Critical: 38" tile for 2 sec before click. |
| **Annotation arrows** | On drawer open: orange callout box over FAIL Score — "FAIL = Frequency × Asset × Impact × Likelihood. Dollarized: $147K." |
| **Callout box** | Blue callout over EPSS field — "87% exploitation probability in 30 days." Red callout over CISA KEV — "Actively exploited in the wild." |
| **Audio cue** | Pace: deliberate. Pause 1 sec after "$147,000" — let it register. |

---

## Scene 3 — Command: Multi-LLM Consensus Drawer (1:00–1:30)

| Field | Detail |
|-------|--------|
| **Screenshot** | `01-command.png` (live drawer, consensus tab) |
| **Duration** | 30 sec |
| **Visual overlay** | Three model vote rows highlighted with a bracket annotation: "3 independent models. 1 consensus threshold: 85%." |
| **Annotation arrows** | Arrow from "94% agreement" label to callout: "Below 85% → auto-escalate to human analyst." |
| **Callout box** | Green callout: "GPT-4: 9.2 | Claude: 9.1 | Gemini: 9.4" displayed as on-screen text overlay if vote panel is not visible at current zoom. |
| **Audio cue** | Slow down for the 85% threshold line — this is a differentiator. |

---

## Scene 4 — Brain Pipeline: 12-Step Grid (1:30–2:00)

| Field | Detail |
|-------|--------|
| **Screenshot** | `03-brain-pipeline.png` |
| **Duration** | 30 sec |
| **Visual overlay** | Numbered step labels 01–12 each get a brief white highlight box as cursor sweeps across. Step 10 pulses (CSS ring animation in recording or simulate by hovering). |
| **Annotation arrows** | Arrow from Step 10 box — "Multi-LLM Council (85% threshold)" label. Arrow from Step 11 box — "AutoFix: PR generated automatically above 85% confidence." |
| **Callout box** | Top-right corner: persistent stat card — "Every source. Same 12 steps. Deterministic." |
| **Audio cue** | Voice-over can be slightly faster here — visual carries the weight. |

---

## Scene 5 — Brain Pipeline: Consensus Pane + 703 DPO Stat (2:00–2:30)

| Field | Detail |
|-------|--------|
| **Screenshot** | `03-brain-consensus.png` |
| **Duration** | 30 sec |
| **Visual overlay** | On-screen text insert (lower-third style, black bg, white text): "703 DPO pairs learned from analyst overrides" — holds for 4 seconds. |
| **Annotation arrows** | Arrow to "Consensus Rate" KPI — callout: "85% threshold. Hard rule. Not configurable per-finding." |
| **Callout box** | Highlight "Self-learning" telemetry section (if visible) with callout: "Your data trains your model. Never anyone else's." |
| **Audio cue** | The DPO pair line is the emotional peak of the Brain section — pause 1 sec before and after. |

---

## Scene 6 — Compliance: Framework Grid and SCIF Panel (2:45–3:20)

| Field | Detail |
|-------|--------|
| **Screenshot** | `05-compliance-posture.png` |
| **Duration** | 35 sec |
| **Visual overlay** | Seven framework cards highlighted in sequence with a sweep animation. SCIF LIVE panel circled with pulsing red ring — label: "FIPS 140 Mode: ENABLED (live)". |
| **Annotation arrows** | Arrow to FIPS 140 badge — "Not a checkbox. A live mode flag wired to all 8 native scanners." |
| **Callout box** | Lower-third: "Air-gapped. Zero external API calls. All 8 scanners on-prem." |
| **Audio cue** | Emphasize "FIPS 204" and "post-quantum" — these are the federal trigger words. |

---

## Scene 7 — Compliance: AC-2 Evidence Chain (3:20–4:00)

| Field | Detail |
|-------|--------|
| **Screenshot** | `05-compliance-posture.png` (live drill-in to NIST 800-53 / AC-2) |
| **Duration** | 40 sec |
| **Visual overlay** | On-screen text: "412 evidence events. Auto-generated. Cryptographically signed." holds for 5 sec. |
| **Annotation arrows** | Arrow to first evidence item — callout: "ML-DSA (FIPS 204) signature. WORM retention. 7 years." |
| **Callout box** | Right side: "SOC 2 Type II ready out of the box." in green badge style. |
| **Audio cue** | "Append-only. Cryptographically chained. Tamper-evident." — deliberate cadence, one phrase at a time. |

---

## Scene 8 — Asset Graph Teaser: Chokepoint (4:00–4:45)

| Field | Detail |
|-------|--------|
| **Screenshot** | `04-assets-chokepoint.png` |
| **Duration** | 45 sec |
| **Visual overlay** | Three choke-point nodes circled in red. Animated line tracing attack path from internet edge → shared-auth-svc → 47 downstream nodes. |
| **Annotation arrows** | Arrow to red node cluster — "Fix 1 of these 3 → sever path to 47 crown-jewel assets." On-screen text: "$4.2M blast radius." |
| **Callout box** | "Edmonds-Karp minimum-cut. XM Cyber-class. Included. No extra license." |
| **Audio cue** | "1,200 assets" followed by deliberate pause — visual of graph is the beat. |

---

## Scene 9 — Close: CTA (4:45–5:00)

| Field | Detail |
|-------|--------|
| **Screenshot** | `01-command.png` (return to Command as visual anchor) |
| **Duration** | 15 sec |
| **Visual overlay** | Lower-third split into 3 tracks fading in sequentially: "Federal SCIF: 20-day pilot path" | "Mid-market: live today" | "Investor demo: book 30 min". |
| **Annotation arrows** | None. Clean close. |
| **Callout box** | Final frame: ALdeci logo + booking URL centered on black background. |
| **Audio cue** | Pace picks back up — confident, not rushed. Silence on logo frame for 2 sec before fade. |

---

## Overlay Spec Reference

| Overlay type | Tool | Style |
|---|---|---|
| Title cards | Loom transcript overlay or Descript title layer | White text, Inter Bold 36px, black semi-transparent bg |
| Annotation arrows | Loom draw tool (live) OR Descript annotation layer (post) | Red (#EF4444) arrows, 3px stroke |
| Callout boxes | Descript text boxes | Yellow (#FBBF24) border, white fill, 14px Inter Medium |
| On-screen stats (703 DPO, $147K, etc.) | Descript lower-third preset | Black bar, white text, 18px |
| LIVE pill pulse | Screen recording captures real UI — no overlay needed | Native UI renders the green LIVE pill |
