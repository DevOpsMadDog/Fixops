---
persona: SOC Analyst (Tier 1)
seo_keyword: "alert fatigue solution multi-LLM triage"
seo_meta: "ALdeci's multi-LLM consensus engine trims 11,300 weekly security alerts to ~340 verified decisions. Tier 1 analysts close real threats — not false positives."
---

# Landing Page — SOC Analyst (Tier 1)

## Hero Headline

Your Next Shift Without the 11,000-Alert Queue

## Sub-Hero

ALdeci's multi-LLM consensus engine votes on every finding with a required 85% agreement threshold — filtering noise before it reaches your queue, so you triage real threats, not theoretical ones.

---

## Three Proof Bullets

- **Three or more LLMs vote on every finding — 85% agreement required to escalate.** llm_consensus.py runs Qwen 3.6+, Kimi K2, Gemma 4, and Opus as independent reviewers. Disagreements trigger a three-stage peer review where models see each other's reasoning and revise. Every vote, confidence score, and position change is logged for audit. (Source: docs/CTEM_PLUS_IDENTITY.md Multi-LLM Consensus Decision Engine)
- **19-phase MPTE proves exploitability before a ticket is created.** The Micro-Pentest Engine runs recon → entry → priv-esc → lateral → exfil → impact with proof artefacts at each phase. A Tier 1 analyst receives a finding with an actual exploit timeline, not a CVSS score and a guess. (Source: docs/CTEM_PLUS_IDENTITY.md MPTE)
- **703 real DPO preference pairs already training the model on your team's decisions.** Every analyst override (accept/reject a finding) lands as a labeled training pair in learning_signals.db and feeds nightly LoRA fine-tuning. The Council gets better with each shift. (Source: docs/investor/TRACTION_METRICS_2026-04-26.md LLM Phase 1)

---

## Pain vs. Outcome

| Before ALdeci | With ALdeci |
|---|---|
| 11,300+ findings per week — 60–70% false positives — and no fast way to know which are real | Multi-LLM consensus cuts to ~340 verified decisions; false positives fail the 85% agreement gate and are logged, not surfaced |
| Escalation to Tier 2 is gut-feel; Tier 2 sends 40% back as noise | Every escalation carries a vote record, confidence breakdown, and MPTE proof — Tier 2 has context on arrival |
| Learning happens informally; the same alert pattern resurfaces next quarter | Analyst overrides become training data; the Council learns your environment's context, not a generic model's |

---

## Primary CTA

Book 30-Min Triage Demo

## Secondary CTA

See How Multi-LLM Consensus Works

---

## Quote Placeholder

> "[Customer logo] — '[One sentence on how ALdeci changed the analyst's daily triage experience — specific queue size reduction or time saved.]'"

---

## SEO Meta Description

ALdeci's multi-LLM consensus engine trims 11,300 weekly security alerts to ~340 verified decisions. Tier 1 analysts close real threats — not false positives.
