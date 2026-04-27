# ALDECI Enterprise Demo — Talking Points One-Pager

**Demo:** 5 days out | **Goal:** Signed design-partner agreement or 14-day POC commitment by minute 30
**Sources:** `docs/competitive_validation_2026-04-26.md` (149 caps × 7 competitors, 83% W/M), `docs/sales/demo_script_30min.md`, `docs/CTEM_PLUS_IDENTITY.md`

---

## What ALDECI Does (3 sentences)

Security teams drown in findings — 10,000+ per quarter, 90% noise. ALDECI ingests output from your existing tools (32 scanner normalizers, zero rip-and-replace), runs 3+ LLMs at 85% consensus to decide what matters, then proves exploitability with a 19-phase Micro-Pentest Engine instead of guessing. Output: a prioritized, verified, remediated backlog with a quantum-safe compliance evidence bundle.

---

## 9 Differentiators No Competitor Has

All 9 scored `NA` for every competitor in the validation matrix. Not roadmap — each maps to a shipped file.

**1. Multi-LLM Consensus (85% threshold)** — `suite-core/core/llm_consensus.py`
3+ models vote per finding. One overconfident model gets outvoted. **703 real DPO preference pairs** already in the self-improvement loop (`data/learning_signals.db`).
*Talking point:* "Ask your current vendor what happens when their single model is wrong. We require 85% agreement across 3+ models before acting."

**2. 12-Step Brain Pipeline** — `suite-core/core/brain_pipeline.py`
Every finding flows intake → triage → enrichment → reachability → exploit-check → consensus → score → policy → autofix → ticket → audit → archive. Every step emits to TrustGraph.
*Talking point:* "Competitors have dashboards. ALDECI has a production line."

**3. 19-Phase MPTE — Proves Exploitability** — `suite-attack/`, 69+ endpoints
*Talking point:* "Demo tenant: 38 scanner-marked criticals. MPTE verified 12 are actually exploitable. 68% less work this week."

**4. FAIL Engine — Chaos for AppSec (Industry First)** — `suite-core/core/fail_engine.py`
*Talking point:* "20-min automated red-team drill. Verifies your WAF, alerting, and AutoFix all fire correctly before the attacker does."

**5. Quantum-Safe Evidence Bundles (FIPS 204 ML-DSA + RSA Hybrid)** — `suite-core/core/quantum_safe_crypto_engine.py`
*Talking point:* "Auditor asks 'show me you knew about this on date X and fixed by date Y.' Signed evidence bundle is the answer."

**6. Air-Gap Native — Full Capability Offline**
All engines + LLM Council (Ollama/vLLM) + Brain Pipeline + MPTE + evidence signing — zero internet required. `FIXOPS_AIR_GAPPED=1`.
*Talking point:* "Classified/SCIF market is structurally unserved by every incumbent. ALDECI runs complete in a SCIF on day one."

**7. MCP Gateway — 650+ Tools** — `suite-core/core/mcp_server.py`
*Talking point:* "If your AI platform team wants to build a security copilot, ALDECI's MCP Gateway gives them 650+ actions."

**8. Switzerland — 32 Scanner Normalizers, Zero Rip-and-Replace** — `suite-core/core/scanner_parsers.py`
Ingests Snyk, Wiz, Trivy, Grype, Semgrep, ZAP, Burp, Checkmarx, SonarQube, Fortify, Veracode, Nessus, Nuclei, Prowler, Checkov, CycloneDX, SPDX, VEX, Dependabot + more.
*Talking point:* "You spent 3 years building Snyk + Wiz + Tenable. We don't ask you to throw it away."

**9. TrustGraph — Graph-Native with Closed-Loop Learning** — `suite-core/trustgraph/`
**119,765 nodes, 425,727 edges. 5 Knowledge Cores. 38.4% of platform emitting. 703 DPO pairs driving self-improvement.**
*Talking point:* "Traditional SIEMs store events. TrustGraph stores meaning."

---

## 30-Minute Demo Arc

| Time | Screen | Proof |
|---|---|---|
| 0–2 min | Command Hero | 1,247 findings → 38 critical → **12 MPTE-verified exploitable** |
| 2–6 min | Issues Hero | Score breakdown: Brain Pipeline contributing factors per finding |
| 6–14 min | Brain Hero | 12-step pipeline + LLM Council votes live (Qwen/Kimi/Gemma, 87% agreement) → MPTE fires |
| 14–20 min | Asset Graph | 119K node graph, Crown Jewels, attack paths, choke points |
| 20–26 min | Compliance Hero | Evidence vault, ML-DSA signature visible, SOC 2 coverage bar, generate report |
| 26–28 min | AutoFix | HIGH-confidence finding → PR diff → confidence score → auto-apply |
| 28–30 min | Close | "What would a 14-day POC need to prove for you to move forward?" |

---

## Top Objections

| Objection | Response |
|---|---|
| "We have Snyk + Wiz + Tenable." | "We ingest all three Day 1. We're the decision layer above your stack, not a replacement." |
| "Too busy to evaluate." | "14-day POC, pre-written SOW. 2 hours on Day 1. ALDECI runs itself after that." |
| "How is this different from Wiz?" | "Wiz doesn't scan app code, doesn't run micro-pentests, doesn't generate PRs, has no offline mode. We WIN or MATCH 83% of the combined capability surface across Wiz + 6 competitors." |
| "FedRAMP?" | "~95% NIST 800-53 Rev 5 in code today. SSP + POA&M complete. FedRAMP High In Process: 18 months post-Series A." |
| "Price?" | "Design partner: $0/90 days, full Enterprise, co-marketing. After: Enterprise $2,499/mo. Federal pricing separate." |

---

## The Ask

**Option A (preferred):** Signed design-partner agreement — $0, full Enterprise, co-marketing, weekly feedback.
**Option B (fallback):** 14-day POC, agreed success criteria, $2,500 (credited to subscription).

**Do not leave without a defined next step and a date.**
