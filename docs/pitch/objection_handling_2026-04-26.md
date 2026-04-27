# ALDECI — Top-10 Objection Handling (2026-04-26)

> Honest playbook. Every response cites a doc, commit, or file. If you can't cite it, you can't say it.
> Audience: Federal SCIF sponsor · Enterprise CISO · Reseller alliance lead.

---

## 1. "You're a startup with no FedRAMP authorization."

**Concede:** Correct. We are FedRAMP High *aware* and *control-mapped* — not *authorized*. We will not put a FedRAMP logo on a slide today.

**Reframe:**
- 3 SCIF requirements **MET** today: air-gapped deployment (1,427 LOC, signed offline bundle), quantum-safe evidence signing (FIPS 203/204/205 engine), tamper-evident audit log.
- 7 PARTIAL — code shipped, packaging or documentation pending. 5 MISSING — all on the 12–18 month plan.
- **95% of in-scope NIST SP 800-53 Rev 5 controls implemented in code** (17 control families enumerated in `core/fedramp_controls.py`); the gap is the SSP document, not the controls.
- We have a documented **20-day pilot path** that gets a working air-gap install inside the sponsor's perimeter on Day 20 — without waiting for the 3PAO timeline.

**Source:** `docs/scif_readiness_2026-04-26.md` §0–§4. Stage 1 hardening shipped today: 8/8 deliverables, 12/12 tests.

---

## 2. "We already have Snyk."

**Concede:** Snyk has a stronger IDE plugin footprint, a richer open-source vulnerability database, and Snyk Code (DeepCode AI) for SAST autofix on PR. We score `LOSE` on 4 of 22 Snyk capabilities and we don't pretend otherwise.

**Reframe:** ALDECI is the **consolidation play**, not the SAST replacement. Of the same 22 Snyk capabilities, we **WIN** on 11 and **MATCH** on 7 — including the 6 moats Snyk has never built (Multi-LLM Consensus, 12-step Brain Pipeline, MPTE 19-phase exploit verification, FAIL chaos engine, quantum-safe evidence, MCP gateway). We also ingest Snyk's output as a normalizer (`scanner_parsers.py`), so you keep Snyk and add ALDECI as the decision layer above it.

**Source:** `docs/competitive_validation_2026-04-26.md` §0 TL;DR + §1.A row "200+ scanner ingestion".

---

## 3. "Why not Wiz?"

**Concede:** Wiz is the deepest gap on our scorecard — 7 LOSE cells of 24 (Security Graph UX polish, agentless snapshot scale, DSPM data classification, CIEM polish, multi-cloud depth on OCI/Alibaba, 100+ frameworks UI, post-Google ecosystem). For a pure cloud-only customer in AWS/Azure/GCP with no on-prem footprint, Wiz is excellent.

**Reframe:** Wiz cannot run inside a SCIF. Wiz is SaaS-only — there is no air-gapped Wiz, no FedRAMP High Wiz, no IL5 Wiz. ALDECI ships an air-gapped distribution today (`core/airgap_deployment.py`, signed offline bundle, 2-machine transfer). For any customer where the sovereignty boundary matters — federal, defense, sovereign cloud, regulated EU — Wiz is structurally unavailable and ALDECI is the only graph-native option.

**Source:** `docs/competitive_validation_2026-04-26.md` §1 row "Air-gapped deployment" (we MET, Wiz NA) + §1.H row "On-prem K8s/Helm".

---

## 4. "Multi-LLM consensus sounds expensive — every finding pays 3x token cost?"

**Concede:** Naively, yes. Three or more model invocations per finding would be cost-prohibitive at scale.

**Reframe:** We solved this. Pre-flight cost gating ships in `GAP-061 DONE` — a tiered LLM router that uses cheaper models (Qwen, DeepSeek free tiers) for low-stakes findings and only escalates to premium models (Opus class) when consensus disagreement crosses a threshold. Self-hosted vLLM and Ollama paths (`core/llm_providers.py` lines 1083 and 1319) bring marginal token cost to the price of GPU time you already pay for. Air-gapped deployments don't pay LLM API costs at all.

**Source:** `docs/competitive_validation_2026-04-26.md` §1.C row "Pre-flight LLM cost gating"; commit history references `vllm_autofix_adapter.py`.

---

## 5. "Multi-tenant SaaS with multi-LLM means our data trains your models."

**Concede:** This is the right concern to raise. Most "AI security" vendors do exfil findings to train shared models.

**Reframe:**
- ALDECI's preference learning loop (commit `cbd01c4d`) writes DPO pairs to **your tenancy's TrustGraph**, not a shared store. Your data improves your tenancy.
- Air-gapped deployments use self-hosted LLMs (vLLM / Ollama) — your data physically cannot leave the perimeter.
- SaaS deployments use a tenant-scoped knowledge core; cross-tenant inference is blocked at the RBAC layer (`core/tenant_isolation_auditor.py`).
- The single-tenant SCIF SKU disables multi-tenant features entirely (Phase 2 of the SCIF plan, Months 2–5).

**Source:** Commit `cbd01c4d` (closed-loop subscriber); `docs/scif_readiness_2026-04-26.md` §2 row 12 ("Multi-tenant tenant-isolation guarantee").

---

## 6. "How do I know your scanners are as good as the specialists?"

**Concede:** For the deepest single-tool benchmarks (Snyk OSS DB scale, Sonatype Advanced Binary Fingerprint, Tenable Nessus host-vuln heritage), we don't claim to beat the specialist. We score `LOSE` on those rows in the validation matrix and we publish the list.

**Reframe:** ALDECI is dual-mode — **WIN** cell on the validation matrix because no other vendor offers this. We run our own native engines (SAST 110 OWASP rules, SCA via OSV/GHSA, IaC via Checkov/tfsec wrap, Container via Trivy/Grype, Secrets entropy + 200 patterns, DAST via ZAP wrap) AND we ingest output from 32 third-party scanners. You keep your specialist for the slice where it wins; you get one decision layer above all of them.

**Source:** `docs/competitive_validation_2026-04-26.md` §1.A (native engines) + §1.H row "Dual-mode (orchestrate + native)" — only ALDECI scored WIN.

---

## 7. "$1,499/month enterprise tier sounds too cheap to be real."

**Concede:** Versus published Snyk/Wiz/Tenable list prices, that is correct.

**Reframe:** Pricing is intentional. We are a consolidation play — the buyer thesis only works if our enterprise tier is dramatically below the sum of the tools we replace. The $1,499/month list is the published per-tenant baseline; large enterprises with custom connectors, MCP gateway entitlements, and support SLA scale up from there. Federal SCIF deployments are a separately-priced single-tenant SKU co-designed with the sponsor — the public price is not the SCIF price.

**Source:** `CLAUDE.md` "WHAT IS ALDECI" pricing line; `docs/competitive_validation_2026-04-26.md` row GAP-054 ("DONE — tiered $199/$499/$1499 pricing page shipped").

---

## 8. "What's your moat once Snyk / Wiz copy this?"

**Concede:** Multi-LLM consensus and 12-step Brain Pipelines are not patentable in any defensible way. Copy is the eventual reality.

**Reframe:** Our moat is the **closed loop on tenant data**. Commit `cbd01c4d` wired the production subscriber today — every finding generates a DPO preference pair, every analyst override silently improves the next decision, every TrustGraph (already 119k nodes / 425k edges) gets denser over time. A vendor copying the architecture next year still starts with an empty graph and zero preference history. The compounding asset is the tenancy's accumulated preferences, not the model.

Secondary moats: air-gap shipping (zero-day for SCIF customers), 6-of-6 unique technical capabilities (MPTE 19-phase, FAIL chaos, MCP gateway, quantum-safe evidence) — each one is 6+ months of work to clone from scratch.

**Source:** Commit `cbd01c4d` + `docs/competitive_validation_2026-04-26.md` §0 ("All 6 unique moats shipped, 806 tests passing").

---

## 9. "We tried 'AI security' before. It hallucinated and we turned it off."

**Concede:** Single-model AI in security has a real false-positive problem. The cohort of "ChatGPT for SAST" tools that shipped in 2024–2025 earned the skepticism.

**Reframe:** Consensus is the antidote to hallucination. ALDECI requires **3+ models to agree at an 85% threshold** before any decision ships (`core/llm_consensus.py`). If they don't agree, the finding is escalated to human review with the full disagreement trace. The Brain Pipeline has a verification stage (MPTE 19-phase) that *proves exploitability with a real test* before any high-confidence call is made — we don't infer from a graph, we run the exploit in a sandbox. Confidence-gated AutoFix means automated remediation only ships when confidence crosses your configured threshold.

**Source:** `docs/CTEM_PLUS_IDENTITY.md` (Multi-LLM Consensus Decision Engine + MPTE sections); `docs/competitive_validation_2026-04-26.md` §1.C row "Continuous exploit verification" — ALDECI WIN, all 7 competitors NA or LOSE.

---

## 10. "Why should we believe a startup can keep up with 32 scanner integrations and 28 threat feeds?"

**Concede:** Maintaining 32 normalizers and 28 feeds is real engineering surface. We ship a per-week regression risk every time an upstream vendor changes their JSON schema.

**Reframe:**
- We have **806 Beast Mode tests passing today** with zero regressions on the last verified commit (`5f17b5e6`).
- We use a **universal connector** abstraction (`GAP-034 DONE` in the validation matrix) — adding a new scanner is field-mapping work, not a new codebase.
- Our **autonomous build infrastructure** (Beast Mode v6, see `CLAUDE.md`) runs an overnight test + rebuild loop on a Kanban-controlled agent fleet (SwarmClaw + OpenClaw), which means scanner schema drift gets caught and fixed without human intervention in most cases.
- Open-source scanners have stable formats (SARIF, CycloneDX, SPDX); commercial vendors with stable APIs (Snyk, Wiz) are integrated via API-LIVE adapters, not parser scraping.

**Source:** `CLAUDE.md` "EXISTING INVENTORY" table + `docs/competitive_validation_2026-04-26.md` §1.F row "Universal connector".

---

## Closing posture

If an objection isn't on this list and we don't have a citation for the answer, we say "I don't know — let me get back to you with a doc reference." Honesty is the moat the validation matrix and the SCIF scorecard were built to enable. Every response above traces to a file in this repo.

*Sources of truth: `docs/competitive_validation_2026-04-26.md` · `docs/scif_readiness_2026-04-26.md` · `docs/CTEM_PLUS_IDENTITY.md` · `CLAUDE.md` · git log on `features/intermediate-stage`.*
