# Self-Learning LLM Scope

**Date:** 2026-04-26
**Branch:** `features/intermediate-stage`
**Author:** enterprise-architect
**User ask:** "We are going to build an LLM that self-learns from these [TrustGraph] interconnections."

---

## 0. TL;DR

**Recommendation: Path (a) RAG over TrustGraph + lightweight DPO from existing self-learning feedback signals — ship in 6–8 weeks.**

Defer (b) continued pre-training and (c) full RLHF until we have:
- ≥10K closed remediation events as a training corpus
- A SCIF customer or design partner who values bespoke weights enough to accept the operational cost
- Hardware budget for ≥1× H100 / 8× A100 cluster

We have **most of the infrastructure already**. The marketing narrative ("self-learning LLM") is achievable today by combining:
- `core/llm_council.py` (Karpathy 3-stage council, 1100+ LOC)
- `core/self_learning.py` + `core/ml/online_learning.py` (already exists)
- `suite-api/apps/api/self_learning_router.py` (837 LOC, 5 feedback loops live, DEMO-012)
- `core/trustgraph_event_bus.py` (event fabric)
- `core/trustgraph_indexer.py` (5 Knowledge Cores)
- `core/vllm_autofix_adapter.py` + `OllamaSelfHostedProvider` + `VLLMSelfHostedProvider` (air-gap inference)

The "LLM" is *already* a council. The "self-learning" is *already* a 5-loop feedback router. What's missing is the **closed loop where feedback signal updates model behavior** — and we can do that without retraining a foundation model.

---

## 1. Current State (Honest)

### 1a. LLM Council (`core/llm_council.py`)

Implements Karpathy 3-stage:
1. Independent analysis (parallel, no cross-talk)
2. Anonymous peer review (members can revise)
3. Chairman synthesis (strongest model writes verdict)

Council members today (per `CouncilFactory`):
- Vulnerability Researcher (DeepSeek R1 free tier)
- Regulatory Analyst (DeepSeek R1)
- Attack Chain Analyst (DeepSeek R1)
- + Qwen 3.6, Gemma, Kimi K2, Llama 4 (via OpenRouter / MuleRouter / Ollama / vLLM)
- Optional Opus escalation when disagreement > threshold

This is **real, working, and unique to us** — Snyk/Wiz/Tenable have monolithic LLM features, not councils.

### 1b. Self-Learning Router (`suite-api/apps/api/self_learning_router.py`)

5 feedback loops live:
- `/feedback/decision` — was the AI's action correct?
- `/feedback/mpte` — was the predicted-exploitable signal correct?
- `/feedback/false-positive` — analyst FP flag
- `/feedback/remediation` — did the autofix actually fix?
- `/feedback/policy` — policy violation outcome

Plus learning ops:
- `/compute-adjustments` — runs the learning step (feedback → weight updates)
- `/score-with-learning` — before/after demo
- `/weights` GET/PUT — inspect/override learned weights
- `/metrics/trends` — learning improvement over time

These already produce a **weight vector** that is consumed by scoring. That's a real signal; what it's NOT is a re-trained transformer.

### 1c. TrustGraph Indexer (`core/trustgraph_indexer.py`)

5 Knowledge Cores:
- Core 1 — Customer Environment (assets, connectors, scanners)
- Core 2 — Threat Intelligence (28 feeds)
- Core 3 — Compliance & Regulatory (7 frameworks)
- Core 4 — Decision Memory (LLM verdicts, analyst overrides)
- Core 5 — (reserved — likely Remediation outcomes)

This is a knowledge store ready to be a RAG retrieval index.

### 1d. Air-gap LLM (vLLM + Ollama)

`VLLMSelfHostedProvider` + `OllamaSelfHostedProvider` exist. CLAUDE.md notes Ollama is "labeled retired" — interpret that as **vLLM is the production air-gap path**, Ollama remains for dev convenience.

### 1e. ML Training Infrastructure

Grep for `LoRA`, `peft`, `RLHF`, `DPO`, `fine-tune`, `distill` returns **no actual training code**. The grep hits in 10 files are passing references in docstrings/finding-content, not implementations. **We have no training stack today.**

---

## 2. The Four Paths — Evaluated

### Path (a) — RAG over TrustGraph as knowledge store + lightweight DPO on weights

| Dimension | Estimate |
|---|---|
| Engineering complexity | Low |
| Time-to-ship | **6–8 weeks** |
| Hardware | Existing inference (vLLM on 1× A100 / L40S) |
| Quality at launch | Good — RAG-anchored answers feel "learning" because they reflect *this* customer's history |
| SCIF compatibility | Excellent (everything stays on-prem) |
| Marketing message | "LLM grounded in your security graph that gets better as you triage" — defensible |

**Mechanism:**
1. RAG retriever over TrustGraph nodes/edges (bm25 + dense via SentenceTransformers)
2. Council prompts include retrieved context: "Per Core 4 Decision Memory, this org has accepted-risk on similar findings 14× in last 90 days …"
3. Self-learning router's weight vector adjusts retrieval rerank + council member voting weight (we already store this)
4. Lightweight DPO: the existing `feedback/decision` outcomes form (chosen, rejected) pairs for prompt-template tuning, not weight tuning. Use trl `DPOConfig` against a small adapter.

**Risk:** "DPO without retraining the base model" sounds inadequate to investors. Reframe as "online preference learning + RAG personalization."

### Path (b) — Continued pre-training of small open-weight model on org-specific corpus

| Dimension | Estimate |
|---|---|
| Engineering complexity | Medium-High |
| Time-to-ship | **4–9 months** |
| Hardware | 8× A100 80GB or 4× H100 for ~7 days per training run |
| Quality | High but plateau-prone unless corpus is large |
| SCIF compatibility | Excellent — model is yours |
| Cost | $40–120K per training run on cloud, ~$300K capex if owning hardware |

Candidates: Llama 3.1 8B (best general), Qwen 3.6 Coder 7B (best code), Phi-3.5 (cheapest), DeepSeek Coder V2 16B (best code at moderate scale).

**Reality check:** Continued pre-training assumes a domain corpus large and high-signal enough to shift weights. Our entire TrustGraph today is small-data per customer. This path is *premature* — would produce a slightly-better-at-jargon model that doesn't pay back the 4-month investment.

**When it becomes worth doing:** when we have ≥3 SCIF customers each with ≥6 months of operational data. **Earliest realistic: Q4-2026 / Q1-2027.**

### Path (c) — Full RLHF / DPO loop where each closed remediation = positive signal

| Dimension | Estimate |
|---|---|
| Engineering complexity | High (research-grade) |
| Time-to-ship | **9–18 months** |
| Hardware | 8× H100 + reward-model training rig |
| Quality | Highest *if* signal volume is sufficient |
| SCIF compatibility | Excellent (post-launch) — but training itself probably needs internet |
| Risk | Reward hacking, distribution shift, expensive rollback |

**Reality check:** RLHF needs ~100K+ preference pairs to be stable per Anthropic/OpenAI literature. We have ~hundreds today. **Premature by 12+ months.**

### Path (d) — Knowledge distillation: Opus generates training data, smaller model learns

| Dimension | Estimate |
|---|---|
| Engineering complexity | Medium |
| Time-to-ship | **3–5 months** |
| Hardware | 4× A100 for student training; Opus API spend $20–80K depending on corpus size |
| Quality | Very good for narrow tasks (triage, severity scoring) |
| SCIF compatibility | Excellent — final student is on-prem |
| Cost | $100K–250K total |

**This is the second-best near-term path.** Distill Opus's behavior on triage/severity/policy tasks into a Qwen 3.6 7B student. Ship as a swappable council member that runs at 50× lower cost.

**When to do this:** *After* Path (a) ships and we have a baseline to measure against.

---

## 3. Recommended Path: (a) Now → (d) in 6 months → (b) in 12 months

### Phase 1 — Self-Learning v1 (Weeks 0–8)

Goal: ship the user-visible "LLM is learning from your decisions" experience.

| Task | Effort |
|---|---:|
| RAG retriever (bm25 + dense) over Core 4 Decision Memory | 2 wk |
| Wire self-learning weight vector into council voting weights (currently isolated) | 1 wk |
| DPO on prompt templates using `trl` + existing feedback pairs | 2 wk |
| Demo flow: "Show before/after on the same finding after 100 feedback events" | 1 wk |
| Telemetry: learning-curve dashboard at `/api/v1/self-learning/metrics/trends` (already exists — extend) | 1 wk |
| Air-gap path: vLLM + DPO LoRA adapter, signed adapter bundle for offline import | 1 wk |

**Deliverable:** "ALDECI's council learns from your triage decisions and reranks future decisions accordingly. Demonstrable in 30 seconds."

### Phase 2 — Distilled Specialist Member (Weeks 8–24)

Goal: replace the most-expensive council member (Opus escalation) with a distilled local model on triage tasks.

- Collect 50K Opus verdicts from production
- Distill into Qwen 3.6 7B with LoRA
- Add as council member; benchmark against Opus on held-out set
- Ship if quality ≥ 90% of Opus on triage; keep Opus for novel/high-disagreement cases only

**Deliverable:** "10× cheaper inference per finding. SCIF-native."

### Phase 3 — Org-Specific Continued Pre-Training (Quarters 4–8)

Only if a SCIF customer demands it AND we have ≥6mo of their data. Use Llama 3.1 8B base + LoRA continued pre-training on their normalized graph + decisions corpus.

**Deliverable:** "Bespoke model per facility — your weights stay in your SCIF."

---

## 4. Architecture Decisions Triggered

Three new ADRs to write:

- **ADR-NEW-1** — Self-Learning v1 = RAG + DPO on prompt templates (NOT base-model retraining)
- **ADR-NEW-2** — vLLM is the canonical air-gap inference backend; Ollama is dev-only
- **ADR-NEW-3** — Council member roster is dynamic; distilled student models can replace API members per-task

These will land in `.claude/team-state/architecture/adrs/` as a follow-up.

---

## 5. Honest Caveats

- **"Self-learning" is a loaded marketing term.** What we'll ship in Phase 1 is *not* a model that updates its weights at inference time. It's a council whose retrieval, voting, and prompt templates adapt to feedback. That is a *legitimate* form of learning and matches what Cursor/Copilot/Codeium ship — but be precise in materials.
- **The user's framing — "LLM that self-learns from TrustGraph interconnections"** — implies some form of graph-aware reasoning. RAG over the graph satisfies this. A graph neural network *consumed by* the LLM as additional context would satisfy it more deeply; consider as Phase 2.5 if a customer pushes.
- **Air-gap training is hard.** All three "real training" paths (b, c, d) implicitly require internet access for at least the initial base-model download. SCIF customers will need a "model-card SBOM" (training data, weights hash, attestation chain) for ATO. Plan that artefact alongside Phase 2.

---

## 6. Open Questions for CTO

1. **Hardware budget approval.** Phase 2 distillation needs ~$100K. In or out for FY-2026?
2. **Marketing posture.** Is "self-learning LLM" the headline, or "Council that learns from your decisions"? The latter is more defensible.
3. **Customer co-design.** Are any current design partners interested in Phase 3 bespoke weights? That would justify the H100 rig spend.

---

*End scorecard.*
