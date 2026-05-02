# suite-core 19 INSTALL / RETIRE / KEEP-AS-STUB Decisions — 2026-05-03

**Backlog:** suite-core triage `248911be`, "INSTALL/RETIRE-DEP" bucket (20 items).
**Excluded:** `quantum_crypto` (covered separately at `docs/quantum_crypto_retire_decision_2026-05-03.md`).
**Mode:** Read-only batch judgement. Caller counts from grep across `suite-*` + `tests/`. **None** of the 19 deps are pinned in `requirements.txt` / `requirements-test.txt` / `suite-api/backend/requirements*.txt` today.

## Tally

**5 INSTALL** + **9 RETIRE** + **5 KEEP-AS-STUB** = 19.

## Decision matrix

| # | Dep | Module (LOC) | Sites | Module consumers | Fallback in same file? | Decision | Rationale |
|---|---|---|---|---|---|---|---|
| 1 | `google.cloud.storage` | `cspm_engine.py` (1,813) | 1 | **9** | yes (boto/azure paths) | **INSTALL** | CSPM is shipped 3-cloud feature; AWS+Azure resolve, GCP path silently empty for tenants with GCP — pin `google-cloud-storage`. |
| 2 | `google.cloud.securitycenter` | `gcp_scc.py` (703) | 1 | 3 | yes (REST shim) | **INSTALL** | GCP SCC normalizer is one of 32 scanner normalizers in moat list — pin `google-cloud-securitycenter`. |
| 3 | `google.oauth2.service_account` | `cloud_connectors.py` (1,483) | 1 | 3 | yes (ADC env) | **INSTALL** | Required by both #1 and #2 — pin `google-auth` (transitive but make explicit). |
| 4 | `peft` | `llm_distill_router.py` (532) | 1 | 0 | yes (full-FT path) | **INSTALL** | LLM Phase 2 distillation is SCAFFOLDED in CLAUDE.md (Qwen 2.5 7B + LoRA r=16). LoRA = `peft`. Pin gated by `FIXOPS_DISTILL_TRAIN=1` so no install cost for non-training tenants. |
| 5 | `dilithium_py` | `crypto.py` | 1 | n/a | yes (RSA-only) | **INSTALL** | Pure-Python, zero C deps, activates real ML-DSA path per quantum_crypto decision. 5-line change for "PQ-ACTIVATE" follow-up. |
| 6 | `dilithium` | `quantum_crypto.py` (2,610) | 2 | 101 | yes | **KEEP-AS-STUB** | C-based PQ-Crystals SDK; superseded by `dilithium_py` (#5). Leave guard for opportunistic use; don't pin. |
| 7 | `oqs` | `quantum_crypto.py` | 2 | 101 | yes | **KEEP-AS-STUB** | `liboqs` adds C-library install burden for self-hosted SCIF tenants only. Algorithm-agile envelope already stubbed. |
| 8 | `pkcs11` | `hsm_provider.py` (556) | 2 | 4 | yes (software-keystore) | **KEEP-AS-STUB** | HSM integration is enterprise-tier feature; software fallback ships. INSTALL only when first SCIF/IL5 tenant signs (per quantum_crypto note). |
| 9 | `sentry_sdk` | `airgap_deployment.py` (1,723) | 1 | 2 | yes (no-op `init()`) | **KEEP-AS-STUB** | Observability is opt-in; airgap mode actively *disables* via `init()` reset. Guard is correct as-is. |
| 10 | `llama_cpp` | `single_agent.py` (2,404) | 1 | 2 | yes (HF transformers) | **KEEP-AS-STUB** | GGUF-quantised local inference path; we use HF/torch primary. Future "edge-deploy" mode. |
| 11 | `llm_guard` | `llm_guard_service.py` (427) | 4 | 2 | yes (own `aidefence_*`) | **RETIRE** | Per triage doc §3 — we ship our own guards (`core.aidefence_*`). 4 import sites all dead-fallback. **Delete the `try/except` arms** + module if no consumer remains. |
| 12 | `celery` | `task_queue.py` (522) | 1 | 1 | yes (in-process queue) | **RETIRE** | Project explicitly uses in-process queues (CLAUDE.md). Single consumer. Delete celery branch — keep in-process path only. |
| 13 | `chromadb` | `vector_store.py` (475) | 2 | 3 | yes (in-mem JSON) | **RETIRE** | Superseded by AgentDB (8,034+ entries, MiniLM-l6-v2, HNSW) per CLAUDE.md PRIMARY stack. Delete chromadb branch + redirect callers to `agentdb_bridge`. |
| 14 | `pomegranate` | `processing_layer.py` (492) | 1 | 3 | yes (custom Bayes) | **RETIRE** | Probabilistic-ML alt; never wired downstream. Custom Bayes path is what actually runs. Delete fallback. |
| 15 | `mchmm` | `processing_layer.py` (492) | 1 | 3 | yes (custom HMM) | **RETIRE** | Same as #14 — Markov-chain alt that never landed. Delete. |
| 16 | `river` | `zero_gravity.py` (2,157) | 1 | 3 | yes (custom NB) | **RETIRE** | Online-learning alt; custom GaussianNB ships. Delete river branch. |
| 17 | `headroom` | `context_compression.py` (123) | 1 | 2 | yes (truncate) | **RETIRE** | Marketing-only ML compression; truncation fallback ships and is sufficient. 123-LOC module. Delete headroom branch (likely retire whole module — only 2 consumers). |
| 18 | `feeds.feeds_service.FeedsService` | `intelligent_security_engine.py` | 2 | n/a | yes (no-op) | **RETIRE** | DEAD module per triage (not third-party — internal). Already in §1 DELETE bucket of triage doc. Listed here only because it sits beside the optional-dep cluster. |
| 19 | `trustgraph.store.KnowledgeStore` | `deployment_manager.py` | 1 | n/a | yes (no-op) | **RETIRE** | DEAD internal — superseded by `trustgraph.knowledge_store`. Already in §1 DELETE bucket of triage doc. |

## Top-5 INSTALL (highest customer impact)

1. **`google-cloud-storage`** + **`google-cloud-securitycenter`** + **`google-auth`** (#1-#3) — unblocks GCP CSPM/SCC for any tenant that selects GCP. 3-cloud parity is in the moat narrative; today GCP path silently empties.
2. **`peft`** (#4) — activates LoRA path for LLM Phase 2 distillation. Already 5,196/10,000 DPO pairs collected (52% to threshold). Install gated by `FIXOPS_DISTILL_TRAIN=1` so zero-cost for non-training tenants.
3. **`dilithium_py`** (#5) — flips quantum_crypto from "stub" to "real ML-DSA" with zero C-deps. Closes the gap between marketing claim ("FIPS 204 hybrid") and runtime reality.

## Top-5 RETIRE (cleanup wins)

1. **`llm_guard`** (#11) — 4 sites in a 427-LOC module that duplicates own `aidefence_*` guards. Largest dead-fallback surface in the bucket.
2. **`chromadb`** (#13) — directly contradicts CLAUDE.md PRIMARY stack (AgentDB). Removing reduces "two vector stores" confusion in onboarding docs + cuts 475-LOC module to ~150.
3. **`celery`** (#12) — in-process queue is canonical per CLAUDE.md; celery branch is dead.
4. **`pomegranate` + `mchmm` + `river`** (#14-#16) — three probabilistic-ML alts, none wired downstream. Custom paths ship. Delete all three guards in one PR.
5. **`headroom`** (#17) — marketing-only compression with truncation fallback that suffices. Module itself (123 LOC) is a candidate for full deletion — only 2 consumers.

## Top-3 actionable next moves

1. **One-line `requirements.txt` PR** pinning `google-cloud-storage`, `google-cloud-securitycenter`, `google-auth`, `dilithium-py` (and `peft` behind extras-flag) — unblocks #1-#5 in <30 min, zero engine changes. Tests stay green because guards already permit absence.
2. **Single retire PR** deleting the `try/except` fallbacks for `llm_guard` + `chromadb` + `celery` + `pomegranate` + `mchmm` + `river` + `headroom` — net ~80 LOC removed, zero behavior change (custom paths already ship). Pairs cleanly with the Wave-A DELETE PR from `60a8ea9e`.
3. **File "PQ-ACTIVATE" ticket** (per quantum_crypto doc) — pin `dilithium-py`, add Beast Mode test asserting `_backend == "dilithium-py"` when env flag set, update CEO_VISION/CTEM_PLUS_IDENTITY/ARCHITECTURE_v3 marketing copy from "live FIPS 204" to "algorithm-agile, activatable". <1 day total.
