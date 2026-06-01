# PM-4: Intelligence Quality Pre-Mortem — "the SCIF used free OSS instead"

**Lens:** does the intelligence justify $100K vs free Trivy + DefectDojo + OpenVAS, air-gapped?
**Method:** adversarial, grep-verified, file:line. No trust to docs.

## Verdict: 3 of 4 differentiating claims are NOT operational air-gapped today

| Claim | Reality (code) | Air-gap $100K-worthy? |
|---|---|---|
| Automated pen-test "proves exploitability" | `openclaw_engine.py:589` raises NotImplementedError; `:869` outcomes are `random.random()<success_prob`; router returns 501 | ❌ No — OpenVAS local does this free |
| AI council "multi-LLM consensus that gets smarter" | air-gap falls to `DeterministicLLMProvider` = CVSS→action lookup (`llm_providers.py:67`); learning loop off by default (`llm_learning_loop.py:105`) + drops cost=0 verdicts so learns nothing air-gapped; no trained local model (5,196<10k threshold) | ❌ No — equals a 10-line severity rule |
| TrustGraph blast-radius | `AttackPathEngine` never populated from scans (`brain_pipeline.py:909` read-only); returns 0 for fresh tenant | ❌ No — returns 0 |
| Function-level reachability (FP reduction) | Python real + solid (`function_reachability_engine.py:610`); TS/Java raise NotImplementedError (tree-sitter not in requirements.txt); Go absent; not auto-run on pipeline | ✅ **Yes, for Python** — the one real moat |

## What IS genuinely better than free OSS today
1. Python call-graph reachability (Endor charges $50k/yr for this).
2. Multi-scanner normalization + unified finding lifecycle + dedup/correlation into exposure cases.
3. SOC2 evidence-pack generation.
4. Multi-LLM consensus **when cloud keys present** (not air-gap).

## The 3 builds that make $100K honest in a SCIF
- **SPEC-002** Nuclei (local, MIT) pentest connector → real exploit verification, no SaaS. ~2-3wk.
- **SPEC-003** trigger Qwen LoRA distillation (lower threshold to 5k) + wire as AirGapLLMProvider → real local verdicts. ~1.5wk.
- **SPEC-001 (done) + SPEC-005** auto-populate TrustGraph + attack-path from scans on ingest so blast-radius ≠ 0. ~1wk.

Full evidence index in the agent transcript; key file:lines: openclaw_engine.py:1-18/589/869, llm_providers.py:67, llm_learning_loop.py:105/376, brain_pipeline.py:909, function_reachability_engine.py:875-1013.
