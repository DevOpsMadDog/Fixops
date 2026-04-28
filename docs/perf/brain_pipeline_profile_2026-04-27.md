# Brain Pipeline — Performance Profile

**Date:** 2026-04-27
**Branch:** features/intermediate-stage
**Profiler:** cProfile (cumulative + tottime), single end-to-end run
**Payload:** 50 findings, 10 assets, representative CVE mix
**Pipeline status:** COMPLETED (all 12 steps, micro_pentest skipped)
**Total elapsed:** 3,006 ms

---

## Step-by-Step Wall-Clock Breakdown

| Step | Duration (ms) | % of total |
|------|---------------|------------|
| `generate_evidence` | **2,124** | **70.7 %** |
| `score_risk` | **710** | **23.6 %** |
| `deduplicate` | 91 | 3.0 % |
| `resolve_identity` | 44 | 1.5 % |
| `build_graph` | 9 | 0.3 % |
| `apply_policy` | 4 | 0.1 % |
| `run_playbooks` | 3 | 0.1 % |
| `enrich_threats` | 1 | 0.0 % |
| `normalize` | 1 | 0.0 % |
| `fp_auto_suppress` | 0.2 | — |
| `connect` | 0.04 | — |
| `llm_consensus` | 0.03 | — |

---

## cProfile — Top 30 by Cumulative Time

```
1,273,195 function calls in 2.976 s

ncalls  tottime  cumtime  location
     1    0.000    3.006  brain_pipeline.py:313(run)
     1    0.000    2.124  brain_pipeline.py:3905(_step_generate_evidence)
     1    0.000    2.121  quantum_crypto.py:542(sign)
     1    0.000    2.120  crypto.py:1252(sign_base64)
     1    0.000    2.120  crypto.py:1226(sign)
     1    0.000    2.111  crypto.py:468(private_key)
     1    0.000    2.111  crypto.py:514(_load_or_generate_keys)
     1    0.000    2.111  crypto.py:572(_generate_key_pair)          ← RSA-4096 keygen
     1    2.111    2.111  {built-in rsa.generate_private_key}        ← THE hotspot
     1    0.001    0.710  brain_pipeline.py:2603(_step_score_risk)
  2050    0.003    0.645  sklearn/ensemble/_gb.py:2141(predict)
    50    0.003    0.527  ml/risk_scorer.py:507(predict)             ← 50 separate predict() calls
  2050    0.169    0.494  sklearn/ensemble/_gb.py:970(_raw_predict)
    50    0.013    0.343  ml/risk_scorer.py:530(<listcomp>)
  4200    0.018    0.298  sklearn/utils/validation.py:2793(validate_data)
  2050    0.004    0.290  sklearn/ensemble/_gb.py:956(_raw_predict_init)
  4200    0.045    0.243  sklearn/utils/validation.py:725(check_array)
    50    0.003    0.182  ml/risk_scorer.py:582(explain_prediction)  ← 50 SHAP calls
  2050    0.002    0.155  sklearn/tree/_classes.py:485(_validate_X_predict)
  6250    0.006    0.102  sklearn/utils/validation.py:1621(check_is_fitted)
     1    0.000    0.091  brain_pipeline.py:1996(_step_deduplicate)
  4200    0.019    0.081  sklearn/utils/validation.py:103(_assert_all_finite)
  2050    0.002    0.075  sklearn/ensemble/_gb.py:94(_init_raw_predictions)
  2050    0.005    0.072  sklearn/dummy.py:624(predict)
     6    0.000    0.070  threading.py:295(wait)                     ← thread blocking
    22    0.070    0.070  {method 'acquire' of '_thread.lock'}
     2    0.000    0.070  concurrent/futures/_base.py:428(result)
 12500    0.007    0.062  sklearn/utils/_tags.py:250(get_tags)
```

---

## Top-5 Bottlenecks

### Bottleneck 1 — RSA-4096 key generation on every pipeline run
**File:** `suite-core/core/crypto.py:572` (`_generate_key_pair`)
**Cumulative time:** 2,111 ms — **70 % of total pipeline time**

`_generate_key_pair` is called on every evidence signing because no private key
path is configured (`FIXOPS_RSA_PRIVATE_KEY_PATH` unset), forcing the cryptography
library to generate a fresh 4096-bit RSA key pair in-process each run. RSA-4096
keygen is a computationally expensive operation (~2 s on Apple Silicon).

**Why it's slow:** CPU-bound prime factorisation in native C (`rsa.generate_private_key`
from the `cryptography` package). Single call, 2,111 ms self-time.

**Fix (high priority):**
1. Generate a persistent key pair once on first startup, persist to
   `data/keys/pipeline_signing.pem` (or a configurable path), and load it on
   subsequent runs. Add `FIXOPS_RSA_PRIVATE_KEY_PATH` to the deployment env.
2. Cache the loaded/generated key in the `CryptoManager` singleton so it
   survives across multiple `BrainPipeline.run()` calls in the same process.
3. Alternatively, switch Step 12 to HMAC-SHA256 for internal audit trails and
   reserve RSA for the final customer-export bundle only.

**Expected saving:** ~2,100 ms per run (from cold; ~0 ms warm when key is cached).

---

### Bottleneck 2 — GradientBoosting predict() called once per finding (N=50 → 2,050 tree evaluations)
**File:** `suite-core/core/ml/risk_scorer.py:507` (`predict`)
**Cumulative time:** 527 ms (≈ 10.5 ms per finding)

`_step_score_risk` loops over every finding and calls `risk_model.predict(finding)`
individually (line 2689 in `brain_pipeline.py`). Each sklearn GBT `predict()` call
carries per-call overhead from `validate_data` + `check_array` + `check_is_fitted`
(4,200 invocations of validation code for 50 findings). The sklearn GBT is not
batch-aware when called in a Python loop.

**Why it's slow:** Sklearn's `predict()` validates, reshapes, and calls
`_raw_predict` per individual call. 2,050 tree-level `_raw_predict` calls +
12,500 `get_tags` metadata calls are all fixed overhead multiplied by N.

**Fix:**
1. Batch all findings into a single numpy feature matrix and call
   `risk_model.predict_batch(X)` once. sklearn GBT natively handles 2D arrays
   with one `validate_data` pass → expected ~40x reduction in validation overhead.
2. Similarly batch `explain_prediction()` (currently 50 separate SHAP calls,
   182 ms cumulative). SHAP supports matrix input natively.

**Expected saving:** ~450–500 ms per 50-finding run; scales linearly with N.

---

### Bottleneck 3 — DeduplicationService thread overhead + SQLite writes
**File:** `suite-core/core/brain_pipeline.py:1996` (`_step_deduplicate`)
**Cumulative time:** 91 ms

`_step_deduplicate` wraps `DeduplicationService.process_findings_batch()` in a
`ThreadPoolExecutor(max_workers=1)` for timeout enforcement. For 50 findings this
adds thread startup + join overhead (~15–20 ms) on top of the SQLite writes in
`fixops_dedup.db`. At 10,000 findings the thread-per-step pattern becomes a
significant bottleneck because each step spawns a new pool.

**Why it's slow:** Thread creation overhead per pipeline run + synchronous SQLite
`INSERT OR REPLACE` for each finding cluster (no bulk-insert/executemany).

**Fix:**
1. Reuse a persistent `ThreadPoolExecutor` at the `BrainPipeline` instance level
   rather than creating a new one per step.
2. Replace per-finding `INSERT` with `executemany()` in `DeduplicationService`.
3. For local fallback path (`_local_dedup_findings`): the `hashlib.sha256` call
   inside the cluster-ID loop is redundant — pre-hash the dedup key during
   finding normalization in Step 2.

**Expected saving:** ~30–50 ms per run; 150–300 ms at 1,000 findings.

---

### Bottleneck 4 — Pure-Python Levenshtein in FuzzyIdentityResolver (O(n²) string matching)
**File:** `suite-core/core/services/fuzzy_identity.py:121` (`levenshtein_distance`)
**Self-time:** 25 ms (4,600 calls for 50 findings + 10 assets)

Step 3 (`resolve_identity`) runs Levenshtein edit-distance matching between every
finding's `asset_name` and every registered canonical asset. The function is a
pure-Python O(m×n) DP loop with no C extension. At 50 findings × 10 assets =
500 comparisons, cost is 25 ms. At 5,000 findings × 100 assets it becomes ~25 s.

**Why it's slow:** Pure Python inner loop; no early-exit on candidate shortlisting;
no index on string prefix/trigram to prune the candidate set before distance
computation.

**Fix:**
1. Replace with `rapidfuzz.distance.Levenshtein.distance()` (C extension, ~50x
   faster) — drop-in compatible since the function signature is identical.
2. Pre-filter candidates by first character or length-ratio before calling
   Levenshtein (prune candidates where `abs(len(a)-len(b)) / max(len(a),len(b)) > threshold`).
3. Cache `levenshtein_similarity(a, b)` results with `functools.lru_cache` for
   repeated asset-name comparisons across pipeline runs.

**Expected saving:** ~20–25 ms for 50 findings; 5–25 s at scale.

---

### Bottleneck 5 — sklearn `validate_data` / `check_array` called 4,200 times
**File:** `sklearn/utils/validation.py:2793` (`validate_data`)
**Cumulative time:** 298 ms (driven by Bottleneck 2)

This is a consequence of Bottleneck 2 — each individual `risk_model.predict()`
call triggers sklearn's full validation pipeline. `validate_data` (18 ms self),
`check_array` (45 ms self), `_assert_all_finite` (19 ms self), and `get_tags`
(14 ms self) are called 4,200 times total for 50 findings.

**Why it's slow:** sklearn's safety guards are designed for one-shot batch calls,
not N individual single-row calls in a tight loop.

**Fix:** Same as Bottleneck 2 — batch the predict call. Once inputs are a (N, F)
matrix, sklearn calls validate_data exactly once. All 4,200 repeated validation
calls collapse to a single pass.

**Expected saving:** ~280 ms per 50-finding run (scales linearly with findings count).

---

## Summary Table

| Rank | Bottleneck | File:Line | Cumul. ms | Root cause | Fix |
|------|-----------|-----------|-----------|-----------|-----|
| 1 | RSA-4096 keygen every run | `crypto.py:572` | 2,111 ms | No persistent key | Cache key in singleton |
| 2 | GBT predict() per-finding loop | `risk_scorer.py:507` | 527 ms | No batch predict | Batch N×F matrix |
| 3 | DeduplicationService thread + SQLite | `brain_pipeline.py:1996` | 91 ms | New ThreadPool per step | Persistent pool + executemany |
| 4 | Pure-Python Levenshtein | `fuzzy_identity.py:121` | 34 ms | Pure Python O(mn) | rapidfuzz C extension |
| 5 | sklearn validate_data × 4200 | `validation.py:2793` | 298 ms | Corollary of #2 | Fixed by batch predict |

---

## Profiler Artifacts

| File | Contents |
|------|---------|
| `docs/perf/brain_pipeline_profile_2026-04-27.txt` | Raw pstats output, top-30 cumtime |
| `docs/perf/brain_pipeline_profile_2026-04-27.json` | Structured JSON: step timings + top-30 cumtime + top-30 tottime |
| `scripts/profile_brain_pipeline.py` | Reproducible cProfile harness (run from repo root) |

---

## Reproduction

```bash
cd /Users/devops.ai/fixops/Fixops
python scripts/profile_brain_pipeline.py
```

Results written to `docs/perf/`.

---

## Notes

- pyinstrument was not installed; flamegraph skipped. Install with
  `pip install pyinstrument` then run
  `pyinstrument -o docs/perf/brain_pipeline_flamegraph.html scripts/profile_brain_pipeline.py`
  for an interactive flamegraph.
- LLM consensus (Step 9) took 0.03 ms because no LLM API keys are configured
  in the profiling environment — it fell through to the deterministic fallback.
  In production with 3 LLM providers the step will dominate at ~5–30 s (network-bound,
  not CPU-bound).
- `_sync_to_analytics` and `_mirror_to_security_findings_engine` did not fire
  because `data/analytics.db` does not exist in the profiling environment; both
  are O(N) SQLite writes and will add ~20–50 ms per 50 findings in production.
