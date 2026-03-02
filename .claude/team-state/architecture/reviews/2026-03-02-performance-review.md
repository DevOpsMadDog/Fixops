# Performance & Data Flow Review: Brain Pipeline (V3, V5)

**Date**: 2026-03-02 (Run 7 — updated with deeper analysis)
**Reviewer**: enterprise-architect
**Scope**: `suite-core/core/brain_pipeline.py` (1,597 LOC), `suite-core/core/services/deduplication.py`
**Pillar**: V3 (Decision Intelligence), V5 (MPTE Verification)
**Grade**: **B** (Good for demo, two P1 optimizations for Phase 2)

---

## 1. Data Flow Trace (End-to-End)

```
PipelineInput
  └─ findings: List[Dict]
  └─ assets: List[Dict]
  └─ options: run_pentest, run_playbooks, generate_evidence

┌─── PIPELINE EXECUTION (Sequential, 300s timeout) ───────────────────────┐
│                                                                          │
│  [1] Connect ─────── tally counts, O(1)                                 │
│  [2] Normalize ───── setdefault on each finding, O(n)                   │
│  [3] Identity ────── FuzzyIdentityResolver.resolve() per finding, O(n)  │
│  [4] Deduplicate ─── DeduplicationService per finding, O(n) DB writes   │
│  [5] Graph ───────── upsert_node per finding in batches of 500, O(n)    │
│  [6] Enrich ──────── ThreatEnricher or severity-based estimate, O(n)    │
│  [7] Score Risk ──── ML model or deterministic formula, O(n)            │
│  [8] Policy ──────── Rule evaluation per finding, O(n × rules)          │
│  [9] LLM ─────────── Severity-grouped batch, O(1) LLM call (capped)    │
│  [10] MPTE ───────── Top 10 CVEs × 5 URLs, O(1) bounded                │
│  [11] Playbooks ──── AutoFix for blocked findings, O(actionable)        │
│  [12] Evidence ───── Bundle generation, O(1)                            │
│                                                                          │
│  Overall: O(n) per step × 12 steps ≈ O(12n)                            │
│  Worst case: Step 4 creates n DB connections (each with I/O)            │
└──────────────────────────────────────────────────────────────────────────┘
```

## 2. Context (ctx) Object — Shared Mutable State

The `ctx` dict is passed to all 12 steps, carrying state between them:

| Key | Populated By | Consumed By |
|-----|-------------|-------------|
| `findings` | Input + Step 2 mutates | Steps 3-8, 10, 11 |
| `assets` | Input | Steps 3, 5, 7, 10 |
| `clusters` | Step 4 | Step 5 |
| `exposure_cases` | Step 4 | Step 5 |
| `risk_scores` | Step 7 | Step 9, Summary |
| `policy_decisions` | Step 8 | Step 12 |
| `llm_results` | Step 9 | — |
| `pentest_results` | Step 10 | Summary |
| `playbook_results` | Step 11 | Step 12, Summary |
| `graph_stats` | Step 5 | Step 12 |
| `metrics` | All steps | Final metrics |

**Observation**: Steps 9 (LLM) and 10 (MPTE) are independent — they both READ from `findings` and `risk_scores` but write to different keys. They could be parallelized.

## 3. Performance Bottleneck Analysis

### P1: Dedup Service — N DB Connections per Pipeline Run
**File**: `suite-core/core/services/deduplication.py:166-278`
**Issue**: `process_finding()` opens a NEW `sqlite3.connect()` for EACH finding.
For 1000 findings: 1000 connections opened, committed, and closed.
**Impact**: SQLite open/close is ~1ms per connection. At 10K findings = ~10s overhead.
**Fix (Phase 2)**: Refactor `process_findings_batch()` to open ONE connection and pass to `process_finding()`. Batch commit every 100 findings.
**Status**: Connection leak FIXED this session (added try/finally). Connection-per-finding remains as TD-020.

### P2: AutoFixEngine Created Per Finding (FIXED)
**File**: `suite-core/core/brain_pipeline.py:1352-1364` (Step 11)
**Issue**: `AutoFixEngine()` was instantiated inside the per-finding loop. Each instance creates empty caches.
**Impact**: For 50 blocked findings: 50 instantiations instead of 1.
**Status**: ✅ FIXED this session. Engine hoisted outside loop.

### P3: Knowledge Graph — Serial upsert_node Per Finding
**File**: `suite-core/core/brain_pipeline.py:806-857` (Step 5)
**Issue**: Each finding calls `brain.upsert_node()` individually, even though batched at 500.
**Impact**: If `upsert_node` does DB I/O, this is serial I/O within each batch.
**Mitigation**: Already batched at GRAPH_BATCH_SIZE=500. CVE nodes deduplicated.
**Fix (Phase 2)**: Add `brain.upsert_nodes_batch()` for bulk operations.

### P4: Steps 9+10 Sequential but Independent
**Issue**: LLM consensus (Step 9) and MPTE (Step 10) run sequentially. Both are I/O-bound. Combined timeout: 60s + 120s = 180s worst case.
**Fix (Phase 2)**: Run Steps 9+10 in parallel using `asyncio.gather()` or `concurrent.futures`.
**Savings**: ~60-120s on average pipeline run with both enabled.

## 4. Memory Safety Analysis

| Control | Limit | Location | Status |
|---------|-------|----------|--------|
| Findings cap | 50,000 | Line 254-258 | ✅ |
| Assets cap | 10,000 | Line 259-263 | ✅ |
| String truncation | 10,000 chars | Line 211-235 | ✅ |
| Runs history | 1,000 | Line 272-279 | ✅ |
| Metrics history | 100 | Line 429-430 | ✅ |
| LLM batch cap | 100 findings | Line 1138 | ✅ |
| Graph batch | 500 per batch | Line 187 | ✅ |
| Sanitize depth | 5 levels | Line 203-204 | ✅ |
| MPTE CVE cap | 10 CVEs | Line 1263 | ✅ |
| MPTE URL cap | 5 URLs | Line 1270 | ✅ |

**Verdict**: All memory bounds are properly enforced. No unbounded growth vectors.

## 5. Timeout Analysis

| Timeout | Value | Protected By | Location |
|---------|-------|-------------|----------|
| Pipeline global | 300s | monotonic check per step | Line 313, 346 |
| Dedup step | 60s | ThreadPoolExecutor + timeout | Line 630 |
| LLM step | 60s | ThreadPoolExecutor + timeout | Line 1194 |
| MPTE step | 120s | ThreadPoolExecutor + timeout | Line 1293/1347 |
| STEP_TIMEOUT_S | 60s | Used by dedup + LLM | Line 206 |

**Gap**: Steps 3, 5, 6, 7, 8, 11 have NO individual timeout protection. If `FuzzyIdentityResolver` or `get_brain()` hangs, only the 300s global timeout catches it.

## 6. Thread Safety Analysis

| Component | Thread-Safe? | Mechanism |
|-----------|-------------|-----------|
| `_runs` dict | ✅ | `threading.Lock` at line 200, 270, 341, 426, 453, 509, 514 |
| `_metrics` list | ✅ | Same lock |
| `_cancelled` set | ✅ | Same lock |
| Singleton creation | ✅ | Double-checked locking at line 1517-1533 |
| `run()` method body | ⚠️ | Each run operates on own ctx — thread-safe by isolation |
| External services | Depends | Each service manages its own thread safety |

## 7. Error Handling Quality

| Step | Handles Failure? | Error Sanitized? | Degradation |
|------|-----------------|-------------------|-------------|
| 3 Identity | ✅ returns skipped | ✅ type name only | Continues without resolution |
| 4 Dedup | ✅ returns skipped | ✅ type name only | Continues with empty clusters |
| 5 Graph | ✅ returns skipped | ✅ type name only | Continues without graph |
| 6 Enrich | ✅ severity fallback | ✅ type name only | Uses calibrated estimates |
| 7 Score | ✅ deterministic fallback | ✅ type name only | Weighted formula |
| 8 Policy | Always succeeds | N/A | Default rules |
| 9 LLM | ✅ deterministic fallback | ✅ type name only | Risk distribution decision |
| 10 MPTE | ✅ returns skipped | ✅ type name only | Continues without validation |
| 11 Playbooks | ✅ per-finding try/except | ✅ type name only | Skips failing fixes |
| 12 Evidence | Always succeeds | N/A | Bundle generation |

**Verdict**: ✅ Excellent graceful degradation. Every external dependency has a fallback.

## 8. Performance Benchmarks (Estimated)

| Findings | Steps 1-8 | Step 9 (LLM) | Step 10 (MPTE) | Total |
|----------|-----------|---------------|----------------|-------|
| 100 | ~2s | ~5s | ~10s | ~17s |
| 1,000 | ~10s | ~5s | ~10s | ~25s |
| 10,000 | ~60s | ~5s | ~10s | ~75s |
| 50,000 | ~240s | ~5s | Timeout (300s) | Timeout |

**Bottleneck at scale**: Step 4 (Dedup) with N DB connections dominates at >10K findings.

## 9. Fixes Applied This Session

1. **brain_pipeline.py Step 11**: Hoisted `AutoFixEngine()` creation outside per-finding loop. Saves N-1 instantiations for N blocked findings.
2. **deduplication.py**: Added `try/finally` around SQLite connection in `process_finding()`. Prevents connection leak on SQL error.

## 10. New Tech Debt Items Identified

| ID | Title | Priority | Impact |
|----|-------|----------|--------|
| TD-020 | Dedup opens N DB connections per batch | Phase 2 | 10s overhead at 10K findings |
| TD-021 | Steps 9+10 sequential but independent | Phase 2 | 60-120s savings if parallelized |
| TD-022 | No per-step timeout on Steps 3,5,6,7,8,11 | Phase 2 | Steps can hang until global 300s timeout |

## 11. Overall Assessment

**Strengths**:
- Comprehensive memory bounds prevent DoS
- Graceful degradation on all external dependencies
- Error messages sanitized (no PII/secret leakage)
- Thread-safe singleton with proper locking
- Pipeline timeout prevents infinite blocking
- Cooperative cancellation support

**Weaknesses**:
- Dedup creates N DB connections (perf at scale)
- Steps 9+10 sequential when they could be parallel
- No per-step timeout for computational steps
- AutoFixEngine was per-finding (FIXED)
- Connection leak in dedup (FIXED)

**Demo Readiness**: ✅ READY — All issues are performance-at-scale, not correctness. Demo with <1000 findings runs in <30s.

## 12. Memory Profile (Updated Run 7)

| Object | Size at N=50K | Bounded? |
|--------|-------------|----------|
| `ctx["findings"]` | ~250 MB (50K x 5KB avg) | Yes (MAX_FINDINGS) |
| `ctx["clusters"]` | ~500 KB (list of IDs) | Yes (<=findings) |
| `ctx["risk_scores"]` | ~2 MB (dict + list) | Yes (<=findings) |
| `_runs` | ~50 MB (1000 x 50KB) | Yes (MAX_RUNS_HISTORY) |
| `_metrics` | ~500 KB (100 x 5KB) | Yes (capped at 100) |
| **Peak total** | **~300 MB** | All bounded |

## 13. Thread Safety Detail (Updated Run 7)

The `_cancelled` set read at line 331 (`if result.run_id in self._cancelled`) occurs without the lock.
This is technically a race condition but is benign because:
1. Python GIL makes `set.__contains__` atomic
2. Worst case: one extra step executes before cancellation detected
3. Stale reads are acceptable for cooperative cancellation

For Phase 2 multi-process: Add `_lock` around the read.

## 14. Parallelization Blueprint (Phase 2)

Steps 6-8 are mutually independent post-step-5:
- Step 6 (enrich) reads `ctx["findings"]` CVE IDs
- Step 7 (score) reads enriched data (has fallback if missing)
- Step 8 (policy) reads risk scores (has defaults if missing)

Steps 9 and 10 are independent:
- Step 9 (LLM) evaluates severity buckets
- Step 10 (MPTE) validates exploitability

```python
# Phase 2 parallel pipeline sketch:
async def run_parallel(self, inp):
    # Sequential: 1-5 (dependency chain)
    for step in [connect, normalize, identity, dedup, graph]:
        await step(ctx, inp)
    # Parallel: 6-8
    await asyncio.gather(enrich(ctx), score(ctx), policy(ctx))
    # Parallel: 9-10
    await asyncio.gather(llm(ctx), mpte(ctx))
    # Sequential: 11-12
    await playbooks(ctx, inp)
    await evidence(ctx, inp)
```

**Expected improvement**: Steps 9+10 worst case: 120s -> 60s (50% improvement on I/O path).

---

*Generated by enterprise-architect on 2026-03-02 (Run 7). Serves pillars: V3, V5.*
