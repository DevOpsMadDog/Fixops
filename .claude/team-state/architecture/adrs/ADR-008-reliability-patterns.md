# ADR-008: Reliability Patterns for Brain Pipeline and External Dependencies

- **Status**: Accepted
- **Date**: 2026-03-02
- **Context**: Enterprise demo requires reliable behavior even when external services (LLM APIs, MPTE, threat feeds) are unavailable. Current Brain Pipeline handles step-level failures but lacks circuit breakers and per-step timeouts.
- **Pillar**: V3 (Decision Intelligence)
- **Author**: enterprise-architect

## Decision

### 1. Graceful Degradation Pattern (Already Implemented)
The Brain Pipeline follows a **fallback chain** pattern for all external dependencies:
- **Step 6 (Enrich Threats)**: ThreatEnricher API -> calibrated severity-based estimation
- **Step 7 (Score Risk)**: ML GBT model -> deterministic weighted formula
- **Step 9 (LLM Consensus)**: EnhancedDecisionEngine -> deterministic consensus (risk distribution)
- **Step 10 (MicroPenTest)**: MPTE service -> skip with reason logged

This ensures the pipeline ALWAYS produces a result, even in air-gapped environments (V9).

### 2. Database Connection Safety Pattern (New Requirement)
All SQLite connection usage MUST follow try/finally:
```python
conn = sqlite3.connect(db_path)
try:
    cursor = conn.cursor()
    # ... operations ...
    conn.commit()
finally:
    conn.close()
```

**Rationale**: Discovered connection leak in `suite-core/core/services/history.py` where exceptions during INSERT would leave connections open. Fixed 2026-03-02. All new database code must use this pattern.

### 3. Circuit Breaker Pattern (Phase 2 Requirement)
For external HTTP dependencies (LLM APIs, MPTE, threat feeds):
- Reuse `_AsyncCircuitBreaker` from `suite-core/connectors/universal_connector.py`
- OPEN after 3-5 consecutive failures
- Recovery timeout: 60s (LLM), 30s (MPTE)
- Thread-safe implementation (add `threading.Lock`)

### 4. Timeout Hierarchy
```
Global Pipeline: 300s (PIPELINE_TIMEOUT_S)
  └─ Per-Step (Phase 2): configurable, defaults:
     ├─ connect/normalize/resolve: 30s
     ├─ build_graph/enrich: 30s
     ├─ score_risk/apply_policy: 30s
     ├─ llm_consensus: 60s
     └─ micro_pentest: 120s
```

### 5. Memory Bounds (Already Implemented)
| Collection | Bound | Mechanism |
|-----------|-------|-----------|
| `_runs` | 1,000 | Evict oldest |
| `_metrics` | 100 | Truncate |
| Findings input | 50,000 | Truncate with warning |
| Assets input | 10,000 | Truncate with warning |
| String fields | 10,000 chars | Sanitize |
| LLM batch | 100 findings | Top-N by risk |

## Consequences

### Positive
- Pipeline never blocks indefinitely on external service failure
- Database connections never leak, even under error conditions
- Memory usage is bounded regardless of input size
- System remains functional in air-gapped mode (V9)

### Negative
- Deterministic fallbacks produce lower-quality decisions than ML/LLM paths
- Circuit breaker may over-aggressively short-circuit during transient failures
- Per-step timeouts add complexity to the pipeline execution loop

### Trade-offs
- **Prefer availability over accuracy**: A quick deterministic answer beats a slow or failed LLM answer
- **Prefer bounded resources over unbounded quality**: Cap at 50K findings even if customer has 100K
- **Prefer fail-safe over fail-fast**: Pipeline continues after step failure (PARTIAL status)

## Verification
- `suite-core/core/services/history.py` connection leak fix verified with 5 method tests: all PASS
- Core tests: 237/237 PASS (Run 10 verified)
- Brain Pipeline memory bounds verified via `test_large_findings_batch` test

---

*Enterprise-architect, 2026-03-02. Serves V3 (Decision Intelligence), V9 (Air-Gapped).*
