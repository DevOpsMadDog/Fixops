# Reliability Review — Error Handling, Retries & Circuit Breakers

- **Date**: 2026-03-02
- **Reviewer**: enterprise-architect (Run 5)
- **Scope**: suite-core/, suite-api/ — full reliability audit
- **Pillars**: [V3] Decision Intelligence, [V7] MCP Platform, [V10] CTEM Loop
- **Focus**: How does the system behave when things go wrong?

---

## Executive Summary

**Overall Reliability Grade: B-** (Acceptable for demo, needs hardening for production)

The system handles happy-path failures well: the Brain Pipeline has a 5-minute timeout, individual steps catch exceptions and continue, and the `universal_connector.py` has a proper circuit breaker. However, several reliability gaps would cause issues under sustained load or during partial failures of external services.

**Critical Findings**: 3 items requiring attention before design partner phase.

---

## 1. Error Handling Audit

### 1.1 Exception Patterns

| Pattern | Count | Location | Risk |
|---------|-------|----------|------|
| `except Exception:` (bare catch) | 71 | 30 files in suite-core/core/ | ⚠️ Some swallow silently |
| `except:pass` (B110) | 101 | Full suite | ⚠️ Hides bugs |
| `except Exception:` in API routers | 72 | 20 files in suite-api/ | ⚠️ May leak internal details |
| `except TimeoutError:` (explicit) | 2 | brain_pipeline.py | ✅ Correct |

**Analysis**: The Brain Pipeline (brain_pipeline.py) handles exceptions well:
- Step-level catch at line 326-331: catches Exception, logs with exc_info, sets step status to FAILED
- Error messages sanitized (line 329): `f"{type(e).__name__}: pipeline step failed"` — does NOT expose exception details
- Pipeline continues after step failure (PARTIAL status) — resilient by design

**Concern**: Many services use `except Exception: pass` which silently hides failures. The worst offenders:
- `playbook_runner.py`: 19 bare except blocks
- `single_agent.py`: 16 bare except blocks
- `dast_engine.py`: 16 bare except blocks
- `mcp_server.py`: 10 bare except blocks

### 1.2 SQLite Connection Leak Pattern — **P1 BUG**

**Found**: `suite-core/core/services/history.py` `record_run()` (line 91-150)

```python
# VULNERABLE PATTERN — Connection leaks if INSERT fails
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
# ... multiple INSERT operations ...
conn.commit()
conn.close()  # NEVER REACHED if INSERT throws
```

**Scope**: 5 methods in `history.py` use this unsafe pattern (no try/finally).

**Mitigation**: `deduplication.py` and `remediation.py` properly use try/finally blocks.

**Impact**: Under error conditions (disk full, schema mismatch, concurrent writes), connections leak and eventually exhaust file descriptors.

**Fix**: Wrap all `conn = sqlite3.connect()` blocks in `try/finally: conn.close()`.

---

## 2. Retry & Backoff Audit

### 2.1 Where Retries Exist ✅

| Component | Retry Mechanism | Config |
|-----------|----------------|--------|
| `exploit_signals.py` | urllib3.Retry | 3 retries, 0.5s backoff, status=[500,502,503,504] |
| `playbook_runner.py` | Step-level retry | Configurable per step, recursive |
| `universal_connector.py` | Circuit breaker recovery | 30s timeout, 5 failure threshold |
| Rate limiter middleware | Retry-After header | Token bucket, returns 429 |

### 2.2 Where Retries Are Missing ❌

| Component | Risk | Recommendation |
|-----------|------|---------------|
| **Brain Pipeline LLM call (Step 9)** | LLM API returns 429/503 → step fails, no retry | Add 1 retry with 5s backoff |
| **Brain Pipeline MPTE call (Step 10)** | MPTE service unavailable → step fails | Add circuit breaker |
| **Scanner ingest router** | External webhook payload rejected → lost data | Add dead-letter queue pattern |
| **Knowledge Graph upserts (Step 5)** | SQLite lock contention → step failure | Add retry with jitter |
| **Event bus emission** | Fire-and-forget, no retry, no delivery guarantee | OK for Phase 1, needs queue for Phase 2 |

### 2.3 LLM Consensus Timeout Handling

**Location**: `brain_pipeline.py:990-1038` — `_step_llm_consensus()`

The implementation catches `TimeoutError` explicitly (line 1033) and falls back to `_deterministic_consensus()`. This is **correct** — the system never blocks indefinitely on an LLM call.

However, the timeout comes from the LLM provider's HTTP timeout, not from the Brain Pipeline itself. If `EnhancedDecisionEngine.evaluate_pipeline()` hangs, there's no deadline enforcement from the pipeline side (only the 300s global pipeline timeout at line 305).

**Recommendation**: Add a per-step timeout (e.g., 60s for LLM, 120s for MPTE) in addition to the global 300s pipeline timeout.

---

## 3. Circuit Breaker Audit

### 3.1 Implementation Quality

**Location**: `suite-core/connectors/universal_connector.py:99-137` — `_AsyncCircuitBreaker`

The circuit breaker is well-implemented:
- Three states: CLOSED → OPEN → HALF_OPEN → CLOSED
- 5 failure threshold to open
- 30s recovery timeout
- 2 half-open successes to close
- Monotonic clock (not wall clock) — correct for timeouts

**Concern**: Not thread-safe. Multiple concurrent requests can race on `_failure_count` and `_state`. Acceptable for demo, needs `threading.Lock` for production.

### 3.2 Where Circuit Breakers Are Missing ❌

| External Dependency | Current Behavior | Risk |
|---------------------|-----------------|------|
| LLM APIs (OpenAI, Anthropic) | Catch-and-fallback | If API is down, every request retries, burning latency |
| MPTE service (localhost:8443) | Catch-and-skip | If MPTE is down, every pipeline run wastes 120s on timeout |
| NVD/EPSS/KEV feeds | Catch-and-skip | Feed fetch failures are silent |
| FalkorDB (graph) | Catch-and-skip | Graph operations fail silently |
| MindsDB | Not used in pipeline | N/A |

**Recommendation**: Add circuit breakers around LLM and MPTE calls. If they fail 3 times, short-circuit for 60s. This prevents cascading timeouts.

---

## 4. Database Reliability

### 4.1 Connection Management

| File | Connections | Pattern | Safe? |
|------|------------|---------|-------|
| `deduplication.py` | 17 connects | try/finally ✅ | Yes |
| `remediation.py` | 13 connects | try/finally ✅ | Yes |
| `history.py` | 5 connects | No try/finally ❌ | **No — leak risk** |
| `collaboration.py` | 18 connects | Mixed ⚠️ | Partial |
| `*_db.py` (14 files) | 1-2 each | Varies | Mostly safe |

### 4.2 SQLite WAL Behavior

SQLite WAL mode is used throughout. Key reliability properties:
- **Readers don't block writers** — good for concurrent API requests
- **WAL file growth** — agent-doctor regularly cleans WAL files (10 files, 1.6MB cleaned on last run)
- **WAL corruption** — `fixops_brain.db` corruption was FIXED by agent-doctor (run 28)
- **Timeout**: Most connections use `timeout=30.0` — prevents indefinite blocking

### 4.3 No Connection Pooling

Each database operation creates a new `sqlite3.connect()`. This is fine for SQLite (cheap to connect), but indicates the codebase is not prepared for PostgreSQL migration (which requires connection pooling).

**Phase 2 action**: Implement connection pooling (asyncpg pool or SQLAlchemy engine pool) before PostgreSQL migration.

---

## 5. Async / Event Loop Management

### 5.1 Brain Pipeline Async Pattern

**Location**: `brain_pipeline.py:1104-1132` — `_step_micro_pentest()`

The implementation handles async event loops correctly but with complexity:
```python
try:
    loop = asyncio.get_running_loop()
    # Inside async context: use thread pool
    with ThreadPoolExecutor(max_workers=1) as pool:
        def _run_pentest():
            _loop = asyncio.new_event_loop()
            ...
except RuntimeError:
    # No running loop: create one
    loop = asyncio.new_event_loop()
    ...
```

This is correct but fragile. The `run_async()` method (line 392-401) uses `run_in_executor(None, self.run, inp)` which runs the sync pipeline in a thread — so when `_step_micro_pentest` hits, it's in a thread that may or may not have an event loop.

**Risk**: Low. The try/except handles both cases. But this pattern should be documented for future maintainers.

### 5.2 Event Bus Emission

**Location**: `brain_pipeline.py:1257-1303` — `_emit_event()`

Similar pattern: tries `get_running_loop()`, falls back to creating a new one. The event emission is fire-and-forget — failures are caught and logged at DEBUG level.

**Concern**: Creating a new event loop per emission (in the non-async path) is wasteful. Should reuse a module-level loop or use `asyncio.run()`.

---

## 6. Memory Management

### 6.1 Bounded Caches ✅

| Component | Bound | Mechanism |
|-----------|-------|-----------|
| Brain Pipeline `_runs` | 1,000 | Eviction of oldest (line 247-253) |
| Brain Pipeline `_metrics` | 100 | Truncation (line 386-387) |
| LLM Consensus `critical` | 100 | Top-100 by risk (line 1004-1008) |
| Findings input | 50,000 | Truncation with warning (line 228-232) |
| Assets input | 10,000 | Truncation with warning (line 233-237) |
| String fields | 10,000 chars | Sanitization (line 204-208) |

### 6.2 Unbounded Collections ⚠️

| Component | Risk | Impact |
|-----------|------|--------|
| EventBus listeners | Listeners never removed | Low — finite set registered at startup |
| Singleton caches in *_db.py | Each module has a global instance | Low — bounded by table size |
| Deduplication batch results | Results not bounded | Medium — large batches could OOM |

---

## 7. Recommendations

### P0 — Fix Before Demo (Mar 6)
None — all critical reliability issues are addressed.

### P1 — Fix Before Design Partner (Phase 2)

1. **[TD-017] Fix SQLite connection leaks in `history.py`** — Wrap all 5 methods in try/finally. Estimated: 0.5 days.

2. **[TD-018] Add circuit breakers for LLM and MPTE calls** — Prevent cascading timeouts when external services are down. Reuse `_AsyncCircuitBreaker` from universal_connector. Estimated: 1 day.

3. **[TD-019] Add per-step timeouts to Brain Pipeline** — Each step should have a configurable timeout (60s LLM, 120s MPTE, 30s default). Currently only the 300s global timeout exists. Estimated: 0.5 days.

### P2 — Fix Before GA (Phase 3)

4. **Replace 101 bare `except:pass` with specific exception handling** — Already tracked as TD-004.

5. **Add dead-letter queue for scanner ingest** — Failed ingestion payloads should be persisted for retry.

6. **Thread-safety for circuit breaker** — Add `threading.Lock` to `_AsyncCircuitBreaker`.

---

## 8. Verdict

The Brain Pipeline is the most reliability-hardened component in the codebase:
- Global timeout ✅
- Step-level exception handling ✅
- Memory bounds on all caches ✅
- Input sanitization and size limits ✅
- LLM timeout fallback ✅
- Async event loop safety ✅

The weakest areas are:
- Database connection management (mixed quality)
- Missing circuit breakers on external dependencies
- Bare exception swallowing across the codebase

**For the enterprise demo on March 6, the system is reliable enough.** The recommendations above target Phase 2 (design partner) readiness.

---

*Generated by enterprise-architect on 2026-03-02. Serves pillars: V3, V7, V10.*
