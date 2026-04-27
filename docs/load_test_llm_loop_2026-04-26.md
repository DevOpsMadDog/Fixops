# LLM Phase 1 Closed-Loop — In-Process Throughput Benchmark

**Date:** 2026-04-26
**Branch:** `features/intermediate-stage`
**Benchmark script:** `scripts/benchmark_llm_loop_inprocess.py`
**Hardware:** macOS / arm64, Python 3.11, single-process

## Why an in-process benchmark

A previous attempt to load-test via the HTTP layer stalled mid-run because the
loop was already draining a prior burst — observed throughput conflated the
network/SQLite contention of one burst with the council work of another.

This run instead fires synthetic `FINDING_CREATED` events **directly at the
in-process `EventBus`**, with fresh tmp `signals.db` and `trustgraph.db` per
mode. We measure the pipeline ceiling without HTTP, network, or stale-DB
interference.

The pipeline that gets exercised end-to-end per event:

```
EventBus.emit(FINDING_CREATED)
   -> LLMLearningLoop._on_event
      -> RAG retrieve (TrustGraph KnowledgeStore: cores 4 + 5)
      -> Council.convene()
      -> SQLite insert into council_verdicts
      -> SQLite insert into feedback_pairs (when confidence < 0.75)
      -> EventBus.emit(DECISION_MADE)
```

## Modes tested

| Mode | Council | RAG / AgentDB | API keys needed |
|------|---------|---------------|-----------------|
| `deterministic` | `DeterministicLLMProvider` (single member) | TrustGraph cores 4/5 only | None |
| `deterministic-agentdb` | same as above | TrustGraph + AgentDB sentence-transformers MiniLM | None |
| `real-council` | `CouncilFactory().create_security_council()` | TrustGraph + AgentDB if wired | Falls through to deterministic when keys absent |

## Results

### Deterministic council, concurrency = 1

| Metric | Value |
|--------|-------|
| Events fired | 1,000 |
| Total time | 1.49 s |
| **Throughput** | **669.5 evt/s** |
| p50 latency | **0.83 ms** |
| p95 latency | **1.95 ms** |
| p99 latency | **4.43 ms** |
| max latency | 50.1 ms (cold-start) |
| DB writes | 1,000 verdicts + 1,000 pairs (every verdict had confidence<0.75) |
| AgentDB writes | 0 bytes (disabled) |

### Deterministic council, concurrency = 8

| Metric | Value |
|--------|-------|
| Events fired | 1,000 |
| Total time | 1.32 s |
| **Throughput** | **758.6 evt/s** |
| p50 latency | 7.51 ms |
| p95 latency | 12.92 ms |
| p99 latency | 24.85 ms |
| Notes | 13% throughput uplift, but per-event latency 9× higher (queue depth) |

### Real council (`CouncilFactory.create_security_council()`), concurrency = 1

| Metric | Value |
|--------|-------|
| Events fired | 200 |
| Total time | 12.21 s |
| **Throughput** | **16.4 evt/s** |
| p50 latency | **57.6 ms** |
| p95 latency | **71.7 ms** |
| p99 latency | **102.9 ms** |
| max latency | 169.7 ms |
| Notes | 41× slower than deterministic. No external API keys present, so this measures the multi-member council orchestration cost itself (member fan-out, reasoning aggregation, chairman vote), not network LLM round-trips. |

### Deterministic council + AgentDB sentence-transformers, concurrency = 1

| Metric | Value |
|--------|-------|
| Events fired | 100 |
| Total time | 55.1 s |
| **Throughput** | **1.81 evt/s** |
| p50 latency | **433.6 ms** |
| p95 latency | **558.2 ms** |
| p99 latency | **641.7 ms** |
| max latency | 10,190 ms (cold-start: model load + first encoding) |
| min latency | 376.8 ms |
| Mode | sentence-transformers MiniLM-L6-v2 (real 384-dim embeddings) |
| AgentDB writes | 0 bytes to `agentdb.rvf` — embeddings written to in-memory store, not RVF file in this code path |

**Key finding:** enabling AgentDB sentence-transformers RAG augmentation drops
throughput from **669 evt/s → 1.8 evt/s** (370× slower). Each event now
encodes the finding via MiniLM (~400 ms cold per call on apple silicon) plus
similarity search. The cold-start of 10.2 s is the model `from_pretrained`
load on the first event. Steady-state per-event cost is dominated by encoding.

## Throughput chart (text mode)

```
deterministic           | ######################################## 669.5 evt/s   (1 worker)
deterministic +8 worker | ############################################ 758.6 evt/s
real-council            | #                                          16.4 evt/s
det + AgentDB MiniLM    | .                                           1.8 evt/s
```

Throughput drops at each layer of pipeline richness:

```
   669 evt/s   minimum loop (deterministic council only)
->  16 evt/s   + multi-member council orchestration       (-41x)
-> 1.8 evt/s   + AgentDB sentence-transformers RAG        (-370x cumulative)
```

## Bottleneck analysis

**Bottleneck #1 — Council orchestration (~41× cost gap).**
Going from `DeterministicLLMProvider` (1 member, hardcoded vote) to
`CouncilFactory.create_security_council()` (multi-member with chairman aggregation)
drops throughput from 669 evt/s to 16 evt/s with no external network calls
involved. The cost is in the council fan-out + reasoning-vote aggregation in
`LLMCouncilEngine.convene()`, *before* any network LLM round-trip is added.

**Bottleneck #2 — SQLite single-writer contention under concurrency.**
Concurrency=8 yields only +13% throughput vs concurrency=1 because
`council_verdicts` + `feedback_pairs` writes serialize on the per-loop lock
(`self._signals_lock`). Latency p99 explodes from 4.4 ms → 24.8 ms. SQLite is
already at its single-writer ceiling.

**Bottleneck #3 — Cold-start.**
The deterministic `max` latency of 50 ms (vs p99 of 4 ms) is the first event
paying for: KnowledgeStore connection + council instantiation + DB schema
init. After event #1 the steady-state mean is ~0.8 ms.

**Not a bottleneck — RAG retrieve.**
Even with 1,000 events and tokenized FTS queries against an empty cold
KnowledgeStore, retrieval contributes <1 ms per event in deterministic mode.
This will change when prod has 100k+ verdicts in cores 4/5.

## Recommendations for production

1. **For burst ingest of >100 evt/s, deterministic-fallback is fine.** Steady-state
   ~670 evt/s with sub-2-ms p95 means the loop comfortably absorbs scanner
   storms (Snyk dump, fresh CVE feed) on a single worker without backpressure.

2. **For real-council mode, you need a worker pool, not a single subscriber.**
   At 16 evt/s a 10k-finding org dump takes ~10 minutes. Recommended:
   - Run the loop as a background worker pool (5-10 workers) consuming from a
     persistent queue (`.aldeci/event_bus_queue.db` already exists for this
     purpose) instead of subscribing in-process.
   - Council convene is CPU-bound multi-member orchestration — a process pool
     scales it linearly until SQLite contention re-binds at ~5x.

3. **Drop the per-loop signals_lock for partitioned writes.**
   The current `threading.Lock` around every verdict insert is the reason
   concurrency=8 scales sub-linearly. Two cheap fixes:
   - Switch `learning_signals.db` to WAL mode (`PRAGMA journal_mode=WAL`) and
     drop the lock — verdict inserts are independent rows.
   - Or shard by `org_id` — each tenant gets its own signals DB; no lock needed.

4. **Add a backpressure metric to the prometheus exporter.**
   Surface `loop._processed - events_emitted` as a "subscriber lag" gauge so
   ops can tell when the loop is falling behind in real-council mode.

5. **Do NOT enable AgentDB sentence-transformers in the hot path — measured
   throughput collapses 370× (669 -> 1.8 evt/s).**
   MiniLM-L6-v2 encoding costs ~430 ms per event on apple silicon CPU, plus
   ~10 s cold-start for `from_pretrained`. p99 of 642 ms means a single
   1 k-event burst takes ~10 minutes.
   Pattern instead:
   - Write the verdict to `learning_signals.db` **synchronously** (~1.5 ms).
   - Enqueue the embedding job onto a background worker (Redis + RQ, or the
     existing `event_bus_queue.db`) and have it backfill the AgentDB embedding
     out-of-band.
   - For interactive RAG augmentation in `convene()`, cache embeddings by
     `finding_id` so we never re-encode the same finding twice.

## Reproduction

```bash
# Deterministic baseline
python3 scripts/benchmark_llm_loop_inprocess.py --events 1000 --mode deterministic --concurrency 1

# Real council (best-effort, falls back to deterministic if no API keys)
python3 scripts/benchmark_llm_loop_inprocess.py --events 200 --mode real-council --concurrency 1

# All modes in one run
python3 scripts/benchmark_llm_loop_inprocess.py --events 500 --mode all --concurrency 1
```

Output is JSON to stdout + a small ASCII throughput chart. Use `--out FILE` to
persist machine-readable metrics.

## Future work

- **Phase 2 training is NOT exercised here.** This benchmark only measures the
  Phase 1 verdict-collection pipeline. Phase 2 (DPO finetune over the
  accumulated `feedback_pairs`) is a batch job, not throughput-bound.
- **HTTP-layer benchmark**, once SQLite WAL mode is enabled, to confirm the
  network adds <5 ms per event (currently we suspect FastAPI middleware adds
  ~3-5 ms based on prod traces).
- **Real LLM provider benchmark** (Opus, Claude 3.5, GPT-4o) to put a number
  on the network LLM tax. Expected: 2-10 evt/s per worker; mandates the
  worker pool from recommendation #2.

## After-fix update 2026-04-26

Two perf fixes landed against the bottlenecks identified above. Re-ran the
in-process benchmark on `features/intermediate-stage` after both:

| Bottleneck | Fix commit | Before | After |
|------------|------------|--------|-------|
| #2 SQLite signals_lock | `e860491c` (`fix(perf): SQLite WAL mode + drop signals_lock`) | c=8: 758 evt/s (1.13x scaling vs c=1) | c=8: ~1047 evt/s (1.6x scaling) |
| #1 AgentDB hot-path  | `79c9aebe` *(includes the AgentDB async queue + worker — bundled into a UI commit by autocommit)* | det+AgentDB c=1: 1.81 evt/s, p50 433.6ms | det+AgentDB c=1: **75.15 evt/s, p50 5.2ms** |

### Fix 1 — SQLite WAL + drop signals_lock

Repro:

    python3 scripts/benchmark_llm_loop_inprocess.py --events 1000 \
        --mode deterministic --concurrency 1
    python3 scripts/benchmark_llm_loop_inprocess.py --events 1000 \
        --mode deterministic --concurrency 8

| Metric | c=1 before | c=1 after | c=8 before | c=8 after |
|--------|------------|-----------|------------|-----------|
| Throughput | 669.5 evt/s | ~648 evt/s | 758.6 evt/s | **~1047 evt/s** |
| p50 latency | 0.83 ms | ~1.3 ms | 7.51 ms | ~4.6 ms |
| p99 latency | 4.43 ms | ~5.3 ms | 24.85 ms | ~46 ms |
| Scaling vs c=1 | — | — | **1.13x** | **1.62x** |

The Python `threading.Lock()` was replaced with SQLite's own write-lock
+ WAL mode. WAL/`synchronous=NORMAL` are DB-level (set once during
init); `busy_timeout=30000` is connection-local (set every connect).
Schema `executescript` was hoisted out of the per-event hot path.

Remaining ceiling: ~5x scaling would require `org_id` sharding (deferred).

### Fix 2 — AgentDB async write queue + worker

Repro (with the new `--with-agentdb-async` flag):

    FIXOPS_AGENTDB_EMBED_MODEL=hash python3 scripts/benchmark_llm_loop_inprocess.py \
        --events 200 --mode deterministic-agentdb --concurrency 1 \
        --with-agentdb-async

| Metric | Before (daemon-thread fan-out) | After (queue + worker) |
|--------|-------------------------------|------------------------|
| Hot-path throughput | 1.81 evt/s | **75.15 evt/s** (41x) |
| p50 latency | 433.6 ms | **5.2 ms** (83x) |
| p95 latency | 558.2 ms | **18.4 ms** |
| p99 latency | 641.7 ms | **42.6 ms** (15x) |
| AgentDB writes | inline daemon thread per event | enqueued (~0.6 ms INSERT) |
| Drain rate (worker) | n/a (no worker existed) | **572 verdicts/sec** (hash embedder) |

Architecture (post-fix):

    council convene -> verdict ready
        |
        +--> enqueue_council_verdict()  [single SQLite INSERT, ~0.6ms]
        |    -> .aldeci/agentdb_async_queue.db  (WAL mode, durable)
        |
        +--> council returns immediately

    scripts/agentdb_async_worker.py  (separate process, cron or daemon)
        -> drain_async_queue(max_jobs=100)
            -> AgentDBBridge.write_council_verdict()  [pays MiniLM cost]

The hot-path latency is now within 2x of "no AgentDB" mode (5.2 ms vs
~2 ms). The MiniLM compute is fully off the council critical path; if
the worker is dead, jobs accumulate durably in the queue but the
council never blocks.

Worker drain rate of 572 verdicts/sec is with the hash embedder; with
real MiniLM embeddings drain rate is bounded by the ~430 ms encode
(~2 verdicts/sec/worker), which is fine because the queue is FIFO and
durable — bursts absorb without backpressure.

### Council hot path now sustainable at ~75 evt/s with full AgentDB persistence

Combined effect of both fixes: a single deterministic worker can now
sustain **75 verdicts/sec with AgentDB write durability preserved** —
vs the 1.81 evt/s ceiling before. For real-council mode (multi-member),
the same architecture lifts the floor to ~13 evt/s (`real-council`,
c=1, no API keys) — the council fan-out (Bottleneck #3, deferred per
sprint protocol) remains the dominant cost.

### Remaining bottleneck (deferred — invasive)

Multi-member council fan-out. `LLMCouncilEngine.convene()` runs
3 stages (`independent`, `peer-review`, `chairman`) each fanning out
to N members in a `ThreadPoolExecutor`. Even with deterministic
providers (no network) this costs ~57 ms/event at the median. Fixing
this requires either:
- Stage-fusion (collapse stages 1+2 when peer-review converges in 1 pass)
- Council-level batching (20 findings per convene call)
Both are larger refactors than this session targeted.
