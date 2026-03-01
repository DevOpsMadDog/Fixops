# Architecture Review: Self-Learning Feedback Loops
- **Date**: 2026-03-01
- **Reviewer**: enterprise-architect
- **Area**: V8 Self-Learning Engine
- **Verdict**: READY FOR DEMO (minor improvements noted)

## Data Flow Analysis

### Record Feedback
```
Client POST /api/v1/self-learning/feedback/{loop}
  → self_learning_router.py validates Pydantic model
  → get_learning_engine() returns singleton SelfLearningEngine
  → engine.{loop}_loop.record(...) creates FeedbackRecord
  → FeedbackDB.store_feedback() writes to SQLite WAL
  → Returns feedback_id
```

### Compute Adjustments
```
Client POST /api/v1/self-learning/compute-adjustments
  → engine.compute_adjustments()
  → For each of 5 loops:
    → Fetch feedback records from DB (last 90 days)
    → Compute accuracy/FP-rate/success-rate statistics
    → Calculate new weight via exponential moving average
    → Clamp to [0.2, 1.5] range
    → Store in weights table
    → Log as LearningAdjustment
  → Returns list of adjustments with reasoning
```

### Score With Learning
```
Client POST /api/v1/self-learning/score-with-learning
  → engine.score_with_learning(finding)
  → Compute baseline score (deterministic formula)
  → Lookup 5 weight keys from weights table
  → Multiply baseline by combined weight
  → Clamp result to [0.0, 1.0]
  → Returns baseline, adjusted, delta, and adjustment details
```

## Security Review

| Check | Status | Notes |
|-------|--------|-------|
| Auth on all endpoints | OK | All endpoints behind `_verify_api_key` via app.py mounting |
| Input validation | OK | Pydantic models with field constraints (ge, le) |
| SQL injection | OK | All queries use parameterized statements |
| Path traversal | OK | No file path parameters |
| Rate limiting | WARN | No per-endpoint rate limiting (global only) |
| Secret exposure | OK | No secrets in responses |

## Performance Review

| Aspect | Status | Notes |
|--------|--------|-------|
| DB queries | OK | Indexed on feedback_type, source, recorded_at |
| Lock contention | WARN | Single threading.Lock for all DB ops |
| Bulk operations | WARN | seed_demo_data does 98 individual INSERTs |
| Memory | OK | Records fetched per-query, not cached globally |

### Recommendations
1. **Batch inserts** for seed_demo_data — use executemany instead of 98 individual calls
2. **Read-write lock** — use RLock or separate readers from writers
3. **Connection pooling** — current single connection is OK for demo but not production

## Reliability Review

| Check | Status | Notes |
|-------|--------|-------|
| Error handling | OK | try/except with HTTPException in all endpoints |
| Graceful degradation | OK | Status endpoint returns "degraded" on errors |
| Idempotency | PARTIAL | seed_demo_data is deterministic but not idempotent (appends) |
| Recovery | OK | SQLite WAL mode survives crashes |

## Scalability Review

| Aspect | Current | Phase 2 | Phase 3 |
|--------|---------|---------|---------|
| Weights scope | Global | Per-tenant | Per-app |
| DB backend | SQLite | PostgreSQL | PostgreSQL + Redis cache |
| Concurrency | Single lock | Async driver | Connection pool |
| Learning mode | On-demand | Scheduled (cron) | Real-time streaming |

## Code Quality

- Engine: 1,100 LOC — well-structured with clear loop separation
- Router: 420 LOC — clean REST patterns with Pydantic validation
- Tests: 73 passing (42 unit + 31 demo) — strong coverage of core logic
- Documentation: ADR-005 covers architecture decisions
- Type hints: Present throughout
- Logging: structlog-compatible logger usage

## Issues Found

1. **TD-008**: `seed_demo_data` uses `random.Random(42)` — deterministic but slow due to individual inserts
2. **TD-009**: No per-tenant weight isolation — all users share same weights
3. **TD-010**: `compute_adjustments` runs synchronously — could block on large datasets
4. **TD-011**: No rollback mechanism for bad weight adjustments

## Verdict

**READY FOR DEMO.** The self-learning system demonstrates all 5 feedback loops with real data flow and measurable scoring changes. The architecture is sound for single-instance deployment. Phase 2 improvements (multi-tenant, PostgreSQL, async) are documented but not blocking for the enterprise demo.
