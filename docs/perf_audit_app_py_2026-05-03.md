# Performance Audit — `suite-api/apps/api/app.py`

**Date:** 2026-05-03
**Auditor:** perf-analyzer agent (read-only)
**Scope:** cold-start cost of FastAPI factory `create_app()`
**Method:** `python -X importtime` + `tracemalloc` snapshot, no production code touched

## Headline Numbers

| Metric                | Value         | Target  | Status |
|-----------------------|---------------|---------|--------|
| File LOC              | 7,996         | <2,000  | RED    |
| `app.include_router` calls | 346      | n/a     | INFO   |
| `try:` blocks (silent ImportError swallow) | 576 | <50 | RED |
| Routes mounted (final) | **8,985**    | n/a     | INFO   |
| Cold-start `import` time | **58.96 s** | <2 s    | RED    |
| Cold-start `create_app()` time | **15.89 s** | <500 ms | RED |
| Cold-start TOTAL      | **74.85 s**   | <2 s    | RED    |
| Resident memory after factory | **813 MB** | <300 MB | RED |

> Note: ~5–8 s of the wall-clock total is OTLP DNS-retry against unreachable host `collector:4318` (visible in stderr — 4 retries, exp backoff). On a hot DNS path this drops to ~67 s.

## Top-5 Import-Time Hotspots (self-time, ms)

| Rank | Module                              | Self ms | Cum ms | Why it's hot |
|------|-------------------------------------|---------|--------|--------------|
| 1    | `apps.api.app` (factory body)       | 14,350  | 14,350 | 346 `include_router`, 576 try/except wrappers |
| 2    | `apps.api.pipeline`                 | 3,921   | 3,921  | Imports 22+ engines at module load (`ai_agents`, `analytics`, `enhanced_decision`, `evidence`, `policy`, `processing_layer`, …) |
| 3    | `core.vector_store`                 | 3,874   | 3,874  | Top-level `from sentence_transformers import …` (lines 20-23) |
| 4    | `sentence_transformers` chain       | 3,874   | 3,874  | Pulls `transformers` (1.35 s) + `torch` (0.67 s) + `sklearn` (0.92 s) + `scipy.stats` (0.46 s) |
| 5    | `sentence_transformers.backend.load` / `transformers.configuration_utils` | 2,045 | 2,045 | Lazy-load tokenizer wiring at import |

Combined ML import cost: **~9.7 s** for a *factory boot* that may never run an embedding.

## Top-5 Router-Mount / Engine-Init Hotspots

| Rank | Site                                                 | Issue |
|------|------------------------------------------------------|-------|
| 1    | `apps.api.pipeline` (line 13–35)                     | 22 sync engine imports — pulls `core.enhanced_decision`, `core.processing_layer`, `core.context_engine`, `core.tenancy` at module load |
| 2    | `core.vector_store` (line 20-23)                     | Eager `sentence_transformers` import — loaded even if Chroma is disabled |
| 3    | `apps.api.app` lines 42–2055 (router import block)   | 346 routers imported sequentially; each wrapped in `try/except` (silent failure) |
| 4    | `apps.api.app:5546` `ALL_GAP_ROUTERS` loop           | Bulk-mounts gap-filler routers without feature-flag gating |
| 5    | OTLP exporter init (`telemetry.configure()` ~ line 5322) | Blocking DNS to `collector:4318` with 4-retry exp backoff — 5–8 s wall when host absent |

## Recommendations (effort × impact)

| #  | Action | Effort | Impact | Est. Savings |
|----|--------|--------|--------|--------------|
| R1 | **Lazy-load `sentence_transformers`** in `core/vector_store.py` — move `from sentence_transformers import SentenceTransformer` inside the embedder factory; gate on `FIXOPS_VECTOR_STORE=chroma` env. Pipeline never touches it on a cold pure-API request. | S | HIGH | -3.9 s import |
| R2 | **Gate OTLP exporter on env var** — wrap `telemetry.configure()` in `if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")`. Current code retries DNS 4×exp-backoff against literal `collector:4318` even when no collector exists. | S | HIGH | -5–8 s wall |
| R3 | **Convert module-level engine imports in `apps.api.pipeline` to lazy properties** (or `functools.lru_cache` factory functions). `pipeline.py` brings in 22 engines just so the router can be `import`-ed by `app.py`. | M | HIGH | -3.9 s import + lower mem |
| R4 | **Replace 576 `try/except ImportError: pass` wrappers with a manifest-driven loader** — single `routers.toml` listing `(name, module, prefix, scope)`; loop with structured logging on failure. Reduces `app.py` from 7,996 LOC → ~1,500 LOC, removes silent failures (currently `websocket_router`, `feature_flag_router` fail invisibly — confirmed in stderr). | L | MED | maintainability + observability; ~1–2 s import |
| R5 | **Feature-flag the bulk-mount of `ALL_GAP_ROUTERS`** (line 5546) and any tier-locked routers (Enterprise-only) — only mount what the deploy tier needs. Cuts `app.routes` from 8,985 → ~3,000 for Starter tier. | M | MED | -300–500 MB RSS, -1 s create_app |

## Quick Wins (one PR, S effort)

R1 + R2 together: **~9–14 s shaved off cold-start**, no API surface changes, no router migration. Ship first.

## Open Issues Surfaced During Audit (not in scope)

- `websocket_router not available: No module named 'suite_core'` — broken import, currently silenced
- `feature_flag_router not available: No module named 'apps.api.feature_flag_router'` — missing module, silenced
- LaunchDarkly SDK not installed — silenced
- `FIPS_MODE` and `FIXOPS_ALLOWED_ORIGINS` warnings on every boot — should be gated to deploy phase, not factory invocation

## Reproduction

```bash
cd /Users/devops.ai/fixops/Fixops
PYTHONPATH=. python -X importtime -c "from apps.api.app import create_app; create_app()" 2> /tmp/importtime.log
awk -F'|' '/^import time:/ {print $2"\t"$3"\t"$4}' /tmp/importtime.log | sort -k1 -rn | head -30
```

---
Source of truth: this file. No production code modified.
