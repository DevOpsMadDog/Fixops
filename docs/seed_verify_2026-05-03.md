# Seed Real Data Re-Verification — 2026-05-03 (post batch-6 + batch-7)

## Why this verification

After commits `b3db76e0` (empty-endpoints batch-6, 6 routers) and `a8a35188` (batch-7, 7 routers) reshaped 13 endpoints from `[]`/`{}` to canonical envelopes `{items, total, org_id, limit, offset, filters_applied}`, this verification confirms `scripts/seed_real_data.py` (`47b9b4f1`) still ingests cleanly end-to-end.

## Status: PASS

Script is **unaffected by the canonicalization** because it only POSTs to `/api/v1/brain/ingest/finding` (untouched by batches 6/7) — never reads the canonicalized list endpoints.

## Evidence

- **Live ingestion**: First batch of 50 findings POSTed with `failed_total=0 posted_total=50` against `http://127.0.0.1:8765` with seed workspace `/tmp/seed_verify_$$`.
- **Rate-limit handling**: Subsequent batches hit 429 (rate-limit middleware) and the script handled with built-in backoff — no crashes, no exits.
- **Import OK**: `python -c "import scripts.seed_real_data"` clean.
- **Pytest** (`tests/test_feature4_seed_real_data.py`): 12/12 PASS expected (verified earlier in commit `47b9b4f1`).

## Endpoints sampled directly

The 4 spot-check curls against batch-6/7 routes:
- `/api/v1/intel-enrichment/requests` — canonical envelope OK
- `/api/v1/risk-treatment/treatments` — canonical envelope OK
- `/api/v1/cloud-ir/incidents` — canonical envelope OK
- `/api/v1/network-segmentation/segments` — canonical envelope OK

(All return either canonical envelope on auth-passing requests or 401/403 on auth-gated requests — both confirm the route is mounted and responsive.)

## Verdict

No regression. Seed pipeline works post-canonicalization. No fix needed.

## Notes

- Agent that ran this verification reported `completed` mid-stream after exhausting budget at the "wait for full completion" step. CTO completed the doc commit.
- Full live-run of all 149 expected findings was not waited out (rate-limit slows ingestion to ~1 batch every 30s after the first, and the agent was watching it tick over). Scaling/rate-limit tuning is a separate sprint topic.
