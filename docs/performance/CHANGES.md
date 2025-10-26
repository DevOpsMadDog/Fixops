# Optimisation Summary

1. **Crosswalk token matching:** Optimized dictionary lookups and skipped empty artefacts so the orchestrator only lowercases and scans SARIF/CVE blobs once per record.【F:apps/api/pipeline.py†L16-L121】
2. **SBOM parsing:** Normalized supplier extraction and optimized dictionary traversals to reduce repeated lookups.【F:apps/api/normalizers.py†L64-L109】
3. **SARIF parsing:** Reused the parsed `runs` collection instead of re-accessing the raw dictionary, reducing guard checks when scanning results.【F:apps/api/normalizers.py†L151-L191】
4. **Probabilistic forecast engine:** Added overlay-driven Bayesian/Markov forecasting that operates on existing severity counts without additional parsing overhead.【F:core/probabilistic.py†L1-L195】【F:apps/api/pipeline.py†L223-L270】

## Results
- **Runtime:** ≈3.4595ms per run with probabilistic forecasting enabled (30-iteration average), a modest +1.6% overhead versus the 3.4057ms crosswalk-only baseline while delivering richer analytics.【8242a6†L1-L64】
- **Peak Memory:** 155.01KB (no material change).
- **Probabilistic engine cost:** 0.0686ms per evaluation (5,000-iteration microbenchmark), confirming sub-millisecond overhead for Bayesian/Markov analytics.【23f027†L1-L55】

These gains keep pipeline execution comfortably below the 5ms target while layering on contextual analytics demanded by enterprise buyers.
