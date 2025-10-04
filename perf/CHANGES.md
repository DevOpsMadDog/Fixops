# Optimisation Summary

1. **Crosswalk token matching:** Replaced per-call dictionary re-initialisation with `defaultdict` caches and skipped empty artefacts so the orchestrator only lowercases and scans SARIF/CVE blobs once per record.【F:backend/pipeline.py†L16-L27】【F:backend/pipeline.py†L73-L121】
2. **SBOM parsing:** Cached lib4sbom relationship/service/vulnerability calls and normalised supplier extraction to avoid repeated dictionary traversals.【F:backend/normalizers.py†L64-L109】
3. **SARIF parsing:** Reused the parsed `runs` collection instead of re-accessing the raw dictionary, reducing guard checks when scanning results.【F:backend/normalizers.py†L151-L191】

## Results
- **Runtime:** 0.3351s for 50 runs (≈6.70ms per iteration), a 2.1% speed-up on the synthetic workload.【2dbc2e†L1-L1】
- **Peak Memory:** 150.65KB (↓2.8% vs. baseline).【bf61df†L1-L1】

These gains compound in larger batches where hundreds of SARIF findings and CVE entries previously re-triggered redundant string conversions.
