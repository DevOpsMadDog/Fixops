**Purpose:** Tracks performance baselines and optimisation outcomes for the ingestion service.

**Key Files:**
- `BASELINE.md` — narrative description of hotspots and measurement approach.
- `BENCHMARKS.csv` — before/after metrics for critical scenarios.
- `CHANGES.md` — rationale for code-level optimisations and their impact.

**Data In/Out:**
- Inputs: Synthetic payloads defined in the benchmark scripts within the tests/ directory.
- Outputs: Markdown and CSV summaries under this directory.

**Gotchas:**
- Keep measurements reproducible by documenting commands and seeds.
- Re-run benchmarks after touching pipeline or normaliser logic.
