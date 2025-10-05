# backend/

**Purpose:** FastAPI ingestion service that accepts security artefacts, normalises them, and runs the
pipeline correlator.

**Key Files**
- `app.py` — FastAPI entrypoint with overlay-aware endpoints.
- `normalizers.py` — Dataclasses and helpers to parse SBOM, SARIF, and CVE uploads.
- `pipeline.py` — Correlates artefacts and emits summaries/crosswalks.
- `requirements.txt` — Optional dependencies for a richer demo experience.

**Module API**
- `create_app()` returns a configured FastAPI application ready for uvicorn.
- `InputNormalizer` exposes `load_sbom`, `load_cve_feed`, `load_sarif` helpers.
- `PipelineOrchestrator.run(design_dataset, sbom, sarif, cve)` correlates artefacts.

**Data In/Out**
- Inputs: HTTP file uploads for design CSV, SBOM JSON, SARIF JSON, CVE feeds.
- Outputs: JSON metadata previews and `/pipeline/run` report including overlay metadata.

**Gotchas**
- Overlay toggles control required inputs; Demo mode allows missing design context.
- Optional parser libraries are imported lazily—install them for production-grade accuracy.
