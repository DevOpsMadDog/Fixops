# FixOps Ingestion Demo

This repository includes a lightweight FastAPI backend that demonstrates how FixOps normalises
security artefacts before running the decision pipeline. The new ingestion endpoints rely on
maintained OSS parsers and are covered by an end-to-end regression test.

## Key Dependencies

The backend now depends on maintained parsers for each artefact type:

- [`lib4sbom`](https://github.com/anchore/lib4sbom) for CycloneDX/SPDX normalisation.
- [`snyk-to-sarif`](https://github.com/snyk/snyk-to-sarif) (optional) for converting Snyk JSON into
  SARIF when necessary.
- [`sarif-om`](https://github.com/microsoft/sarif-python-om) for SARIF schema handling.
- [`cvelib`](https://github.com/redhat-product-security/cvelib) to validate CVE/KEV records using the
  official JSON schemas.

These dependencies are declared in `backend/requirements.txt`.

## API Walkthrough

1. **Upload the design CSV** to `/inputs/design` using `multipart/form-data`.
   The service parses the CSV, persists the structured rows in memory, and returns the detected
   columns and row count.
2. **Upload an SBOM** via `/inputs/sbom`. The payload is normalised through `lib4sbom` and the
   response includes component metadata and a preview of the first five components.
3. **Upload the CVE/KEV feed** to `/inputs/cve`. Each record is validated with `cvelib`. Validation
   errors are returned alongside the record count.
4. **Upload SARIF findings** through `/inputs/sarif`. The SARIF log is parsed with `sarif-om`; if a
   raw Snyk payload is provided, it is converted using `snyk-to-sarif` before parsing.
5. **Execute the pipeline** with `POST /pipeline/run`. The orchestrator correlates design rows with
   SBOM components, SARIF findings, and CVE entries, returning a `crosswalk` for each design row and
   summary statistics for every layer.

## Testing the Flow

Run the FastAPI test suite to exercise the entire scenario end-to-end:

```bash
pytest -q
```

The regression covers uploading a design CSV, SBOM, CVE feed, and SARIF log followed by a pipeline
execution, asserting that every intermediate response contains the expected information.
