# External Integrations

The ingestion service relies on a set of third-party libraries to parse and validate uploaded
artefacts. This guide captures their purpose, how they are invoked, and the fallback behaviour if a
library is unavailable.

| Integration | Purpose | Invocation Point | Failure Mode |
| ----------- | ------- | ---------------- | ------------ |
| `lib4sbom` | Parses SPDX/CycloneDX SBOM documents into a common representation. | `InputNormalizer.load_sbom()` creates an `SBOMParser`, reads the SBOM string, and extracts packages/relationships/services. | Raises whichever exception the parser surfaces; the API wraps it in HTTP 400. |
| `cvelib` | Validates CVE/KEV records against the official schema. | `InputNormalizer.load_cve_feed()` calls `CveRecord.validate()` when available. | Missing library downgrades to best-effort ingestion; validation errors are appended to the response. |
| `snyk-to-sarif` | Converts proprietary Snyk JSON payloads into SARIF. | `InputNormalizer.load_sarif()` detects missing `runs` and calls `convert`/`to_sarif` if the converter exists. | Absent converter means non-SARIF payloads are rejected with `ValueError`. |
| `sarif-om` | Provides typed SARIF models for introspection. | `InputNormalizer.load_sarif()` instantiates `SarifLog` to carry metadata and normalise access. | Missing dependency is fatal at import time, raising `RuntimeError` to alert deployers. |

## HTTP Surface

- All endpoints are public within the FastAPI app. In production deployments you should layer
  authentication (API keys or OAuth) in front of the service.
- CORS is currently wide open to support local prototyping. Restrict `allow_origins` before exposing
  the API on the internet.

## Observability

- The backend uses Python's standard logging. Configure log handlers in your deployment environment
  (e.g., JSON logs shipped to ELK) to capture normalisation metadata and error traces.
- Add request/response metrics by integrating FastAPI middleware such as Prometheus or OpenTelemetry.

