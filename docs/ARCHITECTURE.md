# FixOps Ingestion Demo — Architecture Overview

This document explains how the backend FastAPI service ingests security artefacts, normalises
them, and correlates the data during the pipeline run. It is written for a mixed audience — you
do not need to be a developer to understand how requests move through the system.

## Key Components

1. **FastAPI Application (`backend/app.py`)**
   - Exposes `/inputs/*` endpoints for uploading CSV, SBOM, CVE/KEV, and SARIF artefacts.
   - Stores the normalised artefacts in `app.state.artifacts` for later orchestration.
   - Delegates all parsing to `InputNormalizer` and orchestration to `PipelineOrchestrator`.
2. **Normalisation Layer (`backend/normalizers.py`)**
   - Converts raw files into structured Python dataclasses using maintained OSS parsers.
   - Provides consistent `to_dict()` helpers so the API can serialise responses quickly.
3. **Pipeline Orchestrator (`backend/pipeline.py`)**
   - Correlates design rows with SBOM components, SARIF findings, and CVE entries.
   - Generates summary statistics for each artefact and returns a crosswalk.

## Lifecycle of a Typical Session

```mermaid
sequenceDiagram
    actor User
    participant API as FastAPI App
    participant Normalizer
    participant Store as In-Memory Store
    participant Orchestrator

    User->>API: POST /inputs/design (CSV)
    API->>Normalizer: parse design CSV
    Normalizer-->>API: columns + rows
    API->>Store: save design dataset

    User->>API: POST /inputs/sbom (SBOM file)
    API->>Normalizer: load_sbom
    Normalizer-->>API: NormalizedSBOM
    API->>Store: save SBOM

    User->>API: POST /inputs/cve (JSON feed)
    API->>Normalizer: load_cve_feed
    Normalizer-->>API: NormalizedCVEFeed
    API->>Store: save CVE feed

    User->>API: POST /inputs/sarif (JSON)
    API->>Normalizer: load_sarif
    Normalizer-->>API: NormalizedSARIF
    API->>Store: save SARIF

    User->>API: POST /pipeline/run
    API->>Orchestrator: run(design, sbom, sarif, cve)
    Orchestrator-->>API: summaries + crosswalk
    API-->>User: HTTP 200 + JSON report
```

## Deployment Boundary Diagram

```mermaid
graph TD
    subgraph Client
        Browser[(Analyst UI)]
    end
    subgraph Backend
        A[FastAPI App]
        B[InputNormalizer]
        C[PipelineOrchestrator]
    end
    subgraph OSS Parsers
        L[lib4sbom]
        S[sarif-om]
        CVE[cvelib]
        SY[snyk-to-sarif]
    end

    Browser -->|HTTP| A
    A --> B
    A --> C
    B --> L
    B --> S
    B --> CVE
    B --> SY
```

## Data Flow Highlights

- All uploads are processed in-memory. The service does **not** persist artefacts to disk or a
  database.
- Normalised objects store both concise fields (e.g., component name, severity) and the full raw
  payload for traceability.
- The orchestrator pre-computes lowercase lookup tables so string matching across artefacts is
  fast and case-insensitive.

## Error Handling & Logging

- Upload endpoints wrap parser failures in HTTP 400 errors with human-readable messages.
- Normalisation emits structured debug logs containing metadata counts to help operations teams
  inspect the flow without dumping raw artefacts.
- Missing artefacts during `/pipeline/run` result in a single 400 response that names every missing
  stage.

## Extensibility Considerations

- Additional artefact types can be added by creating new normaliser methods and storing the result
  in `app.state.artifacts` using the `_store` helper.
- The orchestrator is deliberately stateless; you can replace it or run multiple orchestrators in
  parallel by instantiating a new object per request or per tenant.

