# Provenance Graph MVP

The provenance graph stitches together FixOps artefacts (git history, SLSA attestations, normalized SBOMs, risk reports, and release metadata) into a queryable knowledge graph. The Phase 6 MVP ships with a lightweight SQLite store plus an in-memory [NetworkX](https://networkx.org/) view that powers API queries and future visualisations.

## Data ingestion

The graph builder gathers data from the following locations (override via `config/data_directories`):

| Source | Default location | Notes |
| --- | --- | --- |
| Git metadata | repository working tree | Latest 100 commits with parents, authors, timestamps |
| SLSA attestations | `artifacts/attestations/` | Parsed via `services.provenance.attestation` |
| Normalized SBOM | `artifacts/sbom/normalized.json` | Component metadata, hashes, licences |
| Risk report | `artifacts/risk.json` | FixOpsRisk, KEV/EPSS annotations per CVE |
| Release manifest | `analysis/releases.json` | Optional mapping of releases → artefacts → component versions |

Each ingestion step upserts nodes and typed edges into SQLite while mirroring the structure in a `networkx.MultiDiGraph`. Subsequent phases can enrich the dataset without refactoring earlier steps.

## Query capabilities

Three query families are exposed via the API and service layer:

1. **Lineage** – Trace back an artefact (e.g. release tarball) to its attestation, builder, source URI, materials, and upstream commits.
2. **KEV coverage** – List components that still carry KEV CVEs across the most recent _N_ releases, including which CVEs are outstanding per component.
3. **Version anomalies** – Detect unexpected downgrades or regressions by comparing component versions across ordered releases.

The `services.graph.ProvenanceGraph` class exposes these queries along with ingestion helpers, enabling CLI tooling or notebooks to reuse the same logic.

## API surface

The FastAPI app mounts `backend.api.graph` and provides:

- `GET /graph/` – Node/edge counts plus configured data sources.
- `GET /graph/lineage/{artifact}` – Structured lineage payload for a given artefact filename.
- `GET /graph/kev-components?last=N` – Components with KEV CVEs across the most recent N releases (default: 3).
- `GET /graph/anomalies` – Component downgrades/version drift alerts derived from release manifests.

All endpoints require the same authentication strategy configured for the rest of the ingestion API.

## Release manifests

Add `analysis/releases.json` (or configure `graph_dir`) with entries like:

```json
{
  "releases": [
    {
      "tag": "v1.2.0",
      "date": "2024-01-05T00:00:00Z",
      "artifacts": ["fixops-v1.2.0.tar.gz"],
      "components": [
        {"slug": "pkg-a", "name": "pkgA", "version": "1.2.0"}
      ]
    }
  ]
}
```

Component `slug` values should match the normalized SBOM / risk report entries to unlock KEV correlation and anomaly detection.

## Testing

Unit coverage for the MVP lives in `services/graph/tests/test_graph.py`, exercising ingestion, lineage, KEV queries, and anomaly detection against golden fixtures.
