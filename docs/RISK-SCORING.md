# Risk Scoring Pipeline

The FixOps risk pipeline combines exploitability intelligence (EPSS), the CISA
Known Exploited Vulnerabilities (KEV) catalogue, component freshness and
exposure hints to produce a reproducible **FixOpsRisk** score per
component/CVE.

## Inputs

- **Normalized SBOM** – produced by `fixops-sbom normalize`, enriched with
  component exposure hints and vulnerability metadata.
- **EPSS feed** – cached CSV stored in `data/feeds/epss.csv`.
- **CISA KEV feed** – cached JSON stored in `data/feeds/kev.json`.

Both feeds can be refreshed with the helper utilities under `risk/feeds/` or via
CI.

## Risk formula

For every vulnerability discovered in a component we derive the following
signals:

| Signal | Description | Normalisation |
| ------ | ----------- | ------------- |
| `epss` | Exploit Prediction Scoring System value for the CVE. | CSV value clamped to `[0, 1]`. |
| `kev` | Whether the CVE is present in the KEV catalogue. | `1.0` if present, otherwise `0.0`. |
| `version_lag` | How stale the deployed version is compared to a fixed release or age metadata. | Normalised to `[0, 1]` using a 180 day cap. |
| `exposure` | Exposure hints from SBOM metadata (e.g. `internet`, `internal`). | Highest exposure weight mapped from configured aliases. |

Weights can be tuned but default to:

- `epss`: **0.50**
- `kev`: **0.20**
- `version_lag`: **0.20**
- `exposure`: **0.10**

The FixOpsRisk score is the weighted sum of the normalised values scaled to a
percentage:

```
FixOpsRisk = 100 × (epss×0.50 + kev×0.20 + version_lag×0.20 + exposure×0.10)
```

Outputs include the raw contributions, applied weights, exposure flags and the
normalised risk value so downstream services can audit the calculation.

## CLI usage

```
# Generate risk scores into artifacts/risk.json
./cli/fixops-risk score --sbom artifacts/sbom/normalized.json --out artifacts/risk.json
```

Optional overrides allow pointing at pre-fetched feeds:

```
./cli/fixops-risk score --sbom artifacts/sbom/normalized.json \
  --epss data/feeds/epss.csv --kev data/feeds/kev.json \
  --out artifacts/risk.json
```

The CLI prints how many components received scores. Re-running the command will
update the JSON deterministically.

## API endpoints

The FastAPI application exposes the following read-only endpoints once a risk
report is stored under the configured `risk_dir`:

- `GET /risk/` – summary metadata (generated timestamp, counts).
- `GET /risk/component/{slug}` – component level risk JSON.
- `GET /risk/cve/{cve}` – KEV/EPSS enriched view for the CVE.

Component slugs are derived from the component PURL (or name/version) by
lowercasing and replacing separators.

## Verifying results

1. Normalize SBOMs and build feeds (e.g. via CI cron).
2. Run the CLI scoring command and inspect `artifacts/risk.json`.
3. Call the API endpoints above to fetch the component or CVE level payloads.
4. Cross-check the `risk_breakdown` to confirm inputs (EPSS, KEV, exposure,
   version lag) were captured correctly.

The JSON structure is stable to support downstream automation and HTML report
rendering in future phases.
