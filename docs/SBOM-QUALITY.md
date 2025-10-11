# SBOM Quality Normalization and Reporting

This guide documents how FixOps consolidates software bills of materials (SBOMs) from multiple generators, removes duplicates, and produces measurable quality scores.

## Normalization workflow

1. Export SBOMs from supported generators (for example Syft, Trivy, and osv-scanner) in JSON form.
2. Run the normalizer CLI to merge and de-duplicate the inputs:

   ```bash
   ./cli/fixops-sbom normalize --in path/to/syft.json path/to/trivy.json --out artifacts/sbom/normalized.json
   ```

   The command accepts CycloneDX and SPDX JSON documents. Components are deduplicated using the combination of Package URL (purl), version, and the most reliable hash present. Source generator metadata is retained for variance analysis.

## Quality metrics

Generate machine-readable and human-friendly quality reports from the normalized SBOM:

```bash
./cli/fixops-sbom quality --in artifacts/sbom/normalized.json --html reports/sbom_quality_report.html
```

This command emits two artefacts:

- `analysis/sbom_quality_report.json` – canonical metrics for automated validation.
- `reports/sbom_quality_report.html` – dashboard-style view for manual review.

### Metrics captured

| Metric | Description |
| --- | --- |
| Coverage % | Ratio of unique components versus total component observations across generators. |
| License Coverage % | Percentage of unique components with at least one declared or concluded license. |
| Resolvability % | Share of components that include a package URL or checksum, making downstream enrichment possible. |
| Generator Variance Score | Jaccard-like score (0 to 1) showing how much component coverage diverges between generators. |

All outputs are deterministic for a fixed input set, ensuring reproducible reports across runs.

## Troubleshooting

- **Missing metrics** – confirm the normalized SBOM includes metadata for `total_components` and `unique_components`. The normalizer sets these automatically.
- **Unexpected duplicates** – ensure each generator exported the same SBOM format (CycloneDX or SPDX) and that component entries include consistent purl/hash values.
- **Directory creation** – the CLI automatically creates the `artifacts/sbom/`, `analysis/`, and `reports/` directories when writing outputs.
