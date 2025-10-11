# Evidence Bundles & Policy Evaluation

Phase 8 delivers an end-to-end evidence packaging workflow, combining SBOM artefacts, risk scores, provenance attestations, and reproducibility attestations into a single signed bundle accompanied by a policy-evaluated manifest.

## Policy configuration

Policies live in `config/policy.yml` (override via `--policy`). Each rule supports `warn_above`, `warn_below`, `fail_above`, and `fail_below` thresholds:

```yaml
risk:
  max_risk_score:
    warn_above: 70
    fail_above: 85
sbom_quality:
  coverage_percent:
    warn_below: 80
    fail_below: 60
  license_coverage_percent:
    warn_below: 75
    fail_below: 50
repro:
  require_match: true
provenance:
  require_attestations: true
```

## CLI

The new `fixops-ci` orchestration CLI proxies existing tooling and adds evidence packaging:

```bash
# Normalize SBOMs via fixops-sbom
cli/fixops-ci sbom normalize --in sboms/*.json --out artifacts/sbom/normalized.json

# Produce SBOM quality + HTML reports
cli/fixops-ci sbom quality --in artifacts/sbom/normalized.json --json analysis/sbom_quality_report.json --html reports/sbom_quality_report.html

# Compute risk scores
cli/fixops-ci risk score --sbom artifacts/sbom/normalized.json --out artifacts/risk.json

# Generate provenance + verify reproducibility
cli/fixops-ci provenance attest --artifact dist/fixops.tar.gz --out artifacts/attestations/fixops.json ...
cli/fixops-ci repro verify --tag v1.2.3 --plan build/plan.yaml

# Package evidence bundle
cli/fixops-ci evidence bundle \
  --tag v1.2.3 \
  --normalized artifacts/sbom/normalized.json \
  --quality-json analysis/sbom_quality_report.json \
  --quality-html reports/sbom_quality_report.html \
  --risk artifacts/risk.json \
  --provenance-dir artifacts/attestations \
  --repro-dir artifacts/repro/attestations \
  --policy config/policy.yml \
  --out evidence
```

If `--sign-key` is provided (typically populated from a GitHub Actions secret containing a cosign private key), the CLI will execute `cosign sign-blob` to produce `MANIFEST.yaml.sig` inside the bundle.

## Outputs

`evidence/` contains two directories:

- `evidence/bundles/<tag>.zip` – zipped artefacts and manifest
- `evidence/manifests/<tag>.yaml` – standalone manifest for API consumption

Each manifest includes:

- `artefacts` – file paths, original locations, and SHA-256 digests
- `metrics` – SBOM quality metrics, risk summary, reproducibility result, provenance count
- `evaluations` – per-check status and aggregate `overall`

## API

The FastAPI surface exposes:

- `GET /evidence/` – list available manifests and whether bundles are present
- `GET /evidence/{release}` – return manifest JSON (plus bundle metadata)

App state paths derive from overlay `data_directories.evidence_dir` or default to `<data-root>/evidence`.

## Testing

`tests/test_evidence_bundle.py` validates packager integrity, manifest structure, and CLI orchestration against golden policies.
