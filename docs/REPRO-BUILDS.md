# Reproducible Builds in FixOps

## Overview

FixOps supports reproducible builds to ensure that identical source code produces bit-for-bit identical artifacts. This enables cryptographic verification of build integrity and supply chain security.

Phase 7 introduces a hermetic rebuild harness that replays release plans, re-creates artefacts, and records whether the rebuilt digest matches the attested reference.

## Quick Start

### 1. Seed Reference Checksum

```bash
./scripts/repro_seed.sh v1.0.0
```

### 2. Verify Reproducibility

```bash
PYTHONPATH=$(pwd) python cli/fixops_repro.py verify \
  --tag v1.0.0 \
  --plan build/plan.yaml \
  --out artifacts/repro/attestations \
  --repo .
```

## Build Plans

Plans live in `build/plan.yaml` (or alternative paths passed to the CLI) and support the following keys:

| Key | Required | Description |
| --- | --- | --- |
| `version` | No | Schema version marker (default `1`). |
| `tag` | No | Populated automatically from the CLI `--tag` flag; used for attestation naming. |
| `artifact` | Yes | Relative path to the artefact produced inside the hermetic workspace. `"{tag}"` tokens are replaced automatically. |
| `sources` | No | List of paths (strings or `{path, destination}` mappings) copied from the repository into the workspace before execution. |
| `steps` | Yes | Ordered commands to run. Each step accepts `run` as a string (shell) or list (exec form). |
| `reference_attestation` | Optional | Existing SLSA attestation used to derive the expected digest for comparison. |
| `reference_artifact` | Optional | Canonical artefact on disk that supplies the expected digest if no attestation is available. |
| `expected_digest` | Optional | Literal digest string (`sha256:...`) to compare against when no reference file exists. |
| `environment` | No | Environment variables injected into each step (LC_ALL, LANG, TZ recommended).

### Minimal Example

```yaml
version: 1
artifact: dist/fixops-{tag}.tar.gz
sources:
  - path: .
    destination: source
steps:
  - run: |
      mkdir -p dist
      tar -czf dist/fixops-{tag}.tar.gz -C source .
reference_attestation: artifacts/attestations/fixops-{tag}.json
```

### Deterministic Example (Recommended)

```yaml
version: 1
artifact: dist/fixops-{tag}.tar.gz
sources:
  - path: .
    destination: source
steps:
  - run: |
      mkdir -p dist
      rm -rf source/dist source/artifacts source/analysis source/reports source/tmp source/.pytest_cache source/__pycache__; find source -type d -name '__pycache__' -exec rm -rf {} +; find source -name '*.pyc' -delete
      GZIP=-n tar --sort=name --mtime='UTC 2023-01-01' \
        --owner=0 --group=0 --numeric-owner \
        --pax-option=delete=atime,delete=ctime,exthdr.name=%d/PaxHeaders/%f \
        -czf dist/fixops-{tag}.tar.gz -C source .
reference_attestation: artifacts/attestations/fixops-{tag}.json
environment:
  LC_ALL: C.UTF-8
  LANG: C.UTF-8
  TZ: UTC
```

## Deterministic Tar/Gzip Flags

| Flag | Purpose |
|------|---------|
| `GZIP=-n` | Disable gzip timestamps |
| `--sort=name` | Sort files alphabetically |
| `--mtime='UTC 2023-01-01'` | Fixed modification time |
| `--owner=0 --group=0` | Fixed ownership |
| `--numeric-owner` | Use numeric IDs (not names) |
| `--pax-option=delete=atime,delete=ctime` | Remove access/change times |
| `--pax-option=exthdr.name=%d/PaxHeaders/%f` | Stable PAX header names |

## CLI usage

The `fixops-repro` CLI orchestrates plan loading, execution, and attestation writing:

```bash
# Rebuild the v1.2.3 release and store the attestation under artifacts/repro/attestations
cli/fixops-repro verify --tag v1.2.3 --plan build/plan.yaml --out artifacts/repro/attestations
```

Exit codes:

- `0` – rebuild digest matches the attested/reference digest.
- `1` – referenced artefact/attestation missing.
- `2` – invalid plan definition.
- `3` – digest mismatch.

## Output

Successful runs emit `artifacts/repro/attestations/<tag>.json` with the following schema:

```json
{
  "tag": "v1.2.3",
  "artifact": "dist/fixops-v1.2.3.tar.gz",
  "generated_digest": {"sha256": "..."},
  "reference_digest": {"sha256": "..."},
  "match": true,
  "reference_source": "attestation:artifacts/attestations/fixops-v1.2.3.json",
  "verified_at": "2024-07-01T12:00:00Z"
}
```

## Continuous verification

`.github/workflows/repro-verify.yml` runs nightly (03:00 UTC) or on-demand via `workflow_dispatch`. It installs dependencies, executes `cli/fixops-repro verify`, and uploads generated attestations as workflow artefacts for downstream auditing.

## Testing

`services/repro/tests/test_verifier.py` covers happy-path and mismatch scenarios using toy plans to ensure digest comparison, attestation emission, and exit codes behave as expected.
