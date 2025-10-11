# Reproducible Builds Verifier

Phase 7 introduces a hermetic rebuild harness that replays release plans, re-creates artefacts, and records whether the rebuilt digest matches the attested reference.

## Build plans

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
| `environment` | No | Environment variables injected into each step.

Example (`build/plan.yaml`):

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
