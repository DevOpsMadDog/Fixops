# SSDLC Simulation Runner

The `simulations/ssdlc/` package contains deterministic fixtures for each Secure SDLC stage and a unified CLI runner. Outputs land in a supplied directory so downstream analytics or demos can ingest consistent artifacts.

## Stage Matrix
| Stage | Inputs (under `simulations/ssdlc/<stage>/inputs/`) | Outputs | CLI Entry Point |
| --- | --- | --- | --- |
| design | `design_context.csv`, optional overlay YAML | `design_crosswalk.json` | `python simulations/ssdlc/run.py --stage design --out ./artifacts/design` |
| requirements | `controls.json`, optional overlay policy fragments | `policy_plan.json` | `python simulations/ssdlc/run.py --stage requirements --out ./artifacts/requirements` |
| build | `sbom.json`, component metadata overlays | `component_index.json` | `python simulations/ssdlc/run.py --stage build --out ./artifacts/build` |
| test | `scanner.sarif`, baselines for noise suppression | `normalized_findings.json` | `python simulations/ssdlc/run.py --stage test --out ./artifacts/test` |
| deploy | `iac.tfplan.json`, posture policy overrides | `iac_posture.json` | `python simulations/ssdlc/run.py --stage deploy --out ./artifacts/deploy` |
| operate | `kev.json`, `epss.json`, vulnerability override lists | `exploitability.json` | `python simulations/ssdlc/run.py --stage operate --out ./artifacts/operate` |

## Example Usage
```bash
# Generate design stage outputs with an overlay file
python simulations/ssdlc/run.py --stage design --overlay overrides/design.yaml --out ./artifacts/design

# Run all stages into a single directory
for stage in design requirements build test deploy operate; do
  python simulations/ssdlc/run.py --stage "$stage" --out ./artifacts/$stage
done
```

## Implementation Notes
- Each stage adapter validates required input files before emitting artifacts.
- The runner exits with non-zero status if validation fails or the stage is unknown.
- Overlays are merged shallowly onto base fixtures, ensuring deterministic output with optional customization.
- Outputs are JSON (or CSV if indicated by the stage) to simplify ingestion into dashboards and follow-on analysis.
