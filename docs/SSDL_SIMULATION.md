# SSDLC Simulation Pack

The `simulations/ssdlc/` directory bundles deterministic fixtures that mirror each stage of the Secure Software Development Life Cycle. These artefacts provide a quick way to demo the FixOps pipeline without sourcing production data.

## Directory layout

| Stage | Inputs | Outputs | Runner |
| ----- | ------ | ------- | ------ |
| design | `design_context.csv`, `overlay.yaml` | `design_crosswalk.json` | `python simulations/ssdlc/run.py --stage design` |
| requirements | `controls.json` | `policy_plan.json` | `python simulations/ssdlc/run.py --stage requirements` |
| build | `sbom.json` | `component_index.json` | `python simulations/ssdlc/run.py --stage build` |
| test | `scanner.sarif` | `normalized_findings.json` | `python simulations/ssdlc/run.py --stage test` |
| deploy | `iac.tfplan.json` | `iac_posture.json` | `python simulations/ssdlc/run.py --stage deploy` |
| operate | `kev.json`, `epss.json` | `exploitability.json` | `python simulations/ssdlc/run.py --stage operate` |

## Usage

```bash
python simulations/ssdlc/run.py --stage design
python simulations/ssdlc/run.py --stage requirements
```

Each command prints the generated payload and updates the corresponding `outputs/` directory.
