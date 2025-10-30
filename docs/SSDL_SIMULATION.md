# SSDLC Simulation Runner

The FixOps SSDLC simulator generates deterministic artefacts for each lifecycle stage using curated sample inputs located under `simulations/ssdlc/*/inputs`. The CLI consolidates the existing normalisers into a single entry point so that demos, tests, and CI pipelines can reproduce the blended evidence set without standing up the full platform.

## Usage

```bash
python -m simulations.ssdlc.run --stage design --overlay overlays/demo.yaml --out ./sim_out
```

### Stage adapters

| Stage | Input file | Output artefact | Description |
| --- | --- | --- | --- |
| `design` | `design/inputs/design_context.csv` | `design_crosswalk.json` | Normalises architecture context and exposure classes, producing a component crosswalk. |
| `requirements` | `requirements/inputs/controls.json` | `policy_plan.json` | Maps control definitions into a remediation plan highlighting outstanding rules. |
| `build` | `build/inputs/sbom.json` | `component_index.json` | Extracts SBOM metadata and sorts components for downstream reconciliation. |
| `test` | `test/inputs/scanner.sarif` | `normalized_findings.json` | Flattens SARIF runs into a severity histogram and participating tooling list. |
| `deploy` | `deploy/inputs/iac.tfplan.json` | `iac_posture.json` | Summarises Terraform plan ingress rules to capture exposed ports and internet reachability. |
| `operate` | `operate/inputs/kev.json`, `operate/inputs/epss.json` | `exploitability.json` | Correlates KEV + EPSS digests to highlight active exploitation priorities. |

### Running all stages

Use the special `all` stage to materialise every artefact in a single command. Stage-specific overlay overrides can be provided via a YAML or JSON file using a `stages.<name>` structure.

```bash
python -m simulations.ssdlc.run --stage all --overlay overlays/demo.yaml --out ./sim_out
```

Example overlay snippet:

```yaml
stages:
  design:
    risk_summary:
      internet: 2
  test:
    severity_breakdown:
      error: 3
```

### Output layout

All outputs are written beneath the directory supplied to `--out`. When `--stage all` is used the command prints a JSON summary listing the generated files:

```json
{
  "stage": "all",
  "outputs": {
    "design": "sim_out/design_crosswalk.json",
    "requirements": "sim_out/policy_plan.json",
    "build": "sim_out/component_index.json",
    "test": "sim_out/normalized_findings.json",
    "deploy": "sim_out/iac_posture.json",
    "operate": "sim_out/exploitability.json"
  }
}
```

These artefacts feed the CI adapters and evidence lake, enabling deterministic regression baselines for the FixOps blended platform.
