# Stage Workflow Runbook

Each stage uses the bundled fixtures and the canonical CLI to produce reproducible outputs. Run the commands from the repository root.

| Stage | Input | Command | Output |
| --- | --- | --- | --- |
| Requirements | `fixtures/sample_inputs/requirements/requirements-input.csv` | `python -m apps.fixops_cli stage-run --stage requirements --input fixtures/sample_inputs/requirements/requirements-input.csv --app life-claims-portal --mode demo` | `fixtures/expected_outputs/requirements/requirements.json` |
| Design | `fixtures/sample_inputs/design/design-input.json` | `python -m apps.fixops_cli stage-run --stage design --input fixtures/sample_inputs/design/design-input.json --app life-claims-portal --mode demo` | `fixtures/expected_outputs/design/design.manifest.json` |
| Build | `fixtures/sample_inputs/build/sbom.json` | `python -m apps.fixops_cli stage-run --stage build --input fixtures/sample_inputs/build/sbom.json --app life-claims-portal --mode demo` | `fixtures/expected_outputs/build/build.report.json` |
| Test | `fixtures/sample_inputs/test/scanner.sarif` | `python -m apps.fixops_cli stage-run --stage test --input fixtures/sample_inputs/test/scanner.sarif --app life-claims-portal --mode demo` | `fixtures/expected_outputs/test/test.report.json` |
| Deploy | `fixtures/sample_inputs/deploy/tfplan.json` | `python -m apps.fixops_cli stage-run --stage deploy --input fixtures/sample_inputs/deploy/tfplan.json --app life-claims-portal --mode demo` | `fixtures/expected_outputs/deploy/deploy.manifest.json` |
| Operate | `fixtures/sample_inputs/operate/ops-telemetry.json` | `python -m apps.fixops_cli stage-run --stage operate --input fixtures/sample_inputs/operate/ops-telemetry.json --app life-claims-portal --mode demo` | `fixtures/expected_outputs/operate/operate.snapshot.json` |
| Decision | `fixtures/sample_inputs/decision/decision-input.json` | `python -m apps.fixops_cli stage-run --stage decision --input fixtures/sample_inputs/decision/decision-input.json --app life-claims-portal --mode demo` | `fixtures/expected_outputs/decision/decision.json`, `fixtures/expected_outputs/decision/manifest.json`, `fixtures/expected_outputs/decision/evidence_bundle.zip` |

Use `scripts/run_stage_workflow.py` to execute the entire sequence with one command:

```bash
FIXOPS_RUN_ID_SEED=stage-demo \
FIXOPS_FAKE_NOW=2024-01-01T00:00:00Z \
python scripts/run_stage_workflow.py \
  --fixtures fixtures/sample_inputs \
  --artefacts artefacts/stage-demo \
  --summary artefacts/stage-demo/summary.json
```

The script prints a success line for each stage and captures a JSON summary listing the canonical artefacts.
