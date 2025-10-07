# Contributing Guide

Thanks for improving FixOps! This document explains how to set up a development environment, run
checks, and contribute changes safely.

## Environment Setup

1. Create a virtual environment with Python 3.11.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Install the extended parser toolchain:
   ```bash
   pip install lib4sbom sarif-om cvelib pyyaml
   # Only if you have access to the private Snyk converter repository
   pip install -r backend/requirements-optional.txt
   ```

## Overlay Configuration

- Copy `config/fixops.overlay.yml` and adjust values as needed. The default file contains Demo settings
  plus Enterprise overrides and AI agent watchlists.
- Export `FIXOPS_OVERLAY_PATH` to point to your custom overlay when running locally.
- If `auth.strategy: token`, export `FIXOPS_API_TOKEN=<secret>` (or whichever env var you reference)
  before starting the FastAPI app or hitting the endpoints.
- Optionally constrain data directories with
  `FIXOPS_DATA_ROOT_ALLOWLIST=/srv/fixops/data:/var/lib/fixops` to mimic production hardening.

## Running Tests

```bash
pytest
```

Key test suites:

- `tests/test_end_to_end.py` — exercises the FastAPI endpoints end-to-end.
- `tests/test_new_backend_*` — covers the decision-engine subset in `new_backend/`.
- `tests/test_overlay_configuration.py` — verifies overlay parsing, defaults, validation, env-var
  enforcement, and allowlisted data directories.
- `tests/test_cve_simulation.py` — runs the Log4Shell contextual scoring simulation for Demo and Enterprise overlays.
- `tests/test_feedback.py` — checks the feedback recorder JSONL workflow.
- `tests/test_ai_agents.py` — validates AI agent detection helpers.

To execute the CVE simulation manually and capture the generated evidence bundles:

```bash
python simulations/cve_scenario/runner.py --mode demo
python simulations/cve_scenario/runner.py --mode enterprise
```

Use the bundled CLI to exercise the entire pipeline without FastAPI:

```bash
python -m fixops.cli run \
  --overlay config/fixops.overlay.yml \
  --sbom path/to/sbom.json \
  --sarif path/to/scan.sarif \
  --cve path/to/cve.json \
  --output tmp/pipeline.json \
  --evidence-dir tmp/evidence \
  --offline
```

The CLI writes contextual scorecards and evidence JSON files to the `evidence_dir` configured by your overlay and honours module toggles provided via command-line overrides.

## Linting & Formatting

- Follow PEP 8 style conventions and format docstrings using Google style.
- Run `python -m compileall backend new_backend fixops` if you need a quick syntax validation pass.
- If you add static analysis tooling (e.g., `ruff`, `mypy`), document the commands here.

## Pull Request Checklist

- Update documentation when behaviour changes (architecture, configuration, or onboarding guides).
- Add or update tests for new features and bug fixes.
- Ensure `/pipeline/run` responses still include overlay metadata in Demo mode.
- Include citations when updating market-facing documents.

## Filing Issues

When reporting bugs, include:

- Reproduction steps with sample artefacts (design CSV, SBOM snippet, SARIF finding, CVE entry).
- Active overlay mode and relevant toggles.
- Stack traces or response payloads showing the failure.
