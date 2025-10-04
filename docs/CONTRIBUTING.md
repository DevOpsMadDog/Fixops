# Contributing Guide

Thanks for improving FixOps! This document explains how to set up a development environment, run
checks, and contribute changes safely.

## Environment Setup

1. Create a virtual environment with Python 3.11.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Install optional parser libraries for richer normalisation:
   ```bash
   pip install lib4sbom sarif-om snyk-to-sarif cvelib pyyaml
   ```

## Overlay Configuration

- Copy `config/fixops.overlay.yml` and adjust values as needed. The default file contains Demo settings
  plus Enterprise overrides.
- Export `FIXOPS_OVERLAY_PATH` to point to your custom overlay when running locally.

## Running Tests

```bash
pytest
```

Key test suites:

- `tests/test_end_to_end.py` — exercises the FastAPI endpoints end-to-end.
- `tests/test_new_backend_*` — covers the decision-engine subset in `new_backend/`.
- `tests/test_overlay_configuration.py` — verifies overlay parsing, defaults, and environment overrides.
- `tests/test_cve_simulation.py` — runs the Log4Shell contextual scoring simulation for Demo and Enterprise overlays.

To execute the CVE simulation manually and capture the generated evidence bundles:

```bash
python simulations/cve_scenario/runner.py --mode demo
python simulations/cve_scenario/runner.py --mode enterprise
```

The CLI writes contextual scorecards and evidence JSON files to the `evidence_dir` configured by your overlay.

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
