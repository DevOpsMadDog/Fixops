# Contributing to FixOps

Thanks for investing time in improving FixOps! This short guide explains how to set up a reliable development environment and submit high-signal pull requests.

## Prerequisites

- Python 3.10 or newer
- `pip` and `virtualenv` support
- Access to the FixOps repository (SSH or HTTPS)

Optional but recommended:

- Docker (for running the FastAPI service or database locally)
- direnv or dotenv support for loading `.env` files

## Quick start

```bash
# Clone the repository
$ git clone git@github.com:DevOpsMadDog/Fixops.git
$ cd Fixops

# Bootstrap the development environment
$ ./scripts/bootstrap.sh

# Run formatting, linting, typing, and tests
$ make fmt lint typecheck test

# Execute both demo profiles to ensure deterministic outputs
$ make demo
$ make demo-enterprise
```

The `scripts/bootstrap.sh` helper creates `.venv`, installs runtime + dev dependencies, and configures pre-commit hooks.

## Pre-commit hooks

After running the bootstrap script, pre-commit hooks install automatically. You can run them manually with:

```bash
$ pre-commit run --all-files
```

The configured hooks enforce formatting (Ruff/Black), typing (mypy), and secret scanning (detect-secrets). Keep the `.secrets.baseline` file up to date by running `detect-secrets scan` whenever legitimate secrets move or rotate.

## Running the demo pipelines

FixOps ships with deterministic fixtures under `demo/fixtures`. You can run the pipeline in both demo and enterprise modes:

```bash
$ make demo
$ make demo-enterprise
```

Results are printed to stdout and archived under the configured evidence directory.

## Tests & coverage

Run the main test suite with `make test`. For quick iterations use pytest markers, e.g. `pytest tests/test_context_engine.py -k "enterprise"`.

When adding new features, include unit/integration tests to preserve behaviour. Aim for at least 70% coverage on critical modules and update regression fixtures as needed.

## Submitting pull requests

1. Create a feature branch from `main`.
2. Commit your work with clear, conventional commit messages.
3. Update documentation, changelogs, and the PR checklist.
4. Ensure CI is green before requesting review.
5. Reference any related issues or product requirements in the PR body.

Thank you for helping keep FixOps investor-demo ready!
