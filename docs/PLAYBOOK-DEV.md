# Developer Playbook

This playbook captures the day-to-day conventions for contributing to the FixOps demo branch. Follow it to keep the
hardening, provenance, and evidence surfaces healthy while we iterate in public.

## Principles

- **Security-first defaults** – never disable signing, provenance, or repro verification in committed code. Prefer feature
  toggles backed by environment variables.
- **Deterministic artefacts** – all reproducible outputs (`artifacts/`, `analysis/`, `reports/`, `evidence/`) must be generated
  from committed fixtures or documented commands so investors can replay the run.
- **Small, reviewable commits** – each phase lands as a single, scoped commit with matching docs/tests so the provenance chain
  stays auditable.

## Environment bootstrap

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements.dev.txt
```

For CI parity install the optional extras used by the API and demo stack:

```bash
pip install -r apps/api/requirements-optional.txt  # optional, enables richer FastAPI features
```

## Local quality gates

| Task | Command |
| --- | --- |
| Format | `black .` |
| Import hygiene | `isort .` |
| Lint | `flake8` |
| Type checking | `mypy .` |
| Unit tests | `pytest` |
| Coverage report (target ≥ 70%) | `coverage run -m pytest && coverage report -m` |
| HTML coverage export | `coverage html -d reports/coverage/html && coverage xml -o reports/coverage/coverage.xml` |
| Evidence bundle smoke test | `cli/fixops-ci evidence bundle --help` |

`reports/coverage/summary.txt` is committed so reviewers can diff the aggregate metrics; regenerate it with
`coverage report -m > reports/coverage/summary.txt` after running the full coverage command above.

## Continuous integration expectations

The `qa` workflow (`.github/workflows/qa.yml`) enforces linting, mypy, unit tests, and coverage on every push and pull request.
Local changes should pass the same command matrix before you open a PR:

```bash
coverage run -m pytest
coverage xml -o reports/coverage/coverage.xml
coverage report -m > reports/coverage/summary.txt
mypy .
flake8
```

Keep `reports/coverage/coverage.xml` and `reports/coverage/summary.txt` up to date in your commits so CI can display the
threshold deltas.

## Telemetry-aware development

- Telemetry is enabled by default (OTLP HTTP → `http://collector:4318`).
- Disable spans and metrics locally with `FIXOPS_DISABLE_TELEMETRY=1` or point the exporter to another collector by overriding
  `OTEL_EXPORTER_OTLP_ENDPOINT`.
- When running the demo stack (`docker compose -f docker-compose.demo.yml up --build`), traces flow to the bundled collector and
  surface in the dashboard at `http://localhost:8080`.

## Demo & evidence workflow

1. Generate SBOM, risk, provenance, and repro artefacts via the dedicated CLIs (`cli/fixops-sbom`, `cli/fixops-risk`,
   `cli/fixops-provenance`, `cli/fixops-repro`).
2. Package evidence bundles using `cli/fixops-ci evidence bundle --tag vX.Y.Z`.
3. Start the observability stack: `docker compose -f docker-compose.demo.yml up --build`.
4. Browse `http://localhost:8080` for the telemetry-enabled dashboard and download bundles from `backend/api/evidence/{release}`.

## Branching and reviews

- Work from short-lived branches that carry the phase prefix (e.g. `feature/phase10-hardening`).
- Document every new surface in the README documentation map and backfill playbook/security posture updates.
- Attach coverage diffs and demo screenshots to PR descriptions so stakeholders can validate the investor-ready experience.
