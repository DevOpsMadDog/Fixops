# FixOps Pull Request Checklist

Use this checklist to keep investor/demo branches production ready. Copy the list into your PR description and tick each item before requesting review.

- [ ] I have run `make fmt`, `make lint`, and `make test` locally (or explained why checks are skipped).
- [ ] I ran `python -m mypy --config-file mypy.ini core apps scripts` to monitor typing regressions when my change touched typed modules.
- [ ] I executed `make demo` **and** `make demo-enterprise` to ensure the bundled fixtures still succeed.
- [ ] Secrets and access tokens have been sourced from environment variables or vaults (no new secrets committed).
- [ ] Dependency updates are pinned and documented in `requirements*.txt` (including dev requirements when applicable).
- [ ] I updated documentation (`README.md`, runbooks, or changelogs) where behaviour changed.
- [ ] I considered backwards compatibility for API/CLI surfaces and noted any breaking changes.
- [ ] I ran `pre-commit run --all-files` before pushing.
