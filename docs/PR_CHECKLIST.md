# FixOps Pull Request Checklist

Use this checklist to keep investor/demo branches production ready. Copy the list into your PR description and tick each item before requesting review.

- [ ] I have run `make fmt` and `make lint` locally.
- [ ] I have run `make typecheck` and `make test` (or explained why tests are skipped).
- [ ] I executed `make demo` **and** `make demo-enterprise` to ensure the bundled fixtures still succeed.
- [ ] Secrets and access tokens have been sourced from environment variables or vaults (no new secrets committed).
- [ ] Dependency updates are pinned and documented in `requirements*.txt` (including dev requirements when applicable).
- [ ] I updated documentation (`README.md`, runbooks, or changelogs) where behaviour changed.
- [ ] I considered backwards compatibility for API/CLI surfaces and noted any breaking changes.
- [ ] I ran `pre-commit run --all-files` before pushing.
