# CI Gate Enforcement Map — 2026-06-03

Audited all 10 workflows for which gates actually BLOCK a PR-to-main vs are non-blocking.
A gate is toothless if it has `|| true`, `|| echo "...skipping"`, `continue-on-error: true`,
or doesn't run on `pull_request: [main]`.

## BLOCKING (enforce on PR-to-main) — verified
| Gate | Workflow / job | Notes |
|------|----------------|-------|
| Beast Mode smoke (13 files / 756) | ci.yml `beast-mode` | `-x`, no guard — the T1 change-gate |
| Coverage ≥18% baseline | ci.yml (run tests w/ coverage) | `--cov-fail-under=18 -x` |
| OWASP regression lockdown | regression-gates `owasp-lockdown` | blocking |
| Engine + router import sweep | regression-gates | made blocking 2026-06-03 (#9087) |
| **Auth gate** (no unauthenticated /api/v1) | regression-gates | made blocking 2026-06-03 (#9087) |
| **UI NO-MOCKS static** | regression-gates | made blocking 2026-06-03 (#9087) |
| **UI TypeScript compile** (tsc) | ci.yml | made blocking 2026-06-03 (#9086) |
| Job env supports the above | owasp-lockdown env | PYTHONPATH + FIXOPS_* present (verified #9087) |

## NON-BLOCKING — deliberate policy / debt-tolerance (FOUNDER decisions, not bugs)
| Gate | Why non-blocking | To enforce |
|------|------------------|-----------|
| diff-cover ≥80% new-code | `continue-on-error: true` | flip if the team adopts an 80%-new-code-coverage policy |
| Ruff lint (all suites) | continue-on-error | ~13K legacy violations — needs a cleanup epic before blocking |
| mypy type check | continue-on-error | legacy untyped backend — same |
| pip-audit / snyk / trivy / semgrep | `|| true` (report-capture) | "a CVE fails the build" is a security-policy call |
| perf-lockdown (benchmarks) | `|| echo skip` | timing-flaky (cf. the documented test_100_findings flake) |
| cleanup (kill/docker stop/down -v), healthcheck probes, install fallbacks | `|| true` | correctly non-blocking |

## Net
The correctness + security gates that matter for a $100K SCIF review now genuinely block
(several were toothless until 2026-06-03). The remaining non-blocking gates are policy choices
the founder should decide explicitly (coverage-80%, lint/type-debt blocking, CVE-blocking).
