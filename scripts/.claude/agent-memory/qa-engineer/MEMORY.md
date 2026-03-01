# QA Engineer Persistent Memory

## Key Project Patterns

### PEP 563 and Pydantic Annotations
- The test files use `from __future__ import annotations` (PEP 563)
- This causes ALL annotations to be lazy strings, including Pydantic models
- `_extract_request_body_schema()` in mcp_router.py checks `isinstance(annotation, type)` which fails with PEP 563
- **Workaround**: Use `compile(code, "<test>", "exec", flags=0, dont_inherit=True)` then `exec()` to define test functions without inheriting the future flag
- `print` builtin has a valid `inspect.signature` in Python 3.11+ (not like older versions)

### Test Infrastructure
- pyproject.toml: timeout=10s, cov-fail-under=60, black line-length=88
- Auth: `X-API-Key` header from `FIXOPS_API_TOKEN` env var (enterprise key required)
- Rate limiting disabled via `FIXOPS_DISABLE_RATE_LIMIT=1`
- conftest.py has `app_client`, `authenticated_client`, `auth_headers` fixtures
- TestClient with `raise_server_exceptions=False` for isolated router testing

### Coverage Targets Achieved (2026-02-27)
- analytics_router: 94.71% | reports_router: 92.94% | rate_limiter: 100%
- connectors_router: 95.77% | fail_router: 95.16% | mcp_router: 86.57%
- monitoring.py: 75.78%

### Test File Locations
- tests/test_{module}_unit.py pattern for all router tests
- 450 total tests across 8 test files, all passing

### Black Formatting
- Always run `python -m black --line-length 88` after editing test files
- The linter auto-reformats on save, so re-read file after first edit attempt

### Evidence Router Notes
- evidence_router.py: `list_evidence()` only globs `*.yaml`, NOT `*.yml`
- `evidence_stats()` globs both `*.yaml` AND `*.yml`
- This is an inconsistency worth noting but reflects actual behavior
- Demo data returned when no manifests on disk (for UI dev)
