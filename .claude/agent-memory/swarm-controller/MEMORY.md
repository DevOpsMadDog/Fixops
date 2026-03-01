# Swarm Controller Memory

## Key Patterns

### Task Decomposition
- Senior agent status files are sparse — extract work from `decisions.log` instead
- Read-only tasks (tests, lint, audit) work great with haiku model (80% cost savings)
- 8 tasks per wave is optimal for this codebase (avoids resource contention)

### Test Performance
- Brain pipeline: 73 tests, ~68s (heavy — 1 test = 3.1s)
- AutoFix engine: 37 tests, ~2.5s (fast)
- Compliance engine: 42 tests, ~2.7s (fast)
- Crypto/evidence: 88 tests, ~18s (medium — RSA key gen)
- E2E comprehensive: 24 tests, ~28s (slow — app init per test)
- API smoke: 29 tests but EXTREMELY slow — full app init creates 766 routes per test client
  - `/api/v1/brain/most-connected` returns 500 (knowledge_brain.py:326 lock timeout)

### Known Issues
- `core.cspm_analyzer` doesn't exist — correct module is `core.cspm_engine`
- pyproject.toml has expanded `--cov=` directives but coverage still low (~19%)
- 3 E2E edge-case failures: wrong status code (413→422), CLI demo arg, API key not enforced
- Docker socket mount CRITICAL in docker-compose.aldeci-complete.yml
- Postman collections use mixed URL variables: `{{apiBase}}` (81%) vs `{{base_url}}` (18%)

### API Surface
- 766 routes, 77 `/api/v1/` prefixes, 683 OpenAPI paths
- Top: copilot (46), feeds (31), brain (31), webhooks (25)
- V3=54, V5=42, V7=68 endpoints for active pillars

### UI
- 81 TSX files, 5 TS files, 30,581 LOC, 59 pages, 19 components
- TypeScript: 0 errors
- Vite build: 1.63s, 534 KB bundle

### Lint Status
- suite-core: 95 issues (55 F401 unused imports, 60 auto-fixable)
- suite-api: 74 issues (60 E402 import order, 7 auto-fixable)
- suite-attack: 3 issues (2 F401, 1 F841)
