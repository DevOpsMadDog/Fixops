# Backend Hardener Persistent Memory

## Project Structure
- FastAPI app: `suite-api/apps/api/app.py` (~2737 LOC)
- Evidence router: `suite-evidence-risk/api/evidence_router.py` (1,116 LOC, 10 routes)
- Tests: `tests/` directory, run with `PYTHONPATH=suite-evidence-risk:suite-core:suite-api`
- Evidence router is mounted at prefix `/api/v1` in app.py, with internal prefix `/evidence`
- Brain pipeline: `suite-core/core/brain_pipeline.py` (~1016 LOC, 12 steps)
- E2E test: `scripts/enterprise_e2e_test.py` (uses token from `TOKEN` variable, not env)

## Key Patterns
- All endpoints require API key auth via `X-API-Key` header (token from `FIXOPS_API_TOKEN` env)
- Demo/fallback data pattern: try real data from disk, fall back to hardcoded demo data for air-gapped mode
- Path traversal defense: ALWAYS check raw input for `..` and `/` BEFORE using `Path(x).name`
- Pydantic validation for all request bodies; use `field_validator` for custom checks
- Event bus integration: wrap in try/except, use `_HAS_BRAIN` guard
- Every router MUST have both `/health` and `/status` endpoints (DEMO-001 requirement)
- E2E test uses hardcoded token `aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh`

## Security Lessons
1. `Path("../../etc/passwd").name` returns `"passwd"` -- bypasses traversal. Always validate RAW string first.
2. Pydantic `Optional[list[str]]` with `default=None` is better than `default=["SOC2"]` for legacy compat.
3. FastAPI URL-decodes path params before route matching -- accept both 400 and 404 in traversal tests.
4. **SSRF**: DAST scanner takes user URLs. Block RFC1918, localhost, link-local, metadata (169.254.x.x). Validate scheme is http/https only.
5. **Shell injection**: Container scanner passes `image_ref` to CLI. Block `;|&$(){}!><\n\r` characters.
6. **Secrets leakage**: Never include exception details in 500 responses from secrets scanner -- may contain the secret itself. Use `type(e).__name__` only.
7. **OpenAPI duplicates**: `@app.api_route(methods=["GET","POST"])` creates duplicate operation IDs. Split into separate `@app.get` and `@app.post` with unique function names.

## Test Commands
```bash
# Run evidence tests
PYTHONPATH=suite-evidence-risk:suite-core:suite-api python -m pytest tests/test_security_evidence_bundles_api.py tests/test_evidence_router_unit.py -v --timeout=30

# Run health/status tests
PYTHONPATH=suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations FIXOPS_API_TOKEN=test-token FIXOPS_DISABLE_RATE_LIMIT=1 python -m pytest tests/test_health_status_endpoints.py -v --timeout=30

# Run scanner hardening tests
PYTHONPATH=suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations FIXOPS_API_TOKEN=test-token FIXOPS_DISABLE_RATE_LIMIT=1 python -m pytest tests/test_security_scanner_hardening.py -v --timeout=30

# Run brain pipeline tests
PYTHONPATH=suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations FIXOPS_API_TOKEN=test-token FIXOPS_DISABLE_RATE_LIMIT=1 python -m pytest tests/test_brain_pipeline.py -v --timeout=30

# E2E test (needs running server with correct token)
FIXOPS_API_TOKEN="aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh" FIXOPS_DISABLE_RATE_LIMIT=1 python -m uvicorn apps.api.app:create_app --factory --port 8000 &
sleep 10 && python scripts/enterprise_e2e_test.py
```

## Files I Own
- `suite-evidence-risk/api/evidence_router.py` -- Evidence bundle API (10 endpoints)
- `tests/test_security_evidence_bundles_api.py` -- 54 security + functional tests
- `tests/test_health_status_endpoints.py` -- 28 health/status endpoint tests
- `tests/test_security_scanner_hardening.py` -- 35 scanner security tests
- `suite-core/core/fail_engine.py` -- FAIL Engine core
- `suite-core/core/fail_db.py` -- FAIL DB persistence
- `suite-core/automation/remediation.py` -- Self-healing remediation with CWE fixes
- `suite-core/core/brain_pipeline.py` -- Brain pipeline (12-step CTEM)

## Brain Pipeline Notes
- `inp.org_id` can be empty string but not None (existing tests use `org_id=""`)
- Pipeline `_step_build_graph` uses batches of 500 findings
- CVE nodes are deduplicated in graph step (seen_cves set)
- LLM consensus caps at 100 findings, falls back to deterministic if LLM unavailable
- Pipeline metrics stored in `self._metrics`, accessible via `get_metrics()`
- MAX_FINDINGS=50,000 and MAX_ASSETS=10,000 prevent DoS
