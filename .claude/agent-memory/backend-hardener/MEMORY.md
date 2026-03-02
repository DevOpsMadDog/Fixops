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

## Security Lessons (Sprint 2)
8. **XXE protection**: Python's ET.fromstring() is vulnerable to XXE by default. Strip DOCTYPE/ENTITY with regex before parsing. Avoids adding defusedxml dependency.
9. **Sandbox self-correction injection**: _self_correct() in sandbox_verifier.py generates code from error messages. Always whitelist allowed modules/commands. Use shlex.quote() for any shell values.
10. **Docker hardening checklist**: --cap-drop=ALL, --memory-swap=limit, --ulimit nofile=256, --nodev on tmpfs, --pids-limit=30, 0o700 temp dir permissions.
11. **PipelineInput has no app_id field**: Use org_id only. Tests must use PipelineInput(org_id="test") not PipelineInput(app_id="test").
12. **Error message pattern**: step.error = f"{type(e).__name__}: pipeline step failed" — NEVER include str(e) as it may leak DB creds, file paths, or API keys.
13. **Container scanner class is ContainerImageScanner** not ContainerScanner.

## Files I Own
- `suite-evidence-risk/api/evidence_router.py` -- Evidence bundle API (10 endpoints)
- `tests/test_security_evidence_bundles_api.py` -- 54 security + functional tests
- `tests/test_health_status_endpoints.py` -- 28 health/status endpoint tests
- `tests/test_security_scanner_hardening.py` -- 35 scanner security tests
- `tests/test_security_hardening_v2.py` -- 35 security tests (XXE, SSRF, shell injection, self-correction)
- `suite-core/core/fail_engine.py` -- FAIL Engine core
- `suite-core/core/fail_db.py` -- FAIL DB persistence
- `suite-core/automation/remediation.py` -- Self-healing remediation with CWE fixes
- `suite-core/core/brain_pipeline.py` -- Brain pipeline (12-step CTEM)
- `tests/test_hardening_2026_03_02.py` -- 41 hardening tests (brain pipeline, scanner ingest, parsers, sandbox, DAST, container)
- `suite-api/apps/api/scanner_ingest_router.py` -- Scanner ingest router (hardened)
- `suite-core/core/scanner_parsers.py` -- Scanner parsers (crash resilience added)

## Brain Pipeline Notes
- `inp.org_id` can be empty string but not None (existing tests use `org_id=""`)
- Pipeline `_step_build_graph` uses batches of 500 findings
- CVE nodes are deduplicated in graph step (seen_cves set)
- LLM consensus caps at 100 findings, falls back to deterministic if LLM unavailable
- Pipeline metrics stored in `self._metrics`, accessible via `get_metrics()`
- MAX_FINDINGS=50,000 and MAX_ASSETS=10,000 prevent DoS
- Thread-safe: `self._lock = threading.Lock()` guards `_runs` and `_metrics` dicts
- Async: `run_async()` uses `loop.run_in_executor(None, self.run, inp)` for non-blocking execution
- Pipeline timeout: PIPELINE_TIMEOUT_S=300, checked before each step via monotonic deadline
- String sanitization: MAX_FIELD_LEN=10,000 chars, truncated with `...[truncated]` suffix
- Step 10 async loop safety: detects running event loop, uses ThreadPoolExecutor fallback
- **50K findings dedup is SLOW** (~hangs). Tests should use small finding sets (<1000). DoS protection works but dedup step needs O(n) optimization for large sets.

## Scanner Ingest Hardening
- Upload limit: 100MB (_MAX_UPLOAD_BYTES), webhook limit: 50MB (_MAX_WEBHOOK_BYTES)
- File extension allowlist: .json, .xml, .html, .csv, .sarif, .nessus, .nmap, .txt, .log, .yaml, .yml, .cdx, .spdx, .vex
- Scanner type validation: regex `^[a-z0-9][a-z0-9_-]{0,63}$` prevents injection
- Filename validation: check raw string for `..`, `/`, `\\` BEFORE os.path.basename()
- Error responses: only expose `type(e).__name__`, never str(e)
- Findings cap in response: 100 items max (total_findings field shows real count)

## Scanner Parsers Hardening
- normalize() wrapped in try/except — individual parser crash doesn't break pipeline
- Return type validation: ensure list, not generator or None
- Findings cap: _MAX_FINDINGS_PER_PARSE = 50,000 per parse call

## Secrets Scanner Lessons
14. **YAML values are unquoted**: Patterns with `['\"]...['\"]` don't match YAML `key: value` syntax. Must add separate patterns with `(?!['\"])` lookahead for unquoted values.
15. **Real scanner is the builtin fallback**: `suite-core/core/real_scanner.py` — `RealSecretsScanner` uses `SECRETS_PATTERNS` dict. External tools (gitleaks/trufflehog) are preferred when available.
16. **Pattern count**: SECRETS_PATTERNS now has 21 entries (11 original + 10 YAML/config/cloud). Zero false positives on safe YAML config.
17. **SendGrid key format**: `SG.{22chars}.{43chars}` — both segments have fixed lengths. Test data must match exactly.

## Error Handling Patterns
18. **Never `except Exception: pass`** — always at minimum `logger.debug("context: %s", type(e).__name__)`
19. **DAST engine uses `httpx`** — catch `httpx.TimeoutException` specifically before generic Exception
20. **Container scanner uses `asyncio.create_subprocess_exec`** — catch `asyncio.TimeoutError`, `json.JSONDecodeError`, `FileNotFoundError` specifically
21. **CSPM engine parses JSON** — catch `json.JSONDecodeError` specifically with `e.msg` and `e.pos`
22. **AutoFix LLM response parsing** — `re.search(r"\{[\s\S]*\}", resp.reasoning)` + `json.loads()` is common pattern. Always wrap with JSONDecodeError handler.
23. **API error messages**: NEVER use `str(exc)` in API responses or metadata. Use `type(exc).__name__` only. The full error is logged server-side.
24. **Test assertions after hardening**: Existing tests may assert on old error message format (e.g., "Unexpected error"). Update to check for exception type name pattern instead.
