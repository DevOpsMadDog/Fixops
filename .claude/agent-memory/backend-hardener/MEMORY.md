# Backend Hardener Persistent Memory

## Project Structure
- FastAPI app: `suite-api/apps/api/app.py` (~2737 LOC)
- Evidence router: `suite-evidence-risk/api/evidence_router.py` (1,116 LOC, 10 routes)
- Tests: `tests/` directory, run with `PYTHONPATH=suite-evidence-risk:suite-core:suite-api`
- Evidence router is mounted at prefix `/api/v1` in app.py, with internal prefix `/evidence`
- Brain pipeline: `suite-core/core/brain_pipeline.py` (~1828 LOC, 12 steps + progress + cancellation + batch async + graph optimization)
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

## Endpoint Alias Pattern
- To add /health alias: define `async def {router}_health() -> Dict[str, Any]: return await {router}_status()` BEFORE the /status endpoint
- To add /status alias: define it with full response body including `status`, `engine`, `version` fields
- evidence_router.py: `/health` and `/status` return storage config + crypto availability
- CSPM engine file is `cspm_engine.py` NOT `cspm_analyzer.py` (naming discrepancy in docs)

## Brain Pipeline Lessons
31. **get_progress elapsed_ms bug**: `time.monotonic() - time.monotonic()` always returns 0. Use datetime-based calculation instead.
32. **Running pipeline elapsed time**: Parse `started_at` ISO string with `datetime.fromisoformat()`, compute delta from `datetime.now(timezone.utc)`
33. **Debug logger safety**: All 5 debug loggers in brain_pipeline.py now use `type(e).__name__` — lines 638, 1103, 1151, 1600, 1638. Server-side debug is OK for diagnostics, but consistent pattern prevents accidental exposure.

## Files I Own
- `suite-evidence-risk/api/evidence_router.py` -- Evidence bundle API (10+ endpoints, incl /health + /status)
- `tests/test_security_evidence_bundles_api.py` -- 54 security + functional tests
- `tests/test_health_status_endpoints.py` -- 28 health/status endpoint tests
- `tests/test_security_scanner_hardening.py` -- 35 scanner security tests
- `tests/test_security_hardening_v2.py` -- 35 security tests (XXE, SSRF, shell injection, self-correction)
- `tests/test_hardening_2026_03_02_day3.py` -- 29 tests (progress fix, autofix validation, batch async, sanitization)
- `tests/test_hardening_2026_03_02_day3_v2.py` -- 58 tests (parser crash resilience, sandbox template injection, blocked patterns, logger safety)
- `suite-core/core/fail_engine.py` -- FAIL Engine core
- `suite-core/core/fail_db.py` -- FAIL DB persistence
- `suite-core/automation/remediation.py` -- Self-healing remediation with CWE fixes
- `suite-core/core/brain_pipeline.py` -- Brain pipeline (12-step CTEM + cancel + batch async + progress tracking)
- `tests/test_hardening_2026_03_02.py` -- 41 hardening tests (brain pipeline, scanner ingest, parsers, sandbox, DAST, container)
- `tests/test_hardening_2026_03_02_v3.py` -- 37 hardening tests (cancellation, batch async, SAST redaction, PII, sandbox)
- `tests/test_hardening_2026_03_02_v4.py` -- 45 hardening tests (input validation, CEF injection, progress tracking, autofix safety)
- `suite-api/apps/api/scanner_ingest_router.py` -- Scanner ingest router (hardened)
- `suite-api/apps/api/bulk_router.py` -- Bulk operations (path traversal + status validation hardened)
- `suite-api/apps/api/mcp_router.py` -- MCP auto-discovery (path param injection hardened)
- `suite-api/apps/api/audit_router.py` -- Audit log (CEF injection hardened)
- `suite-api/apps/api/workflows_router.py` -- Workflows (field size limits hardened)
- `suite-api/apps/api/policies_router.py` -- Policies (field size limits hardened)
- `suite-core/core/scanner_parsers.py` -- Scanner parsers (crash resilience + size limits)
- `suite-core/core/sandbox_verifier.py` -- Sandbox verifier (code validation + non-root + template injection prevention)
- `suite-core/core/sast_engine.py` -- SAST engine (CWE-798 snippet redaction)
- `suite-core/core/dast_engine.py` -- DAST engine (URL length validation + header limits)
- `suite-core/core/secrets_scanner.py` -- Secrets scanner (PII redaction)
- `suite-core/core/autofix_engine.py` -- AutoFix engine (7-check safety validation)
- `tests/test_jwt_hardening.py` -- 31 tests (JWT secret strength, token decode hardening, brute-force tracker, iat validation)

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
- **Cancellation**: `cancel(run_id)` adds to `_cancelled` set; checked before each step. Set is cleaned after processing.
- **Batch async**: `run_async_batch(inputs, max_concurrent=4)` uses asyncio.Semaphore. Exceptions → failed PipelineResult.
- **Singleton**: `get_brain_pipeline()` uses double-checked locking with `_pipeline_lock`.
- **Progress tracking**: PipelineResult has `current_step`, `current_step_index`, `total_steps`, `progress_percent` fields. Updated before each step.
- **get_progress(run_id)**: Lightweight method for UI polling — returns dict with step name, index, percent, status.
- **Graph step error isolation**: Per-finding try/except in `_step_build_graph` — bad findings are skipped, first 5 errors logged. Pipeline continues.

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
25. **SAST CWE-798 redaction**: Regex `r"""(=\s*['"])[A-Za-z0-9+/=_\-]{4}[A-Za-z0-9+/=_\-]*(['"])"""` replaces secret values with `****...` in snippets. Only applies to CWE-798 findings.
26. **PII in secrets metadata**: Gitleaks stores Author/Email, Trufflehog stores RawV2/ExtraData — all contain sensitive data. Strip before returning to API.
27. **Sandbox code validation**: Defense-in-depth beyond Docker isolation. Block fork bombs, rm -rf /, disk access, eval(input), etc. 64KB size limit. Non-root (65534:65534).
28. **DAST URL length**: RFC 2616 recommends 2048 chars max. Enforce before SSRF check.
29. **Class names**: DAST=`DASTEngine`, SAST=`SASTEngine`, Secrets=`SecretsDetector` (not `DastScanner`/`SastEngine`/`RealSecretsScanner`). `RealSecretsScanner` is in `real_scanner.py` (different file).
30. **Scanner parsers content limit**: 500MB hard cap in `parse_scanner_output()` prevents OOM on huge uploads.
31. **Pydantic v2 PrivateAttr gotcha**: Underscore-prefixed class attributes inside `BaseModel` subclasses become `PrivateAttr` automatically. A `_ALLOWED_STATUSES` set inside a model causes `TypeError: argument of type 'ModelPrivateAttr' is not iterable`. Fix: move to module-level variable (e.g., `_BULK_ALLOWED_STATUSES = frozenset({...})`).
32. **CEF injection**: Common Event Format uses `|` as delimiter. Sanitize all user-controlled fields with: backslash→`\\`, pipe→`\|`, newline→`\n`, CR→`\r`, then truncate to 1024 chars. Apply BEFORE embedding in CEF strings.
33. **AutoFix 7-check validation**: (1) at least one fix artifact, (2) 30+ dangerous code patterns, (3) path traversal in patch file_path, (4) dangerous imports (ctypes/pty/resource/signal), (5) old/new code validity, (6) dep version validity, (7) patch size limit 64KB.
34. **Bulk router routes**: Status update is POST `/api/v1/bulk/clusters/status` (not PUT `/api/v1/bulk/status`). Always verify route paths in router source before writing tests.
35. **Connectors router not mounted by default**: `connectors_router.py` may not be included in `app.py` router mounts. Test Pydantic models directly if HTTP route unavailable.
36. **Template injection in PoC generation**: `_generate_basic_poc()` embeds user-controlled CVE IDs, titles, URLs into f-string code templates. Must sanitize with `_sanitize_template_str()` which strips shell metacharacters (`"';` backtick, `$()`, parens, newlines) while preserving URL chars.
37. **f-string logging detection**: Use regex `logger\.\w+\(f[\"']` to find all f-string logging calls. Convert to `%s` format for lazy evaluation.
38. **Test assertion on injected content**: When testing sanitization, check the sanitized VALUE separately (via `_sanitize_template_str`), not the entire generated code (which contains template shell commands that naturally include semicolons like `grep -q "200"; then`).

## JWT Auth Hardening (2026-03-03)
39. **JWT secret min length**: `_MIN_JWT_SECRET_LENGTH=32`. Secrets < 32 chars rejected with CRITICAL log, ephemeral secret generated instead.
40. **Token max length**: `_MAX_TOKEN_LENGTH=4096` bytes. Checked before jwt.decode() to prevent parsing attacks.
41. **Required JWT claims**: `options={"require": ["exp", "iat"]}` in jwt.decode(). Tokens without `iat` are rejected.
42. **generate_access_token includes iat**: `"iat": datetime.now(timezone.utc)` added to all generated tokens.
43. **JWT iat precision**: PyJWT encodes iat as integer seconds — tests must account for sub-second truncation (use `replace(microsecond=0)` for before timestamp).
44. **Auth brute-force tracker**: `_AUTH_FAIL_TRACKER` dict (IP -> list of monotonic timestamps), `_AUTH_FAIL_WINDOW=300s`, `_AUTH_FAIL_MAX=20`. Thread-safe via `_AUTH_FAIL_LOCK`.
45. **429 on rate limit**: `_verify_api_key` checks `_check_auth_rate_limit(client_ip)` first, raises 429 if exceeded.
46. **Memory cap**: Tracker prunes oldest IP when >1000 entries to prevent unbounded growth.
47. **Imports added**: `threading` and `time` now imported in app.py (were missing before).

## Brain Pipeline Optimization (2026-03-03)
48. **StepResult has findings_in/findings_out**: Recorded in run loop at line ~398. to_dict() includes both. Default 0 for backward compat.
49. **Graph step 3-phase approach**: Phase 1 pre-computes all node data/edges/CVE set in pure Python (no I/O). Phase 2 batch upserts nodes. Phase 3 batch adds edges. Each phase timed separately in result["timing"].
50. **CVE dedup via set comprehension**: `unique_cves = {f["cve_id"] for f in findings if f.get("cve_id")}` — O(n) upfront, then upsert each CVE exactly once.
51. **_local_dedup_findings fallback**: O(n) dict-keyed by (title, asset_name, severity) tuple. Used when DeduplicationService unavailable or times out. Generates stable "LC-" prefixed cluster IDs via SHA256.
52. **Graph step error isolation**: Per-node and per-edge try/except, first 5 errors logged. graph_errors count in result.
53. **Test file**: `tests/test_brain_pipeline_optimization.py` — 26 tests covering new fields, metrics, local dedup, graph optimization, backward compat.

## Day 3 Hardening (see topic files for details)
- MPTE/pentest SSRF: `_validate_target_url()` / `_validate_pentest_url()` patterns
- Concurrent limiters: `_acquire_scan_slot()`/`_release_scan_slot()` with `threading.Lock()`
- JWT: min 32-char secret, 4096-byte token limit, required iat claim, brute-force tracker
- Webhook SSRF: `_validate_external_url()` on `CreateMappingRequest`

## Day 7 Hardening (2026-03-07)
54. **WIQL injection**: Azure DevOps `list_work_items()` interpolates strings into WIQL. Added `_sanitize_wiql_value()` — escapes single quotes, strips control chars, 256-char limit.
55. **CLI URL scheme validation**: `_validate_api_url()` in cli.py blocks file://, ftp://, custom schemes. Applied to all 9 FIXOPS_API_URL usages.
56. **Info disclosure (100+ fixes)**: Replaced `str(exc)` with `type(exc).__name__` in error dicts across security_connectors.py (28), connectors.py (34), cve_tester.py (31), llm_providers.py (5), mpte_advanced.py (2), scanner_ingest_router.py (2), middleware.py (1). See `info-disclosure-patterns.md`.
57. **LLM reasoning field**: Never embed `{exc}` in reasoning strings — API keys can leak. Use `{type(exc).__name__}` instead.
58. **LLM HTTP error detail**: Use `f"HTTP {exc.response.status_code}"` not `str(exc)` for HTTP errors.
59. **Bandit clean**: 0 HIGH findings, 64 MEDIUM (false positives in SSRF blocklists). 139K LOC scanned.
60. **pypdf CVE-2026-28804**: Fixed by upgrading 6.7.4 → 6.7.5.

## Files I Own (Updated 2026-03-07)
- `tests/test_hardening_2026_03_07.py` — 28 tests (WIQL, CLI URL, info disclosure, bandit, pypdf CVE)
- `tests/test_hardening_2026_03_03.py` — 46 tests
- `tests/test_hardening_2026_03_03_session2.py` — 52 tests
- `tests/test_jwt_hardening.py` — 31 tests
- `tests/test_brain_pipeline_optimization.py` — 26 tests

## Topic Files
- `info-disclosure-patterns.md` — str(exc) remediation patterns and file inventory
