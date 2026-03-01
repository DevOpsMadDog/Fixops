# Swarm Task swarm-102 — API Smoke Tests

## Summary
- **Status**: PARTIAL_FAILURE
- **Total tests**: 29 collected
- **Passed**: 3
- **Failed**: 0
- **Timeout**: 1 (test interrupted after 2 minutes)
- **Test completion**: 10% (3 of 29 tests)

## Test Results

### Passed Tests (3/29)
1. `TestOpenAPISchema::test_openapi_schema_accessible` [3%] — ✓ PASSED
2. `TestOpenAPISchema::test_openapi_schema_has_paths` [6%] — ✓ PASSED
3. `TestOpenAPISchema::test_openapi_schema_version` [10%] — ✓ PASSED

### Failed / Timeout
- `TestAPISmokeSweep::test_all_get_endpoints` — **TIMEOUT** (10s per-test limit exceeded)
  - Failed endpoint: `/api/v1/brain/most-connected`
  - Error: `HTTP/1.1 500 Internal Server Error`
  - Root cause: Test timeout triggered on most-connected endpoint after 10 seconds

## Key Findings

### What Worked
- OpenAPI schema generation and validation ✓
- Basic schema accessibility checks ✓
- Path enumeration in OpenAPI spec ✓
- Version field present in schema ✓

### What Failed
1. **Endpoint Sweep Timeout**: The `test_all_get_endpoints` test timed out while testing GET endpoints
2. **Most-Connected Endpoint Issue**: `/api/v1/brain/most-connected` returned 500 error
   - This endpoint appears to be synchronously accessing the knowledge brain graph
   - Heavy computation or unfinished initialization may be causing the timeout
   - Stack traces show multiple workers waiting on locks in knowledge_brain.py line 326

### Performance Issues Detected
- 29 total endpoints in OpenAPI schema
- GET endpoint sweep test could not complete in 120 seconds
- Single endpoint `/api/v1/brain/most-connected` exceeded 10s timeout
- Multiple background worker threads (ReachabilityWorker, APScheduler) still initializing

## Infrastructure Status
- **FastAPI app initialization**: ✓ Working
- **Router mounting**: ✓ All 34 routers mounted successfully
- **API auth system**: ✓ Working (X-API-Key validation)
- **Database connections**: ✓ Initialized for all domains
- **Background job queue**: ✓ Running
- **Feature flags**: ✓ Using CombinedProvider (Local + LaunchDarkly offline)

## Recommendations
1. **Optimize `/api/v1/brain/most-connected`**: This endpoint blocks on knowledge_brain.py lock operations
   - Consider async implementation or connection pooling
   - Pre-compute most-connected nodes or cache results

2. **Increase Test Timeout**: Current 10s per-test limit too aggressive for complex graph operations
   - Smoke tests should use longer timeout or run subset of endpoints
   - Consider separating fast vs. slow endpoint tests

3. **Fix Background Initialization**: Reachability workers and other threads taking long to initialize
   - May benefit from lazy initialization of background tasks
   - Consider deferring non-critical jobs until after smoke tests

4. **Run Subset of Endpoints**: For CI, test critical paths only:
   - Health endpoints: `/api/v1/health`, `/api/v1/ready`, `/api/v1/status`
   - Schema endpoint: `/api/v1/openapi.json`
   - Core routers: brain, risk, evidence, triage

## Exit Code
- **Command exit code**: 124 (timeout signal)
- **Test status**: INTERRUPTED (incomplete)

## Test Environment
- Python 3.14
- FastAPI + TestClient
- pytest-timeout: 10 seconds per test
- pytest-asyncio: enabled
- Coverage reporting: enabled (warning noted: .coverage db issue)
