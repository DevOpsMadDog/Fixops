# Iteration 1 Round 4 — Failure Analysis

**Date:** 2026-03-01
**Pass Rate:** 84.7% (404/477)
**Remaining Failures:** 73

## Failure Categories

### 1. 404 — Null/Empty IDs (20 failures)
**Root Cause:** Pre-request scripts try to capture IDs from list endpoints, but database is empty.
**Agent to fix:** backend-hardener (seed demo data)

| Collection | Endpoint | Issue |
|------------|----------|-------|
| 4-Remediate | GET /remediation/tasks/null | No tasks in DB |
| 4-Remediate | GET /autofix/fixes/ | No fixes in history |
| 4-Remediate | POST /workflows//execute | No workflow ID |
| 5-Comply | PUT /policies/ | No policy ID |
| 5-Comply | DELETE /policies/ | No policy ID |
| 6-Personas | POST /autofix//validate | No autofix ID |

**Fix:** Create a seed-data script that populates test data before Newman runs.

### 2. 422 — Complex Validation (30 failures)
**Root Cause:** Request bodies don't match complex nested Pydantic models.
**Agent to fix:** qa-engineer (next iteration) + backend-hardener (add defaults)

| Collection | Endpoint | Missing Field |
|------------|----------|--------------|
| 2-Discover | POST /inputs/sarif | file (multipart upload expected) |
| 2-Discover | POST /inputs/sbom | file (multipart upload expected) |
| 4-Remediate | POST /bulk/findings/update | ids, status |
| 5-Comply | POST /business-context/upload | file, service_name |
| 7-Scanners | POST /sast/scan/files | files should be dict not list |

**Fix:** Update request bodies to match exact Pydantic model schemas.

### 3. 500 — Server Errors (2 failures)
**Root Cause:** Search endpoint has a bug.
**Agent to fix:** backend-hardener (DEMO-001)
**Priority:** BLOCKER for demo

| Collection | Endpoint | Error |
|------------|----------|-------|
| 1-MissionControl | GET /search?q=CVE-2024-3094 | Internal Server Error |
| 1-MissionControl | GET /search?q=payment | Internal Server Error |

### 4. 405 — Method Not Allowed (4 failures)
**Root Cause:** Wrong HTTP methods in collections or endpoint doesn't support the method.
**Agent to fix:** qa-engineer (collection fix) or backend-hardener (add method support)

| Collection | Endpoint | Issue |
|------------|----------|-------|
| 4-Remediate | POST /remediation/tasks/check | POST not allowed, try GET |
| 5-Comply | PUT /policies/ | PUT not allowed, try PATCH |

### 5. Other Assertion Failures (17 failures)
**Root Cause:** Test assertions don't match actual response shapes.

| Collection | Endpoint | Issue |
|------------|----------|-------|
| 7-Scanners | POST /sast/scan/code | Response missing expected `findings` property |
| 7-Scanners | GET /brain/stats | Response shape different from expected |
| 5-Comply | POST /evidence/bundles/.../verify | Signature verification returns false |
| 1-MissionControl | POST /teams | 409 — team already exists |

## Priority Matrix

| Priority | Count | Action |
|----------|-------|--------|
| BLOCKER | 2 | Fix /search endpoint (500 error) — DEMO-001 |
| HIGH | 20 | Seed demo data for pre-request ID capture |
| MEDIUM | 30 | Fix complex request bodies |
| LOW | 21 | Fix assertions and method mismatches |

## Next Steps
1. **backend-hardener**: Fix /search endpoint (BLOCKER)
2. **backend-hardener**: Create /api/v1/seed-demo endpoint for test data
3. **qa-engineer**: Next iteration — fix remaining 30 body validation errors
4. **qa-engineer**: Add seed-data pre-request to collections
