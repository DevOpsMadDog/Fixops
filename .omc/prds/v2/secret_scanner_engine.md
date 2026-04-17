# US-0213: Secret Scanner

## Sub-Epic: ASPM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Emma Davis (DevSecOps Engineer)**, I need to detect and manage secrets exposure
so that the platform delivers enterprise-grade aspm capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Secret Scanner replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone ASPM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/secrets"]
    API --> Auth["api_key_auth"]
    Auth --> Router["secret_scanner_router.py"]
    Router --> Engine["SecretScannerEngine"]
    Engine --> DB[(SQLite: {org_id}_secret_scanner.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    SecretScannerEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `for_org()` — implemented (line 126)
- ✅ `create_scan_job()` — Create a new scan job in pending state. (line 225)
- ✅ `start_scan()` — Mark job as running and execute simulation, returning completed job. (line 266)
- ✅ `list_scan_jobs()` — List scan jobs with optional filters. (line 386)
- ✅ `get_scan_job()` — Return job with its findings list. (line 405)
- ✅ `list_findings()` — List findings with optional filters. (line 429)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/secret_scanner_engine.py` — 679 lines)
- `SecretScannerEngine.for_org()` — Handle for org (line 126)
- `SecretScannerEngine.create_scan_job()` — Create a new scan job in pending state. (line 225)
- `SecretScannerEngine.start_scan()` — Mark job as running and execute simulation, returning completed job. (line 266)
- `SecretScannerEngine.list_scan_jobs()` — List scan jobs with optional filters. (line 386)
- `SecretScannerEngine.get_scan_job()` — Return job with its findings list. (line 405)
- `SecretScannerEngine.list_findings()` — List findings with optional filters. (line 429)
- `SecretScannerEngine.update_finding()` — Update finding status and optional remediation notes. (line 454)
- `SecretScannerEngine.validate_finding()` — Mark a finding as confirmed or false_positive. (line 486)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/secret_scanner_engine.py` (679 lines)
- **Router file**: `suite-api/apps/api/secret_scanner_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/secrets/scan` | scan secrets |
| POST | `/api/v1/secrets/text-scan` | scan text for secrets |
| GET | `/api/v1/secrets/active` | list active secrets |
| GET | `/api/v1/secrets/rotation-status` | get rotation status |
| GET | `/api/v1/secrets/patterns` | list patterns |
| POST | `/api/v1/secrets/patterns` | add pattern |
| GET | `/api/v1/secrets/precommit-config` | get precommit config |
| POST | `/api/v1/secrets/{secret_id}/rotate` | rotate secret |
| POST | `/api/v1/secrets/{secret_id}/false-positive` | mark false positive |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Emma Davis (DevSecOps Engineer) can access /api/v1/secrets and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 41+ tests passing in `tests/test_secret_scanner_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 49 (est. April 25-27, 2026)

## Test Coverage
- **Test file**: `tests/test_secret_scanner_engine.py`
- **Tests**: 41 tests
- **Status**: Passing
