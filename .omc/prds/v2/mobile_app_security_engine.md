# US-0155: Mobile App Security

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **James Wilson (Security Engineer)**, I need to secure mobile applications
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Mobile App Security replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/mobile-app-security"]
    API --> Auth["api_key_auth"]
    Auth --> Router["mobile_app_security_router.py"]
    Router --> Engine["MobileAppSecurityEngine"]
    Engine --> DB[(SQLite: mobile_app_security.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    MobileAppSecurityEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `register_app()` — Register a new mobile application. Returns the app record. (line 141)
- ✅ `list_apps()` — List apps for org, optionally filtered by platform or risk_level. (line 190)
- ✅ `get_app()` — Fetch a single app scoped to org_id. Returns None if not found. (line 210)
- ✅ `record_finding()` — Record a security finding for an app. Returns the finding record. (line 225)
- ✅ `list_findings()` — List findings for org, optionally filtered. (line 266)
- ✅ `update_finding_status()` — Update the status of a finding. Returns updated record. (line 290)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/mobile_app_security_engine.py` — 475 lines)
- `MobileAppSecurityEngine.register_app()` — Register a new mobile application. Returns the app record. (line 141)
- `MobileAppSecurityEngine.list_apps()` — List apps for org, optionally filtered by platform or risk_level. (line 190)
- `MobileAppSecurityEngine.get_app()` — Fetch a single app scoped to org_id. Returns None if not found. (line 210)
- `MobileAppSecurityEngine.record_finding()` — Record a security finding for an app. Returns the finding record. (line 225)
- `MobileAppSecurityEngine.list_findings()` — List findings for org, optionally filtered. (line 266)
- `MobileAppSecurityEngine.update_finding_status()` — Update the status of a finding. Returns updated record. (line 290)
- `MobileAppSecurityEngine.create_scan()` — Create a new scan for an app. Returns the scan record. (line 323)
- `MobileAppSecurityEngine.complete_scan()` — Mark a scan as completed and update app.last_scanned. (line 357)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/mobile_app_security_engine.py` (475 lines)
- **Router file**: `suite-api/apps/api/mobile_app_security_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/mobile-app-security/apps` | register app |
| GET | `/api/v1/mobile-app-security/apps` | list apps |
| GET | `/api/v1/mobile-app-security/apps/{app_id}` | get app |
| POST | `/api/v1/mobile-app-security/findings` | record finding |
| GET | `/api/v1/mobile-app-security/findings` | list findings |
| PUT | `/api/v1/mobile-app-security/findings/{finding_id}/status` | update finding status |
| POST | `/api/v1/mobile-app-security/scans` | create scan |
| PUT | `/api/v1/mobile-app-security/scans/{scan_id}/complete` | complete scan |
| GET | `/api/v1/mobile-app-security/scans` | list scans |
| GET | `/api/v1/mobile-app-security/stats` | get mobile stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] James Wilson (Security Engineer) can access /api/v1/mobile-app-security and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 59+ tests passing in `tests/test_mobile_app_security_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 47 (est. April 23-25, 2026)

## Test Coverage
- **Test file**: `tests/test_mobile_app_security_engine.py`
- **Tests**: 59 tests
- **Status**: Passing
