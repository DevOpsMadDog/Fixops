# US-0023: Application Security

## Sub-Epic: ASPM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Tom Anderson (AppSec Lead)**, I need to manage application security scanning and findings
so that the platform delivers enterprise-grade aspm capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Application Security replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone ASPM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/appsec"]
    API --> Auth["api_key_auth"]
    Auth --> Router["application_security_router.py"]
    Router --> Engine["ApplicationSecurityEngine"]
    Engine --> DB[(SQLite: {org_id}_application_security.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    ApplicationSecurityEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `register_app()` — Register a new application. Returns the created record. (line 180)
- ✅ `list_apps()` — List applications, optionally filtered by app_type and/or criticality. (line 233)
- ✅ `get_app()` — Retrieve a single application with open findings summary. (line 252)
- ✅ `add_sast_finding()` — Add a SAST finding to an application. (line 285)
- ✅ `list_sast_findings()` — List SAST findings with optional filters. (line 332)
- ✅ `add_dast_finding()` — Add a DAST finding to an application. (line 359)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/application_security_engine.py` — 576 lines)
- `ApplicationSecurityEngine.register_app()` — Register a new application. Returns the created record. (line 180)
- `ApplicationSecurityEngine.list_apps()` — List applications, optionally filtered by app_type and/or criticality. (line 233)
- `ApplicationSecurityEngine.get_app()` — Retrieve a single application with open findings summary. (line 252)
- `ApplicationSecurityEngine.add_sast_finding()` — Add a SAST finding to an application. (line 285)
- `ApplicationSecurityEngine.list_sast_findings()` — List SAST findings with optional filters. (line 332)
- `ApplicationSecurityEngine.add_dast_finding()` — Add a DAST finding to an application. (line 359)
- `ApplicationSecurityEngine.list_dast_findings()` — List DAST findings with optional filters. (line 406)
- `ApplicationSecurityEngine.log_scan_run()` — Log a scan run for an application. (line 433)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/application_security_engine.py` (576 lines)
- **Router file**: `suite-api/apps/api/application_security_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/appsec/apps` | register app |
| GET | `/api/v1/appsec/apps` | list apps |
| GET | `/api/v1/appsec/apps/{app_id}` | get app |
| GET | `/api/v1/appsec/apps/{app_id}/sast` | list sast findings |
| POST | `/api/v1/appsec/apps/{app_id}/sast` | add sast finding |
| GET | `/api/v1/appsec/apps/{app_id}/dast` | list dast findings |
| POST | `/api/v1/appsec/apps/{app_id}/dast` | add dast finding |
| POST | `/api/v1/appsec/apps/{app_id}/scans` | log scan run |
| PATCH | `/api/v1/appsec/findings/sast/{finding_id}/status` | update sast finding status |
| PATCH | `/api/v1/appsec/findings/dast/{finding_id}/status` | update dast finding status |
| GET | `/api/v1/appsec/stats` | get stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Tom Anderson (AppSec Lead) can access /api/v1/appsec and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 28+ tests passing in `tests/test_application_security_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 42 (est. April 18-20, 2026)

## Test Coverage
- **Test file**: `tests/test_application_security_engine.py`
- **Tests**: 28 tests
- **Status**: Passing
