# US-0185: Privacy Gdpr

## Sub-Epic: GRC
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Robert Kim (Compliance Officer)**, I need to assess privacy impact
so that the platform delivers enterprise-grade grc capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Privacy Gdpr replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone GRC tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/privacy"]
    API --> Auth["api_key_auth"]
    Auth --> Router["privacy_gdpr_router.py"]
    Router --> Engine["PrivacyGDPREngine"]
    Engine --> DB[(SQLite: {org_id}_privacy_gdpr.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    PrivacyGDPREngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `create_dsr()` — Create a Data Subject Request. Sets regulation-aware due date. (line 221)
- ✅ `list_dsrs()` — List DSRs with optional filters. Adds overdue flag. (line 280)
- ✅ `fulfill_dsr()` — Mark a DSR as fulfilled. Returns True if found. (line 311)
- ✅ `update_dsr_status()` — Update DSR status. Returns True if found. (line 325)
- ✅ `record_consent()` — Save a consent record. (line 342)
- ✅ `list_consents()` — List consent records with optional filters. (line 389)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/privacy_gdpr_engine.py` — 708 lines)
- `PrivacyGDPREngine.create_dsr()` — Create a Data Subject Request. Sets regulation-aware due date. (line 221)
- `PrivacyGDPREngine.list_dsrs()` — List DSRs with optional filters. Adds overdue flag. (line 280)
- `PrivacyGDPREngine.fulfill_dsr()` — Mark a DSR as fulfilled. Returns True if found. (line 311)
- `PrivacyGDPREngine.update_dsr_status()` — Update DSR status. Returns True if found. (line 325)
- `PrivacyGDPREngine.record_consent()` — Save a consent record. (line 342)
- `PrivacyGDPREngine.list_consents()` — List consent records with optional filters. (line 389)
- `PrivacyGDPREngine.withdraw_consent()` — Mark consent as withdrawn. Returns True if found. (line 409)
- `PrivacyGDPREngine.report_incident()` — Create a privacy incident record. (line 427)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/privacy_gdpr_engine.py` (708 lines)
- **Router file**: `suite-api/apps/api/privacy_gdpr_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/privacy/dsrs` | create dsr |
| GET | `/api/v1/privacy/dsrs` | list dsrs |
| POST | `/api/v1/privacy/dsrs/{request_id}/fulfill` | fulfill dsr |
| PATCH | `/api/v1/privacy/dsrs/{request_id}/status` | update dsr status |
| POST | `/api/v1/privacy/consents` | record consent |
| GET | `/api/v1/privacy/consents` | list consents |
| POST | `/api/v1/privacy/consents/{consent_id}/withdraw` | withdraw consent |
| POST | `/api/v1/privacy/incidents` | report incident |
| GET | `/api/v1/privacy/incidents` | list incidents |
| POST | `/api/v1/privacy/incidents/{incident_id}/notify-dpa` | notify dpa |
| PATCH | `/api/v1/privacy/incidents/{incident_id}/status` | update incident status |
| POST | `/api/v1/privacy/processing-activities` | add processing activity |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Robert Kim (Compliance Officer) can access /api/v1/privacy and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 53+ tests passing in `tests/test_privacy_gdpr_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 48 (est. April 24-26, 2026)

## Test Coverage
- **Test file**: `tests/test_privacy_gdpr_engine.py`
- **Tests**: 53 tests
- **Status**: Passing
