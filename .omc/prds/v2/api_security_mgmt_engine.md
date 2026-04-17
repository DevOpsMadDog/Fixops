# US-0019: Api Security Mgmt

## Sub-Epic: ASPM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Emma Davis (DevSecOps Engineer)**, I need to secure APIs against OWASP Top 10 threats
so that the platform delivers enterprise-grade aspm capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Api Security Mgmt replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone ASPM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/api-security-engine"]
    API --> Auth["api_key_auth"]
    Auth --> Router["api_security_mgmt_router.py"]
    Router --> Engine["APISecurityEngine"]
    Engine --> DB[(SQLite: {safe}_api_security.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    APISecurityEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `register_endpoint()` — Register a new API endpoint. Returns the created record. (line 208)
- ✅ `list_endpoints()` — List API endpoints with optional filters. (line 260)
- ✅ `create_api_key()` — Create an API key record. Does NOT store or return the raw key. (line 287)
- ✅ `list_api_keys()` — List API keys. hashed_key is never returned. (line 334)
- ✅ `revoke_api_key()` — Revoke an API key. Returns True if found and updated. (line 360)
- ✅ `record_abuse_event()` — Record an API abuse event. (line 374)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/api_security_mgmt_engine.py` — 597 lines)
- `APISecurityEngine.register_endpoint()` — Register a new API endpoint. Returns the created record. (line 208)
- `APISecurityEngine.list_endpoints()` — List API endpoints with optional filters. (line 260)
- `APISecurityEngine.create_api_key()` — Create an API key record. Does NOT store or return the raw key. (line 287)
- `APISecurityEngine.list_api_keys()` — List API keys. hashed_key is never returned. (line 334)
- `APISecurityEngine.revoke_api_key()` — Revoke an API key. Returns True if found and updated. (line 360)
- `APISecurityEngine.record_abuse_event()` — Record an API abuse event. (line 374)
- `APISecurityEngine.list_abuse_events()` — List abuse events with optional filters. (line 416)
- `APISecurityEngine.create_scan()` — Create an API scan job. (line 445)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/api_security_mgmt_engine.py` (597 lines)
- **Router file**: `suite-api/apps/api/api_security_mgmt_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/api-security-engine/apis` | list apis |
| POST | `/api/v1/api-security-engine/apis` | register api |
| GET | `/api/v1/api-security-engine/keys` | list api keys |
| POST | `/api/v1/api-security-engine/keys` | create api key |
| DELETE | `/api/v1/api-security-engine/keys/{key_id}` | revoke api key |
| GET | `/api/v1/api-security-engine/abuse-events` | list abuse events |
| POST | `/api/v1/api-security-engine/abuse-events` | record abuse event |
| POST | `/api/v1/api-security-engine/scan/{api_name}` | run owasp scan |
| GET | `/api/v1/api-security-engine/stats` | get security stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Emma Davis (DevSecOps Engineer) can access /api/v1/api-security-engine and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 34+ tests passing in `tests/test_api_security_mgmt_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 42 (est. April 18-20, 2026)

## Test Coverage
- **Test file**: `tests/test_api_security_mgmt_engine.py`
- **Tests**: 34 tests
- **Status**: Passing
