# US-0225: Security Champions

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Emily Chang (Developer Security Champion)**, I need to run champions program
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Security Champions replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/security-champions"]
    API --> Auth["api_key_auth"]
    Auth --> Router["security_champions_router.py"]
    Router --> Engine["SecurityChampionsEngine"]
    Engine --> DB[(SQLite: {org_id}_security_champions.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    SecurityChampionsEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `add_champion()` — Register a new security champion. Returns the created record. (line 178)
- ✅ `list_champions()` — List champions, optionally filtered by status and/or department. (line 227)
- ✅ `get_champion()` — Retrieve a single champion by ID. (line 247)
- ✅ `log_activity()` — Log an activity for a champion. Auto-awards points and auto-promotes level. (line 261)
- ✅ `add_certification()` — Add a certification for a champion. Returns the created record. (line 338)
- ✅ `list_certifications()` — List certifications, optionally filtered by champion. (line 374)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/security_champions_engine.py` — 502 lines)
- `SecurityChampionsEngine.add_champion()` — Register a new security champion. Returns the created record. (line 178)
- `SecurityChampionsEngine.list_champions()` — List champions, optionally filtered by status and/or department. (line 227)
- `SecurityChampionsEngine.get_champion()` — Retrieve a single champion by ID. (line 247)
- `SecurityChampionsEngine.log_activity()` — Log an activity for a champion. Auto-awards points and auto-promotes level. (line 261)
- `SecurityChampionsEngine.add_certification()` — Add a certification for a champion. Returns the created record. (line 338)
- `SecurityChampionsEngine.list_certifications()` — List certifications, optionally filtered by champion. (line 374)
- `SecurityChampionsEngine.create_campaign()` — Create an awareness campaign. Returns the created record. (line 392)
- `SecurityChampionsEngine.list_campaigns()` — List campaigns, optionally filtered by status. (line 433)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/security_champions_engine.py` (502 lines)
- **Router file**: `suite-api/apps/api/security_champions_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/security-champions/champions` | list champions |
| POST | `/api/v1/security-champions/champions` | add champion |
| GET | `/api/v1/security-champions/champions/{champion_id}` | get champion |
| POST | `/api/v1/security-champions/champions/{champion_id}/activities` | log activity |
| GET | `/api/v1/security-champions/champions/{champion_id}/certifications` | list certifications |
| POST | `/api/v1/security-champions/champions/{champion_id}/certifications` | add certification |
| GET | `/api/v1/security-champions/campaigns` | list campaigns |
| POST | `/api/v1/security-champions/campaigns` | create campaign |
| GET | `/api/v1/security-champions/stats` | get program stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Emily Chang (Developer Security Champion) can access /api/v1/security-champions and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 36+ tests passing in `tests/test_security_champions_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 49 (est. April 25-27, 2026)

## Test Coverage
- **Test file**: `tests/test_security_champions_engine.py`
- **Tests**: 36 tests
- **Status**: Passing
