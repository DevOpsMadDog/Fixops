# US-0108: Endpoint Compliance

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **James Wilson (Security Engineer)**, I need to enforce endpoint security compliance
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Endpoint Compliance replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/endpoint-compliance"]
    API --> Auth["api_key_auth"]
    Auth --> Router["endpoint_compliance_router.py"]
    Router --> Engine["EndpointComplianceEngine"]
    Engine --> DB[(SQLite: {org_id}_endpoint_compliance.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    EndpointComplianceEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `register_endpoint()` — Register a new endpoint. (line 224)
- ✅ `list_endpoints()` — List endpoints with optional filters. (line 272)
- ✅ `get_endpoint()` — Return endpoint with a check summary. (line 295)
- ✅ `record_check()` — Record a single compliance check and recompute endpoint score. (line 325)
- ✅ `bulk_record_checks()` — Batch-record compliance checks. Returns list of created records. (line 381)
- ✅ `list_checks()` — List compliance checks with optional filters. (line 442)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/endpoint_compliance_engine.py` — 673 lines)
- `EndpointComplianceEngine.register_endpoint()` — Register a new endpoint. (line 224)
- `EndpointComplianceEngine.list_endpoints()` — List endpoints with optional filters. (line 272)
- `EndpointComplianceEngine.get_endpoint()` — Return endpoint with a check summary. (line 295)
- `EndpointComplianceEngine.record_check()` — Record a single compliance check and recompute endpoint score. (line 325)
- `EndpointComplianceEngine.bulk_record_checks()` — Batch-record compliance checks. Returns list of created records. (line 381)
- `EndpointComplianceEngine.list_checks()` — List compliance checks with optional filters. (line 442)
- `EndpointComplianceEngine.add_exception()` — Create a compliance exception for an endpoint check. (line 473)
- `EndpointComplianceEngine.create_baseline()` — Create a compliance baseline definition. (line 507)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/endpoint_compliance_engine.py` (673 lines)
- **Router file**: `suite-api/apps/api/endpoint_compliance_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/endpoint-compliance/endpoints` | register endpoint |
| GET | `/api/v1/endpoint-compliance/endpoints` | list endpoints |
| GET | `/api/v1/endpoint-compliance/endpoints/{endpoint_id}` | get endpoint |
| POST | `/api/v1/endpoint-compliance/endpoints/{endpoint_id}/checks` | record check |
| POST | `/api/v1/endpoint-compliance/endpoints/{endpoint_id}/checks/bulk` | bulk record checks |
| GET | `/api/v1/endpoint-compliance/checks` | list checks |
| POST | `/api/v1/endpoint-compliance/exceptions` | add exception |
| POST | `/api/v1/endpoint-compliance/baselines` | create baseline |
| GET | `/api/v1/endpoint-compliance/baselines` | list baselines |
| GET | `/api/v1/endpoint-compliance/stats` | get endpoint stats |
| GET | `/api/v1/endpoint-compliance/department-compliance` | get department compliance |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] James Wilson (Security Engineer) can access /api/v1/endpoint-compliance and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 41+ tests passing in `tests/test_endpoint_compliance_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 45 (est. April 21-23, 2026)

## Test Coverage
- **Test file**: `tests/test_endpoint_compliance_engine.py`
- **Tests**: 41 tests
- **Status**: Passing
