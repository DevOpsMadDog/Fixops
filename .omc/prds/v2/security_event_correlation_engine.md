# US-0232: Security Event Correlation

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Priya Sharma (SOC T2 Analyst)**, I need to correlate security events
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Security Event Correlation replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/event-correlation"]
    API --> Auth["api_key_auth"]
    Auth --> Router["security_event_correlation_router.py"]
    Router --> Engine["SecurityEventCorrelationEngine"]
    Engine --> DB[(SQLite: {org_id}_sec_event_correlation.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    SecurityEventCorrelationEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `ingest_event()` — Ingest a security event from any source system. (line 162)
- ✅ `list_events()` — List security events with optional filters. (line 204)
- ✅ `create_correlation_rule()` — Create a correlation rule based on event type patterns. (line 234)
- ✅ `list_correlation_rules()` — List all correlation rules for an org. (line 276)
- ✅ `run_correlation()` — Run all enabled rules against recent events, return matched incidents. (line 292)
- ✅ `create_correlated_incident()` — Create a correlated incident from matched events. (line 342)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/security_event_correlation_engine.py` — 428 lines)
- `SecurityEventCorrelationEngine.ingest_event()` — Ingest a security event from any source system. (line 162)
- `SecurityEventCorrelationEngine.list_events()` — List security events with optional filters. (line 204)
- `SecurityEventCorrelationEngine.create_correlation_rule()` — Create a correlation rule based on event type patterns. (line 234)
- `SecurityEventCorrelationEngine.list_correlation_rules()` — List all correlation rules for an org. (line 276)
- `SecurityEventCorrelationEngine.run_correlation()` — Run all enabled rules against recent events, return matched incidents. (line 292)
- `SecurityEventCorrelationEngine.create_correlated_incident()` — Create a correlated incident from matched events. (line 342)
- `SecurityEventCorrelationEngine.list_correlated_incidents()` — List correlated incidents, optionally filtered by status. (line 376)
- `SecurityEventCorrelationEngine.get_correlation_stats()` — Return aggregated correlation statistics for an org. (line 398)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/security_event_correlation_engine.py` (428 lines)
- **Router file**: `suite-api/apps/api/security_event_correlation_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/event-correlation/events` | ingest event |
| GET | `/api/v1/event-correlation/events` | list events |
| POST | `/api/v1/event-correlation/rules` | create rule |
| GET | `/api/v1/event-correlation/rules` | list rules |
| POST | `/api/v1/event-correlation/run` | run correlation |
| POST | `/api/v1/event-correlation/incidents` | create incident |
| GET | `/api/v1/event-correlation/incidents` | list incidents |
| GET | `/api/v1/event-correlation/stats` | get stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Priya Sharma (SOC T2 Analyst) can access /api/v1/event-correlation and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 31+ tests passing in `tests/test_security_event_correlation_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 49 (est. April 25-27, 2026)

## Test Coverage
- **Test file**: `tests/test_security_event_correlation_engine.py`
- **Tests**: 31 tests
- **Status**: Passing
