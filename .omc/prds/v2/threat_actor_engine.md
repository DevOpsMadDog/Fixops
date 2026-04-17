# US-0280: Threat Actor

## Sub-Epic: AI Intelligence
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Nina Patel (Threat Intel Analyst)**, I need to track threat actor TTPs
so that the platform delivers enterprise-grade ai intelligence capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Threat Actor replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone AI Intelligence tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/threat-actors"]
    API --> Auth["api_key_auth"]
    Auth --> Router["threat_actor_router.py"]
    Router --> Engine["ThreatActorEngine"]
    Engine --> DB[(SQLite: {org_id}_threat_actors.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    ThreatActorEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `add_actor()` — Register a new threat actor. Returns the created record. (line 191)
- ✅ `list_actors()` — List threat actors, optionally filtered by type and/or active status. (line 254)
- ✅ `get_actor()` — Retrieve a single actor with campaign list and IOC count. (line 274)
- ✅ `add_campaign()` — Add a campaign attributed to an actor. (line 306)
- ✅ `list_campaigns()` — List campaigns with optional actor_id and/or status filters. (line 358)
- ✅ `add_ioc()` — Add an IOC attributed to an actor. (line 382)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/threat_actor_engine.py` — 553 lines)
- `ThreatActorEngine.add_actor()` — Register a new threat actor. Returns the created record. (line 191)
- `ThreatActorEngine.list_actors()` — List threat actors, optionally filtered by type and/or active status. (line 254)
- `ThreatActorEngine.get_actor()` — Retrieve a single actor with campaign list and IOC count. (line 274)
- `ThreatActorEngine.add_campaign()` — Add a campaign attributed to an actor. (line 306)
- `ThreatActorEngine.list_campaigns()` — List campaigns with optional actor_id and/or status filters. (line 358)
- `ThreatActorEngine.add_ioc()` — Add an IOC attributed to an actor. (line 382)
- `ThreatActorEngine.list_iocs()` — List IOCs with optional filters. (line 422)
- `ThreatActorEngine.add_to_watchlist()` — Add an actor to the org watchlist. (line 450)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/threat_actor_engine.py` (553 lines)
- **Router file**: `suite-api/apps/api/threat_actor_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/threat-actors/actors` | add actor |
| GET | `/api/v1/threat-actors/actors` | list actors |
| GET | `/api/v1/threat-actors/actors/{actor_id}` | get actor |
| POST | `/api/v1/threat-actors/actors/{actor_id}/campaigns` | add campaign |
| GET | `/api/v1/threat-actors/campaigns` | list campaigns |
| POST | `/api/v1/threat-actors/actors/{actor_id}/iocs` | add ioc |
| GET | `/api/v1/threat-actors/iocs` | list iocs |
| POST | `/api/v1/threat-actors/actors/{actor_id}/watchlist` | add to watchlist |
| GET | `/api/v1/threat-actors/watchlist` | get watchlist |
| GET | `/api/v1/threat-actors/stats` | get stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Nina Patel (Threat Intel Analyst) can access /api/v1/threat-actors and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 47+ tests passing in `tests/test_threat_actor_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 51 (est. April 27-29, 2026)

## Test Coverage
- **Test file**: `tests/test_threat_actor_engine.py`
- **Tests**: 47 tests
- **Status**: Passing
