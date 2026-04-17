# US-0167: Network Traffic

## Sub-Epic: Network
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **James Wilson (Security Engineer)**, I need to monitor and secure network traffic
so that the platform delivers enterprise-grade network capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Network Traffic replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Network tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/network-traffic"]
    API --> Auth["api_key_auth"]
    Auth --> Router["network_traffic_router.py"]
    Router --> Engine["NetworkTrafficEngine"]
    Engine --> DB[(SQLite: {org_id}_network_traffic.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    NetworkTrafficEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `record_flow()` — Record a network flow. Runs anomaly detection. Returns saved flow dict. (line 253)
- ✅ `list_flows()` — List traffic flows with optional filters. (line 358)
- ✅ `get_flow()` — Retrieve a single flow by ID. (line 384)
- ✅ `list_anomalies()` — List traffic anomalies with optional filters. (line 398)
- ✅ `resolve_anomaly()` — Mark an anomaly as resolved. Returns True if found. (line 420)
- ✅ `create_rule()` — Create a traffic rule. Returns the created record. (line 436)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/network_traffic_engine.py` — 557 lines)
- `NetworkTrafficEngine.record_flow()` — Record a network flow. Runs anomaly detection. Returns saved flow dict. (line 253)
- `NetworkTrafficEngine.list_flows()` — List traffic flows with optional filters. (line 358)
- `NetworkTrafficEngine.get_flow()` — Retrieve a single flow by ID. (line 384)
- `NetworkTrafficEngine.list_anomalies()` — List traffic anomalies with optional filters. (line 398)
- `NetworkTrafficEngine.resolve_anomaly()` — Mark an anomaly as resolved. Returns True if found. (line 420)
- `NetworkTrafficEngine.create_rule()` — Create a traffic rule. Returns the created record. (line 436)
- `NetworkTrafficEngine.list_rules()` — List all traffic rules for an org, ordered by priority. (line 477)
- `NetworkTrafficEngine.get_traffic_stats()` — Return aggregated traffic stats for org. (line 493)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/network_traffic_engine.py` (557 lines)
- **Router file**: `suite-api/apps/api/network_traffic_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/network-traffic/flows` | record flow |
| GET | `/api/v1/network-traffic/flows` | list flows |
| GET | `/api/v1/network-traffic/flows/{flow_id}` | get flow |
| GET | `/api/v1/network-traffic/anomalies` | list anomalies |
| POST | `/api/v1/network-traffic/anomalies/{anomaly_id}/resolve` | resolve anomaly |
| POST | `/api/v1/network-traffic/rules` | create rule |
| GET | `/api/v1/network-traffic/rules` | list rules |
| GET | `/api/v1/network-traffic/stats` | get traffic stats |
| GET | `/api/v1/network-traffic/top-talkers` | get top talkers |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] James Wilson (Security Engineer) can access /api/v1/network-traffic and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 36+ tests passing in `tests/test_network_traffic_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 47 (est. April 23-25, 2026)

## Test Coverage
- **Test file**: `tests/test_network_traffic_engine.py`
- **Tests**: 36 tests
- **Status**: Passing
