# US-0284: Threat Correlation

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Priya Sharma (SOC T2 Analyst)**, I need to correlate threat indicators
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Threat Correlation replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/threat-correlation"]
    API --> Auth["api_key_auth"]
    Auth --> Router["threat_correlation_router.py"]
    Router --> Engine["ThreatCorrelationEngine"]
    Engine --> DB[(SQLite: {org_id}_threat_correlation.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    ThreatCorrelationEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `for_org()` — implemented (line 68)
- ✅ `create_rule()` — Create a correlation rule. (line 180)
- ✅ `list_rules()` — implemented (line 228)
- ✅ `ingest_signal()` — Ingest a threat signal, then attempt correlation. (line 248)
- ✅ `list_signals()` — implemented (line 458)
- ✅ `list_incidents()` — implemented (line 486)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/threat_correlation_engine.py` — 652 lines)
- `ThreatCorrelationEngine.for_org()` — Handle for org (line 68)
- `ThreatCorrelationEngine.create_rule()` — Create a correlation rule. (line 180)
- `ThreatCorrelationEngine.list_rules()` — Handle list rules (line 228)
- `ThreatCorrelationEngine.ingest_signal()` — Ingest a threat signal, then attempt correlation. (line 248)
- `ThreatCorrelationEngine.list_signals()` — Handle list signals (line 458)
- `ThreatCorrelationEngine.list_incidents()` — Handle list incidents (line 486)
- `ThreatCorrelationEngine.get_incident()` — Return incident with full signal timeline. (line 506)
- `ThreatCorrelationEngine.resolve_incident()` — Mark incident as resolved. Returns True if found. (line 530)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/threat_correlation_engine.py` (652 lines)
- **Router file**: `suite-api/apps/api/threat_correlation_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/threat-correlation/signals` | ingest signal |
| GET | `/api/v1/threat-correlation/signals` | list signals |
| GET | `/api/v1/threat-correlation/incidents` | list incidents |
| GET | `/api/v1/threat-correlation/incidents/{incident_id}` | get incident |
| POST | `/api/v1/threat-correlation/incidents/{incident_id}/resolve` | resolve incident |
| POST | `/api/v1/threat-correlation/rules` | create rule |
| GET | `/api/v1/threat-correlation/rules` | list rules |
| GET | `/api/v1/threat-correlation/stats` | get stats |
| GET | `/api/v1/threat-correlation/context/{entity_id}` | get trustgraph context |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Priya Sharma (SOC T2 Analyst) can access /api/v1/threat-correlation and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 39+ tests passing in `tests/test_threat_correlation_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 51 (est. April 27-29, 2026)

## Test Coverage
- **Test file**: `tests/test_threat_correlation_engine.py`
- **Tests**: 39 tests
- **Status**: Passing
