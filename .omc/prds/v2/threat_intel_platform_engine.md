# US-0294: Threat Intel Platform

## Sub-Epic: AI Intelligence
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Nina Patel (Threat Intel Analyst)**, I need to automate threat intelligence
so that the platform delivers enterprise-grade ai intelligence capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Threat Intel Platform replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone AI Intelligence tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/tip"]
    API --> Auth["api_key_auth"]
    Auth --> Router["threat_intel_platform_router.py"]
    Router --> Engine["ThreatIntelPlatformEngine"]
    Engine --> DB[(SQLite: {org_id}_tip.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    ThreatIntelPlatformEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `add_source()` — Register a new intel source. (line 206)
- ✅ `list_sources()` — List intel sources, optionally filtered by status. (line 258)
- ✅ `add_indicator()` — Add an IOC/indicator, checking for duplicates by value+type. (line 274)
- ✅ `search_indicators()` — Full-text search on value + tags. (line 356)
- ✅ `get_indicator()` — Get a single indicator with its relationships. (line 380)
- ✅ `bulk_ingest()` — Batch add indicators. Returns {added, duplicates, errors}. (line 399)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/threat_intel_platform_engine.py` — 659 lines)
- `ThreatIntelPlatformEngine.add_source()` — Register a new intel source. (line 206)
- `ThreatIntelPlatformEngine.list_sources()` — List intel sources, optionally filtered by status. (line 258)
- `ThreatIntelPlatformEngine.add_indicator()` — Add an IOC/indicator, checking for duplicates by value+type. (line 274)
- `ThreatIntelPlatformEngine.search_indicators()` — Full-text search on value + tags. (line 356)
- `ThreatIntelPlatformEngine.get_indicator()` — Get a single indicator with its relationships. (line 380)
- `ThreatIntelPlatformEngine.bulk_ingest()` — Batch add indicators. Returns {added, duplicates, errors}. (line 399)
- `ThreatIntelPlatformEngine.add_relationship()` — Add a relationship between two indicators. (line 431)
- `ThreatIntelPlatformEngine.get_relationships()` — Get all relationships for an indicator. (line 469)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/threat_intel_platform_engine.py` (659 lines)
- **Router file**: `suite-api/apps/api/threat_intel_platform_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/tip/sources` | add source |
| GET | `/api/v1/tip/sources` | list sources |
| POST | `/api/v1/tip/indicators` | add indicator |
| GET | `/api/v1/tip/indicators` | search indicators |
| GET | `/api/v1/tip/indicators/{indicator_id}` | get indicator |
| POST | `/api/v1/tip/indicators/bulk` | bulk ingest |
| POST | `/api/v1/tip/relationships` | add relationship |
| GET | `/api/v1/tip/relationships/{indicator_id}` | get relationships |
| POST | `/api/v1/tip/reports` | create report |
| GET | `/api/v1/tip/reports` | list reports |
| POST | `/api/v1/tip/check` | check indicator |
| POST | `/api/v1/tip/expire` | expire indicators |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Nina Patel (Threat Intel Analyst) can access /api/v1/tip and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 33+ tests passing in `tests/test_threat_intel_platform_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 51 (est. April 27-29, 2026)

## Test Coverage
- **Test file**: `tests/test_threat_intel_platform_engine.py`
- **Tests**: 33 tests
- **Status**: Passing
