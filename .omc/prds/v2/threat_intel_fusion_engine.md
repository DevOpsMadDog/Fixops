# US-0293: Threat Intel Fusion

## Sub-Epic: AI Intelligence
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Nina Patel (Threat Intel Analyst)**, I need to automate threat intelligence
so that the platform delivers enterprise-grade ai intelligence capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Threat Intel Fusion replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone AI Intelligence tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/threat-intel-fusion"]
    API --> Auth["api_key_auth"]
    Auth --> Router["threat_intel_fusion_router.py"]
    Router --> Engine["ThreatIntelFusionEngine"]
    Engine --> DB[(SQLite: {org_id}_threat_intel_fusion.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    ThreatIntelFusionEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `add_intel_source()` — Register a new threat intelligence source. (line 144)
- ✅ `list_intel_sources()` — List all intel sources for an org. (line 193)
- ✅ `ingest_indicator()` — Ingest a threat indicator from a source. (line 209)
- ✅ `search_indicators()` — Search indicators by value substring, optionally filtered by type. (line 258)
- ✅ `fuse_indicator()` — Aggregate all records for an indicator value, return consensus confidence. (line 275)
- ✅ `get_high_confidence_indicators()` — Return active indicators meeting the minimum confidence threshold. (line 312)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/threat_intel_fusion_engine.py` — 393 lines)
- `ThreatIntelFusionEngine.add_intel_source()` — Register a new threat intelligence source. (line 144)
- `ThreatIntelFusionEngine.list_intel_sources()` — List all intel sources for an org. (line 193)
- `ThreatIntelFusionEngine.ingest_indicator()` — Ingest a threat indicator from a source. (line 209)
- `ThreatIntelFusionEngine.search_indicators()` — Search indicators by value substring, optionally filtered by type. (line 258)
- `ThreatIntelFusionEngine.fuse_indicator()` — Aggregate all records for an indicator value, return consensus confidence. (line 275)
- `ThreatIntelFusionEngine.get_high_confidence_indicators()` — Return active indicators meeting the minimum confidence threshold. (line 312)
- `ThreatIntelFusionEngine.expire_old_indicators()` — Mark indicators past their expiry_date as expired. (line 332)
- `ThreatIntelFusionEngine.get_fusion_stats()` — Return aggregated fusion statistics for an org. (line 356)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/threat_intel_fusion_engine.py` (393 lines)
- **Router file**: `suite-api/apps/api/threat_intel_fusion_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/threat-intel-fusion/sources` | add source |
| GET | `/api/v1/threat-intel-fusion/sources` | list sources |
| POST | `/api/v1/threat-intel-fusion/indicators` | ingest indicator |
| GET | `/api/v1/threat-intel-fusion/indicators/search` | search indicators |
| GET | `/api/v1/threat-intel-fusion/indicators/high-confidence` | get high confidence |
| POST | `/api/v1/threat-intel-fusion/indicators/expire` | expire indicators |
| GET | `/api/v1/threat-intel-fusion/fuse/{indicator_value}` | fuse indicator |
| GET | `/api/v1/threat-intel-fusion/stats` | get stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Nina Patel (Threat Intel Analyst) can access /api/v1/threat-intel-fusion and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 32+ tests passing in `tests/test_threat_intel_fusion_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 51 (est. April 27-29, 2026)

## Test Coverage
- **Test file**: `tests/test_threat_intel_fusion_engine.py`
- **Tests**: 32 tests
- **Status**: Passing
