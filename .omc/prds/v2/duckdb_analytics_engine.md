# US-0104: Duckdb Analytics

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Chris Lee (Security Data Scientist)**, I need to run cross-domain analytics queries
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Duckdb Analytics replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/duckdb-analytics"]
    API --> Auth["api_key_auth"]
    Auth --> Router["duckdb_analytics_router.py"]
    Router --> Engine["AnalyticsEngine"]
    Engine --> DB[(SQLite: {name}.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    AnalyticsEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 70% Complete
- ✅ `get_db_path()` — Return the absolute path to <name>.db, or None if it doesn't exist. (line 77)
- ✅ `cross_domain_risk_summary()` — Return a unified risk picture across available domain databases. (line 116)
- ✅ `asset_vulnerability_correlation()` — Cross-join asset data with vulnerability / risk data. (line 181)
- ✅ `threat_intel_correlation()` — Search for an IOC across multiple threat databases. (line 221)
- ✅ `compliance_posture_trend()` — Return last 10 compliance scan results ordered newest first. (line 268)
- ✅ `executive_dashboard_data()` — Aggregate across ALL available domains for CISO executive view. (line 298)
- ❌ No dedicated router — endpoint may be in gap_router.py
- ❌ No test file found — needs test coverage
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/duckdb_analytics_engine.py` — 428 lines)
- `AnalyticsEngine.get_db_path()` — Return the absolute path to <name>.db, or None if it doesn't exist. (line 77)
- `AnalyticsEngine.cross_domain_risk_summary()` — Return a unified risk picture across available domain databases. (line 116)
- `AnalyticsEngine.asset_vulnerability_correlation()` — Cross-join asset data with vulnerability / risk data. (line 181)
- `AnalyticsEngine.threat_intel_correlation()` — Search for an IOC across multiple threat databases. (line 221)
- `AnalyticsEngine.compliance_posture_trend()` — Return last 10 compliance scan results ordered newest first. (line 268)
- `AnalyticsEngine.executive_dashboard_data()` — Aggregate across ALL available domains for CISO executive view. (line 298)
- `AnalyticsEngine.list_available_domains()` — Scan data_dir for *.db files and return metadata list. (line 367)
- `AnalyticsEngine.run_custom_query()` — Execute a safe SELECT on any domain database table. (line 391)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/duckdb_analytics_engine.py` (428 lines)
- **Router file**: `suite-api/apps/api/N/A`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/duckdb-analytics` | List resources |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Create dedicated router (needs wiring in app.py) (3h)
6. Write unit tests (4h)

## Definition of Done
- [ ] Chris Lee (Security Data Scientist) can access /api/v1/duckdb-analytics and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 20+ tests passing in `tests/test_duckdb_analytics_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 45 (est. April 21-23, 2026)

## Test Coverage
- **Test file**: `tests/test_duckdb_analytics_engine.py`
- **Tests**: 0 tests
- **Status**: Needs coverage
