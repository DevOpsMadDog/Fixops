# US-0089: Data Classification

## Sub-Epic: GRC
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Robert Kim (Compliance Officer)**, I need to classify and label sensitive data
so that the platform delivers enterprise-grade grc capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Data Classification replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone GRC tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/classification"]
    API --> Auth["api_key_auth"]
    Auth --> Router["data_classification_router.py"]
    Router --> Engine["DataClassificationEngine"]
    Engine --> DB[(SQLite: {org_id}_data_classification.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    DataClassificationEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `register_asset()` — Register a new data asset. Returns the created record. (line 224)
- ✅ `list_assets()` — List data assets, optionally filtered by classification level and/or PII detecti (line 295)
- ✅ `get_asset()` — Retrieve a single data asset by ID. (line 315)
- ✅ `classify_asset()` — Update the classification level of a data asset. (line 325)
- ✅ `scan_asset()` — Simulate a PII scan on the asset using asset-type heuristics. (line 356)
- ✅ `add_rule()` — Add a new classification rule. (line 430)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/data_classification_engine.py` — 611 lines)
- `DataClassificationEngine.register_asset()` — Register a new data asset. Returns the created record. (line 224)
- `DataClassificationEngine.list_assets()` — List data assets, optionally filtered by classification level and/or PII detecti (line 295)
- `DataClassificationEngine.get_asset()` — Retrieve a single data asset by ID. (line 315)
- `DataClassificationEngine.classify_asset()` — Update the classification level of a data asset. (line 325)
- `DataClassificationEngine.scan_asset()` — Simulate a PII scan on the asset using asset-type heuristics. (line 356)
- `DataClassificationEngine.add_rule()` — Add a new classification rule. (line 430)
- `DataClassificationEngine.list_rules()` — List all classification rules for the org. (line 474)
- `DataClassificationEngine.log_violation()` — Log a data classification violation. (line 490)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/data_classification_engine.py` (611 lines)
- **Router file**: `suite-api/apps/api/data_classification_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/classification/assets` | classify asset |
| GET | `/api/v1/classification/assets` | list classified assets |
| GET | `/api/v1/classification/assets/{asset_id}` | get asset classification |
| POST | `/api/v1/classification/assets/{asset_id}/auto-classify` | auto classify asset |
| POST | `/api/v1/classification/assets/{asset_id}/upgrade` | upgrade classification |
| POST | `/api/v1/classification/assets/{asset_id}/downgrade` | downgrade classification |
| GET | `/api/v1/classification/stats` | get classification stats |
| GET | `/api/v1/classification/audit` | audit classification changes |
| GET | `/api/v1/classification/handling/{level}` | get handling instructions |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Robert Kim (Compliance Officer) can access /api/v1/classification and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 42+ tests passing in `tests/test_data_classification_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 44 (est. April 20-22, 2026)

## Test Coverage
- **Test file**: `tests/test_data_classification_engine.py`
- **Tests**: 42 tests
- **Status**: Passing
