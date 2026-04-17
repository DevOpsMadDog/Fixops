# US-0031: Attack Surface

## Sub-Epic: CTEM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Lisa Zhang (Pentester)**, I need to model attack paths and simulate adversary behavior
so that the platform delivers enterprise-grade ctem capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Attack Surface replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone CTEM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/attack-surface"]
    API --> Auth["api_key_auth"]
    Auth --> Router["attack_surface_router.py"]
    Router --> Engine["AttackSurfaceEngine"]
    Engine --> DB[(SQLite: {org_id}_attack_surface.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    AttackSurfaceEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `add_asset()` — Register a surface asset. (line 216)
- ✅ `list_assets()` — List surface assets with optional filters. (line 273)
- ✅ `get_asset()` — Get asset with its exposures. (line 297)
- ✅ `add_exposure()` — Add an exposure finding for an asset. (line 319)
- ✅ `list_exposures()` — List exposures with optional filters. (line 376)
- ✅ `fix_exposure()` — Mark an exposure as fixed. Returns True if found. (line 402)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/attack_surface_engine.py` — 599 lines)
- `AttackSurfaceEngine.add_asset()` — Register a surface asset. (line 216)
- `AttackSurfaceEngine.list_assets()` — List surface assets with optional filters. (line 273)
- `AttackSurfaceEngine.get_asset()` — Get asset with its exposures. (line 297)
- `AttackSurfaceEngine.add_exposure()` — Add an exposure finding for an asset. (line 319)
- `AttackSurfaceEngine.list_exposures()` — List exposures with optional filters. (line 376)
- `AttackSurfaceEngine.fix_exposure()` — Mark an exposure as fixed. Returns True if found. (line 402)
- `AttackSurfaceEngine.create_scan()` — Create a scan job. (line 441)
- `AttackSurfaceEngine.complete_scan()` — Mark scan complete with discovery metrics. Returns True if found. (line 479)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/attack_surface_engine.py` (599 lines)
- **Router file**: `suite-api/apps/api/attack_surface_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/attack-surface/assets` | register asset |
| GET | `/api/v1/attack-surface/assets` | list assets |
| GET | `/api/v1/attack-surface/assets/{asset_id}` | get asset |
| DELETE | `/api/v1/attack-surface/assets/{asset_id}` | delete asset |
| GET | `/api/v1/attack-surface/summary` | get surface summary |
| GET | `/api/v1/attack-surface/external` | get external assets |
| GET | `/api/v1/attack-surface/paths` | get exposure paths |
| GET | `/api/v1/attack-surface/changes` | get surface changes |
| POST | `/api/v1/attack-surface/discover` | discover from findings |
| POST | `/api/v1/attack-surface/paths` | map exposure path |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Lisa Zhang (Pentester) can access /api/v1/attack-surface and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 30+ tests passing in `tests/test_attack_surface_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 43 (est. April 19-21, 2026)

## Test Coverage
- **Test file**: `tests/test_attack_surface_engine.py`
- **Tests**: 30 tests
- **Status**: Passing
