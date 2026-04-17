# US-0025: Asset Group

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Maria Lopez (IT Director)**, I need to maintain accurate asset inventory and risk scoring
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Asset Group replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/asset-groups"]
    API --> Auth["api_key_auth"]
    Auth --> Router["asset_group_router.py"]
    Router --> Engine["AssetGroupEngine"]
    Engine --> DB[(SQLite: {org_id}_asset_group.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `create_group()` — Create a new asset group. (line 154)
- ✅ `add_member()` — Add an asset to a group. INSERT OR IGNORE prevents duplicates. (line 194)
- ✅ `remove_member()` — Remove an asset from a group. member_count floored at 0. (line 231)
- ✅ `add_policy()` — Attach a policy to a group. config stored as JSON string. (line 251)
- ✅ `toggle_policy()` — Flip policy enabled: 0→1 or 1→0. (line 286)
- ✅ `get_group()` — Get a group with all its members and policies. (line 304)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/asset_group_engine.py` — 453 lines)
- `AssetGroupEngine.create_group()` — Create a new asset group. (line 154)
- `AssetGroupEngine.add_member()` — Add an asset to a group. INSERT OR IGNORE prevents duplicates. (line 194)
- `AssetGroupEngine.remove_member()` — Remove an asset from a group. member_count floored at 0. (line 231)
- `AssetGroupEngine.add_policy()` — Attach a policy to a group. config stored as JSON string. (line 251)
- `AssetGroupEngine.toggle_policy()` — Flip policy enabled: 0→1 or 1→0. (line 286)
- `AssetGroupEngine.get_group()` — Get a group with all its members and policies. (line 304)
- `AssetGroupEngine.list_groups()` — List groups with optional filters. (line 327)
- `AssetGroupEngine.get_asset_groups()` — Find all groups that contain a given asset_id. (line 347)

## Dependencies
- **Depends on**: standalone
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/asset_group_engine.py` (453 lines)
- **Router file**: `suite-api/apps/api/asset_group_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/asset-groups/groups` | create group |
| GET | `/api/v1/asset-groups/groups` | list groups |
| GET | `/api/v1/asset-groups/groups/{group_id}` | get group |
| POST | `/api/v1/asset-groups/groups/{group_id}/members` | add member |
| DELETE | `/api/v1/asset-groups/groups/{group_id}/members/{asset_id}` | remove member |
| POST | `/api/v1/asset-groups/groups/{group_id}/bulk-members` | bulk add members |
| POST | `/api/v1/asset-groups/groups/{group_id}/policies` | add policy |
| POST | `/api/v1/asset-groups/groups/{group_id}/policies/{policy_id}/toggle` | toggle policy |
| GET | `/api/v1/asset-groups/assets/{asset_id}/groups` | get asset groups |
| GET | `/api/v1/asset-groups/stats` | get stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Maria Lopez (IT Director) can access /api/v1/asset-groups and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 31+ tests passing in `tests/test_asset_group_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 42 (est. April 18-20, 2026)

## Test Coverage
- **Test file**: `tests/test_asset_group_engine.py`
- **Tests**: 31 tests
- **Status**: Passing
