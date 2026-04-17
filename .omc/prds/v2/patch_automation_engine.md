# US-0175: Patch Automation

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **James Wilson (Security Engineer)**, I need to manage patch deployment lifecycle
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Patch Automation replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/patch-automation"]
    API --> Auth["api_key_auth"]
    Auth --> Router["patch_automation_router.py"]
    Router --> Engine["PatchAutomationEngine"]
    Engine --> DB[(SQLite: {org_id}_patch_automation.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    PatchAutomationEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `add_patch()` — Add a patch to the catalog. Returns the created record. (line 160)
- ✅ `list_patches()` — List patches from catalog with optional filters. (line 224)
- ✅ `approve_patch()` — Approve a patch (sets status=approved). Returns True if found. (line 256)
- ✅ `deploy_patch()` — Create a deployment record with status=pending. Returns the record. (line 270)
- ✅ `update_deployment()` — Update a deployment's status. Returns True if found and updated. (line 310)
- ✅ `list_deployments()` — List deployments with optional filters. (line 334)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/patch_automation_engine.py` — 563 lines)
- `PatchAutomationEngine.add_patch()` — Add a patch to the catalog. Returns the created record. (line 160)
- `PatchAutomationEngine.list_patches()` — List patches from catalog with optional filters. (line 224)
- `PatchAutomationEngine.approve_patch()` — Approve a patch (sets status=approved). Returns True if found. (line 256)
- `PatchAutomationEngine.deploy_patch()` — Create a deployment record with status=pending. Returns the record. (line 270)
- `PatchAutomationEngine.update_deployment()` — Update a deployment's status. Returns True if found and updated. (line 310)
- `PatchAutomationEngine.list_deployments()` — List deployments with optional filters. (line 334)
- `PatchAutomationEngine.add_exception()` — Create a patch exception (risk acceptance). Returns the created record. (line 359)
- `PatchAutomationEngine.list_exceptions()` — List all patch exceptions for the org. (line 388)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/patch_automation_engine.py` (563 lines)
- **Router file**: `suite-api/apps/api/patch_automation_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/patch-automation/patches` | add patch |
| GET | `/api/v1/patch-automation/patches` | list patches |
| PATCH | `/api/v1/patch-automation/patches/{patch_id}/approve` | approve patch |
| POST | `/api/v1/patch-automation/deployments` | deploy patch |
| PATCH | `/api/v1/patch-automation/deployments/{deployment_id}/status` | update deployment |
| GET | `/api/v1/patch-automation/deployments` | list deployments |
| POST | `/api/v1/patch-automation/exceptions` | add exception |
| GET | `/api/v1/patch-automation/exceptions` | list exceptions |
| POST | `/api/v1/patch-automation/windows` | create patch window |
| GET | `/api/v1/patch-automation/windows` | list patch windows |
| GET | `/api/v1/patch-automation/cve/{cve_id}/patches` | get cve patch map |
| GET | `/api/v1/patch-automation/stats` | get patch stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] James Wilson (Security Engineer) can access /api/v1/patch-automation and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 52+ tests passing in `tests/test_patch_automation_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 47 (est. April 23-25, 2026)

## Test Coverage
- **Test file**: `tests/test_patch_automation_engine.py`
- **Tests**: 52 tests
- **Status**: Passing
