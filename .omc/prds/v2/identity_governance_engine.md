# US-0126: Identity Governance

## Sub-Epic: Identity
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Maria Lopez (IT Director)**, I need to manage identity analytics and risk
so that the platform delivers enterprise-grade identity capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Identity Governance replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Identity tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/identity-governance"]
    API --> Auth["api_key_auth"]
    Auth --> Router["identity_governance_router.py"]
    Router --> Engine["IdentityGovernanceEngine"]
    Engine --> DB[(SQLite: {org_id}_identity_governance.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    IdentityGovernanceEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `create_review()` — Create a new access review. Returns the created record. (line 178)
- ✅ `list_reviews()` — List access reviews, optionally filtered by status. (line 228)
- ✅ `get_review()` — Retrieve a review with item summary. (line 242)
- ✅ `add_review_item()` — Add an identity/entitlement item to a review. (line 272)
- ✅ `submit_decision()` — Record a reviewer decision for a review item. Returns True if found. (line 324)
- ✅ `complete_review()` — Mark a review as completed and compute final metrics. (line 378)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/identity_governance_engine.py` — 612 lines)
- `IdentityGovernanceEngine.create_review()` — Create a new access review. Returns the created record. (line 178)
- `IdentityGovernanceEngine.list_reviews()` — List access reviews, optionally filtered by status. (line 228)
- `IdentityGovernanceEngine.get_review()` — Retrieve a review with item summary. (line 242)
- `IdentityGovernanceEngine.add_review_item()` — Add an identity/entitlement item to a review. (line 272)
- `IdentityGovernanceEngine.submit_decision()` — Record a reviewer decision for a review item. Returns True if found. (line 324)
- `IdentityGovernanceEngine.complete_review()` — Mark a review as completed and compute final metrics. (line 378)
- `IdentityGovernanceEngine.add_entitlement()` — Register an entitlement for an identity. (line 412)
- `IdentityGovernanceEngine.list_entitlements()` — List entitlements with optional filters. (line 453)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/identity_governance_engine.py` (612 lines)
- **Router file**: `suite-api/apps/api/identity_governance_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identity-governance/reviews` | create review |
| GET | `/api/v1/identity-governance/reviews` | list reviews |
| GET | `/api/v1/identity-governance/reviews/{review_id}` | get review |
| POST | `/api/v1/identity-governance/reviews/{review_id}/items` | add review item |
| POST | `/api/v1/identity-governance/items/{item_id}/decision` | submit decision |
| POST | `/api/v1/identity-governance/reviews/{review_id}/complete` | complete review |
| POST | `/api/v1/identity-governance/entitlements` | add entitlement |
| GET | `/api/v1/identity-governance/entitlements` | list entitlements |
| POST | `/api/v1/identity-governance/entitlements/flag-orphaned` | flag orphaned |
| POST | `/api/v1/identity-governance/policies` | create policy |
| GET | `/api/v1/identity-governance/policies` | list policies |
| GET | `/api/v1/identity-governance/stats` | get governance stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Maria Lopez (IT Director) can access /api/v1/identity-governance and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 39+ tests passing in `tests/test_identity_governance_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 46 (est. April 22-24, 2026)

## Test Coverage
- **Test file**: `tests/test_identity_governance_engine.py`
- **Tests**: 39 tests
- **Status**: Passing
