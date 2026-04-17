# US-0331: Zero Trust

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Richard Adams (Security Architect)**, I need to enforce zero trust policies
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Zero Trust replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/zero-trust"]
    API --> Auth["api_key_auth"]
    Auth --> Router["zero_trust_router.py"]
    Router --> Engine["ZeroTrustEngine"]
    Engine --> DB[(SQLite: data/zero_trust.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `create_policy()` — Create a zero-trust access policy. (line 201)
- ✅ `get_policy()` — implemented (line 264)
- ✅ `list_policies()` — implemented (line 274)
- ✅ `update_policy()` — implemented (line 293)
- ✅ `delete_policy()` — implemented (line 335)
- ✅ `compute_trust_score()` — Compute trust level for a request context. (line 350)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/zero_trust_engine.py` — 874 lines)
- `ZeroTrustEngine.create_policy()` — Create a zero-trust access policy. (line 201)
- `ZeroTrustEngine.get_policy()` — Handle get policy (line 264)
- `ZeroTrustEngine.list_policies()` — Handle list policies (line 274)
- `ZeroTrustEngine.update_policy()` — Handle update policy (line 293)
- `ZeroTrustEngine.delete_policy()` — Handle delete policy (line 335)
- `ZeroTrustEngine.compute_trust_score()` — Compute trust level for a request context. (line 350)
- `ZeroTrustEngine.evaluate_access()` — Evaluate an access request against all active policies. (line 437)
- `ZeroTrustEngine.get_access_log()` — Handle get access log (line 562)

## Dependencies
- **Depends on**: standalone
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/zero_trust_engine.py` (874 lines)
- **Router file**: `suite-api/apps/api/zero_trust_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/zero-trust/policies` | create policy |
| GET | `/api/v1/zero-trust/policies` | list policies |
| GET | `/api/v1/zero-trust/policies/{policy_id}` | get policy |
| PUT | `/api/v1/zero-trust/policies/{policy_id}` | update policy |
| DELETE | `/api/v1/zero-trust/policies/{policy_id}` | delete policy |
| POST | `/api/v1/zero-trust/evaluate` | evaluate access |
| POST | `/api/v1/zero-trust/trust-score` | compute trust score |
| GET | `/api/v1/zero-trust/access-log` | get access log |
| GET | `/api/v1/zero-trust/analytics` | get analytics |
| GET | `/api/v1/zero-trust/trust-score/{subject_id}` | get trust score |
| GET | `/api/v1/zero-trust/stats` | get policy stats |
| GET | `/api/v1/zero-trust/segments` | get micro segmentation map |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Richard Adams (Security Architect) can access /api/v1/zero-trust and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 51+ tests passing in `tests/test_zero_trust_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 53 (est. April 29-31, 2026)

## Test Coverage
- **Test file**: `tests/test_zero_trust_engine.py`
- **Tests**: 51 tests
- **Status**: Passing
