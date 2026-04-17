# US-0330: Zero Trust Enforcement

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Richard Adams (Security Architect)**, I need to enforce zero trust policies
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Zero Trust Enforcement replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/zero-trust"]
    API --> Auth["api_key_auth"]
    Auth --> Router["zero_trust_enforcement_router.py"]
    Router --> Engine["ZeroTrustEnforcementEngine"]
    Engine --> DB[(SQLite: {org_id}_zero_trust.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    ZeroTrustEnforcementEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `create_policy()` — Create a Zero Trust access policy. (line 258)
- ✅ `list_policies()` — List policies for an org, ordered by priority. (line 311)
- ✅ `get_policy()` — Get a single policy by ID. (line 340)
- ✅ `update_policy()` — Update a policy. Returns the updated policy. (line 353)
- ✅ `evaluate_access()` — Evaluate an access request against Zero Trust policies. (line 404)
- ✅ `set_trust_score()` — Create or update the trust score for an entity. (line 571)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/zero_trust_enforcement_engine.py` — 868 lines)
- `ZeroTrustEnforcementEngine.create_policy()` — Create a Zero Trust access policy. (line 258)
- `ZeroTrustEnforcementEngine.list_policies()` — List policies for an org, ordered by priority. (line 311)
- `ZeroTrustEnforcementEngine.get_policy()` — Get a single policy by ID. (line 340)
- `ZeroTrustEnforcementEngine.update_policy()` — Update a policy. Returns the updated policy. (line 353)
- `ZeroTrustEnforcementEngine.evaluate_access()` — Evaluate an access request against Zero Trust policies. (line 404)
- `ZeroTrustEnforcementEngine.set_trust_score()` — Create or update the trust score for an entity. (line 571)
- `ZeroTrustEnforcementEngine.get_trust_score()` — Get the trust score record for a specific entity. (line 615)
- `ZeroTrustEnforcementEngine.list_trust_scores()` — List trust scores for an org with optional filters. (line 628)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/zero_trust_enforcement_engine.py` (868 lines)
- **Router file**: `suite-api/apps/api/zero_trust_enforcement_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/zero-trust/policies` | list policies |
| POST | `/api/v1/zero-trust/policies` | create policy |
| GET | `/api/v1/zero-trust/policies/{policy_id}` | get policy |
| PATCH | `/api/v1/zero-trust/policies/{policy_id}` | update policy |
| POST | `/api/v1/zero-trust/evaluate` | evaluate access |
| GET | `/api/v1/zero-trust/trust-scores` | list trust scores |
| POST | `/api/v1/zero-trust/trust-scores` | set trust score |
| GET | `/api/v1/zero-trust/trust-scores/{entity_id}` | get trust score |
| GET | `/api/v1/zero-trust/sessions` | list sessions |
| POST | `/api/v1/zero-trust/sessions` | create session |
| POST | `/api/v1/zero-trust/sessions/{session_id}/revoke` | revoke session |
| GET | `/api/v1/zero-trust/access-log` | list access requests |

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
- [ ] 60+ tests passing in `tests/test_zero_trust_enforcement_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 53 (est. April 29-31, 2026)

## Test Coverage
- **Test file**: `tests/test_zero_trust_enforcement_engine.py`
- **Tests**: 60 tests
- **Status**: Passing
