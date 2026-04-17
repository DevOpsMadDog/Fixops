# US-0241: Security Maturity

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Sarah Chen (CISO)**, I need to assess security program maturity
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Security Maturity replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/security-maturity"]
    API --> Auth["api_key_auth"]
    Auth --> Router["security_maturity_router.py"]
    Router --> Engine["SecurityMaturityEngine"]
    Engine --> DB[(SQLite: {org_id}_security_maturity.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    SecurityMaturityEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `for_org()` — implemented (line 101)
- ✅ `create_assessment()` — Create a new maturity assessment with framework-appropriate domains. (line 214)
- ✅ `list_assessments()` — implemented (line 285)
- ✅ `get_assessment()` — Return assessment with its domains. (line 297)
- ✅ `add_domain_score()` — Score a domain. Computes level from score. (line 317)
- ✅ `add_control()` — Add a control with implementation status to a domain. (line 348)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/security_maturity_engine.py` — 541 lines)
- `SecurityMaturityEngine.for_org()` — Handle for org (line 101)
- `SecurityMaturityEngine.create_assessment()` — Create a new maturity assessment with framework-appropriate domains. (line 214)
- `SecurityMaturityEngine.list_assessments()` — Handle list assessments (line 285)
- `SecurityMaturityEngine.get_assessment()` — Return assessment with its domains. (line 297)
- `SecurityMaturityEngine.add_domain_score()` — Score a domain. Computes level from score. (line 317)
- `SecurityMaturityEngine.add_control()` — Add a control with implementation status to a domain. (line 348)
- `SecurityMaturityEngine.list_controls()` — Handle list controls (line 393)
- `SecurityMaturityEngine.complete_assessment()` — Compute overall_score as average of domain scores, set status=completed. (line 403)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/security_maturity_engine.py` (541 lines)
- **Router file**: `suite-api/apps/api/security_maturity_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/security-maturity/assessments` | create assessment |
| GET | `/api/v1/security-maturity/assessments` | list assessments |
| GET | `/api/v1/security-maturity/assessments/{assessment_id}` | get assessment |
| POST | `/api/v1/security-maturity/assessments/{assessment_id}/complete` | complete assessment |
| PUT | `/api/v1/security-maturity/domains/{domain_id}/score` | score domain |
| POST | `/api/v1/security-maturity/domains/{domain_id}/controls` | add control |
| GET | `/api/v1/security-maturity/domains/{domain_id}/controls` | list controls |
| POST | `/api/v1/security-maturity/targets` | set target |
| GET | `/api/v1/security-maturity/targets` | list targets |
| GET | `/api/v1/security-maturity/stats` | get stats |
| GET | `/api/v1/security-maturity/roadmap` | get roadmap |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Sarah Chen (CISO) can access /api/v1/security-maturity and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 32+ tests passing in `tests/test_security_maturity_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 50 (est. April 26-28, 2026)

## Test Coverage
- **Test file**: `tests/test_security_maturity_engine.py`
- **Tests**: 32 tests
- **Status**: Passing
