# US-0061: Cloud Security

## Sub-Epic: CSPM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Jennifer Wu (Cloud Security Architect)**, I need to secure cloud infrastructure and workloads
so that the platform delivers enterprise-grade cspm capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Cloud Security replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone CSPM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/cloud-security-engine"]
    API --> Auth["api_key_auth"]
    Auth --> Router["cloud_security_engine_router.py"]
    Router --> Engine["CloudSecurityEngine"]
    Engine --> DB[(SQLite: {org_id}_cloud_security.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    CloudSecurityEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `add_account()` — Register a cloud account. Returns the created record. (line 170)
- ✅ `list_accounts()` — List cloud accounts, optionally filtered by provider. (line 219)
- ✅ `add_finding()` — Create a cloud security finding. Returns the created record. (line 234)
- ✅ `list_findings()` — List cloud findings with optional filters. (line 295)
- ✅ `resolve_finding()` — Mark a finding as resolved. Returns True if found and updated. (line 333)
- ✅ `add_resource()` — Register a cloud resource. Returns the created record. (line 349)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/cloud_security_engine.py` — 561 lines)
- `CloudSecurityEngine.add_account()` — Register a cloud account. Returns the created record. (line 170)
- `CloudSecurityEngine.list_accounts()` — List cloud accounts, optionally filtered by provider. (line 219)
- `CloudSecurityEngine.add_finding()` — Create a cloud security finding. Returns the created record. (line 234)
- `CloudSecurityEngine.list_findings()` — List cloud findings with optional filters. (line 295)
- `CloudSecurityEngine.resolve_finding()` — Mark a finding as resolved. Returns True if found and updated. (line 333)
- `CloudSecurityEngine.add_resource()` — Register a cloud resource. Returns the created record. (line 349)
- `CloudSecurityEngine.list_resources()` — List cloud resources with optional filters. (line 395)
- `CloudSecurityEngine.add_benchmark_result()` — Save a benchmark run result. Returns the created record. (line 429)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/cloud_security_engine.py` (561 lines)
- **Router file**: `suite-api/apps/api/cloud_security_engine_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/cloud-security-engine/accounts` | add account |
| GET | `/api/v1/cloud-security-engine/accounts` | list accounts |
| POST | `/api/v1/cloud-security-engine/findings` | add finding |
| GET | `/api/v1/cloud-security-engine/findings` | list findings |
| PATCH | `/api/v1/cloud-security-engine/findings/{finding_id}/resolve` | resolve finding |
| POST | `/api/v1/cloud-security-engine/resources` | add resource |
| GET | `/api/v1/cloud-security-engine/resources` | list resources |
| POST | `/api/v1/cloud-security-engine/benchmarks` | add benchmark result |
| GET | `/api/v1/cloud-security-engine/benchmarks` | list benchmarks |
| GET | `/api/v1/cloud-security-engine/stats` | get cloud stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Jennifer Wu (Cloud Security Architect) can access /api/v1/cloud-security-engine and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 43+ tests passing in `tests/test_cloud_security_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 44 (est. April 20-22, 2026)

## Test Coverage
- **Test file**: `tests/test_cloud_security_engine.py`
- **Tests**: 43 tests
- **Status**: Passing
