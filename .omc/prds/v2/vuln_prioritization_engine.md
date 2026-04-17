# US-0314: Vuln Prioritization

## Sub-Epic: CTEM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **James Wilson (Security Engineer)**, I need to prioritize vulnerabilities by risk
so that the platform delivers enterprise-grade ctem capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Vuln Prioritization replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone CTEM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/vuln-prioritization"]
    API --> Auth["api_key_auth"]
    Auth --> Router["vuln_prioritization_router.py"]
    Router --> Engine["VulnerabilityPrioritizationEngine"]
    Engine --> DB[(SQLite: {org_id}_vuln_prioritization.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    VulnerabilityPrioritizationEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `score_vulnerability()` — Compute priority score + tier + risk explanation, save and return. (line 186)
- ✅ `batch_score()` — Score multiple vulnerabilities, create a run record, return summary. (line 264)
- ✅ `list_scored()` — List scored vulnerabilities, optionally filtered. (line 316)
- ✅ `get_score()` — Get a single scored vulnerability by ID. (line 339)
- ✅ `assign_sla()` — Assign SLA to a scored vulnerability, calculate due_date from tier. (line 353)
- ✅ `list_sla_assignments()` — List SLA assignments, optionally filtered by status or team. (line 389)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/vuln_prioritization_engine.py` — 573 lines)
- `VulnerabilityPrioritizationEngine.score_vulnerability()` — Compute priority score + tier + risk explanation, save and return. (line 186)
- `VulnerabilityPrioritizationEngine.batch_score()` — Score multiple vulnerabilities, create a run record, return summary. (line 264)
- `VulnerabilityPrioritizationEngine.list_scored()` — List scored vulnerabilities, optionally filtered. (line 316)
- `VulnerabilityPrioritizationEngine.get_score()` — Get a single scored vulnerability by ID. (line 339)
- `VulnerabilityPrioritizationEngine.assign_sla()` — Assign SLA to a scored vulnerability, calculate due_date from tier. (line 353)
- `VulnerabilityPrioritizationEngine.list_sla_assignments()` — List SLA assignments, optionally filtered by status or team. (line 389)
- `VulnerabilityPrioritizationEngine.get_run()` — Get a specific prioritization run. (line 415)
- `VulnerabilityPrioritizationEngine.list_runs()` — List all prioritization runs for an org. (line 425)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/vuln_prioritization_engine.py` (573 lines)
- **Router file**: `suite-api/apps/api/vuln_prioritization_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/vuln-prioritization/score` | score vulnerability |
| POST | `/api/v1/vuln-prioritization/batch-score` | batch score |
| GET | `/api/v1/vuln-prioritization/scored` | list scored |
| GET | `/api/v1/vuln-prioritization/scored/{vuln_id}` | get scored |
| POST | `/api/v1/vuln-prioritization/scored/{vuln_id}/sla` | assign sla |
| GET | `/api/v1/vuln-prioritization/sla` | list sla assignments |
| GET | `/api/v1/vuln-prioritization/runs` | list runs |
| GET | `/api/v1/vuln-prioritization/stats` | get stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] James Wilson (Security Engineer) can access /api/v1/vuln-prioritization and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 46+ tests passing in `tests/test_vuln_prioritization_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 52 (est. April 28-30, 2026)

## Test Coverage
- **Test file**: `tests/test_vuln_prioritization_engine.py`
- **Tests**: 46 tests
- **Status**: Passing
