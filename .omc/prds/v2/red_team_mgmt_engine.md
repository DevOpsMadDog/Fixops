# US-0197: Red Team Mgmt

## Sub-Epic: CTEM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Lisa Zhang (Pentester)**, I need to manage red team operations
so that the platform delivers enterprise-grade ctem capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Red Team Mgmt replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone CTEM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/red-team"]
    API --> Auth["api_key_auth"]
    Auth --> Router["red_team_mgmt_router.py"]
    Router --> Engine["RedTeamManagementEngine"]
    Engine --> DB[(SQLite: {org_id}_red_team_mgmt.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    RedTeamManagementEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `create_engagement()` — Create a new red team engagement. Returns the created record. (line 173)
- ✅ `list_engagements()` — List engagements, optionally filtered by status. (line 234)
- ✅ `get_engagement()` — Retrieve a single engagement by ID, including findings summary. (line 248)
- ✅ `update_engagement_status()` — Update engagement status. Returns updated record. (line 277)
- ✅ `add_finding()` — Add a finding to an engagement. Returns the created record. (line 300)
- ✅ `list_findings()` — List findings with optional filters. (line 357)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/red_team_mgmt_engine.py` — 548 lines)
- `RedTeamManagementEngine.create_engagement()` — Create a new red team engagement. Returns the created record. (line 173)
- `RedTeamManagementEngine.list_engagements()` — List engagements, optionally filtered by status. (line 234)
- `RedTeamManagementEngine.get_engagement()` — Retrieve a single engagement by ID, including findings summary. (line 248)
- `RedTeamManagementEngine.update_engagement_status()` — Update engagement status. Returns updated record. (line 277)
- `RedTeamManagementEngine.add_finding()` — Add a finding to an engagement. Returns the created record. (line 300)
- `RedTeamManagementEngine.list_findings()` — List findings with optional filters. (line 357)
- `RedTeamManagementEngine.add_ttp()` — Log a TTP executed during an engagement. Returns the created record. (line 381)
- `RedTeamManagementEngine.list_ttps()` — List TTPs for a specific engagement. (line 422)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/red_team_mgmt_engine.py` (548 lines)
- **Router file**: `suite-api/apps/api/red_team_mgmt_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/red-team/engagements` | list engagements |
| POST | `/api/v1/red-team/engagements` | create engagement |
| GET | `/api/v1/red-team/engagements/{engagement_id}` | get engagement |
| PATCH | `/api/v1/red-team/engagements/{engagement_id}/status` | update engagement status |
| GET | `/api/v1/red-team/engagements/{engagement_id}/findings` | list findings |
| POST | `/api/v1/red-team/engagements/{engagement_id}/findings` | add finding |
| GET | `/api/v1/red-team/engagements/{engagement_id}/ttps` | list ttps |
| POST | `/api/v1/red-team/engagements/{engagement_id}/ttps` | add ttp |
| GET | `/api/v1/red-team/operators` | list operators |
| POST | `/api/v1/red-team/operators` | add operator |
| GET | `/api/v1/red-team/stats` | get stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Lisa Zhang (Pentester) can access /api/v1/red-team and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 38+ tests passing in `tests/test_red_team_mgmt_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 48 (est. April 24-26, 2026)

## Test Coverage
- **Test file**: `tests/test_red_team_mgmt_engine.py`
- **Tests**: 38 tests
- **Status**: Passing
