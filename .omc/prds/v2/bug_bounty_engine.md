# US-0043: Bug Bounty

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Lisa Zhang (Pentester)**, I need to manage bug bounty program submissions
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Bug Bounty replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/bounty"]
    API --> Auth["api_key_auth"]
    Auth --> Router["bug_bounty_router.py"]
    Router --> Engine["BugBountyEngine"]
    Engine --> DB[(SQLite: {org_id}_bug_bounty.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    BugBountyEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `create_program()` — Create a new bug bounty program. (line 171)
- ✅ `list_programs()` — List programs, optionally filtered by status. (line 227)
- ✅ `get_program()` — Retrieve a single program with report stats. (line 240)
- ✅ `submit_report()` — Submit a new vulnerability report. (line 270)
- ✅ `list_reports()` — List reports with optional filters. (line 321)
- ✅ `get_report()` — Retrieve a single report by ID. (line 344)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/bug_bounty_engine.py` — 557 lines)
- `BugBountyEngine.create_program()` — Create a new bug bounty program. (line 171)
- `BugBountyEngine.list_programs()` — List programs, optionally filtered by status. (line 227)
- `BugBountyEngine.get_program()` — Retrieve a single program with report stats. (line 240)
- `BugBountyEngine.submit_report()` — Submit a new vulnerability report. (line 270)
- `BugBountyEngine.list_reports()` — List reports with optional filters. (line 321)
- `BugBountyEngine.get_report()` — Retrieve a single report by ID. (line 344)
- `BugBountyEngine.update_report_status()` — Update report status and optionally set payout. (line 353)
- `BugBountyEngine.add_researcher()` — Add a new researcher to the registry. (line 442)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/bug_bounty_engine.py` (557 lines)
- **Router file**: `suite-api/apps/api/bug_bounty_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/bounty/programs` | create program |
| GET | `/api/v1/bounty/programs` | list programs |
| PATCH | `/api/v1/bounty/programs/{program_id}/status` | update program status |
| POST | `/api/v1/bounty/submissions` | submit vulnerability |
| GET | `/api/v1/bounty/submissions` | list submissions |
| PATCH | `/api/v1/bounty/submissions/{submission_id}/triage` | triage submission |
| PATCH | `/api/v1/bounty/rewards/{reward_id}` | update reward |
| GET | `/api/v1/bounty/programs/{program_id}/metrics` | get program metrics |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Lisa Zhang (Pentester) can access /api/v1/bounty and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 32+ tests passing in `tests/test_bug_bounty_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 43 (est. April 19-21, 2026)

## Test Coverage
- **Test file**: `tests/test_bug_bounty_engine.py`
- **Tests**: 32 tests
- **Status**: Passing
