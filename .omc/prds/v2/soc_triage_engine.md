# US-0270: Soc Triage

## Sub-Epic: SOC
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Alex Rivera (SOC T1 Analyst)**, I need to manage SOC workflow and triage
so that the platform delivers enterprise-grade soc capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Soc Triage replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone SOC tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/soc-triage"]
    API --> Auth["api_key_auth"]
    Auth --> Router["soc_triage_router.py"]
    Router --> Engine["SOCTriageEngine"]
    Engine --> DB[(SQLite: {org_id}_soc_triage.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    SOCTriageEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `for_org()` — Return (or create) the singleton engine for org_id. (line 89)
- ✅ `ingest_alert()` — Ingest an alert, run AI triage, persist, and return the alert dict. (line 301)
- ✅ `list_alerts()` — Return filtered alerts ordered by priority_rank ASC, created_at DESC. (line 413)
- ✅ `get_alert()` — Return a single alert with full context. (line 438)
- ✅ `update_verdict()` — Analyst confirms or disputes the AI verdict. (line 451)
- ✅ `create_rule()` — Create a triage rule. (line 485)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/soc_triage_engine.py` — 742 lines)
- `SOCTriageEngine.for_org()` — Return (or create) the singleton engine for org_id. (line 89)
- `SOCTriageEngine.ingest_alert()` — Ingest an alert, run AI triage, persist, and return the alert dict. (line 301)
- `SOCTriageEngine.list_alerts()` — Return filtered alerts ordered by priority_rank ASC, created_at DESC. (line 413)
- `SOCTriageEngine.get_alert()` — Return a single alert with full context. (line 438)
- `SOCTriageEngine.update_verdict()` — Analyst confirms or disputes the AI verdict. (line 451)
- `SOCTriageEngine.create_rule()` — Create a triage rule. (line 485)
- `SOCTriageEngine.list_rules()` — List all rules for org_id. (line 522)
- `SOCTriageEngine.apply_rules()` — Evaluate all enabled rules against the alert. Returns matching rules. (line 540)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/soc_triage_engine.py` (742 lines)
- **Router file**: `suite-api/apps/api/soc_triage_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/soc-triage/alerts` | ingest alert |
| GET | `/api/v1/soc-triage/alerts` | list alerts |
| GET | `/api/v1/soc-triage/alerts/{alert_id}` | get alert |
| POST | `/api/v1/soc-triage/alerts/{alert_id}/verdict` | update verdict |
| GET | `/api/v1/soc-triage/stats` | get triage stats |
| GET | `/api/v1/soc-triage/metrics` | get daily metrics |
| POST | `/api/v1/soc-triage/rules` | create rule |
| GET | `/api/v1/soc-triage/rules` | list rules |
| POST | `/api/v1/soc-triage/sessions` | start session |
| POST | `/api/v1/soc-triage/sessions/{session_id}/close` | close session |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Alex Rivera (SOC T1 Analyst) can access /api/v1/soc-triage and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 57+ tests passing in `tests/test_soc_triage_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 51 (est. April 27-29, 2026)

## Test Coverage
- **Test file**: `tests/test_soc_triage_engine.py`
- **Tests**: 57 tests
- **Status**: Passing
