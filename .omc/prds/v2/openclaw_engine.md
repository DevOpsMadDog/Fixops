# US-0169: Openclaw

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Richard Adams (Security Architect)**, I need to orchestrate autonomous security agents
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Openclaw replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/openclaw"]
    API --> Auth["api_key_auth"]
    Auth --> Router["openclaw_router.py"]
    Router --> Engine["OpenClawEngine"]
    Engine --> DB[(SQLite: {org_id}_openclaw.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    OpenClawEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `create_campaign()` — Create a new pentest campaign. authorization_token is required. (line 435)
- ✅ `list_campaigns()` — implemented (line 506)
- ✅ `get_campaign()` — Return campaign dict with tasks and findings summary. (line 528)
- ✅ `start_campaign()` — Start a staged campaign: queue initial tasks and simulate execution. (line 567)
- ✅ `advance_phase()` — Advance the campaign to the next MITRE phase and queue new tasks. (line 601)
- ✅ `pause_campaign()` — Pause a running campaign. (line 638)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/openclaw_engine.py` — 1017 lines)
- `OpenClawEngine.create_campaign()` — Create a new pentest campaign. authorization_token is required. (line 435)
- `OpenClawEngine.list_campaigns()` — Handle list campaigns (line 506)
- `OpenClawEngine.get_campaign()` — Return campaign dict with tasks and findings summary. (line 528)
- `OpenClawEngine.start_campaign()` — Start a staged campaign: queue initial tasks and simulate execution. (line 567)
- `OpenClawEngine.advance_phase()` — Advance the campaign to the next MITRE phase and queue new tasks. (line 601)
- `OpenClawEngine.pause_campaign()` — Pause a running campaign. (line 638)
- `OpenClawEngine.resume_campaign()` — Resume a paused campaign. (line 654)
- `OpenClawEngine.complete_campaign()` — Complete a campaign and calculate final risk score. (line 670)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/openclaw_engine.py` (1017 lines)
- **Router file**: `suite-api/apps/api/openclaw_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/openclaw/campaigns` | list campaigns |
| POST | `/api/v1/openclaw/campaigns` | create campaign |
| GET | `/api/v1/openclaw/campaigns/{campaign_id}` | get campaign |
| POST | `/api/v1/openclaw/campaigns/{campaign_id}/start` | start campaign |
| POST | `/api/v1/openclaw/campaigns/{campaign_id}/advance` | advance phase |
| POST | `/api/v1/openclaw/campaigns/{campaign_id}/pause` | pause campaign |
| POST | `/api/v1/openclaw/campaigns/{campaign_id}/complete` | complete campaign |
| GET | `/api/v1/openclaw/campaigns/{campaign_id}/tasks` | list tasks |
| GET | `/api/v1/openclaw/findings` | list findings |
| PATCH | `/api/v1/openclaw/findings/{finding_id}/status` | update finding status |
| GET | `/api/v1/openclaw/stats` | get stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Richard Adams (Security Architect) can access /api/v1/openclaw and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 48+ tests passing in `tests/test_openclaw_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 47 (est. April 23-25, 2026)

## Test Coverage
- **Test file**: `tests/test_openclaw_engine.py`
- **Tests**: 48 tests
- **Status**: Passing
