# US-0318: Vuln Workflow

## Sub-Epic: CTEM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **James Wilson (Security Engineer)**, I need to manage vulnerability workflows
so that the platform delivers enterprise-grade ctem capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Vuln Workflow replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone CTEM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/vuln-workflow"]
    API --> Auth["api_key_auth"]
    Auth --> Router["vuln_workflow_router.py"]
    Router --> Engine["VulnWorkflowEngine"]
    Engine --> DB[(SQLite: {org_id}_vuln_workflow.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    VulnWorkflowEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `for_org()` — implemented (line 112)
- ✅ `create_ticket()` — Create a vuln ticket, auto-setting due_date from SLA config. (line 234)
- ✅ `list_tickets()` — List tickets with optional filters. Adds overdue flag to each. (line 306)
- ✅ `get_ticket()` — Return ticket with comments list. (line 346)
- ✅ `update_ticket()` — Update ticket fields. Logs a status_change comment on status transitions. (line 369)
- ✅ `add_comment()` — Add a comment to a ticket. (line 469)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/vuln_workflow_engine.py` — 818 lines)
- `VulnWorkflowEngine.for_org()` — Handle for org (line 112)
- `VulnWorkflowEngine.create_ticket()` — Create a vuln ticket, auto-setting due_date from SLA config. (line 234)
- `VulnWorkflowEngine.list_tickets()` — List tickets with optional filters. Adds overdue flag to each. (line 306)
- `VulnWorkflowEngine.get_ticket()` — Return ticket with comments list. (line 346)
- `VulnWorkflowEngine.update_ticket()` — Update ticket fields. Logs a status_change comment on status transitions. (line 369)
- `VulnWorkflowEngine.add_comment()` — Add a comment to a ticket. (line 469)
- `VulnWorkflowEngine.assign_ticket()` — Reassign a ticket and log an assignment comment. (line 487)
- `VulnWorkflowEngine.bulk_assign()` — Bulk reassign a list of tickets. (line 524)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/vuln_workflow_engine.py` (818 lines)
- **Router file**: `suite-api/apps/api/vuln_workflow_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/vuln-workflow/tickets` | create ticket |
| GET | `/api/v1/vuln-workflow/tickets` | list tickets |
| GET | `/api/v1/vuln-workflow/tickets/{ticket_id}` | get ticket |
| PATCH | `/api/v1/vuln-workflow/tickets/{ticket_id}` | update ticket |
| POST | `/api/v1/vuln-workflow/tickets/{ticket_id}/comments` | add comment |
| POST | `/api/v1/vuln-workflow/tickets/{ticket_id}/assign` | assign ticket |
| POST | `/api/v1/vuln-workflow/tickets/{ticket_id}/accept-risk` | accept risk |
| POST | `/api/v1/vuln-workflow/tickets/bulk-assign` | bulk assign |
| POST | `/api/v1/vuln-workflow/tickets/bulk-close` | bulk close |
| GET | `/api/v1/vuln-workflow/sla` | get sla config |
| POST | `/api/v1/vuln-workflow/sla` | set sla config |
| GET | `/api/v1/vuln-workflow/stats` | get workflow stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] James Wilson (Security Engineer) can access /api/v1/vuln-workflow and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 43+ tests passing in `tests/test_vuln_workflow_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 52 (est. April 28-30, 2026)

## Test Coverage
- **Test file**: `tests/test_vuln_workflow_engine.py`
- **Tests**: 43 tests
- **Status**: Passing
