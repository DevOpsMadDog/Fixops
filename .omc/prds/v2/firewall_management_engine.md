# US-0115: Firewall Management

## Sub-Epic: Network
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **James Wilson (Security Engineer)**, I need to manage firewall rules and policies
so that the platform delivers enterprise-grade network capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Firewall Management replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Network tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/firewall-mgmt"]
    API --> Auth["api_key_auth"]
    Auth --> Router["firewall_management_router.py"]
    Router --> Engine["FirewallManagementEngine"]
    Engine --> DB[(SQLite: {org_id}_firewall_mgmt.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    FirewallManagementEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `add_firewall()` — Register a new firewall. (line 238)
- ✅ `list_firewalls()` — List firewalls, optionally filtered by status. (line 289)
- ✅ `get_firewall()` — Get a single firewall by ID. (line 303)
- ✅ `add_rule()` — Create a firewall rule. Automatically calculates risk_level. (line 317)
- ✅ `list_rules()` — List firewall rules with optional filters. (line 383)
- ✅ `disable_rule()` — Disable a firewall rule. Returns True if found. (line 407)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/firewall_management_engine.py` — 800 lines)
- `FirewallManagementEngine.add_firewall()` — Register a new firewall. (line 238)
- `FirewallManagementEngine.list_firewalls()` — List firewalls, optionally filtered by status. (line 289)
- `FirewallManagementEngine.get_firewall()` — Get a single firewall by ID. (line 303)
- `FirewallManagementEngine.add_rule()` — Create a firewall rule. Automatically calculates risk_level. (line 317)
- `FirewallManagementEngine.list_rules()` — List firewall rules with optional filters. (line 383)
- `FirewallManagementEngine.disable_rule()` — Disable a firewall rule. Returns True if found. (line 407)
- `FirewallManagementEngine.detect_shadowed_rules()` — Detect rules shadowed by earlier higher-priority (lower-index) rules. (line 418)
- `FirewallManagementEngine.create_change_request()` — Create a firewall rule change request. (line 464)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/firewall_management_engine.py` (800 lines)
- **Router file**: `suite-api/apps/api/firewall_management_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/firewall-mgmt/firewalls` | add firewall |
| GET | `/api/v1/firewall-mgmt/firewalls` | list firewalls |
| GET | `/api/v1/firewall-mgmt/firewalls/{firewall_id}` | get firewall |
| POST | `/api/v1/firewall-mgmt/firewalls/{firewall_id}/rules` | add rule |
| GET | `/api/v1/firewall-mgmt/rules` | list rules |
| POST | `/api/v1/firewall-mgmt/rules/{rule_id}/disable` | disable rule |
| POST | `/api/v1/firewall-mgmt/firewalls/{firewall_id}/detect-shadows` | detect shadowed rules |
| POST | `/api/v1/firewall-mgmt/change-requests` | create change request |
| GET | `/api/v1/firewall-mgmt/change-requests` | list change requests |
| POST | `/api/v1/firewall-mgmt/change-requests/{request_id}/approve` | approve change request |
| POST | `/api/v1/firewall-mgmt/change-requests/{request_id}/reject` | reject change request |
| POST | `/api/v1/firewall-mgmt/change-requests/{request_id}/implement` | implement change request |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] James Wilson (Security Engineer) can access /api/v1/firewall-mgmt and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 51+ tests passing in `tests/test_firewall_management_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 45 (est. April 21-23, 2026)

## Test Coverage
- **Test file**: `tests/test_firewall_management_engine.py`
- **Tests**: 51 tests
- **Status**: Passing
