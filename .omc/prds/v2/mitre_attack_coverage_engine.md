# US-0154: Mitre Attack Coverage

## Sub-Epic: Advanced
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Richard Adams (Security Architect)**, I need to map coverage to MITRE ATT&CK
so that the platform delivers enterprise-grade advanced capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Mitre Attack Coverage replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone Advanced tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/mitre-attack-coverage"]
    API --> Auth["api_key_auth"]
    Auth --> Router["mitre_attack_coverage_router.py"]
    Router --> Engine["MITREAttackCoverageEngine"]
    Engine --> DB[(SQLite: {safe}_mitre_attack.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    MITREAttackCoverageEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 85% Complete
- ✅ `seed_att_ck_techniques()` — Seed the 14 MITRE ATT&CK tactics and all known techniques. (line 261)
- ✅ `add_technique()` — Register a custom MITRE ATT&CK technique. (line 291)
- ✅ `log_detection()` — Log a detection event for a MITRE ATT&CK technique. (line 341)
- ✅ `get_coverage()` — Get overall ATT&CK coverage percentage and per-tactic breakdown. (line 388)
- ✅ `get_gaps()` — Get undetected or low-coverage techniques (critical gaps). (line 476)
- ✅ `get_heatmap()` — Get heatmap data: technique → detection count per tactic. (line 530)
- ❌ No dedicated router — endpoint may be in gap_router.py
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/mitre_attack_coverage_engine.py` — 678 lines)
- `MITREAttackCoverageEngine.seed_att_ck_techniques()` — Seed the 14 MITRE ATT&CK tactics and all known techniques. (line 261)
- `MITREAttackCoverageEngine.add_technique()` — Register a custom MITRE ATT&CK technique. (line 291)
- `MITREAttackCoverageEngine.log_detection()` — Log a detection event for a MITRE ATT&CK technique. (line 341)
- `MITREAttackCoverageEngine.get_coverage()` — Get overall ATT&CK coverage percentage and per-tactic breakdown. (line 388)
- `MITREAttackCoverageEngine.get_gaps()` — Get undetected or low-coverage techniques (critical gaps). (line 476)
- `MITREAttackCoverageEngine.get_heatmap()` — Get heatmap data: technique → detection count per tactic. (line 530)
- `MITREAttackCoverageEngine.get_techniques()` — List all techniques registered for the org. (line 609)
- `MITREAttackCoverageEngine.get_detections()` — List detection events for the org, optionally filtered by technique. (line 629)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/mitre_attack_coverage_engine.py` (678 lines)
- **Router file**: `suite-api/apps/api/N/A`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/mitre-attack-coverage` | List resources |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Create dedicated router (needs wiring in app.py) (3h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Richard Adams (Security Architect) can access /api/v1/mitre-attack-coverage and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 45+ tests passing in `tests/test_mitre_attack_coverage_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 47 (est. April 23-25, 2026)

## Test Coverage
- **Test file**: `tests/test_mitre_attack_coverage_engine.py`
- **Tests**: 45 tests
- **Status**: Passing
