# US-0313: Vuln Intelligence

## Sub-Epic: CTEM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Nina Patel (Threat Intel Analyst)**, I need to fuse vulnerability intelligence
so that the platform delivers enterprise-grade ctem capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Vuln Intelligence replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone CTEM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/vuln-intel"]
    API --> Auth["api_key_auth"]
    Auth --> Router["vuln_intelligence_router.py"]
    Router --> Engine["VulnIntelligenceEngine"]
    Engine --> DB[(SQLite: {safe}_vuln_intel.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    VulnIntelligenceEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `add_cve()` — Add or update CVE intelligence. Upserts on (org_id, cve_id). (line 201)
- ✅ `list_cves()` — List CVEs with optional filters. (line 303)
- ✅ `get_cve()` — Get a single CVE by CVE-ID with full details. (line 332)
- ✅ `update_cve_status()` — Update CVE status. Returns True if found and updated. (line 341)
- ✅ `add_advisory()` — Add a vendor advisory. (line 363)
- ✅ `list_advisories()` — List vendor advisories with optional filters. (line 405)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/vuln_intelligence_engine.py` — 568 lines)
- `VulnIntelligenceEngine.add_cve()` — Add or update CVE intelligence. Upserts on (org_id, cve_id). (line 201)
- `VulnIntelligenceEngine.list_cves()` — List CVEs with optional filters. (line 303)
- `VulnIntelligenceEngine.get_cve()` — Get a single CVE by CVE-ID with full details. (line 332)
- `VulnIntelligenceEngine.update_cve_status()` — Update CVE status. Returns True if found and updated. (line 341)
- `VulnIntelligenceEngine.add_advisory()` — Add a vendor advisory. (line 363)
- `VulnIntelligenceEngine.list_advisories()` — List vendor advisories with optional filters. (line 405)
- `VulnIntelligenceEngine.apply_advisory()` — Mark an advisory as applied. Returns True if found. (line 424)
- `VulnIntelligenceEngine.add_subscription()` — Add an intel subscription. (line 439)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/vuln_intelligence_engine.py` (568 lines)
- **Router file**: `suite-api/apps/api/vuln_intelligence_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/vuln-intel/cves` | add cve |
| GET | `/api/v1/vuln-intel/cves` | list cves |
| GET | `/api/v1/vuln-intel/cves/{cve_id}` | get cve |
| PATCH | `/api/v1/vuln-intel/cves/{cve_id}/status` | update cve status |
| POST | `/api/v1/vuln-intel/advisories` | add advisory |
| GET | `/api/v1/vuln-intel/advisories` | list advisories |
| POST | `/api/v1/vuln-intel/advisories/{advisory_id}/apply` | apply advisory |
| POST | `/api/v1/vuln-intel/subscriptions` | add subscription |
| GET | `/api/v1/vuln-intel/subscriptions` | list subscriptions |
| GET | `/api/v1/vuln-intel/stats` | get intel stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Nina Patel (Threat Intel Analyst) can access /api/v1/vuln-intel and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 38+ tests passing in `tests/test_vuln_intelligence_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 52 (est. April 28-30, 2026)

## Test Coverage
- **Test file**: `tests/test_vuln_intelligence_engine.py`
- **Tests**: 38 tests
- **Status**: Passing
