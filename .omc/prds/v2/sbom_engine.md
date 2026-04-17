# US-0210: Sbom

## Sub-Epic: ASPM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Amanda Scott (Supply Chain Security)**, I need to manage software bill of materials
so that the platform delivers enterprise-grade aspm capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Sbom replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone ASPM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/sbom"]
    API --> Auth["api_key_auth"]
    Auth --> Router["sbom_router.py"]
    Router --> Engine["SBOMEngine"]
    Engine --> DB[(SQLite: {org_id}_sbom.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    SBOMEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `register_asset()` — Register a new asset for SBOM tracking. Returns the created record. (line 241)
- ✅ `list_assets()` — List all assets for an org. (line 296)
- ✅ `get_asset()` — Get asset with live component summary. (line 306)
- ✅ `add_component()` — Add a component to an asset's SBOM. Auto-generates purl if missing. (line 349)
- ✅ `list_components()` — List components with optional asset_id and has_vulns filters. (line 465)
- ✅ `generate_cyclonedx()` — Generate a CycloneDX 1.4 JSON SBOM for an asset. (line 504)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/sbom_engine.py` — 800 lines)
- `SBOMEngine.register_asset()` — Register a new asset for SBOM tracking. Returns the created record. (line 241)
- `SBOMEngine.list_assets()` — List all assets for an org. (line 296)
- `SBOMEngine.get_asset()` — Get asset with live component summary. (line 306)
- `SBOMEngine.add_component()` — Add a component to an asset's SBOM. Auto-generates purl if missing. (line 349)
- `SBOMEngine.list_components()` — List components with optional asset_id and has_vulns filters. (line 465)
- `SBOMEngine.generate_cyclonedx()` — Generate a CycloneDX 1.4 JSON SBOM for an asset. (line 504)
- `SBOMEngine.generate_spdx()` — Generate an SPDX 2.3 JSON SBOM for an asset. (line 579)
- `SBOMEngine.save_export()` — Persist an SBOM export to sbom_exports table. (line 642)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/sbom_engine.py` (800 lines)
- **Router file**: `suite-api/apps/api/sbom_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/sbom/assets` | register asset |
| GET | `/api/v1/sbom/assets` | list assets |
| GET | `/api/v1/sbom/assets/{asset_id}` | get asset |
| POST | `/api/v1/sbom/assets/{asset_id}/components` | add component |
| GET | `/api/v1/sbom/assets/{asset_id}/components` | list components |
| GET | `/api/v1/sbom/assets/{asset_id}/export/cyclonedx` | export cyclonedx |
| GET | `/api/v1/sbom/assets/{asset_id}/export/spdx` | export spdx |
| GET | `/api/v1/sbom/license-summary` | license summary |
| GET | `/api/v1/sbom/vuln-exposure` | vuln exposure |
| GET | `/api/v1/sbom/stats` | sbom stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Amanda Scott (Supply Chain Security) can access /api/v1/sbom and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 44+ tests passing in `tests/test_sbom_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 49 (est. April 25-27, 2026)

## Test Coverage
- **Test file**: `tests/test_sbom_engine.py`
- **Tests**: 44 tests
- **Status**: Passing
