# PRD — Community 392: Asset Groups Dashboard

## Master Goal Mapping
- **Platform Goal**: Logical asset grouping for policy targeting, bulk operations, and inventory management
- **Persona**: Security Engineer, Asset Manager, IT Operations
- **ALDECI Pillar**: Asset Management / Policy Targeting
- **Backend Engine**: `suite-core/core/asset_group_engine.py`

## Architecture Diagram
```mermaid
graph TD
    A[Route: /asset-groups] --> B[AssetGroupsDashboard.tsx]
    B --> C[Group Grid: group_name + group_type + criticality + member_count]
    B --> D[Member List Panel: asset_id + asset_type per group]
    B --> E[Policy List Panel: policy_name + enabled toggle]
    B --> F[Bulk Add Members Form: paste asset IDs]
    B --> G[Group Stats: criticality/type CSS bars]
    C --> H[GET /api/v1/asset-groups]
    H --> I[asset_group_engine.py]
    I --> J[INSERT OR IGNORE add_member dedup]
    I --> K[MAX(0,count-1) floor on remove]
    I --> L[8 group types]
```

## Code Proof
- **File**: `suite-ui/aldeci-ui-new/src/pages/AssetGroupsDashboard.tsx:1-80+`
- **Group types**: server, endpoint, cloud, network, application, iot (+ 2 more)
- **Criticality**: critical/high/medium/low
- **Icons**: Layers, Users, Shield, Plus, BarChart2, AlertTriangle
- **Bulk add**: textarea paste of asset IDs (newline or comma separated)

## Inter-Dependencies
- **Backend**: `asset_group_engine.py` — 31 tests, INSERT OR IGNORE dedup, rowcount-gated counter
- **Router**: `/api/v1/asset-groups`
- **Related**: AssetCriticality, AssetTagging, PolicyEnforcement

## Data Flow
```
GET /api/v1/asset-groups → group grid →
Select group → members list + policies list filter by group_id →
Bulk add form → POST /asset-groups/{id}/members →
INSERT OR IGNORE prevents duplicates → member_count increments
```

## Acceptance Criteria
- [ ] Group grid shows type badge and criticality color
- [ ] member_count pill updates after bulk add
- [ ] Policy enable/disable toggle fires PUT request
- [ ] Bulk add form handles newline and comma delimiters
- [ ] Stats CSS bars show breakdown by criticality and type
- [ ] Largest group label displayed

## Effort Estimate
**M** — 2 days (complete)

## Status
**DONE** — Production dashboard
