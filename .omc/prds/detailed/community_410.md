# PRD — Community 410: Breadcrumbs Navigation Component (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Contextual navigation trail showing current location in the deeply nested ALDECI route structure
- **Persona**: All users — critical UX element in a platform with 100+ routes
- **ALDECI Pillar**: Navigation / UX (Legacy)

## Architecture Diagram
```mermaid
graph TD
    A[MainLayout] --> B[Breadcrumbs.tsx]
    B --> C[useLocation - current path]
    B --> D[useNavigate - click navigation]
    B --> E[routeLabels map: /path → label]
    B --> F[path.split('/') → segments]
    F --> G[Home icon → / link]
    F --> H[ChevronRight separator]
    F --> I[segment labels from routeLabels]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/components/Breadcrumbs.tsx:1-50+`
- **routeLabels**: 30+ route-to-label mappings covering all major sections
- **Sections mapped**: /, /dashboard, /executive, /nerve-center, /ingest, /intelligence, /code/*, /cloud/*, /attack/*, /evidence/*, /protect/*, /discover/*, /settings
- **Icons**: `ChevronRight`, `Home` from lucide-react

## Inter-Dependencies
- **Upstream**: `react-router-dom` (useLocation, useNavigate)
- **Downstream**: MainLayout renders Breadcrumbs in header area
- **routeLabels**: Must be kept in sync with App.tsx route definitions

## Data Flow
```
useLocation().pathname → split on '/' → map segments →
routeLabels[segment] → human label →
render Home > Section > Page chain →
each segment clickable → useNavigate
```

## Acceptance Criteria
- [ ] All 30+ routes have human-readable labels
- [ ] Home icon as first crumb
- [ ] ChevronRight between each segment
- [ ] Clicking segment navigates to that level
- [ ] Current page (last segment) non-clickable or dimmed
- [ ] Unknown routes fallback to path segment

## Effort Estimate
**S** — 1 day (complete, frozen)

## Status
**DONE** — Stable navigation component
