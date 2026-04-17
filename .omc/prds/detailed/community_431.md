# PRD — Community 431: Connector Marketplace Page (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Discovery and installation of security tool integrations — connectors, scanners, threat feeds
- **Persona**: Security Engineer, IT Admin configuring ALDECI integrations
- **ALDECI Pillar**: Connector Framework / Marketplace (Legacy)

## Architecture Diagram
```mermaid
graph TD
    A[Route: /settings/marketplace] --> B[Marketplace.tsx]
    B --> C[useQuery: api integrations list]
    B --> D[Search bar + category filter - useMemo]
    B --> E[Integration cards: name/category/stars/installed]
    B --> F[Install mutation: useMutation]
    B --> G[Download/Package/Star/Check icons]
    C --> H[GET /api/v1/integrations]
    F --> I[POST /api/v1/integrations/{id}/install]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/pages/settings/Marketplace.tsx:1-60+`
- **Hooks**: useState, useMemo (filtered list), useQuery, useMutation
- **Icons**: Store, Search, Download, Package, Star, Shield, Zap, Check
- **API**: `api` from `../../lib/api`
- **Filter**: useMemo search + category filter on integration list

## Inter-Dependencies
- **Backend**: Connector registry, 13 PULL + 7 bidi connectors
- **API**: `/api/v1/integrations`
- **Related**: DataFabric (shows installed connectors)

## Data Flow
```
GET /api/v1/integrations → useMemo filtered by search + category →
Integration cards rendered → Install button → useMutation →
toast.success on install → Check icon replaces Download icon
```

## Acceptance Criteria
- [ ] Search filters integration list in real-time (useMemo)
- [ ] Category filter (scanners/feeds/SIEM/cloud/etc.)
- [ ] Install button → optimistic Check icon
- [ ] Star rating displayed
- [ ] Shield/Zap icons for security/automation category badges

## Effort Estimate
**M** — 2 days (complete, frozen)

## Status
**DONE** — Frozen legacy marketplace
