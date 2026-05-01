# AssetInventoryHub — Phase 3 cluster S9 finish (2026-05-02)

## Source pages folded
| Tab | Source page | Endpoint(s) |
|-----|-------------|-------------|
| `groups` | `AssetGroupsDashboard.tsx` | `GET /api/v1/asset-groups/groups` |
| `tags` | `AssetTagsDashboard.tsx` | `GET /api/v1/asset-tags/tags`, `GET /api/v1/asset-tags/stats` |
| `criticality` | `AssetCriticalityDashboard.tsx` | `GET /api/v1/asset-criticality/*` |

## Routes
- **Canonical**: `/discover/assets/inventory` -> `<AssetInventoryHub />`
- **Redirects**:
  - `/asset-groups` -> `/discover/assets/inventory?tab=groups`
  - `/asset-tags` -> `/discover/assets/inventory?tab=tags`
  - `/asset-criticality` -> `/discover/assets/inventory?tab=criticality`

## Files touched
- `suite-ui/aldeci-ui-new/src/App.tsx` — lazy import + canonical route + 3 redirects
- `suite-ui/aldeci-ui-new/src/pages/AssetGroupsDashboard.tsx` — `// FOLDED ...` marker
- `suite-ui/aldeci-ui-new/src/pages/AssetTagsDashboard.tsx` — `// FOLDED ...` marker
- `suite-ui/aldeci-ui-new/src/pages/AssetCriticalityDashboard.tsx` — `// FOLDED ...` marker
- `docs/ui-snapshots/ux-consolidation-asset-inventory-2026-05-02.png`

## Verification (Playwright, :5173)
- Hub default lands `?tab=groups` — TabsList shows Groups/Tags/Criticality
- Redirects: `/asset-tags`, `/asset-criticality`, `/asset-groups` all land on hub with the right `?tab=`
- 16 real `/api/v1/*` calls fired (asset-groups, asset-tags/tags, asset-tags/stats, asset-criticality/*)
- Zero mock signatures — body text contains no `MOCK_`, `lorem`, `Acme Corp`, `John Doe`, `demo-org`
- Console errors are pre-existing (401 from headless no-auth + unique-key warning in `AssetGroupsDashboard`); NOT introduced by this fold
- Sibling preserved: `/assets` (`AssetGraphHero` -> `AssetInventory.tsx`) is the listing hero, untouched

## Persona target
- Asset Owner (#15)
- GRC Analyst (#12)
- Platform Eng (#16)

## Phase 3 plan reference
`docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` §2.9 (S9 Inventory — Asset metadata sub-cluster).
