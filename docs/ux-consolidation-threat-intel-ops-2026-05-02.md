# Phase 3 UX Consolidation — Threat Intel Operations Hub

**Date:** 2026-05-02
**Cluster:** §2.14 — Threat Intel Operations (combined 4-page pair)
**Plan reference:** `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md`
**Hub route:** `/attack/intel/ops`
**Hub component:** `src/pages/ThreatIntelOpsHub.tsx`

## Goal

Collapse four standalone threat-intel operations dashboards into a single tabbed hero so analysts work one console for watchlist + feeds + briefs + response, instead of context-switching across four sidebar entries.

## Tab map

| Tab | Source page | Backing endpoints |
|-----|-------------|-------------------|
| `watchlist` | `WatchlistManager` | `/api/v1/ioc-enrichment/stats`, `/api/v1/ioc-enrichment/iocs`, `/api/v1/threat-actors` |
| `feeds` | `FeedSubscriptionsDashboard` | `/api/v1/feed-subscriptions/subscriptions` |
| `briefs` | `ThreatBriefDashboard` | `/api/v1/threat-briefs` |
| `response` | `ThreatResponseDashboard` | `/api/v1/threat-response/incidents/active`, `/api/v1/threat-response/playbooks` |

## Routing

- `GET /attack/intel/ops` → renders hub (default tab `watchlist`)
- `GET /attack/intel/ops?tab=<key>` → deep-link, sync via `useSearchParams`
- `GET /watchlist` → 302 redirect → `/attack/intel/ops?tab=watchlist`
- `GET /feed-subscriptions` → 302 → `/attack/intel/ops?tab=feeds`
- `GET /threat-briefs` → 302 → `/attack/intel/ops?tab=briefs`
- `GET /threat-response` → 302 → `/attack/intel/ops?tab=response`

## Behavior preserved

Each tab lazy-imports the original page component (`React.lazy`) wrapped in `Suspense` with `PageSkeleton` fallback. Source pages keep their `useEffect`/`apiFetch` calls, loading/error/empty states and form interactions — no functionality removed.

## NO MOCKS verification

- Dev server: `http://localhost:5173`
- Playwright `domcontentloaded` + 4s settle
- DOM mock-signature scan: **0 hits** (`MOCK_`, `lorem ipsum`, `Acme Corp`, `John Doe`)
- Real `/api/v1/*` requests fired on mount: **7** (ioc-enrichment/stats, ioc-enrichment/iocs, threat-actors, alert-triage/alerts)
- 401/403 console errors are expected (unauth dev session) — confirms real API wiring, not stubs
- Screenshot: `docs/ui-snapshots/ux-consolidation-threat-intel-ops-2026-05-02.png`

## Personas served

Threat Intel Analyst (#9), SOC Analyst (#7), Incident Response Lead (#10), CISO (#1).

## Risk

- Old bookmarks for `/watchlist|/feed-subscriptions|/threat-briefs|/threat-response` continue to work via the redirect routes.
- Sidebar/menu entries that pointed at the 4 old routes now hit the redirect; users land on the correct tab automatically.
