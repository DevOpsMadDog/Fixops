# UI Endpoint Coverage — 5 Newly-Wired Backend Endpoints
> Audit date: 2026-05-05 | Branch: features/intermediate-stage

## Summary: 1/5 endpoints have a real UI callsite

| Endpoint | UI callsite | Real fetch | Notes |
|---|---|---|---|
| `GET /api/v1/access-matrix/` | **None** | No | Zero grep hits across all `.ts`/`.tsx` files. Endpoint is orphaned. |
| `GET /api/v1/connectors/types` | **None** | No | Zero grep hits. `api.ts` has a `connectors` namespace but no `/connectors/types` path. Endpoint is orphaned. |
| `GET /api/v1/fail/` | `src/lib/api.ts:214-226` | **Partial** | `api.ts` defines 11 `/api/v1/fail/*` sub-routes. However, `DeceptionHub.tsx` (the only consumer at `/brain/fail/deception`) has **empty `<Suspense>` blocks** — no lazy component is mounted so none of the `api.fail.*` methods are ever called at runtime. Dead definition. |
| `GET /api/v1/vuln-intel/` | `src/pages/VulnIntelHub.tsx` (comment only) | No | Endpoint referenced only in a JSDoc comment (line 11). `VulnIntelHub.tsx` has 4 **empty `<Suspense>` blocks** — the lazy child components were never inserted. No network call fires on mount. |
| `GET /api/v1/webhooks/` | `src/lib/api.ts:489` | **Partial** | `api.ts` defines `webhooks.list()` → `GET /api/v1/webhooks/events` (sub-path, not root). `WebhookIngestionHub.tsx` has **empty `<Suspense>` blocks**. `APISecurityPage.tsx` references `/api/v1/webhooks` in a **hardcoded mock array** (line 58), not a fetch. |

## Findings detail

### access-matrix — ORPHANED
No UI file references this path in any form. Backend work has no consumer.

### connectors/types — ORPHANED
`api.ts` contains a `connectors` namespace (`list`, `get`, `create`, `delete`, `sync`) but none of the methods target `/connectors/types`. The types endpoint has no UI callsite.

### /fail/ — API CLIENT EXISTS, COMPONENT SHELL IS EMPTY
`api.ts` has a complete `fail` namespace (11 methods) wired to real `/api/v1/fail/*` sub-routes. The route `/brain/fail/deception` exists in `App.tsx` and renders `DeceptionHub`. However `DeceptionHub.tsx` lazy-imports nothing — all three `<TabsContent>` blocks contain only an empty `<Suspense fallback>`. The `api.fail.*` methods are defined but never invoked.

### /vuln-intel/ — SHELL ONLY, NO FETCH
`VulnIntelHub.tsx` at `/discover/vuln-intel` is a tab shell with four empty `<Suspense>` blocks. The endpoint appears only in a JSDoc comment. No `useQuery`, `apiFetch`, or `api.*` call exists in the file. Zero API calls fire on mount.

### /webhooks/ — SUB-PATH ONLY, SHELL EMPTY
`api.ts` calls `/api/v1/webhooks/events` (not root). `WebhookIngestionHub.tsx` shell exists but all `<TabsContent>` blocks are empty — no component renders. The `/api/v1/webhooks` string in `APISecurityPage.tsx` is a hardcoded demo string inside a static array, not a fetch.

## Action items for backend team

| Endpoint | Recommended action |
|---|---|
| `access-matrix` | Build `AccessMatrixHub` page or wire into an existing hub tab before counting as delivered. |
| `connectors/types` | Add `types: () => api.get("/api/v1/connectors/types")` to `api.ts` connectors namespace AND render it in a ConnectorsHub tab. |
| `fail/` | Insert lazy-loaded FAIL drill components into `DeceptionHub.tsx` `<TabsContent>` blocks. Methods exist in `api.ts` — just need component wiring. |
| `vuln-intel/` | Insert `VulnIntelligenceDashboard` (or equivalent) into `VulnIntelHub.tsx` tab slots. Add `vulnIntel` namespace to `api.ts`. |
| `webhooks/` | Insert `WebhookEventCatalogExplorer` and `WebhookRetryConsole` into `WebhookIngestionHub.tsx` tab slots. Align `api.ts` to call root `GET /api/v1/webhooks/` for listing. |
