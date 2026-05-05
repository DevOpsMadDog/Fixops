# UI Wire Smoke Verify — 7 Newly-Consumed Endpoints
_Date: 2026-05-05 | Branch: features/intermediate-stage_

## Build Status
Production build: **CLEAN** — `✓ built in 2.85s` (zero TypeScript errors, zero warnings)

## Wire Verification Table

| Endpoint | UI Component | apiFetch / useQuery call | Mock shadow | Status |
|---|---|---|---|---|
| `/api/v1/access-matrix/` | `IdentityGovernanceHub` → `AccessMatrixPanel` | `accessMatrixApi.index()` + `accessMatrixApi.matrix()` via `Promise.allSettled` in `useEffect` | None | **REAL** |
| `/api/v1/connectors/types` | `settings/Marketplace` → `ConnectorTypesCatalog` | `connectorsApi.types()` via `useQuery({ queryKey: ["connector-types"] })` | None (`COMMUNITY_PLAYBOOKS_EMPTY = []` is a typed default, not a data shadow) | **REAL** |
| `/api/v1/fail/` | `DeceptionHub` → `FAILStatsPanel` | `failApi.stats("default")` via `useEffect` | None | **REAL** |
| `/api/v1/vuln-intel/` | `VulnIntelHub` → `VulnIntelOverview` | `vulnIntelApi.index("default")` via `useQuery({ queryKey: ["vuln-intel","index"] })` | None | **REAL** |
| `/api/v1/webhooks/` | `WebhookIngestionHub` → `WebhookEventsTable` | `webhooksApi.list({ org_id, limit: 100 })` via `useEffect` + `useCallback` | None | **REAL** |
| `/api/v1/audit/` | `AuditLog` | `auditApi.recentLogs(100)` via `useEffect` (`load` callback) | None | **REAL** |
| `/api/v1/incidents/` | `IncidentResponse` | `incidentsApi.list({ limit: 100 })` via `useEffect` | None — `mapApiIncident` is a shape-normaliser, not a data fixture | **REAL** |

**Result: 7/7 REAL — zero mock shadows detected**

## Notes

- **IdentityGovernanceHub**: The hub shell itself has no API import; the real call lives in the delegated `AccessMatrixPanel` component (correct pattern — hub is a tab router only). The `governance`, `analytics`, and `digital` tab slots have empty `<Suspense>` bodies (tabs not yet filled), but the `access-matrix` tab that was specifically wired is fully live.
- **Marketplace / Connector Types**: `COMMUNITY_PLAYBOOKS_EMPTY = []` is a typed empty array used as a fallback when the marketplace API returns no items — it is not a hardcoded data source. The real data path is `marketplaceApi.browse()` + `marketplaceBrowseQuery.data`.
- **DeceptionHub**: Hub shell delegates to `FAILStatsPanel`; the `analytics` and `decoys` tabs have empty `<Suspense>` bodies (same pattern as above — not wired yet, but the primary `engine` tab is live).
- **WebhookIngestionHub**: `catalogue` tab is live via `WebhookEventsTable`; `retry` and `dry-run` tabs have empty `<Suspense>` bodies (not in scope for this session's wire task).
- **IncidentResponse**: `mapApiIncident` is a pure shape-normaliser that maps raw API fields to the local `Incident` type. No hardcoded fixture data; the component renders `EmptyState` if the API returns zero items.

## Critical Fakes
**None detected.**

All 7 endpoints are wired to real `apiFetch`/`useQuery`/`useEffect` calls against the corresponding `/api/v1/...` routes. No component imports from `src/data/`, `src/fixtures/`, or any file with a `MOCK_` prefix.
