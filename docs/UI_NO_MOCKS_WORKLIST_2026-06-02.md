# UI NO-MOCKS Worklist — 2026-06-02

Per CLAUDE.md NO-MOCKS rule: every UI page must render real-tenant `/api/v1/...` data or a real
branded EmptyState — never fabricated/sample data. Scan of `suite-ui/aldeci-ui-new/src` found a
**systemic** mock-fallback plus two pages. No `src/data|fixtures|mocks` dirs (good).

## Findings (real violations)
### 1. SYSTEMIC — `src/lib/api-hooks.ts` (highest priority, drives many pages)
`useApiData(..., fallback: T)` does `catch (err) { setData(fallback) }` (≈line 161-169). Every hook
passes a `MOCK_*` constant as the fallback (MOCK_FINDINGS, MOCK_POSTURE, MOCK_COMPLIANCE, MOCK_SLA,
MOCK_ATTACK_SURFACE, MOCK_INCIDENTS, MOCK_VENDORS, MOCK_INTEGRATION_HEALTH, MOCK_METRICS,
MOCK_THREAT_HUNTING). => **on API failure the user is silently shown fabricated security data.**
FIX: on error, do NOT substitute mock data — set an error/empty state and let consumers render a
branded EmptyState/error. Either (a) pass honest EMPTY-shaped fallbacks (items:[], total:0, scores 0)
so consumers don't crash AND no fabricated numbers, plus surface `error`; or (b) audit each consumer
to handle null and remove the fallback param. (a) is the safer first step; (b) is the clean end-state.
VERIFY: each consumer page still renders (no null crash) and shows empty/error, not fake numbers.

### 2. `src/pages/comply/ComplianceDashboard.tsx`
`MOCK_FRAMEWORKS`/`MOCK_EVIDENCE_ITEMS`/`MOCK_CONTROLS` consts; line ≈924 `... : MOCK_FRAMEWORKS`
(falls back to mock when the query has no data). FIX: use `frameworksQuery.data ?? []` + branded
EmptyState; drop the MOCK_* consts. (Already uses react-query — good; just remove the mock fallback.)

### 3. `src/pages/attack-surface/AttackSurface.tsx`
- line ≈574 `useState<Asset[]>(MOCK_ASSETS)` initial + line ≈604 keeps MOCK_ASSETS as fallback after
  the real `fetch('/api/v1/asm/assets')`.
- line ≈635 `MOCK_PATHS.filter(...)` for the "high risk paths" metric — **always mock, ignores API**.
- `MOCK_CHANGES` similarly.
FIX: initial state `[]`; on fetch fail → empty + error banner (not mock); wire real endpoints for
exposure paths + recent changes (check suite-api for `/api/v1/asm/...` paths/changes endpoints) or
EmptyState; remove MOCK_PATHS/MOCK_CHANGES from displayed metrics.

## Not violations
- `src/assets/docs/sales/POC_PLAYBOOK.md` — sales doc, not code.
- `src/pages/comply/__tests__/ComplianceDashboard.test.tsx` — test file (mocks OK in tests).

## Gate
`npm run build` requires `npm install` first (node_modules was partial — vite missing; install launched
2026-06-02). After each fix: `npm run build` passes; if dev server + Playwright MCP available,
navigate→screenshot→confirm a real /api/v1 call fires on mount and no mock signatures in the DOM.

## Order
1) api-hooks.ts systemic fallback (biggest blast radius) → 2) ComplianceDashboard → 3) AttackSurface.
Each is one verified increment (build + consumer-renders check), committed separately.
