# Frontend Craftsman -- Persistent Memory

## Project Structure
- Legacy UI: `suite-ui/aldeci/` (React + Vite + TypeScript, has real components)
- New UI target: `suite-ui/aldeci-ui-new/` (not yet populated as of 2026-02-27)
- API client: `suite-ui/aldeci/src/lib/api.ts` -- axios-based, uses `api.get()` / `api.post()`
- UI components: `@/components/ui/` has Card, Badge, Button, Input, Tabs, Progress, Textarea (shadcn-style)

## Key Patterns in Codebase
- Dark theme first: bg-gray-900/80, border-gray-600/30, text-gray-200
- Glass-card effect: `bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80`
- Standard card: `border-gray-700/30 bg-gray-900/40 backdrop-blur-md`
- Animation: framer-motion with Apple ease `[0.16, 1, 0.3, 1]` (ease-out-expo)
- Spring animations: `{ type: 'spring', stiffness: 200, damping: 22 }`
- Container stagger: `{ staggerChildren: 0.05 }`, item: `{ opacity: 0, y: 12 } -> { opacity: 1, y: 0 }`
- Animated counters: `AnimatedNumber` component using `useMotionValue` + `animate`
- Priority colors: critical=red, high=orange, medium=yellow, low=blue, info=cyan
- Status colors: open=red, triaging=yellow, fixing=blue, resolved=green
- Severity badge pattern: `bg-{color}-500/20 text-{color}-400 border-{color}-500/30`

## API Import Pattern (IMPORTANT)
- **Use named exports** for new pages: `import { reportsApi } from '../../lib/api'`
- **Named exports available**: reportsApi, auditApi, workflowsApi, sastApi, dastApi, secretsApi, containerScanApi, cspmScanApi, scannerIngestApi, sandboxApi, failApi, feedsApi, remediationApi
- **Raw axios instance**: `import { api } from '../../lib/api'` for custom endpoints
- **Default export** is an object with namespaced methods -- less type-safe, avoid in new code
- Response key pattern: most list endpoints return `data?.items || data`

## Scanner API Signatures (verified)
- `sastApi.scanCode(code: string, filename?: string)` -- NOT an object
- `secretsApi.scanContent(content: string)` -- NOT an object
- `cspmScanApi.scanTerraform({ content: string, filename?: string })` -- IS an object
- `cspmScanApi.scanCloudFormation({ content: string, filename?: string })` -- IS an object
- Scanner status endpoints: `/api/v1/{sast|dast|secrets|container|cspm}/status`

## API Endpoints Used
- `/api/v1/cases` -- list exposure cases (params: org_id, priority)
- `/api/v1/cases/stats/summary` -- case stats (total, by_status, by_priority, avg_risk_score)
- `/api/v1/analytics/triage-funnel` -- pipeline reduction funnel
- `/api/v1/cases/{id}/transition` -- POST to transition case status
- `/api/v1/fail/score` -- FAIL engine scoring
- `/api/v1/reports` -- list/generate reports (response: data?.items)
- `/api/v1/audit/logs` -- audit logs with integrity verification
- `/api/v1/workflows` -- CRUD workflows (response: data?.items)
- `/api/v1/remediation/tasks` -- remediation task list
- `/api/v1/feeds/epss` -- EPSS vulnerability scores
- `/api/v1/feeds/kev` -- CISA KEV entries
- `/api/v1/feeds/health` -- feed health status

## Page Status (as of 2026-03-01)
### Production Quality (wired to real APIs)
- Dashboard.tsx (472 LOC) ✅
- EvidenceBundles.tsx (~400 LOC) ✅
- AutoFixDashboard.tsx (249 LOC) ✅
- CodeScanning.tsx (~500 LOC) ✅
- Integrations.tsx ✅
- IntegrationsSettings.tsx ✅
- ExposureCaseCenter.tsx ✅
- AttackPathGraph.tsx ✅
- Reports.tsx (~280 LOC) ✅ -- rewritten 2026-03-01
- AuditLogs.tsx (~260 LOC) ✅ -- rewritten 2026-03-01
- Workflows.tsx (~350 LOC) ✅ -- rewritten 2026-03-01
- Remediation.tsx (~320 LOC) ✅ -- rewritten 2026-03-01
- IaCScanning.tsx (~240 LOC) ✅ -- rewritten 2026-03-01
- ThreatFeeds.tsx (~270 LOC) ✅ -- rewritten 2026-03-01
- ScannerDashboard.tsx (~380 LOC) ✅ -- NEW 2026-03-01

### Still Needs Work
- CEODashboard.tsx -- TS errors fixed but still needs UX polish
- Collaboration.tsx (72 LOC) -- minimal stub
- Reachability.tsx (103 LOC) -- basic stub
- MPTEConsole.tsx -- needs 19-phase enhancement

## Pre-existing TS Issues (FIXED 2026-03-01)
- CEODashboard.tsx: Fixed `api.get` by importing `{ api }` named export
- AttackPathGraph.tsx: Removed unused imports
- CodeScanning.tsx: Fixed ReactNode type with `String()` wrapper

## Completed Sprint Items
- SPRINT1-002: Attack Path Graph visualization (AttackPathGraph.tsx)
- SPRINT1-014: Triage Dashboard hero (ExposureCaseCenter.tsx, +307 lines)
- DEMO-003: Wire legacy UI to real API data (6 pages rewritten + ScannerDashboard)

## Dark Mode Audit Learnings
- Common light-mode leaks: `bg-gray-50`, `bg-gray-100`, `bg-blue-50`, `bg-purple-50`, `bg-green-100`, `text-green-800`, `text-red-800`
- Safe dark replacements: `bg-gray-950/50` (pre blocks), `bg-gray-800/60` (chat bubbles), `bg-green-500/20 text-green-400`, `bg-gray-500/20 text-gray-400`
- Always grep for `'bg-gray-50'|'bg-gray-100'|'bg-blue-50'` (quoted) to avoid false positives from `bg-blue-500/20`
- Never use `alert()` -- always `toast.success()` / `toast.error()` from sonner

## Parallel Worker Pattern
- Launch 7 junior-worker agents for page rewrites -- each gets detailed spec with interfaces, queries, design tokens
- Check for unused imports after workers finish (common issue: `Button` imported but not used)
- Run `npx tsc --noEmit` after each batch to catch errors early

## Remaining Priority Items
- AutoFix Center UI (Remediate space) -- 10 fix types, confidence badges, diff view
- Brain Pipeline visualization (Mission Control) -- 12-step pipeline
- Scanner Ingest Upload page (Discover) -- drag-and-drop scanner reports
- Sandbox Verification page (Validate) -- PoC editor, Docker health
- Lower priority: Predictions, Policies, AlgorithmicLab, Reachability still basic stubs (functional but not polished)
