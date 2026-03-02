# Frontend Craftsman -- Persistent Memory

## Project Structure
- Legacy UI: `suite-ui/aldeci/` (React + Vite + TypeScript, has real components)
- New UI target: `suite-ui/aldeci-ui-new/` (DOES NOT EXIST -- never create it)
- API client: `suite-ui/aldeci/src/lib/api.ts` -- axios-based, uses `api.get()` / `api.post()`
- UI components: `@/components/ui/` has Card, Badge, Button, Input, Tabs, Progress, Textarea, Dialog, Label, ScrollArea, Tooltip (shadcn-style)

## Key Patterns in Codebase
- Dark theme first: bg-gray-900/80, border-gray-600/30, text-gray-200
- Glass-card effect: `bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80`
- Standard card: `border-gray-700/30 bg-gray-900/40 backdrop-blur-md`
- Animation: framer-motion with Apple ease `[0.16, 1, 0.3, 1]` (ease-out-expo)
- Spring animations: `{ type: 'spring', stiffness: 200, damping: 22 }`
- Container stagger: `{ staggerChildren: 0.05 }`, item: `{ opacity: 0, y: 12 } -> { opacity: 1, y: 0 }`
- Priority colors: critical=red, high=orange, medium=yellow, low=blue, info=cyan
- Status colors: open=red, triaging=yellow, fixing=blue, resolved=green
- Severity badge: `bg-{color}-500/20 text-{color}-400 border-{color}-500/30`
- Never use `alert()` -- always `toast.success()` / `toast.error()` from sonner

## API Import Pattern (IMPORTANT)
- **Named exports**: `import { reportsApi } from '../../lib/api'`
- **Available**: reportsApi, auditApi, workflowsApi, sastApi, dastApi, secretsApi, containerScanApi, cspmScanApi, scannerIngestApi, sandboxApi, failApi, feedsApi, remediationApi, reachabilityApi, mcpApi, brainPipelineApi, complianceApi, analyticsApi, nerveCenterApi
- **Raw axios**: `import { api } from '../../lib/api'` for custom endpoints
- **Default export**: Object with namespaced methods -- avoid in new code
- Response key: most list endpoints return `data?.items || data`

## Scanner API Signatures (verified)
- `sastApi.scanCode(code: string, filename?: string)` -- NOT an object
- `secretsApi.scanContent(content: string)` -- NOT an object
- `cspmScanApi.scanTerraform({ content, filename })` -- IS an object
- `reachabilityApi.analyze({ cve_id, repository? })` -- IS an object (NOT 2 separate args!)
- Scanner status: `/api/v1/{sast|dast|secrets|container|cspm}/status`

## Page Status (as of 2026-03-02 Session 2) -- 61 pages, ALL wired
### Key Pages by Pillar
- V3: BrainPipelineDashboard (724 LOC), AutoFixDashboard (625 LOC), ExposureCaseCenter (1182 LOC), Predictions (~340 LOC), Policies (~310 LOC)
- V5: SandboxVerification (905 LOC), MPTEConsole (1353 LOC), Reachability (~420 LOC)
- V7: ScannerIngestUpload (987 LOC), ScannerDashboard (532 LOC)
- V9: AirGappedIndicator (185 LOC, in GlobalStatusBar)
- V10: EvidenceBundles (2091 LOC), SOC2EvidenceUI, ComplianceReports (~450 LOC)

### Still Needs Work
- MPTEConsole.tsx -- needs 19-phase enhancement
- CEODashboard.tsx -- needs UX polish
- Collaboration.tsx (411 LOC) -- functional but could be improved

## Completed Sprint Items
- SPRINT1-002: Attack Path Graph visualization
- SPRINT1-014: Triage Dashboard hero
- DEMO-003 Day 1: Wire 6 pages + ScannerDashboard
- DEMO-003 Day 2 S1: +2 new pages (ScannerIngest, SandboxVerification), +1 component (AirGapped), enhanced BrainPipeline + AutoFix
- DEMO-003 Day 2 S2: Rewrote Reachability, ComplianceReports, Predictions, Policies (4 pages from stubs to production)

## Build Stats
- 61 pages, 20 components, 34,064 LOC
- TypeScript: 0 errors
- Build: ~3.8s, all pages lazy-loaded
- 100% API-wired (0 mock-only pages)

## Parallel Worker Pattern
- Launch junior-worker agents for page builds (3 concurrent is good)
- Always check for unused imports after workers finish
- Run `npx tsc --noEmit` after each batch
- Workers sometimes use wrong API signatures -- verify call patterns match api.ts

## Remaining Priority Items (Day 3+)
- MPTEConsole 19-phase enhancement (V5, P0)
- Knowledge Graph interactive improvements (V3)
- Loading skeletons across all pages
- Keyboard shortcuts (Ctrl+K for search)
- Page transition polish
- Bundle size optimization (main chunk 540KB — consider code splitting)

## API Patterns for Policy/Prediction Pages
- Predictions: `api.post('/api/v1/predictions/risk-trajectory', { cve_ids })` and `api.post('/api/v1/predictions/attack-chain', { target })`
- Policies: `api.get('/api/v1/policies')` returns `data?.items || data`, `api.post('/api/v1/policies/{id}/validate')`
- complianceApi: `getStatus()`, `generateReport(frameworkId)`, `collectEvidence(id)`, frameworks at `/api/v1/compliance-engine/frameworks`
