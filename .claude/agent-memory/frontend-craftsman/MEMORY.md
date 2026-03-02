# Frontend Craftsman -- Persistent Memory

## Project Structure
- Legacy UI: `suite-ui/aldeci/` (React + Vite + TypeScript, has real components)
- New UI target: `suite-ui/aldeci-ui-new/` (DOES NOT EXIST -- never create it)
- API client: `suite-ui/aldeci/src/lib/api.ts` -- axios-based, uses `api.get()` / `api.post()`
- UI components: `@/components/ui/` has Card, Badge, Button, Input, Tabs, Progress, Textarea, Dialog, Label, ScrollArea, Tooltip, Skeleton (shadcn-style)

## Key Patterns in Codebase
- Dark theme first: bg-gray-900/80, border-gray-600/30, text-gray-200
- Glass-card effect: `bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80`
- Standard card: `border-gray-700/30 bg-gray-900/40 backdrop-blur-md`
- Animation: framer-motion with Apple ease `[0.16, 1, 0.3, 1]` (ease-out-expo)
- Spring animations: `{ type: 'spring', stiffness: 200, damping: 22 }`
- Container stagger: `{ staggerChildren: 0.05 }`, item: `{ opacity: 0, y: 12 } -> { opacity: 1, y: 0 }`
- Page transitions: `initial={{ opacity: 0, y: 12, scale: 0.995 }}` with ease-out-expo
- Priority colors: critical=red, high=orange, medium=yellow, low=blue, info=cyan
- Status colors: open=red, triaging=yellow, fixing=blue, resolved=green
- Severity badge: `bg-{color}-500/20 text-{color}-400 border-{color}-500/30`
- Never use `alert()` -- always `toast.success()` / `toast.error()` from sonner
- Empty states: Icon (w-16 h-16 text-muted-foreground/30), title, description, CTA button

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

## Page Status (as of 2026-03-02 Session 3) -- 62 pages, ALL wired, ZERO mock data
### Key Pages by Pillar
- V3: BrainPipelineDashboard (724 LOC), AutoFixDashboard (625 LOC), ExposureCaseCenter (1182 LOC), Predictions (~340 LOC), Policies (~310 LOC), RiskScoreGauge (260 LOC)
- V5: SandboxVerification (905 LOC), MPTEConsole (2070 LOC, already has 19-phase live demo), Reachability (~420 LOC)
- V7: ScannerIngestUpload (987 LOC), ScannerDashboard (532 LOC)
- V9: AirGappedIndicator (185 LOC, in GlobalStatusBar), DeploymentBadge (in Dashboard)
- V10: EvidenceBundles (2091 LOC), SOC2EvidenceUI, ComplianceReports (~450 LOC)

### Still Needs Work
- CEODashboard.tsx -- needs UX polish
- Per-page skeleton loading states (component exists at components/ui/skeleton.tsx)
- Knowledge Graph interactive improvements

## Completed Sprint Items
- SPRINT1-002: Attack Path Graph visualization
- SPRINT1-014: Triage Dashboard hero
- DEMO-003 Day 1: Wire 6 pages + ScannerDashboard
- DEMO-003 Day 2 S1: +2 new pages (ScannerIngest, SandboxVerification), +1 component (AirGapped), enhanced BrainPipeline + AutoFix
- DEMO-003 Day 2 S2: Rewrote Reachability, ComplianceReports, Predictions, Policies (4 pages from stubs to production)
- DEMO-003 Day 2 S3: Zero mock data (3 pages fixed), CommandPalette, RiskScoreGauge, Skeleton system, 404 page, bundle optimization 540→193KB

## Build Stats (Day 2 S3)
- 62 pages, 25 components, 37,088 LOC
- TypeScript: 0 errors
- Build: ~1.6s
- Bundle: index 193KB + 4 vendor chunks (react 160KB, motion 108KB, ui 85KB, query 42KB)
- 100% API-wired (0 mock-only pages, 0 hardcoded fallback arrays)
- All pages lazy-loaded

## Bundle Optimization Pattern
- vite.config.ts `build.rollupOptions.output.manualChunks` for vendor splitting
- Keep main chunk under 200KB for fast initial load
- Each page is already lazy-loaded via `React.lazy()`

## Remaining Priority Items (Day 3+)
- Per-page skeleton loading states
- Knowledge Graph interactive improvements (V3)
- CEODashboard detailed UX pass
- Dark/light mode toggle polish

## API Patterns for Policy/Prediction Pages
- Predictions: `api.post('/api/v1/predictions/risk-trajectory', { cve_ids })` and `api.post('/api/v1/predictions/attack-chain', { target })`
- Policies: `api.get('/api/v1/policies')` returns `data?.items || data`, `api.post('/api/v1/policies/{id}/validate')`
- complianceApi: `getStatus()`, `generateReport(frameworkId)`, `collectEvidence(id)`, frameworks at `/api/v1/compliance-engine/frameworks`
