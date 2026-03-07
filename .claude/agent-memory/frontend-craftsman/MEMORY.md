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
- **Available**: reportsApi, auditApi, workflowsApi, sastApi, dastApi, secretsApi, containerScanApi, cspmScanApi, scannerIngestApi, sandboxApi, failApi, feedsApi, remediationApi, reachabilityApi, mcpApi, brainPipelineApi, complianceApi, analyticsApi, nerveCenterApi, llmApi, enhancedApi, pentagiApi, attackGraphApi, graphApi
- **Raw axios**: `import { api } from '../../lib/api'` for custom endpoints
- **Default export**: Object with namespaced methods -- avoid in new code
- Response key: most list endpoints return `data?.items || data`

## Scanner API Signatures (verified)
- `sastApi.scanCode(code: string, filename?: string)` -- NOT an object
- `secretsApi.scanContent(content: string)` -- NOT an object
- `cspmScanApi.scanTerraform({ content, filename })` -- IS an object
- `reachabilityApi.analyze({ cve_id, repository? })` -- IS an object (NOT 2 separate args!)
- Scanner status: `/api/v1/{sast|dast|secrets|container|cspm}/status`

## Page Status (as of 2026-03-03 Session 5) -- 101 files, 42.9K LOC, ZERO mock data
### Key Pages by Pillar
- V3: BrainPipelineDashboard (724), AutoFixDashboard (625), ExposureCaseCenter (1182), Predictions (~340), Policies (~310), RiskScoreGauge (260), BrainPipelineLiveFeed (494), MultiLLMConsensusPanel (590), FAILEngineDashboard (~430), SLADashboard (~340)
- V5: SandboxVerification (905), MPTEConsole (2070), Reachability (~420), AttackSimulation (1421)
- V7: ScannerIngestUpload (987), ScannerDashboard (532), MCPToolRegistry (1096)
- V9: AirGappedIndicator (185, in GlobalStatusBar), DeploymentBadge (in Dashboard)
- V10: EvidenceBundles (2091), SOC2EvidenceUI, ComplianceReports (~450)

### Dashboard Components (src/components/dashboard/)
- `LivePipelineIndicator.tsx` (251 LOC) — 12-step pipeline, live findings
- `BrainPipelineLiveFeed.tsx` (494 LOC) — Real-time feed with events, pause/resume
- `CTEMProgressRing.tsx` — CTEM 5-phase progress ring
- `MultiLLMConsensusPanel.tsx` (590 LOC) — Real API-driven consensus
- `RiskScoreGauge.tsx` (260 LOC) — Animated risk gauge

### UX Components
- `CommandPalette.tsx` — Cmd+K global search + 12 chord shortcuts (G+letter)
- `KeyboardShortcutsHelp.tsx` (200 LOC) — ? key shows shortcuts overlay
- `ErrorBoundary.tsx` (381 LOC) — Auto-retry, chunk detection, telemetry, copy stack

## Build Stats (Day 5 Session 8 — 2026-03-07)
- 101 files, 45,532 LOC
- TypeScript: 0 errors
- Build: 1.91s
- Bundle: index 209.68KB (gzip 64.13KB) + 4 vendor chunks
- 100% API-wired, zero mock data, ZERO `any` types in pages
- All pages lazy-loaded, all with proper Skeleton loading states
- WCAG AA: 106 aria-labels across 20 files, global :focus-visible styles, skip-to-content link
- Accessibility: Global focus-visible outlines on all interactive elements (button, a, input, textarea, select, [role=*], [tabindex])

## Completed Sprint Items
- SPRINT1-002: Attack Path Graph visualization
- SPRINT1-014: Triage Dashboard hero
- DEMO-003 Day 1: Wire 6 pages + ScannerDashboard
- DEMO-003 Day 2 S1: +2 new pages + AirGapped component
- DEMO-003 Day 2 S2: Reachability, ComplianceReports, Predictions, Policies rewrites
- DEMO-003 Day 2 S3: Zero mock data, CommandPalette, RiskScoreGauge, 404 page, bundle optimization
- DEMO-003 Day 3: Copilot rewrite, dark/light toggle, Settings skeleton, IntelligenceHub skeleton
- DEMO-003 Day 4 S1: LivePipelineIndicator, Dashboard layout, SOC2 skeleton
- DEMO-003 Day 4 S4: MCPToolRegistry (V7), AttackSimulation rewrite (V5), BrainPipelineLiveFeed (V3), MultiLLM mock→real, ErrorBoundary, KeyboardShortcuts, chord nav
- DEMO-003 Day 5 S5: MainLayout 5-Space rewrite (KP-003 resolved), FAILEngineDashboard (V3/V5), SLADashboard (V3), mock removal from SecretsDetection + BulkOperations
- DEMO-003 Day 5 S6: AlgorithmicLab rewrite (V3), Skeleton upgrades (5 pages), toast notifications
- DEMO-003 Day 4 S7: 6 B-grade pages→A+ (Container, Runtime, SBOM, LiveFeed, EvidenceAnalytics, MultiLLM), accessibility pass

## Remaining Priority Items
- Knowledge Graph interactive improvements (V3)

## Completed Polish Items (2026-03-07)
- ✅ SOC2EvidenceUI — toast notifications, error state, aria-labels, htmlFor
- ✅ Global focus-visible styles in index.css (all interactive elements)
- ✅ Skip-to-content link in App.tsx
- ✅ Settings page — keyboard nav, aria-labels, toast feedback
- ✅ All `any` types eliminated from ~20 page files

## AlgorithmicLab API (verified 2026-03-03)
- Monte Carlo FAIR: `api.post('/api/v1/predictions/risk-trajectory', { cve_ids, simulations: 10000 })`
- Causal Analysis: `api.post('/api/v1/predictions/attack-chain', { target, finding_ids })`
- OLD BROKEN PATTERN: `api.ai.labs.monteCarloQuantify` — DO NOT USE (default export method chaining)

## Theme Toggle Pattern
- Store: `useUIStore` with `theme` and `setTheme` from `../stores`
- MUST also update document classes: `document.documentElement.classList.toggle('dark', theme === 'dark')`
- ThemeInitializer component in App.tsx syncs classes on mount

## TypeScript Gotchas
- When using `analysisMutation.data` in JSX, wrap in `String()` to avoid ReactNode type errors
- `useMemo` with state setter inside triggers linting warnings -- use as initialization pattern sparingly
- Badge `variant` supports: default, secondary, outline, destructive, success, info
- ErrorBoundary must be class component (React limitation for getDerivedStateFromError)

## API Patterns for Policy/Prediction Pages
- Predictions: `api.post('/api/v1/predictions/risk-trajectory', { cve_ids })` and `api.post('/api/v1/predictions/attack-chain', { target })`
- Policies: `api.get('/api/v1/policies')` returns `data?.items || data`
- complianceApi: `getStatus()`, `generateReport(frameworkId)`, `collectEvidence(id)`
- mcpApi: `getTools()`, `getResources()`, `getPrompts()`, `invokeTool(name, args)`, `getStatus()`
- brainPipelineApi: `listRuns()`, `getRun(id)`, `run(data)`, `generateEvidence(data)`
- pentagiApi: `health()`, `capabilities()`, `threatIntel({cve_id})`, `simulate({target, attack_type})`

## failApi Methods (verified 2026-03-03 — SHORT names, not getXxx)
- `failApi.score(data)`, `failApi.scoreBatch(data)`, `failApi.getScore(id)`
- `failApi.listScores(params)`, `failApi.topRisks(limit)`, `failApi.stats()`
- `failApi.scoreByCve(cve_id)`, `failApi.deleteScore(id)`, `failApi.health()`

## analyticsApi Limitation (verified 2026-03-03)
- Exported `analyticsApi` ONLY has: `getFindings()`, `getDecisions()`, `getStats()`
- Dashboard endpoints (getOverview, getMTTR, getTopRisks) are on internal `dashboard` const, NOT exported
- Use raw `api.get('/api/v1/analytics/dashboard/overview')` etc. for dashboard data
- `remediationApi.getTasks(orgId = 'default')` — takes string arg, NOT object

## Navigation Structure (verified 2026-03-03 — KP-003 RESOLVED)
- 5 Workflow Spaces: Mission Control 🎯, Discover 🔍, Validate ⚡, Remediate 🔧, Comply 🛡️
- Per-space accent colors: indigo, cyan, orange, emerald, violet
- Logo text: "CTEM+ Platform" (not "Intelligence Hub")
