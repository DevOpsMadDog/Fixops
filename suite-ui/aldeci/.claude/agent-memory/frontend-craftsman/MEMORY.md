# Frontend Craftsman Memory

## Project Structure
- All UI: `suite-ui/aldeci/` (React + Vite + TypeScript + Tailwind)
- API client: `suite-ui/aldeci/src/lib/api.ts` exports named API objects (~1100 LOC)
- Pages: `suite-ui/aldeci/src/pages/` grouped by section (attack/, evidence/, settings/, core/, etc.)
- UI components (shadcn): `suite-ui/aldeci/src/components/ui/`
- Routing in: `suite-ui/aldeci/src/App.tsx` uses React lazy() imports + React Router

## API Client Exports (frequently used)
- `microPentestApi` — .run(), .getHealth(), .getStatus(), .generateReport()
- `pentagiApi` — .health(), .capabilities(), .threatIntel({cve_id}), .simulate({target, attack_type}), .businessImpact(), .remediation()
- `attackGraphApi` — .getGraph(), .analyze({}), .export(format) — extends graphApi
- `reachabilityApi` — .analyze({cve_id, ...}), .getResults(cveId), .getMetrics()
- `graphApi` — .get(), .getGraph(), .analyzeSurface(), .getCriticalNodes()
- `mpteApi` — extends pentestApi with .getConfigs()
- Response data is loosely typed — always cast with `as Record<string, unknown>` and null checks

## Patterns
- Pages use `useQuery` from `@tanstack/react-query` for data fetching
- Toast via `import { toast } from 'sonner'`
- Animation: framer-motion with `containerVariants` (staggerChildren: 0.05) + `itemVariants` (opacity/y)
- Apple ease: `[0.16, 1, 0.3, 1]`
- Dark mode classes: `bg-gray-900/40`, `border-gray-700/30`, `text-gray-200`, `backdrop-blur-md`
- Glass card: `bg-gradient-to-br from-gray-900/80 via-slate-900/60 to-gray-900/80 border-gray-700/30`
- Skeleton loaders use `animate-pulse` + `bg-gray-700/30` (not Spinner components)
- Severity badge colors: critical=red, high=orange, medium=yellow, low=blue, info=slate
- Badge variants available: default, secondary, destructive, outline, critical, high, medium, low, info, success
- API responses often wrapped in objects with varying keys; use extractors that check `data`, `items`, array root

## Adding New Pages Checklist
1. Create page in `src/pages/{section}/{PageName}.tsx`
2. Add lazy import in `App.tsx` near other section imports
3. Add `<Route>` in App.tsx inside the correct section comment
4. Optionally add nav card in parent page (e.g., Settings.tsx grid)
5. Run `npx tsc --noEmit` to verify zero errors

## TypeScript Gotchas
- When chaining `typedObj?.prop` in ternary, TS may still warn about `undefined` — use `?.` on both branches
- Unused imports/variables cause TS6133 errors — always clean up before finalizing
- Vite env: `(import.meta as any).env?.VITE_API_URL`

## Pre-existing Issues
- `MultiLLMConsensusPanel.tsx:535` has TS2322 error (not our fault, pre-existing)
- `suite-ui/aldeci-ui-new/` does NOT exist -- never reference it
