# UI Overhaul Dispatch — 22 Work Units + NEW-G071

**Author**: ux-architect
**Date**: 2026-04-22
**Source plan**: `~/.claude/plans/swirling-shimmying-karp.md` (pre-crash, 121 lines, 22 units)
**Target codebase**: `suite-ui/aldeci-ui-new/src/` (379 pages, 371 routes in App.tsx)
**Related open thread**: `.omc/TASKS_STATE_2026-04-22.md` thread #4

---

## Section 1 — Plan summary (5 bullets)

1. **Remove mock data, wire every page to a real API.** Plan calls out 8 critical pages still using `MOCK_*` constants with zero fetch calls. A deeper scan now shows **15** files still grepping for `MOCK_` and **216** files with no call to `useEffect`/`useQuery`/`fetch`/`apiFetch` (plan said 57 — the situation has drifted since the plan was written, most of the 57 got partially wired, but many still lack any fetch). Master goal: every page either talks to a real endpoint or is explicitly marked "demo data" for offline graceful fallback.
2. **Restore the enterprise triangle on every page: loading → empty → error.** Plan claims 75% lack loading states and 71% lack empty states. Shared primitives already exist (`components/shared/PageSkeleton.tsx`, `components/shared/EmptyState.tsx`, `components/shared/ErrorBoundary.tsx`) — the work is applying them uniformly, not building them.
3. **Consolidate API plumbing.** 318 page files currently hardcode `/api/v1/...` or `http://localhost` strings; they must route through `buildApiUrl()` + `apiFetch()` in `src/lib/api.ts` so env-based base URLs, auth token injection, and org-id scoping happen in one place.
4. **Tighten the type surface.** 747 `any` annotations inside `pages/` — units 19-20 replace the worst-offender 30 pages with proper response interfaces and remove orphan `console.log` (already 0) + `alert("TODO")` stubs.
5. **Audit the navigation shell itself.** Units 21-22 sweep `App.tsx` (371 `<Route>` elements), `components/layout/WorkspaceLayout.tsx`, `GlobalSearch.tsx`, `NotificationBell.tsx` for dead links, TODO-alert buttons, and form/modal submit handlers that don't actually POST. This is the Steve Jobs UI Redesign cleanup pass — no button should be decorative.

**Master UX vision**: every page of all 379 pages is demonstrably alive — it fetches real data, shows a branded skeleton while loading, shows a meaningful empty state when the dataset is empty, degrades gracefully to a user-readable error (never a silent swallow), and every interactive element performs a real action via the central API helpers. Nothing cosmetic on top of a dead page.

---

## Section 2 — Work unit → code mapping table

| # | Work unit | Current state (files) | Target state | Dependencies | Priority | Effort | Owner |
|---|-----------|-----------------------|--------------|--------------|----------|--------|-------|
| 1 | Critical mock pages — Settings + DeveloperPortal | `pages/settings/Settings.tsx`, `pages/developer/DeveloperPortal.tsx` (both confirmed present, both still grep-hit `MOCK_`) | Replace `MOCK_API_KEYS`/`MOCK_INTEGRATIONS`/`MOCK_USERS`/`MOCK_REPOS` with `useEffect` + `apiFetch(buildApiUrl('/api/v1/apikey'))`, `/api/v1/integrations`, `/api/v1/developer-portal/repos`. Keep mocks as `useState` default for fallback. Add `<PageSkeleton />` while loading, `<EmptyState />` when empty, user-visible error with retry button. | None | P0 | M | frontend-craftsman |
| 2 | Critical mock pages — VendorManagement + SBOMManagement | `pages/vendors/VendorManagement.tsx`, `pages/sbom/SBOMManagement.tsx` (both present, both MOCK-hit) | Same pattern — wire to `/api/v1/vendor-risk`, `/api/v1/sbom`. Triangle + retry. | None | P0 | M | frontend-craftsman |
| 3 | Critical mock pages — RiskRegister + RiskAcceptance | `pages/mission-control/RiskRegister.tsx`, `pages/risk/RiskAcceptance.tsx` (both present, both MOCK-hit) | Wire to `/api/v1/risk-register-engine/risks`, `/api/v1/risk-acceptance`. Triangle + retry. Fix the 1 debug-`console.log` in RiskAcceptance (already 0 hits project-wide per my scan — keep watch). | None | P0 | M | frontend-craftsman |
| 4 | Critical mock pages — IncidentResponse + AttackSurface | `pages/incidents/IncidentResponse.tsx`, `pages/attack-surface/AttackSurface.tsx` (both present, both MOCK-hit) | Wire to `/api/v1/incident-response`, `/api/v1/attack-surface/assets`. Triangle + retry. | None | P0 | M | frontend-craftsman |
| 5 | Static pages Group A — comply/ | `pages/comply/Analytics.tsx`, `pages/comply/EvidenceBundles.tsx`, `pages/comply/EvidenceExportCenter.tsx`, `pages/comply/SOC2Evidence.tsx` (all present; sibling dir also has ComplianceDashboard/AuditTrail/EvidenceVault/Reports/SLSAProvenance — see if those need same treatment) | Add `useEffect` + fetch to `/api/v1/compliance`, `/api/v1/evidence-chain`, `/api/v1/sbom-export`, `/api/v1/soc2`. Triangle applied. | Units 1-4 land patterns first | P1 | M | frontend-craftsman |
| 6 | Static pages Group B — discover/ | `pages/discover/CodeScanning.tsx`, `pages/discover/ContainerSecurity.tsx`, `pages/discover/DataFabric.tsx`, `pages/discover/IaCScanning.tsx` (plus 8 siblings — AttackPaths/CloudPosture/CorrelationEngine/FindingExplorer/KnowledgeGraph/SBOMInventory/SecretsDetection/ThreatFeeds; verify they aren't already live, skip if they are) | Wire to SAST/container/IaC APIs — `/api/v1/sast`, `/api/v1/container-security`, `/api/v1/data-fabric`, `/api/v1/iac`. Triangle applied. | Unit 5 | P1 | M | frontend-craftsman |
| 7 | Static pages Group C — validate/ | `pages/validate/FAILEngine.tsx`, `pages/validate/MPTEConsole.tsx`, `pages/validate/Reachability.tsx` (+ siblings AttackSimulation/PlaybookEditor/Playbooks already covered) | Wire to `/api/v1/fail-engine`, `/api/v1/mpte`, `/api/v1/reachability`. Triangle applied. | Unit 5 | P1 | M | frontend-craftsman |
| 8 | Static pages Group D — mission-control/ | `pages/mission-control/ExecutiveView.tsx`, `pages/mission-control/RiskOverview.tsx` (+ 10 siblings, several already live — CISODashboard/CommandDashboard/ComplianceDashboard/DevSecurityDashboard/LiveFeed/SLADashboard/SOCDashboard/SOCT1Dashboard/ThreatIntelDashboard/RiskRegister) | Wire ExecutiveView → `/api/v1/exec-reporting`, RiskOverview → `/api/v1/risk-aggregator`. Triangle applied. | Unit 3 (shares RiskRegister), Unit 5 | P1 | S | frontend-craftsman |
| 9 | Static pages Group E — settings/ | `pages/settings/SystemHealth.tsx`, `pages/settings/Teams.tsx` (both confirmed present) | Wire to `/api/v1/platform/health`, `/api/v1/teams`. Triangle applied. | Unit 1 (shared Settings.tsx patterns) | P1 | S | frontend-craftsman |
| 10 | Error handling — Batch 1 (A-F) | Project-wide scan shows only **2** silent `.catch(() => {})` today (plan said 59 — plan is stale, this unit is cheap). Grep inside A-F subset of `pages/` to catch what's left. | Replace silent `.catch` with an error-state setter that renders a user-visible banner with a retry button. Use `ErrorBoundary` component from `components/shared/ErrorBoundary.tsx` for render-time errors. | Unit 1 establishes pattern | P2 | S | frontend-craftsman |
| 11 | Error handling — Batch 2 (G-N) | Same scan for pages G-N. | Same pattern. | Unit 10 | P2 | S | frontend-craftsman |
| 12 | Error handling — Batch 3 (O-Z) | Same scan for pages O-Z. | Same pattern. | Unit 10 | P2 | S | frontend-craftsman |
| 13 | Loading states — Batch 1 (A-D) | Grep `pages/[A-D]*/*.tsx` for files with fetch but no skeleton render. `components/shared/PageSkeleton.tsx` already available. | Add `const [loading, setLoading] = useState(true)`, render `<PageSkeleton />` while loading, `setLoading(false)` in `finally`. | Unit 1 (pattern) | P1 | M | frontend-craftsman |
| 14 | Loading states — Batch 2 (E-N) | Same grep for E-N. | Same pattern. | Unit 13 | P1 | M | frontend-craftsman |
| 15 | Loading states — Batch 3 (O-Z) | Same grep for O-Z. | Same pattern. | Unit 13 | P1 | M | frontend-craftsman |
| 16 | Empty states — all list/table pages | Grep for `.map(` in pages where `data.length === 0` isn't handled. `components/shared/EmptyState.tsx` already available. | Wrap data renders in `{data.length === 0 ? <EmptyState title="…" description="…" /> : <Table />}`. Each empty state must have a tailored title+description (no generic "no data"). | Unit 1 | P1 | L | frontend-craftsman |
| 17 | API URL consolidation — Batch 1 | 318 page files contain hardcoded `/api/v1/...` or `http://localhost` (counted now). Split into two batches. First half alphabetical (A-M). | Import `buildApiUrl` from `@/lib/api` and replace hardcoded `fetch("/api/v1/...")` with `apiFetch(buildApiUrl('/api/v1/...'))`. Remove any `http://localhost:8000` references. | Units 10-15 share files; coordinate to avoid merge conflicts | P1 | L | frontend-craftsman |
| 18 | API URL consolidation — Batch 2 | Remaining ~159 files (N-Z). | Same consolidation. | Unit 17 | P1 | L | frontend-craftsman |
| 19 | TypeScript types — critical 30 | `rg -c ": any" pages/` shows 747 hits. Pick top-30 by count (e.g. any dashboard with a dozen `any`). | Define `interface` for API response bodies, replace `any` with typed alternatives. Add to `src/lib/apiTypes.ts` (new module if needed — design decision). | Unit 17 (stable URL helpers first) | P2 | L | frontend-craftsman |
| 20 | Console.log cleanup + polish | `rg "console\.log" pages/` = 0 today. Remaining polish: `aria-label` on icon-only buttons, focus rings on keyboard-reachable elements, remove dead `alert(...)` TODO stubs (none found by my grep — good). | Sweep every page for missing `aria-label`/`aria-describedby`, ensure all icon-only buttons announce themselves, run `axe-core` against build. | All prior units | P2 | M | frontend-craftsman |
| 21 | Routes + navigation audit | `src/App.tsx` (371 routes), `src/components/layout/WorkspaceLayout.tsx`, `src/components/layout/GlobalSearch.tsx`, `src/components/layout/NotificationBell.tsx`, `src/components/layout/CopilotSidebar.tsx`. Note: there is **no** `Sidebar.tsx`/`Navigation.tsx` — plan is wrong; layout lives in `WorkspaceLayout.tsx`. | Audit every `<Route>` resolves to a real page component; every `<Link>` in the sidebar lands on a route that doesn't 404; every sub-route under `/mission-control`, `/discover`, `/validate`, `/remediate`, `/comply` is navigable. Fix dead links by either removing them or stubbing the destination page. | Units 5-9 (establish live pages first, then prune dead links) | P0 | L | ux-architect (design) → frontend-craftsman (exec) |
| 22 | Interactive elements audit | Every page with `<form>`, `<button>`, `<Dialog>`. Grep for stubbed handlers. | Replace any `onClick={() => alert(...)}` or no-op `onClick` with a real `apiFetch` POST/PUT/DELETE. Ensure every `<Dialog>` has working submit + cancel. Tables have working sort/filter via state or URL params. | Unit 21 (need the route map first) | P1 | XL | frontend-craftsman |
| **NEW-G071** | **IDE-in-browser** — file tree + Monaco viewer + analysis time-travel + ER diagram + diff-mode canvas | Not built. Nearest existing: `pages/discover/CodeScanning.tsx` (fetches scan results), `pages/discover/KnowledgeGraph.tsx` (node-link graph), `pages/discover/SBOMInventory.tsx` (component list). None of these expose a file tree + Monaco + historical snapshot picker. | New workspace route `/discover/workspace` or `/inspector`. Components: `FileTreeDrawer.tsx` (left), `MonacoCodeViewer.tsx` (center, wraps `@monaco-editor/react`), `AnalysisSelector.tsx` (top bar — list past analyses like TrueCourse Analyses tab), `DiffModeToggle.tsx` (highlights new/resolved findings), `ERDiagramPanel.tsx` (for DB-schema discovery results via reactflow). Pulls from `/api/v1/findings?commit_hash=…`, `/api/v1/analyses`, `/api/v1/sca/graph`. | Unit 21 (needs a clean route hierarchy first) and Unit 6 (discover/ pages wired) | P1 | XL | ux-architect (mockup + palette) → frontend-craftsman (build) |

**Totals**: 4 P0 (units 1-4 + 21), 13 P1 (5-9, 13-18, 22, NEW-G071), 5 P2 (10-12, 19-20).

---

## Section 3 — Dispatch order (first 5 for frontend-craftsman tomorrow)

### 3.1 — Unit 1: Settings + DeveloperPortal mock removal
**Brief**: `pages/settings/Settings.tsx` and `pages/developer/DeveloperPortal.tsx` are still rendering `MOCK_API_KEYS`, `MOCK_INTEGRATIONS`, `MOCK_USERS`, `MOCK_REPOS` directly in the component body — zero network calls. This is the most visible non-enterprise page because it is the first stop for every onboarding persona (CISO → AppSec engineer → developer all hit Settings). Convert both files to fetch-backed: import `{ buildApiUrl, apiFetch }` from `@/lib/api`, add `useEffect` on mount that calls `/api/v1/apikey`, `/api/v1/integrations`, `/api/v1/users`, `/api/v1/developer-portal/repos`. Keep the MOCK arrays as `useState` defaults so the page never renders empty on offline — but on successful fetch, replace state. Render `<PageSkeleton />` during the first load (use `components/shared/PageSkeleton.tsx`), render `<EmptyState title="No API keys" description="Create your first key to authenticate CI/CD pipelines." />` when the array is empty, render an error banner with retry button on fetch failure.
**Acceptance criteria**:
- `rg "MOCK_" src/pages/settings/Settings.tsx src/pages/developer/DeveloperPortal.tsx` returns 0 hits (or only hits as `useState` defaults, not inline renders)
- `npm run build` exits 0
- Loading Settings.tsx with no backend shows skeleton for ~1s, then error banner with "Retry"
- Loading Settings.tsx with backend up shows real keys/users/integrations
- No console errors
**Estimated clock time**: 3h

### 3.2 — Unit 2: VendorManagement + SBOMManagement mock removal
**Brief**: Same pattern as 3.1 but for `pages/vendors/VendorManagement.tsx` and `pages/sbom/SBOMManagement.tsx`. Backends already live: `/api/v1/vendor-risk/vendors` and `/api/v1/sbom/components`. SBOMManagement should paginate (SBOMs can be 10K+ components) — use the existing `components/Pagination.tsx`.
**Acceptance criteria**: MOCK constants gone, pagination works on SBOM, empty + error + loading all verified, build passes.
**Estimated clock time**: 3h

### 3.3 — Unit 3: RiskRegister + RiskAcceptance mock removal
**Brief**: Same pattern. Backends: `/api/v1/risk-register-engine/risks`, `/api/v1/risk-acceptance`. This unit also closes the last debug `console.log` in RiskAcceptance — scan confirms project-wide count is 0 but double-check after edit.
**Acceptance criteria**: Mock gone, triangle applied, build passes, risk rows editable via `PUT /api/v1/risk-register-engine/risks/:id`.
**Estimated clock time**: 3h

### 3.4 — Unit 4: IncidentResponse + AttackSurface mock removal
**Brief**: Same pattern. Backends: `/api/v1/incident-response/incidents`, `/api/v1/attack-surface/assets`. AttackSurface currently renders a static graph — replace with a real fetch of ASM findings; treat visualization layer as a separate concern (don't rebuild, just feed live data).
**Acceptance criteria**: Mock gone, triangle applied, build passes, incident timeline updates when a new `INCIDENT_CREATED` event fires (optional — WebSocket wiring can come later).
**Estimated clock time**: 3h

### 3.5 — Unit 21: Routes + navigation audit
**Brief**: Before wiring the remaining 17 units, we need a clean route map. Walk `src/App.tsx` (371 `<Route>` entries), cross-reference with `src/components/layout/WorkspaceLayout.tsx` sidebar definitions and `GlobalSearch.tsx` search index. For every sidebar entry, verify the route exists; for every route, verify the lazy import resolves; for every nested space (`/mission-control`, `/discover`, `/validate`, `/remediate`, `/comply`) verify the default landing page. Output: `docs/route-audit-2026-04-22.md` listing dead links and orphan routes. Fix P0 dead links in this unit (redirect orphan sidebar entries, stub pages for orphan routes with `<EmptyState title="Coming soon" />`).
**Acceptance criteria**:
- Every sidebar link navigates without 404
- `npm run build` exits 0
- `npm run dev` + clicking every top-level sidebar section produces no console errors
- `docs/route-audit-2026-04-22.md` committed with the full map
**Estimated clock time**: 5h

**Total for first 5 units**: ~17h (roughly 2 days of focused frontend-craftsman work).

---

## Section 4 — NEW-G071 integration

**Verdict**: **Additive, not subsuming** — but it must be sequenced *after* Units 5-6 (the discover/ directory wiring).

Reasoning:
- The 22 existing units are all "bring what we ship to enterprise quality." None of them create a new top-level page. NEW-G071 is a new surface: a code-inspector workspace modeled on TrueCourse's Files + Analyses + Databases + Violations tabs.
- It does **not** replace any existing page. The closest overlaps are `pages/discover/CodeScanning.tsx` (lists SAST findings in a table) and `pages/discover/KnowledgeGraph.tsx` (node-link code graph). NEW-G071 is the "drill-down" experience those pages currently lack — click a finding in CodeScanning, land in the Monaco viewer with the violating line highlighted; click a commit in the Analyses selector, time-travel the whole finding set.
- Sequencing: don't start NEW-G071 until (a) discover/ pages are live (Unit 6) and (b) the route map is clean (Unit 21). Otherwise you're layering a premium feature on quicksand.
- Scoping: break NEW-G071 into 4 sub-units (file tree, Monaco viewer, analysis selector, diff-mode + ER diagram). Each sub-unit is roughly one P1/M card; the whole feature is ~2 weeks of frontend-craftsman + ux-architect mockups.
- Differentiation: this is the single feature from TrueCourse that Fixops users will notice immediately on a demo. Prioritize P1 with room to promote to P0 if the investor pitch needs a "wow" moment.

**Recommendation**: keep it as row 23 in the table, tag P1, start after Unit 21. Don't let it leapfrog the enterprise-quality sweep — a broken Settings page kills a demo faster than a missing inspector does.

---

## Section 5 — Design-needed-first queue (ux-architect owns these)

| Item | Blocks | What ux-architect must produce | ETA |
|------|--------|-------------------------------|-----|
| Empty-state copy spec | Unit 16 | A table of every page → tailored title + description + illustration slot + CTA. Generic "no data" is forbidden. | 2 days |
| Error banner motion spec | Units 10-12 | Which animation (slide-down vs fade-in), how long visible, retry-button focus ring, do we surface the HTTP error code or a user-safe message. | 1 day |
| Route map & information architecture decision | Unit 21 | Canonical Workflow Spaces (Mission Control / Discover / Validate / Remediate / Comply) vs. existing sidebar — if there's drift, flag it. CLAUDE.md explicitly cites Steve Jobs UI Redesign (VISION Part IV). Confirm which sidebar ships. | 2 days (parallel with frontend work on 1-4) |
| NEW-G071 mockup pack | NEW-G071 build | Figma / hand-drawn of the 4 panels (FileTree, MonacoViewer, AnalysisSelector, ERDiagram), including diff-mode color palette (new = emerald-500, resolved = slate-400, open = rose-500). | 5 days |
| Persona landing map | Cross-cutting | Per-persona default landing page (CISO → Mission Control, Developer → Remediate, Auditor → Comply). Unblocks onboarding work that will eventually surface as a separate unit. | 3 days |

---

## Appendix — raw counts verified 2026-04-22

- Pages with `MOCK_` grep hit: 15 (plan said 8 — more drift than expected)
- Pages with NO fetch mechanism at all (`useEffect`/`useQuery`/`fetch`/`apiFetch`): 216 (plan said 57 — plan is stale)
- Silent `.catch(() => {})` hits: 2 (plan said 59 — plan is stale, mostly cleaned)
- Hardcoded API URL hits: 318 files (plan said 234 — drifted up)
- `: any` annotations in pages: 747
- `console.log` hits in pages: 0 (already clean)
- `alert(...)` hits: 0 (already clean)
- `<Route` entries in App.tsx: 371
- Total `.tsx` files under `pages/`: 379
- Shared primitives confirmed present: `PageSkeleton.tsx` (at `components/shared/`), `EmptyState.tsx`, `ErrorBoundary.tsx`
- Layout shell: `components/layout/WorkspaceLayout.tsx` (1123 lines), `GlobalSearch.tsx`, `NotificationBell.tsx`, `CopilotSidebar.tsx` — **no** `Sidebar.tsx`/`Navigation.tsx` despite plan claiming so
