# Graphify UI Report — ALDECI Frontend
**Path:** `suite-ui/aldeci-ui-new/src/`
**Date:** 2026-04-17
**Method:** AST-only (code corpus, zero LLM tokens)

---

## Totals

| Category | Count |
|---|---|
| Pages (unique) | 365 |
| Components (unique) | 39 |
| Custom Hooks | 7 |
| Shared Utilities (lib + utils) | 8 |
| Graph nodes | 2,258 |
| Graph edges | 2,031 |
| Communities detected | 409 |
| Total files scanned | 442 |
| LLM tokens used | 0 (AST-only) |

---

## Community Map (top 30 by size)

| ID | Label | Nodes |
|---|---|---|
| 0 | Analytics & Live Feed Components | 114 |
| 1 | Core API Utilities & Helpers | 62 |
| 2 | ALDECI API Client | 41 |
| 3 | Custom React Hooks | 31 |
| 4 | Incident & Metrics Dashboards | 27 |
| 5 | CSV Export & Feed Subscriptions | 26 |
| 6 | Asset & Exposure UI | 20 |
| 7 | Settings & Admin Panel | 18 |
| 8 | Finding & Confidence Badges | 18 |
| 9 | IGA & Campaign Management | 16 |
| 10 | Risk Matrix & Heatmap | 16 |
| 11 | EventSource / SSE Stub | 15 |
| 12 | Error Boundary & Test Utils | 14 |
| 13 | Alert Triage & Bulk Actions | 14 |
| 14 | API Query Hooks | 13 |
| 15 | Auth Fetch & Mock Data | 13 |
| 16 | Compliance Grade Components | 12 |
| 17 | Auth Storage Utilities | 11 |
| 18 | Access Review & Deadlines | 11 |
| 19 | Agreement Meter & Timestamps | 11 |
| 20 | Scheduled Reports UI | 10 |
| 21 | Vuln Intelligence Dashboard | 10 |
| 22 | Severity & Status Badges | 10 |
| 23 | Arc SVG & Domain Colors | 10 |
| 24 | Fix Panel & Grade Badge | 10 |
| 25 | Pipeline Step Builder | 10 |
| 26 | EPSS & MPTE Badges | 10 |
| 27 | Detail Panel & Severity | 10 |
| 28 | Auth Provider & RBAC | 9 |
| 29 | OpenClaw & Risk Score | 9 |

---

## Pages → Components Import Map

The import analysis shows most pages are **self-contained monoliths** — they import 0 shared components from `/components/`. This is the dominant pattern: each dashboard page carries all its local helper functions, badge renderers, and sub-components inline.

### Pages by import complexity

Most pages show 0 local imports because they inline all helper code. The few with external imports are the most architecturally coupled:

| Page | Imports | API Calls |
|---|---|---|
| APISecurityPage | varied | 10 |
| APISecurityDashboard | varied | 7 |
| AuditLog | varied | 5 |
| APISecurityMgmtDashboard | varied | 4 |
| APIThreatProtectionDashboard | varied | 4 |
| DASTDashboard | varied | 3 |
| AutoFix | varied | 2 |
| BrainPipeline | varied | 2 |
| PentestManagementDashboard | varied | 2 |

---

## Orphaned Components

Components that are **never imported by any page** — either dead code or only wired via layout/router.

### Truly orphaned (0 importers anywhere)
These are unused — candidates for deletion or wiring:

| Component | Status |
|---|---|
| `EmptyState` | 0 importers — dead code |
| `EntityLink` | 0 importers — dead code |
| `ErrorBoundary` | 0 importers — dead code |
| `ErrorState` | 0 importers — dead code |
| `ExportButton` | 0 importers — dead code (but implemented) |
| `KeyboardShortcutsHelp` | 0 importers — dead code |
| `LiveEventFeed` | 0 importers — dead code |
| `PageSkeleton` | 0 importers — dead code |
| `Pagination` | 0 importers — dead code |
| `WorkspaceLayout` | 0 importers — dead code |

### shadcn/ui primitives (never wired to pages)
All the shadcn/ui base components are installed but pages do **not** import them — pages inline their own Tailwind instead:

`accordion`, `alert`, `avatar`, `badge`, `button`, `card`, `checkbox`, `collapsible`,
`data-table`, `dialog`, `dropdown-menu`, `input`, `kpi-card`, `label`, `page-header`,
`popover`, `progress`, `scroll-area`, `select`, `separator`, `skeleton`, `switch`,
`table`, `tabs`, `textarea`, `tooltip`

**Implication:** The shadcn/ui component library is installed but bypassed. Pages roll their own Tailwind HTML. This is intentional for now but means the shared design system is not being leveraged.

### Layout-only (imported by WorkspaceLayout, not pages directly)
- `CopilotSidebar` — used in layout only
- `GlobalSearch` — used in layout only
- `NotificationBell` — used in layout only

---

## Complexity Hotspots (most API calls)

Pages making real backend calls (wired to live APIs):

| Page | API Endpoints |
|---|---|
| `APISecurityPage` | `/api/v1/auth/login`, `/api/v1/debug`, `/api/v1/auth/token`, `/api/v1/config`, `/api/v1/export` |
| `APISecurityDashboard` | `/api/v1/config`, `/api/v1/export/data`, `/api/v1/auth/login`, `/api/v1/config/update` |
| `AuditLog` | `/api/v1/auth/login`, `/api/v1/admin/backup` |
| `APISecurityMgmtDashboard` | `/api/v1/health`, `/api/v1/admin/config`, `/api/v1/auth/token`, `/api/v1/cve` |
| `APIThreatProtectionDashboard` | `/api/v1/auth/token`, `/api/v1/profile`, `/api/v1/auth/login`, `/api/v1/export` |
| `DASTDashboard` | `/api/v1/health`, `/api/v1/profile`, `/api/v1/auth/login` |
| `AutoFix` | `/api/v1/autofix/generate/bulk`, `/api/v1/autofix/approve` |
| `BrainPipeline` | `/api/v1/brain/health`, `/api/v1/brain/pipeline/run` |
| `ComplianceCalendarDashboard` | `/api/v1/compliance-calendar` |
| `IntelEnrichmentDashboard` | `/api/v1/intel-enrichment` |
| `ArchReviewDashboard` | `/api/v1/arch-review` |
| `ActorTrackingDashboard` | `/api/v1/actor-tracking` |
| `CloudIRDashboard` | `/api/v1/cloud-ir` |
| `ComplianceMappingDashboard` | `/api/v1/compliance-mapping` |
| `PrivacyImpactDashboard` | `/api/v1/privacy-impact` |
| `FeedSubscriptionsDashboard` | `/api/v1/ioc-enrichment` |
| `VulnerabilityAgeDashboard` | `/api/v1/vuln-age` |
| `ThreatModelingPipelineDashboard` | `/api/v1/threat-modeling-pipeline` |

---

## API Endpoint Coverage

| Metric | Value |
|---|---|
| Total unique API endpoints referenced in UI | 61 |
| Pages with at least 1 live API call | 28 |
| Pages with zero API calls (mock/static) | **337** |

### Most referenced API prefixes
| Endpoint prefix | References |
|---|---|
| `/api/v1/nerve-center` | 3 |
| `/api/v1/config` | 3 |
| `/api/v1/mpte` | 3 |
| `/api/v1/brain` | 3 |
| `/api/v1/autofix` | 3 |
| `/api/v1/auth` | 2 |
| `/api/v1/reachability` | 2 |
| `/api/v1/audit` | 2 |
| `/api/v1/compliance-engine` | 2 |
| `/api/v1/evidence` | 2 |

---

## Pages with No API Calls (Mock / Static Data)

**337 of 365 pages (92%)** have zero API calls — they use mock/static data only.

This directly maps to the CLAUDE.md priority item:
> "Connect 93 frontend pages to real backend data (most currently use mock/static data)"

The actual number needing wiring is **337**, not 93.

Sample of pages with no live API wiring:
- SecurityBenchmarksDashboard, ThreatIntelAutomation, CloudIdentityDashboard
- IdentityRiskDashboard, AssetRiskDashboard, PAMDashboard, PostureAdvisor
- AccessRequestManagementDashboard, UBADashboard, AISecurityAdvisor
- IRPlaybookDashboard, ApplicationRiskDashboard, SecurityGamificationDashboard
- FirmwareSecurityDashboard, SecurityKPIDashboard, OpenClawDashboard
- ThreatScoreDashboard, SecurityBaselineDashboard, ThreatAttributionDashboard
- ScheduledReportsDashboard ... and 317 more

---

## Hook Usage

7 custom hooks exist but **none are imported by pages directly** (pages use inline state). The hooks are available but underutilized:

| Hook | Purpose |
|---|---|
| `use-api` | Generic API fetch with loading/error state |
| `use-auto-refresh` | Polling interval management |
| `use-keyboard-shortcuts` | Global keyboard bindings |
| `use-page-title` | Document title sync |
| `use-pagination` | Page offset/limit state |
| `use-preferences` | User preference persistence |
| `use-sort-filter` | Table sort + filter state |

---

## Graphify Output Files

| File | Location |
|---|---|
| Interactive HTML graph | `graphify-out/graph.html` |
| Raw graph JSON | `graphify-out/graph.json` |
| Full audit report | `graphify-out/GRAPH_REPORT.md` |
| This report | `.omc/reports/graphify_ui_report.md` |

---

## Key Findings Summary

1. **365 pages, 92% mock** — Only 28 pages call real APIs. The frontend/backend gap is larger than documented (337 pages, not 93).
2. **Monolithic page pattern** — Pages are self-contained and don't share components. The 39 components in `/components/` and all shadcn/ui primitives are largely bypassed.
3. **39 orphaned component instances** — 10 have zero importers anywhere (dead code). The full shadcn/ui library (25+ primitives) is installed but unused by pages.
4. **7 hooks, 0 page usage** — Custom hooks exist but pages don't import them — each page manages its own fetch/state inline.
5. **409 communities in 365 pages** — High fragmentation; each dashboard is its own isolated island with no shared component architecture.
6. **61 unique API endpoints in UI** vs 574+ routers in backend — Less than 11% of backend surface area has any UI representation.
