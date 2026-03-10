# Perplexity Computer — aldeci-ui-new Audit Report

> **Date**: 2026-03-09
> **Auditor**: DevOps AI (Claude Opus 4.6 Fast Mode)
> **Scope**: `suite-ui/aldeci-ui-new/` — Full customer-readiness assessment
> **Commits Audited**: `b0a1bec5` through `8cda7a5d` (Perplexity Computer)
> **Verdict**: ❌ **NOT CUSTOMER-READY** — Requires targeted fixes before deployment

---

## Executive Summary

The `aldeci-ui-new` frontend is a **solid architectural foundation** with real API integration, modern stack choices, and good code organization. However, it has **106 TypeScript errors**, **10 pages with hardcoded/fake data**, and **state persistence issues** that make it unsuitable for customer deployment today.

**Estimated fix effort**: 2-4 hours for a senior developer (most issues are systematic, not architectural).

| Metric | Status |
|--------|--------|
| npm install | ✅ 235 packages, 0 vulnerabilities |
| Vite build | ✅ Succeeds in 3.58s (~60 chunks) |
| TypeScript strict check | ❌ 106 errors across 20 files |
| API integration | ✅ 81 real endpoints, axios + env config |
| Customer-ready pages | 23/48 CLEAN, 7/48 MOSTLY CLEAN |
| Pages with fake data | ❌ 10/48 NOT READY |
| State persistence | ❌ Zustand in-memory only (lost on refresh) |

---

## 1. TypeScript Errors — 106 Total

The build succeeds because Vite doesn't enforce TypeScript strictness, but `npx tsc -b` reveals 106 errors. These cluster into 2 root causes that account for ~95% of failures.

### Error Distribution by Code

| Error Code | Count | Description |
|------------|-------|-------------|
| TS2322 | 100 | Type not assignable (prop type mismatches) |
| TS7053 | 2 | Element implicitly has 'any' type (index access) |
| TS2304 | 2 | Cannot find name (missing import/declaration) |
| TS2551 | 1 | Property does not exist, did you mean...? |
| TS2339 | 1 | Property does not exist on type |

### Error Distribution by File

| File | Errors | Primary Cause |
|------|--------|---------------|
| Playbooks.tsx | 12 | PageHeaderProps, KpiCardProps, unknown→ReactNode |
| AutoFix.tsx | 10 | PageHeaderProps, KpiCardProps, unknown→ReactNode |
| FAILEngine.tsx | 9 | PageHeaderProps, KpiCardProps, unknown→ReactNode |
| RemediationCenter.tsx | 9 | PageHeaderProps, KpiCardProps |
| Reachability.tsx | 8 | PageHeaderProps, KpiCardProps |
| MPTEConsole.tsx | 8 | PageHeaderProps, KpiCardProps, unknown→ReactNode |
| ExposureCases.tsx | 8 | PageHeaderProps, KpiCardProps |
| AttackSimulation.tsx | 6 | PageHeaderProps, KpiCardProps |
| Workflows.tsx | 5 | PageHeaderProps, KpiCardProps |
| DataFabric.tsx | 5 | PageHeaderProps, type mismatches |
| CorrelationEngine.tsx | 5 | PageHeaderProps, type mismatches |
| PlaybookEditor.tsx | 2 | Type mismatches |
| Integrations.tsx | 2 | Type mismatches |
| CommandDashboard.tsx | 2 | KpiCardProps |
| KnowledgeGraph.tsx | 2 | Type mismatches |
| AttackPaths.tsx | 2 | Type mismatches |
| TicketIntegration.tsx | 1 | Type mismatch |
| Collaboration.tsx | 1 | Type mismatch |
| ExecutiveView.tsx | 1 | Type mismatch |
| ThreatFeeds.tsx | 1 | Type mismatch |

### Root Cause #1: `PageHeaderProps` Missing `children` Prop (~35 errors)

**File**: `src/components/shared/page-header.tsx`

```typescript
// CURRENT (broken):
interface PageHeaderProps {
  title: string;
  description: string;
  icon?: React.ComponentType<{ className?: string }>;
}

// FIX: Add children prop
interface PageHeaderProps {
  title: string;
  description: string;
  icon?: React.ComponentType<{ className?: string }>;
  children?: React.ReactNode;  // ← ADD THIS
}
```

Nearly every page passes action buttons as `children` to `<PageHeader>`, but the interface doesn't declare a `children` prop. **Fix this one interface and ~35 errors disappear.**

### Root Cause #2: `KpiCardProps` Missing `description` Prop (~15 errors)

**File**: `src/components/shared/kpi-card.tsx`

```typescript
// CURRENT (broken):
interface KpiCardProps {
  title: string;
  value: string | number;
  change?: number;
  icon?: React.ComponentType<{ className?: string }>;
  loading?: boolean;
}

// FIX: Add description prop
interface KpiCardProps {
  title: string;
  value: string | number;
  change?: number;
  description?: string;  // ← ADD THIS
  icon?: React.ComponentType<{ className?: string }>;
  loading?: boolean;
}
```

Many pages pass a `description` prop to `<KpiCard>`. **Fix this one interface and ~15 errors disappear.**

### Root Cause #3: `unknown` Not Assignable to `ReactNode` (~20 errors)

Pages render API response fields like `{data?.field}` but TypeScript infers `unknown` from the API response types. Fix by adding explicit type assertions:

```typescript
// CURRENT:
<span>{finding.severity}</span>

// FIX:
<span>{String(finding.severity)}</span>
// or define proper response types
```

### Remaining Errors (~6)

- **TS7053** (2): Dynamic object indexing without type guard — add `Record<string, unknown>` or `as` assertion
- **TS2304** (2): Missing name reference — likely missing import
- **TS2551** (1): Typo in property name — rename to correct property
- **TS2339** (1): Accessing non-existent property — check API response shape

---

## 2. Pages with Hardcoded / Fake Data — 10 Pages

These pages contain `Math.random()`, hardcoded arrays, or mock data that would display fake information to customers.

### Critical (Customer-Visible Fake Data)

| Page | File | Issue | Fix Effort |
|------|------|-------|------------|
| **SystemHealth** | `settings/SystemHealth.tsx` | 7× `Math.random()` for CPU, memory, disk, latency; `// Placeholder` comment | Medium — need `/api/v1/system/health` endpoint |
| **OnboardingWizard** | `onboarding/OnboardingWizard.tsx` | Step 4 scan results entirely fake: `Math.floor(Math.random() * 50)` for finding counts | Medium — should show real scan results or skip |
| **CorrelationEngine** | `discover/CorrelationEngine.tsx` | `DEDUP_TREND` and `NOISE_PIE` arrays hardcoded with static numbers | Low — replace with API data from deduplication endpoints |
| **DataFabric** | `discover/DataFabric.tsx` | `CORRELATION_TIMELINE`, `SOURCE_RADAR`, `SOURCE_LIST` all hardcoded | Low — wire to real data fabric endpoints |
| **ComplianceDashboard** | `comply/ComplianceDashboard.tsx` | 3 hardcoded fallback arrays for framework data | Low — already has API hooks, just remove fallbacks |
| **Integrations** | `settings/Integrations.tsx` | `SYNC_TIMELINE` hardcoded + 2× `Math.random()` for progress bars | Low — wire to integrations API |
| **SettingsHub** | `settings/SettingsHub.tsx` | Hardcoded org name "Acme Corp" + visible API key strings | Low — read from settings API |

### Moderate (Fallback Data, Less Visible)

| Page | File | Issue | Fix Effort |
|------|------|-------|------------|
| **EvidenceExportCenter** | `comply/EvidenceExportCenter.tsx` | `"Mock export history"` comment with fake export entries | Low |
| **LogViewer** | `settings/LogViewer.tsx` | `Math.random()` in log histogram chart data | Low |
| **Marketplace** | `settings/Marketplace.tsx` | Random health scores and ratings for marketplace items | Low |
| **Policies** | `comply/Policies.tsx` | Hardcoded YAML policy content + rule definitions | Low |
| **ContainerSecurity** | `discover/ContainerSecurity.tsx` | `Math.random()` in vulnerability trend chart | Low |

---

## 3. State Persistence Issue

**File**: `src/stores/index.ts`

The Zustand store uses an in-memory `Map` for persistence instead of `localStorage`:

```typescript
// CURRENT: Custom in-memory storage (state lost on page refresh)
const customStorage = {
  getItem: (name: string) => storage.get(name) ?? null,
  setItem: (name: string, value: string) => storage.set(name, value),
  removeItem: (name: string) => storage.delete(name),
};
```

**Impact**: User preferences (theme, role, sidebar state, onboarding completion) are lost on every page refresh.

**Fix**: Replace with `localStorage`:
```typescript
import { persist } from 'zustand/middleware';

// Use built-in localStorage persistence
persist(storeCreator, {
  name: 'aldeci-store',
  // localStorage is the default storage
});
```

---

## 4. Architectural Concerns

### 4.1 No Error Boundaries on Individual Pages
The app-level `ErrorBoundary` catches crashes, but individual page errors white-screen the entire app. Each workflow space should have its own error boundary.

### 4.2 Knowledge Graph Visualization is a Placeholder
`discover/KnowledgeGraph.tsx` renders a basic force-directed graph using `<canvas>`. For customer demos, this needs a proper graph visualization library (e.g., `react-force-graph`, `cytoscape.js`, or `d3-force`).

### 4.3 RemediationCenter Workflow Advance is a No-Op
The "advance finding through remediation stages" logic in `RemediationCenter.tsx` calls an API but doesn't update local state — the UI doesn't reflect the change until the next refetch cycle.

### 4.4 No Loading States on Some Pages
Some pages don't show loading skeletons when API data is being fetched, causing layout shifts.

### 4.5 Extensive Use of `any` Types
Several pages use `any` for API response data instead of proper TypeScript interfaces. This masks potential runtime errors.

---

## 5. What's GOOD (Keep This)

| Area | Assessment |
|------|-----------|
| **Architecture** | ✅ Excellent — React 19 + Vite 6 + TypeScript + TanStack Query + Zustand |
| **API Client** | ✅ Excellent — 81 real endpoints, env-configurable, proper error handling, 401 interceptor |
| **Code Splitting** | ✅ All 48 routes lazy-loaded with Suspense |
| **UI Components** | ✅ 23 shadcn/ui components, consistent design system |
| **Custom Hooks** | ✅ 30+ TanStack Query hooks with proper caching, invalidation, polling |
| **Error Handling** | ✅ Global ErrorBoundary + per-query error states |
| **Routing** | ✅ 5 Workflow Spaces properly organized |
| **Build Output** | ✅ ~60 optimized chunks, fast build (3.58s) |

### Clean Pages (23/48) — Ready for Customer Demo

These pages use real API hooks, have no fake data, and render properly:

1. CommandDashboard
2. ExecutiveView
3. SLADashboard
4. LiveFeed
5. RiskOverview
6. FindingExplorer
7. CodeScanning
8. SecretsDetection
9. IaCScanning
10. SBOMInventory
11. AttackPaths
12. CloudPosture
13. ThreatFeeds
14. MPTEConsole
15. FAILEngine
16. AttackSimulation
17. Playbooks / PlaybookEditor
18. Collaboration
19. ExposureCases
20. Workflows
21. Analytics
22. EvidenceBundles / Reports / SOC2Evidence
23. CopilotDashboard

### Mostly Clean Pages (7/48) — Minor Fixes Needed

These pages work with real APIs but have minor `Math.random()` fallbacks for individual fields:

1. Reachability
2. BulkOperations
3. TicketIntegration
4. AuditTrail
5. SLSAProvenance
6. Teams
7. Users

---

## 6. Fix Priority (Recommended Order)

### P0 — Must Fix Before Any Customer Demo (1 hour)

| # | Fix | Impact | Files |
|---|-----|--------|-------|
| 1 | Add `children?: React.ReactNode` to `PageHeaderProps` | Fixes ~35 TS errors | `page-header.tsx` |
| 2 | Add `description?: string` to `KpiCardProps` | Fixes ~15 TS errors | `kpi-card.tsx` |
| 3 | Add type assertions for `unknown` → `ReactNode` renders | Fixes ~20 TS errors | 10 page files |
| 4 | Fix remaining 6 TS errors (imports, typos, index types) | Clean TS build | 6 files |
| 5 | Replace Zustand in-memory storage with `localStorage` | State persists across refresh | `stores/index.ts` |

### P1 — Must Fix Before Customer Infrastructure Deploy (2 hours)

| # | Fix | Impact | Files |
|---|-----|--------|-------|
| 6 | Remove all `Math.random()` from SystemHealth | No fake metrics shown | `SystemHealth.tsx` |
| 7 | Remove fake scan results from OnboardingWizard Step 4 | No fake findings count | `OnboardingWizard.tsx` |
| 8 | Remove hardcoded data from CorrelationEngine, DataFabric | No fake charts | 2 files |
| 9 | Wire Integrations page to real sync timeline | No fake progress bars | `Integrations.tsx` |
| 10 | Remove "Acme Corp" and fake API keys from SettingsHub | No embarrassing defaults | `SettingsHub.tsx` |

### P2 — Should Fix (1 hour)

| # | Fix | Impact | Files |
|---|-----|--------|-------|
| 11 | Wire ComplianceDashboard fallbacks to error states | Clean error handling | `ComplianceDashboard.tsx` |
| 12 | Remove mock export history from EvidenceExportCenter | No fake data | `EvidenceExportCenter.tsx` |
| 13 | Remove Math.random from LogViewer, Marketplace, ContainerSecurity | Clean charts | 3 files |
| 14 | Remove hardcoded YAML from Policies | Dynamic policy content | `Policies.tsx` |

### P3 — Nice to Have (Future Sprint)

| # | Fix | Impact |
|---|-----|--------|
| 15 | Replace canvas KnowledgeGraph with proper graph library | Professional visualization |
| 16 | Add per-space ErrorBoundaries | Graceful partial failures |
| 17 | Add proper TypeScript interfaces for all API responses | Type safety |
| 18 | Add optimistic updates to RemediationCenter | Instant UI feedback |

---

## 7. Customer Deployment Checklist

Before deploying to customer infrastructure:

- [ ] All 106 TypeScript errors resolved (`npx tsc -b` exits 0)
- [ ] Zero `Math.random()` calls in production pages
- [ ] Zero hardcoded company names, API keys, or demo data
- [ ] `VITE_API_URL` and `VITE_API_KEY` configurable via environment
- [ ] Zustand state persists across page refresh
- [ ] Vite build succeeds with no warnings
- [ ] All API endpoints return proper error states (no silent failures)
- [ ] Loading skeletons on all pages during data fetch
- [ ] 401 redirect to settings page works correctly
- [ ] `.env.production` template provided for customer ops teams

---

## 8. Overall Grade

| Category | Grade | Notes |
|----------|-------|-------|
| Architecture | **A** | Modern stack, proper patterns, great code organization |
| API Integration | **A** | 81 real endpoints, proper hooks, caching, error handling |
| TypeScript Quality | **D** | 106 errors — but fixable in 1 hour (2 root causes) |
| Data Authenticity | **C+** | 23/48 clean, but 10 pages have fake data |
| State Management | **C** | Zustand chosen well, but persistence broken |
| UI Polish | **B+** | shadcn/ui + Tailwind consistent, good animations |
| Customer Readiness | **C** | Needs P0 + P1 fixes (~3 hours total) |

**Overall: B-** — Strong foundation, systematic but fixable issues. Perplexity built the right architecture but shipped without running `tsc --strict` or auditing for hardcoded data.

---

*Generated by DevOps AI audit agent. For questions, see `.claude/agents/` for agent definitions.*
