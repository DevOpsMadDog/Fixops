# UX Directives — Active Queue
> Maintained by: ux-architect (strategic), CEO/Team Lead (interim until ux-architect deployed)
> Last updated: 2026-03-03

---

## UX Directive #1 — Sidebar Restructure: 8 Suites → 5 Workflow Spaces
- **Priority**: P0 (demo-blocking)
- **Assigned to**: frontend-craftsman
- **What**: Rewrite `MainLayout.tsx` NavSection[] array from 8 Technical Suite groups to 5 Workflow Space groups
- **File(s)**: `suite-ui/aldeci/src/layouts/MainLayout.tsx` (lines 74-186)
- **Vision reference**: Section 4.2 of VISION_TO_ACCOMPLISH.MD
- **Acceptance criteria**:
  1. Sidebar shows exactly 5 top-level groups: Mission Control, Discover, Validate, Remediate, Comply
  2. Each group uses correct icon: Target, Search, Zap, Wrench, Shield
  3. All existing pages are accessible (no broken links)
  4. `npm run build` succeeds with 0 errors
  5. No route URL changes needed — just group reorganization

## UX Directive #2 — Remove Math.random() from EvidenceBundles
- **Priority**: P1 (pre-demo polish)
- **Assigned to**: frontend-craftsman
- **What**: Remove DEMO_BUNDLES fallback and Math.random() data generation from EvidenceBundles.tsx. Show proper error state when API fails.
- **File(s)**: `suite-ui/aldeci/src/pages/evidence/EvidenceBundles.tsx`
- **Vision reference**: V3 (Decision Intelligence — real data, not fake)
- **Acceptance criteria**:
  1. Zero Math.random() calls in the file
  2. Zero DEMO_BUNDLES/DEMO_COMPLIANCE hardcoded arrays
  3. API errors show a proper error UI (not fake data)
  4. Loading state shows skeleton, not spinner

## UX Directive #3 — Dark Mode Foundation (post-demo)
- **Priority**: P2 (Sprint 4)
- **Assigned to**: frontend-craftsman (after demo)
- **What**: Add dark mode CSS variables and `dark:` Tailwind classes across all pages
- **File(s)**: All `suite-ui/aldeci/src/pages/**/*.tsx`
- **Vision reference**: Section 4.3 of VISION_TO_ACCOMPLISH.MD — "Dark mode first (Apple Dark Aqua)"
- **Acceptance criteria**:
  1. `dark:` class count > 100 across codebase
  2. Toggle switch in header or settings
  3. Persisted to localStorage
