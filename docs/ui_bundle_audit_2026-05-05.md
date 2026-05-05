# UI Bundle Size Audit — 2026-05-04

## Source inventory

| Metric | Value |
|--------|-------|
| Total `.tsx` files | 583 |
| Page files (`src/pages/**/*.tsx`) | 529 |
| Legacy pages (`src/pages/_legacy/`) | 290 (49% of all pages) |
| Total LOC (`.ts` + `.tsx`) | 190,222 |
| Legacy page LOC | 93,711 (49% of total) |
| Source directory size | 14 MB |
| Lazy imports declared in App.tsx | 511 |
| Lazy imports with **missing files on disk** | 246 (48%) |

## Build status

Current build **fails** at Rollup entry resolution. `App.tsx` imports 246 page modules that do not exist on disk — the hub-fold Phase 3 consolidation removed source files but left dead `lazy()` stubs in the router. One missing file (`CommandDashboard`) halts the entire build immediately. **No production bundle can be produced until these stubs are removed.**

## Prior dist snapshot (2026-05-02 build — partial page set)

| Chunk | Size (minified, uncompressed) |
|-------|-------------------------------|
| `vendor-charts` (recharts + d3) | 408 KB |
| `index` (app entry) | 245 KB |
| `index.css` | 221 KB |
| `vendor-utils` (date-fns, zustand, sonner, clsx…) | 205 KB |
| `vendor-react` (react + react-dom + scheduler) | 190 KB |
| `vendor-motion` (framer-motion) | 112 KB |
| `vendor-radix` (@radix-ui/* 20 primitives) | 110 KB |
| `vendor-icons` (lucide-react) | 105 KB |
| `vendor-query` (@tanstack/react-query + axios) | 78 KB |
| **Total dist/assets** | **7.4 MB** |

Top 5 heaviest page chunks (from same build):

| Page chunk | Size |
|------------|------|
| `FindingsExplorer` | 60 KB |
| `Compliance` (_legacy) | 53 KB |
| `SOCT1Dashboard` (_legacy) | 45 KB |
| `AssetGraph` (_legacy) | 43 KB |
| `SBOMManagement` | 41 KB |

## Key findings

1. **Build is broken.** 246 ghost `lazy()` imports in `App.tsx` reference files deleted during Phase 3 hub consolidation. Any CI/CD pipeline producing a production build will fail on this.

2. **`_legacy/` is 49% of the codebase by file count and LOC** — 290 files, 93 K lines — and is fully dead weight since Phase 3 folded them into hubs. These should be tree-shaken away once the ghost imports are purged.

3. **`index.js` entry chunk (245 KB) is too large.** App.tsx at 1,674 lines registers 511 routes in a single file. Even with `lazy()`, the route-map evaluation is synchronous and bloats the entry chunk. Target is <80 KB.

4. **`vendor-charts` (408 KB) has no sub-splitting.** Recharts and d3 are bundled together. Pages that use only recharts still pull in d3 tree. Split into `vendor-recharts` / `vendor-d3` so hub pages that don't need d3 skip it.

5. **`vendor-utils` (205 KB) is a catch-all.** date-fns alone is ~75 KB uncompressed. If only `format` and `formatDistance` are used, a targeted import from `date-fns/format` can cut this chunk by ~40%.

6. **`@monaco-editor/react` (~2 MB uncompressed) is in `vendor-utils`** — it will land there once any page importing the editor is loaded. It must get its own chunk `vendor-monaco` and be loaded only on editor routes.

7. **CSS chunk (221 KB) is unsplit.** Tailwind v4 JIT should produce ~20-40 KB for a real app. 221 KB indicates either JIT purging is not working or a large static CSS import is bundled. Audit `src/index.css` for non-JIT `@import` blocks.

## Recommendations (priority order)

### P0 — Unblock the build (no source edits to pages required)
- Remove the 246 dead `lazy()` stubs from `App.tsx` and their matching `<Route>` entries. All folded pages now live in hub tabs — their routes are already handled. This single change restores the build.

### P1 — Shrink entry chunk
- Split `App.tsx` route registration into domain route files (`missionControlRoutes.tsx`, `discoverRoutes.tsx`, etc.) each loaded as a dynamic `import()`. Entry chunk drops from ~245 KB to ~40 KB.

### P2 — Vendor chunk refinement in `vite.config.ts`
- Add `vendor-monaco` chunk: `id.includes('node_modules/@monaco-editor/')`.
- Split charts: `vendor-recharts` vs `vendor-d3` (separate `includes` tests).
- Isolate `date-fns`: `id.includes('node_modules/date-fns/')` — then audit call sites for tree-shaking.

### P3 — CSS purge audit
- Verify `tailwind.config` `content` globs cover all `.tsx` paths so JIT can purge unused utilities. Add a build-time `postcss` size check (`postcss-size` or `cssnano` with report).

### P4 — `_legacy/` deletion
- After confirming all hubs render correctly, delete `src/pages/_legacy/` (290 files, 93 K LOC). This removes dead code from the repo, reduces `tsc` check time, and eliminates confusion about which pages are canonical.

### P5 — Route-level prefetch hints
- Add `<link rel="modulepreload">` for the two or three most-visited hub chunks (Mission Control, Findings Explorer) so they are in cache before the user navigates.

## Expected outcome after P0–P3

| Metric | Current | Target |
|--------|---------|--------|
| Build | BROKEN | Green |
| Entry chunk | 245 KB | <80 KB |
| Total JS (vendor + pages) | ~1.8 MB | <1.2 MB |
| CSS | 221 KB | <50 KB |
| FCP (cold, unthrottled) | unmeasurable | <1.5 s |
