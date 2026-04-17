# PRD — Community 403: Vite Build Configuration (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Optimised production build for the legacy aldeci UI — code splitting, vendor chunking, path aliases
- **Persona**: Frontend Engineers, DevOps
- **ALDECI Pillar**: Build System (Legacy)

## Architecture Diagram
```mermaid
graph TD
    A[vite.config.ts] --> B[plugins: react()]
    A --> C[resolve.alias: @ → ./src]
    A --> D[build.rollupOptions.output.manualChunks]
    D --> E[vendor-react: react + react-dom + react-router-dom]
    D --> F[vendor-query: @tanstack/react-query]
    D --> G[vendor-motion: framer-motion]
    D --> H[vendor-ui: sonner + lucide-react]
```

## Code Proof
- **File**: `suite-ui/aldeci/vite.config.ts:1-30`
- **Plugin**: `@vitejs/plugin-react` for JSX transform + Fast Refresh
- **Alias**: `@` → `./src` (matches tsconfig paths)
- **Chunking**: 4 manual chunks to prevent single large bundle
  - `vendor-react`: ~130KB gzipped
  - `vendor-query`: ~15KB
  - `vendor-motion`: ~50KB
  - `vendor-ui`: ~30KB

## Inter-Dependencies
- **Upstream**: Node.js, Vite 5, Rollup
- **Downstream**: Production `/dist` bundle served by static hosting
- **Mirror**: `suite-ui/aldeci-ui-new/vite.config.ts` (newer, Vite 6)

## Acceptance Criteria
- [ ] `@` alias resolves to `./src` in all imports
- [ ] 4 vendor chunks generated in production build
- [ ] React Fast Refresh works in dev mode
- [ ] Build output in `dist/` directory
- [ ] TypeScript compilation via Vite

## Effort Estimate
**XS** — 0.5 days (complete, frozen)

## Status
**DONE** — Stable, frozen legacy build config
