# PRD — Community 415: Scroll Area UI Primitive (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Custom-styled scrollable container for long lists, log feeds, and chat history
- **Persona**: SOC Analysts scrolling through alert feeds, Copilot chat history
- **ALDECI Pillar**: UI Foundation (Legacy)

## Architecture Diagram
```mermaid
graph TD
    A[LogFeed / ChatHistory] -->|import| B[ScrollArea]
    B --> C[@radix-ui/react-scroll-area Root]
    C --> D[Viewport - overflow hidden]
    C --> E[ScrollAreaScrollbar - vertical/horizontal]
    E --> F[ScrollAreaThumb - bg-border rounded-full]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/components/ui/scroll-area.tsx`
- **Exports**: `ScrollArea`, `ScrollAreaScrollbar`
- **Scrollbar style**: `flex touch-none select-none transition-colors`
- **Thumb**: `bg-border rounded-full`
- **Primitive**: `@radix-ui/react-scroll-area`

## Inter-Dependencies
- **Upstream**: `@radix-ui/react-scroll-area`, `@/lib/utils`
- **Downstream**: Copilot chat history, AuditLogs feed, long dropdown menus, SLSAProvenance detail

## Acceptance Criteria
- [ ] Custom scrollbar visible and styled with `bg-border`
- [ ] Touch support (touch-none prevents default scroll behavior)
- [ ] Horizontal scrollbar available when needed
- [ ] Thumb visible on hover/scroll
- [ ] Native overflow hidden on viewport

## Effort Estimate
**XS** — 0.25 days (complete, frozen)

## Status
**DONE** — Stable primitive (legacy)
