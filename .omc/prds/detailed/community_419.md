# PRD — Community 419: Separator UI Primitive (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Visual divider in legacy aldeci UI
- **Persona**: All users — layout separation in panels
- **ALDECI Pillar**: UI Foundation (Legacy)
- **Note**: Legacy version — parallel to C367 (aldeci-ui-new)

## Architecture Diagram
```mermaid
graph TD
    A[Legacy Layout] --> B[Separator - aldeci/src/components/ui/]
    B --> C[@radix-ui/react-separator Root]
    C -->|horizontal| D[h-1px w-full bg-border]
    C -->|vertical| E[h-full w-1px bg-border]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/components/ui/separator.tsx`
- **Identical pattern** to C367 but in legacy path
- **Consumers**: MainLayout section dividers, Settings page sections

## Inter-Dependencies
- **Upstream**: `@radix-ui/react-separator`, `@/lib/utils`
- **Downstream**: MainLayout, Settings, Copilot

## Acceptance Criteria
- [ ] Horizontal and vertical orientations
- [ ] decorative=true omits from a11y tree
- [ ] `bg-border` token applied

## Effort Estimate
**XS** — 0.1 days (complete, frozen)

## Status
**DONE** — Frozen legacy primitive (do not modify)
