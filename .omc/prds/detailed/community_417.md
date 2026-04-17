# PRD — Community 417: Tooltip UI Primitive (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Hover tooltip for legacy aldeci UI (parallel to C360 in aldeci-ui-new)
- **Persona**: All users — icon hints, metric explanations
- **ALDECI Pillar**: UI Foundation (Legacy)
- **Note**: This is the legacy version in `suite-ui/aldeci/` — **different** from C360

## Architecture Diagram
```mermaid
graph TD
    A[Legacy Component] -->|import| B[Tooltip - aldeci/src/components/ui/]
    B --> C[@radix-ui/react-tooltip Root]
    B --> D[TooltipProvider]
    B --> E[TooltipTrigger]
    B --> F[TooltipContent - z-50 rounded-md bg-popover]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/components/ui/tooltip.tsx`
- **Exports**: `Tooltip`, `TooltipTrigger`, `TooltipContent`, `TooltipProvider`
- **Pattern**: Identical structure to C360 but in legacy `suite-ui/aldeci/` path

## Inter-Dependencies
- **Upstream**: `@radix-ui/react-tooltip`, `@/lib/utils`
- **Downstream**: CTEMProgressRing step descriptions, SecurityPostureCard metric hints
- **Note**: Legacy UI is FROZEN — do not merge or modify

## Acceptance Criteria
- [ ] Identical behavior to C360 (aldeci-ui-new version)
- [ ] sideOffset=4 default
- [ ] TooltipProvider wraps app

## Effort Estimate
**XS** — 0.25 days (complete, frozen)

## Status
**DONE** — Frozen legacy primitive (do not modify)
