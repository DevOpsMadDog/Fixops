# Community 367 PRD — separator.tsx

## Master Goal Mapping
Visual dividers between sections in cards, sidebars, and command palettes.

## Architecture Diagram
```mermaid
graph TD
    A[Card / Sidebar / Menu] --> B[Separator]
    B --> C[@radix-ui/react-separator]
    C --> D[orientation=horizontal: h-1px w-full]
    C --> E[orientation=vertical: h-full w-1px]
```

## Code Proof
`suite-ui/aldeci-ui-new/src/components/ui/separator.tsx:7-14`
```tsx
<SeparatorPrimitive.Root
  orientation={orientation}
  className={cn("shrink-0 bg-border",
    orientation === "horizontal" ? "h-[1px] w-full" : "h-full w-[1px]"
  )}
/>
```

## Inter-Dependencies
- **Imports**: `@radix-ui/react-separator`, `cn`
- **Consumers**: Card sections, dropdown menu sections, keyboard shortcuts overlay, nav sidebar

## Data Flow
Static — no API calls. `orientation` prop controls axis.

## Acceptance Criteria
- [ ] `h-[1px] w-full` for horizontal
- [ ] `h-full w-[1px]` for vertical
- [ ] `bg-border` uses theme token (adapts dark/light)
- [ ] `decorative=true` default suppresses ARIA role

## Effort Estimate
Already implemented. **0 SP**

## Status
DONE — production ready
