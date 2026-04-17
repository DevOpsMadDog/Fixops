# Community 360 PRD — tooltip.tsx

## Master Goal Mapping
Provide accessible, animated tooltip overlays across all ALDECI dashboards.
Persona coverage: all 30 personas (universal UI primitive).

## Architecture Diagram
```mermaid
graph TD
    A[Consumer Component] --> B[TooltipProvider]
    B --> C[Tooltip Root]
    C --> D[TooltipTrigger]
    C --> E[TooltipContent]
    E --> F[@radix-ui/react-tooltip]
    E --> G[cn / tailwind classes]
```

## Code Proof
`suite-ui/aldeci-ui-new/src/components/ui/tooltip.tsx:1-22`
```tsx
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
const TooltipContent = React.forwardRef(({ className, sideOffset = 4, ...props }, ref) => (
  <TooltipPrimitive.Content
    sideOffset={sideOffset}
    className={cn("z-50 overflow-hidden rounded-md bg-popover px-3 py-1.5 text-xs text-popover-foreground shadow-md animate-in fade-in-0 zoom-in-95", className)}
  />
));
export { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider };
```

## Inter-Dependencies
- **Imports**: `@radix-ui/react-tooltip`, `cn` from `@/lib/utils`
- **Consumers**: nav items, data-table column headers, badge icons, action buttons throughout all 296+ dashboard pages

## Data Flow
Static render — no API calls. Props flow: `sideOffset` → Radix positioning engine → CSS `translate`.

## Referenced Docs
- Radix UI Tooltip: https://www.radix-ui.com/docs/primitives/components/tooltip
- WCAG 1.4.13 — Content on Hover or Focus

## Acceptance Criteria
- [ ] Tooltip renders with `sideOffset=4` by default
- [ ] `z-50` ensures tooltip appears above all card/modal layers
- [ ] `animate-in fade-in-0 zoom-in-95` transition fires on open
- [ ] Keyboard accessible (focus triggers tooltip)

## Effort Estimate
Already implemented. Maintenance only. **0 SP**

## Status
DONE — production ready
