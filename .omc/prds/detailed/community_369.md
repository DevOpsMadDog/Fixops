# Community 369 PRD — checkbox.tsx

## Master Goal Mapping
Multi-select controls for bulk operations: bulk remediation, bulk asset tagging, policy selection, compliance control selection.

## Architecture Diagram
```mermaid
graph TD
    A[Bulk Action UI] --> B[Checkbox]
    B --> C[@radix-ui/react-checkbox Root]
    C --> D[CheckboxIndicator]
    D --> E[Check icon from lucide-react]
```

## Code Proof
`suite-ui/aldeci-ui-new/src/components/ui/checkbox.tsx:7-20`
```tsx
<CheckboxPrimitive.Root
  className={cn("peer h-4 w-4 rounded-sm border border-primary ... data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground")}
>
  <CheckboxPrimitive.Indicator>
    <Check className="h-4 w-4" />
  </CheckboxPrimitive.Indicator>
</CheckboxPrimitive.Root>
```

## Inter-Dependencies
- **Imports**: `@radix-ui/react-checkbox`, `Check` from `lucide-react`, `cn`
- **Consumers**: Bulk remediation queues, DataTable row selection, compliance control checklists, policy assignment

## Data Flow
`checked` / `onCheckedChange` controlled. Parent aggregates selections into bulk mutation payload.

## Acceptance Criteria
- [ ] `h-4 w-4 rounded-sm` dimensions
- [ ] Check icon visible when `data-[state=checked]`
- [ ] `focus-visible:ring-1` keyboard focus ring
- [ ] ARIA role=checkbox (Radix default)

## Effort Estimate
Already implemented. **0 SP**

## Status
DONE — production ready
