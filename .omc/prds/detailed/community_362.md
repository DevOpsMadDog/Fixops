# Community 362 PRD — switch.tsx

## Master Goal Mapping
Provide a binary toggle control for policy enables, feature flags, and notification preferences in ALDECI settings pages.

## Architecture Diagram
```mermaid
graph TD
    A[Settings / Policy Form] --> B[Switch]
    B --> C[@radix-ui/react-switch Root]
    C --> D[SwitchPrimitive.Thumb]
    D --> E[translate-x-4 checked]
    D --> F[translate-x-0 unchecked]
```

## Code Proof
`suite-ui/aldeci-ui-new/src/components/ui/switch.tsx:7-19`
```tsx
<SwitchPrimitives.Root
  className={cn("peer inline-flex h-5 w-9 ... data-[state=checked]:bg-primary data-[state=unchecked]:bg-input")}
>
  <SwitchPrimitives.Thumb className={cn("... data-[state=checked]:translate-x-4 data-[state=unchecked]:translate-x-0")} />
</SwitchPrimitives.Root>
```

## Inter-Dependencies
- **Imports**: `@radix-ui/react-switch`, `cn`
- **Consumers**: WAF rule toggles, MDM policy enables, notification toggles, zero-trust policy switches

## Data Flow
Controlled by `checked` / `onCheckedChange` props. Parent page calls mutation API on change.

## Referenced Docs
- WCAG 4.1.2 — Name, Role, Value (Radix provides ARIA role=switch)

## Acceptance Criteria
- [ ] Thumb translates `translate-x-4` when checked
- [ ] `h-5 w-9` dimensions maintained across breakpoints
- [ ] `disabled:opacity-50` when disabled prop set
- [ ] `focus-visible:ring-2` keyboard focus ring visible

## Effort Estimate
Already implemented. **0 SP**

## Status
DONE — production ready
