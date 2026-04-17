# PRD — Community 416: Label UI Primitive (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Accessible form field label component associated with inputs/checkboxes
- **Persona**: All users via form elements
- **ALDECI Pillar**: UI Foundation / Accessibility (Legacy)

## Architecture Diagram
```mermaid
graph TD
    A[Form Field] -->|htmlFor=input-id| B[Label]
    B --> C[@radix-ui/react-label Root]
    C --> D[text-sm font-medium leading-none]
    C --> E[peer-disabled: cursor-not-allowed opacity-70]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/components/ui/label.tsx`
- **Exports**: `Label`
- **Style**: `text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70`
- **Primitive**: `@radix-ui/react-label` for proper `for` attribute handling

## Inter-Dependencies
- **Upstream**: `@radix-ui/react-label`, `class-variance-authority`, `@/lib/utils`
- **Downstream**: LoginPage (Email/Password labels), IaCScanning form, AttackSimulation trigger form

## Acceptance Criteria
- [ ] `htmlFor` prop correctly wires to input `id`
- [ ] Peer-disabled opacity reduces when associated input disabled
- [ ] `text-sm font-medium` applied
- [ ] Accessible `for` attribute via Radix primitive

## Effort Estimate
**XS** — 0.1 days (complete, frozen)

## Status
**DONE** — Stable primitive (legacy)
