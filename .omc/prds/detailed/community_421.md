# PRD — Community 421: Select UI Primitive (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Dropdown selector for legacy aldeci UI filter/config forms
- **Persona**: All users
- **ALDECI Pillar**: UI Foundation (Legacy)
- **Note**: Legacy parallel to C372 (aldeci-ui-new)

## Architecture Diagram
```mermaid
graph TD
    A[Legacy Form] --> B[Select - aldeci/src/components/ui/]
    B --> C[@radix-ui/react-select Root]
    B --> D[SelectTrigger + SelectContent + SelectItem]
    D --> E[Check icon on selected]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/components/ui/select.tsx`
- **Consumers**: ScannerDashboard scanner type filter, NerveCenter pipeline selector

## Inter-Dependencies
- **Upstream**: `@radix-ui/react-select`, `lucide-react`, `@/lib/utils`
- **Downstream**: ScannerDashboard, NerveCenter, Settings

## Acceptance Criteria
- [ ] Scrollable content with scroll buttons
- [ ] Selected state shows Check icon
- [ ] Keyboard navigable

## Effort Estimate
**XS** — 0.5 days (complete, frozen)

## Status
**DONE** — Frozen legacy primitive
