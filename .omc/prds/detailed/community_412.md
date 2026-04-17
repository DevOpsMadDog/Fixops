# PRD — Community 412: Tabs UI Primitive (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Tab navigation for multi-view pages in the legacy aldeci UI
- **Persona**: All users — tabs used in SOC2EvidenceUI, RuntimeProtection, AttackPaths, etc.
- **ALDECI Pillar**: UI Foundation (Legacy)

## Architecture Diagram
```mermaid
graph TD
    A[Page Component] -->|import| B[Tabs]
    A -->|import| C[TabsList]
    A -->|import| D[TabsTrigger]
    A -->|import| E[TabsContent]
    B --> F[@radix-ui/react-tabs Root]
    C --> G[TabsList - flex border-b]
    D --> H[TabsTrigger - data-state=active underline]
    E --> I[TabsContent - focus-visible ring]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/components/ui/tabs.tsx`
- **Exports**: `Tabs`, `TabsList`, `TabsTrigger`, `TabsContent`
- **Active state**: `data-[state=active]:border-b-2 data-[state=active]:text-foreground`
- **Primitive**: `@radix-ui/react-tabs`

## Inter-Dependencies
- **Upstream**: `@radix-ui/react-tabs`, `@/lib/utils`
- **Downstream**: SOC2EvidenceUI (evidence tabs), RuntimeProtection (overview/alerts/config), IaCScanning, MultiLLM

## Acceptance Criteria
- [ ] Active tab shows border-bottom indicator
- [ ] Keyboard: arrow keys switch tabs
- [ ] `defaultValue` sets initial active tab
- [ ] Controlled with `value` + `onValueChange`

## Effort Estimate
**XS** — 0.5 days (complete, frozen)

## Status
**DONE** — Stable primitive (legacy)
