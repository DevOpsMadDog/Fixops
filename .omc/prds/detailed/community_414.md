# PRD — Community 414: Progress UI Primitive (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Visual progress indicator for security scores, coverage percentages, and task completion
- **Persona**: All users — coverage %, SLSA scores, compliance rates
- **ALDECI Pillar**: UI Foundation (Legacy)

## Architecture Diagram
```mermaid
graph TD
    A[Dashboard Component] -->|value=75| B[Progress]
    B --> C[@radix-ui/react-progress Root]
    C --> D[bg-secondary h-2 rounded-full]
    C --> E[Indicator: bg-primary translateX]
    E --> F[transform: translateX(-100% + value%)]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/components/ui/progress.tsx`
- **Exports**: `Progress`
- **Height**: `h-2` (8px) — compact design
- **Animation**: CSS transform `translateX` for smooth fill
- **Primitive**: `@radix-ui/react-progress`

## Inter-Dependencies
- **Upstream**: `@radix-ui/react-progress`, `@/lib/utils`
- **Downstream**: SOC2EvidenceUI (evidence coverage), RuntimeProtection (threat score), EndpointSecurity (coverage bar)

## Acceptance Criteria
- [ ] value=0 → empty bar; value=100 → full bar
- [ ] Smooth CSS animation on value change
- [ ] `bg-primary` fill color
- [ ] Accessible via `aria-valuenow`

## Effort Estimate
**XS** — 0.25 days (complete, frozen)

## Status
**DONE** — Stable primitive (legacy)
