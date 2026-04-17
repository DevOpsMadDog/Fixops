# PRD — Community 418: Dialog UI Primitive (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Modal dialog for legacy aldeci UI confirmations and detail views
- **Persona**: All users
- **ALDECI Pillar**: UI Foundation (Legacy)
- **Note**: Legacy version — different from C364 (aldeci-ui-new)

## Architecture Diagram
```mermaid
graph TD
    A[Legacy Page] --> B[Dialog - aldeci/src/components/ui/]
    B --> C[@radix-ui/react-dialog Root]
    B --> D[DialogPortal]
    B --> E[DialogOverlay - bg-black/60]
    B --> F[DialogContent - fixed centered]
    F --> G[Close button top-right]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/components/ui/dialog.tsx`
- **Same pattern** as C364 but legacy path
- **Consumers**: Marketplace install confirm, AuditLogs filter, SOC2EvidenceUI details

## Inter-Dependencies
- **Upstream**: `@radix-ui/react-dialog`, `lucide-react` (X), `@/lib/utils`
- **Downstream**: Marketplace, SOC2EvidenceUI, Playbooks edit form

## Acceptance Criteria
- [ ] Backdrop blur and overlay
- [ ] Focus trap inside dialog
- [ ] Escape key closes
- [ ] Accessible title via DialogTitle

## Effort Estimate
**XS** — 0.5 days (complete, frozen)

## Status
**DONE** — Frozen legacy primitive (do not modify)
