# PRD — Community 430: 404 Not Found Page (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Graceful 404 handling — branded error page with navigation recovery options
- **Persona**: All users who navigate to an invalid route
- **ALDECI Pillar**: UX / Error Handling (Legacy)

## Architecture Diagram
```mermaid
graph TD
    A[App.tsx catch-all route] --> B[NotFound.tsx]
    B --> C[motion.div spring animation]
    B --> D[Shield icon - brand]
    B --> E[404 heading + message]
    B --> F[ArrowLeft - Go Back button]
    B --> G[Home - Dashboard button]
    F --> H[navigate(-1)]
    G --> I[navigate('/')]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/pages/NotFound.tsx:1-40`
- **Animation**: `motion.div` with `initial={{ opacity: 0, scale: 0.95, y: 20 }}` spring transition
- **Icons**: Shield (ALDECI brand), ArrowLeft, Home
- **Buttons**: "Go back" (navigate -1), "Dashboard" (navigate /)
- **Layout**: centered, max-w-md, min-h-[70vh]

## Inter-Dependencies
- **Upstream**: App.tsx `<Route path="*">` catch-all
- **Navigation**: react-router-dom `useNavigate`

## Acceptance Criteria
- [ ] Spring animation on mount
- [ ] Shield brand icon
- [ ] Two recovery options: back and home
- [ ] Centered vertically in viewport
- [ ] Responsive max-w-md

## Effort Estimate
**XS** — 0.5 days (complete, frozen)

## Status
**DONE** — Frozen legacy 404 page
