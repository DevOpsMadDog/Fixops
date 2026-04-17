# PRD — Community 396: Access Denied Page (aldeci-ui-new)

## Master Goal Mapping
- **Platform Goal**: RBAC enforcement UI — show user their role and explain why they lack access
- **Persona**: All roles — displayed when navigating to a page above their RBAC permission level
- **ALDECI Pillar**: Authentication / RBAC / 6-Role System

## Architecture Diagram
```mermaid
graph TD
    A[Protected Route] -->|role check fails| B[AccessDenied.tsx]
    B --> C[useAuth: user.role display]
    B --> D[Shield icon in destructive/10 bg]
    B --> E[Role display: your role is X]
    B --> F[Go back Button → navigate(-1)]
    C --> G[Auth context / JWT claims]
```

## Code Proof
- **File**: `suite-ui/aldeci-ui-new/src/pages/auth/AccessDenied.tsx:1-30`
- **Hooks**: `useNavigate`, `useAuth`
- **Icons**: `Shield` (destructive), `ArrowLeft` (back navigation)
- **Role display**: `user?.role ?? "unknown"` — null-safe
- **Layout**: `flex flex-1 flex-col items-center justify-center gap-4 p-8 text-center`

## Inter-Dependencies
- **Auth context**: `useAuth` from `@/lib/auth` — provides `user.role`
- **RBAC**: 6 roles defined in ALDECI (admin, analyst, viewer, engineer, manager, auditor)
- **Router**: Protected route wrapper redirects here on 403

## Data Flow
```
User navigates to restricted route → ProtectedRoute checks role →
role insufficient → redirect to /access-denied →
AccessDenied reads user.role from auth context → displays message
```

## Acceptance Criteria
- [ ] Displays user's current role in message
- [ ] "Go back" navigates to previous page
- [ ] Shield icon in red (destructive/10) background
- [ ] Null-safe role display (handles logged-out edge case)
- [ ] Centered layout with adequate padding

## Effort Estimate
**XS** — 0.5 days (complete)

## Status
**DONE** — Production RBAC page
