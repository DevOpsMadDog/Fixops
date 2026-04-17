# PRD — Community 395: Login Page (aldeci-ui-new)

## Master Goal Mapping
- **Platform Goal**: Secure authentication entry point for ALDECI platform with JWT-based auth
- **Persona**: All users — first interaction with the platform
- **ALDECI Pillar**: Authentication / RBAC
- **Backend**: `suite-api/apps/api/sso_bridge.py`, JWT auth middleware

## Architecture Diagram
```mermaid
graph TD
    A[Route: /login] --> B[LoginPage.tsx]
    B --> C[useAuth hook: login + loading state]
    B --> D[Email input + Password input toggle]
    B --> E[Form submit → login(email, password)]
    E --> F[POST /api/v1/auth/login]
    F -->|success| G[navigate to / dashboard]
    F -->|failure| H[setError → AlertCircle message]
    B --> I[motion.div fade-in animation]
    B --> J[Shield brand icon]
```

## Code Proof
- **File**: `suite-ui/aldeci-ui-new/src/pages/auth/LoginPage.tsx:1-50+`
- **Hooks**: `useNavigate`, `useAuth` (custom hook), `useState`, `useCallback`
- **Icons**: Shield (brand), LogIn (CTA), Loader2 (loading spinner), AlertCircle (error), Eye/EyeOff (password toggle)
- **Components**: Card, CardContent, CardHeader, CardTitle, CardDescription, Button, Input, Label
- **Animation**: framer-motion `motion.div`

## Inter-Dependencies
- **Auth hook**: `src/lib/auth.ts` — `useAuth()` providing `login`, `loading`, `user`
- **Backend**: `/api/v1/auth/login` → JWT token response
- **Downstream**: redirect to `/` on success, `AccessDenied` page for RBAC failures
- **SAML/OIDC**: SSO bridge supports redirect flow from this page

## Data Flow
```
User enters email + password → handleSubmit → login(email, password) →
loading=true → Loader2 spinner → POST /api/v1/auth/login →
JWT stored in auth context → navigate('/') OR setError(message)
```

## Referenced Docs
- SSO Bridge: `suite-core/core/sso_bridge.py` (70+68 tests, RS256 JWKs)
- CLAUDE.md: SAML/OIDC SSO Bridge completed

## Acceptance Criteria
- [ ] Password visibility toggle (Eye/EyeOff)
- [ ] Loading spinner during login request
- [ ] Error message rendered in AlertCircle on failure
- [ ] Navigate to `/` on successful login
- [ ] Email and password inputs validated (non-empty)
- [ ] Shield brand icon with ALDECI label
- [ ] Keyboard: Enter submits form

## Effort Estimate
**S** — 1 day (complete)

## Status
**DONE** — Production auth page
