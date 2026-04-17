# Community 363 PRD — avatar.tsx

## Master Goal Mapping
Render user/org avatars in navigation, user profiles, and SOC analyst assignment UI.

## Architecture Diagram
```mermaid
graph TD
    A[Nav / Profile / Assignment] --> B[Avatar]
    B --> C[AvatarImage]
    B --> D[AvatarFallback]
    C --> E[@radix-ui/react-avatar Image]
    D --> F[Initials fallback text]
```

## Code Proof
`suite-ui/aldeci-ui-new/src/components/ui/avatar.tsx:6-28`
```tsx
const Avatar = forwardRef(({ className, ...props }, ref) => (
  <AvatarPrimitive.Root className={cn("relative flex h-10 w-10 shrink-0 overflow-hidden rounded-full", className)} />
));
const AvatarFallback = forwardRef(({ className, ...props }, ref) => (
  <AvatarPrimitive.Fallback className={cn("flex h-full w-full items-center justify-center rounded-full bg-muted text-sm")} />
));
```

## Inter-Dependencies
- **Imports**: `@radix-ui/react-avatar`, `cn`
- **Consumers**: TopNav user menu, SOC analyst cards, threat actor profiles, insider threat user risk view

## Data Flow
`src` prop on `AvatarImage` loads from user profile API or CDN. `AvatarFallback` renders initials when image fails.

## Acceptance Criteria
- [ ] `h-10 w-10 rounded-full` default dimensions
- [ ] Fallback renders when image `src` is empty or errors
- [ ] `bg-muted` fallback background consistent with dark theme

## Effort Estimate
Already implemented. **0 SP**

## Status
DONE — production ready
