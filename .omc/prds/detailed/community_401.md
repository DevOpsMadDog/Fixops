# PRD — Community 401: Tailwind CSS Configuration (aldeci legacy UI)

## Master Goal Mapping
- **Platform Goal**: Design system foundation for the legacy aldeci UI — CSS custom properties, color tokens, animations
- **Persona**: Frontend Engineers maintaining the frozen legacy UI
- **ALDECI Pillar**: UI Foundation (Legacy)
- **Note**: Legacy `suite-ui/aldeci/` is FROZEN — do not modify

## Architecture Diagram
```mermaid
graph TD
    A[tailwind.config.js] --> B[darkMode: class]
    A --> C[content: index.html + src/**/*.tsx]
    A --> D[theme.extend.colors]
    D --> E[border: hsl(--border)]
    D --> F[background: hsl(--background)]
    D --> G[primary: hsl(--primary) + foreground]
    D --> H[secondary / destructive / muted / accent / popover / card]
    A --> I[plugins: tailwindcss-animate]
```

## Code Proof
- **File**: `suite-ui/aldeci/tailwind.config.js:1-60+`
- **darkMode**: `["class"]` — toggled via className on html element
- **Color system**: CSS custom properties via `hsl(var(--token))` pattern
- **Tokens**: border, input, ring, background, foreground, primary, secondary, destructive, muted, accent, popover, card
- **Plugin**: `tailwindcss-animate` for enter/exit animations

## Inter-Dependencies
- **Upstream**: PostCSS (`postcss.config.js`), Vite build
- **Downstream**: All legacy aldeci components in `src/components/ui/`
- **Mirror**: `suite-ui/aldeci-ui-new/` uses Tailwind v4 (different config approach)

## Data Flow
```
Tailwind scans content paths → generates utility classes →
CSS custom props from index.css resolve at runtime →
darkMode class on <html> flips to dark theme variants
```

## Acceptance Criteria
- [ ] All HSL color tokens map to CSS custom properties
- [ ] `darkMode: ["class"]` enables theme toggling
- [ ] `tailwindcss-animate` plugin provides animate-* utilities
- [ ] Content paths cover all .tsx files
- [ ] No unused purge of in-use classes

## Effort Estimate
**XS** — 0.5 days (complete, frozen)

## Status
**DONE** — Stable, frozen legacy config
