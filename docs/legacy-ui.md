# Legacy UI — Micro-Frontend Deprecation Notice

## Status: Deprecated

The original micro-frontend (MFE) architecture that lived under `web/` has been
**deprecated** in favour of the unified **Aldeci** single-page application located
at `suite-ui/aldeci/`.

## Migration

All legacy MFE source code has been relocated to:

```
archive/web_mfe_legacy/
```

No new features will be added to the legacy MFEs.  Bug-fixes and security
patches will only be applied to the Aldeci UI going forward.

## Rationale

The MFE approach introduced unnecessary build complexity, inconsistent styling,
and duplicated authentication logic.  The consolidated Vite + React + TypeScript
application in `suite-ui/aldeci/` provides:

- A single build pipeline with Vite for fast HMR and production builds.
- Shared TailwindCSS design tokens for consistent branding.
- Centralised API client backed by `SCREEN_API_MAPPING.md`.
- Playwright-based E2E tests co-located with the UI code.

## References

- Official UI: `suite-ui/aldeci/`
- Screen-to-API mapping: `suite-ui/aldeci/SCREEN_API_MAPPING.md`
- Archive location: `archive/web_mfe_legacy/`
