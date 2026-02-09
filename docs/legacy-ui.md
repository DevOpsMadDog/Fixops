# Legacy UI Documentation

## Deprecation Notice

The micro-frontend (MFE) stack previously located at `web/` has been **deprecated** as of February 2026 and moved to `archive/web_mfe_legacy/`.

## Reason for Deprecation

The legacy MFE stack was built with Next.js and a micro-frontend architecture. It has been replaced by the simpler, unified `suite-ui/aldeci` application for the following reasons:

1. **Complexity Reduction** - The MFE architecture introduced unnecessary complexity for a single-tenant deployment model.
2. **Maintenance Burden** - Multiple packages and build pipelines created CI/CD overhead.
3. **Mock Data Prevalence** - The MFEs contained extensive mock data that was never connected to real backend services.
4. **Unified Experience** - The new ALdeci UI provides a cohesive, single-application experience backed by real API endpoints.

## Official UI: ALdeci

The official FixOps frontend is now located at:

```
suite-ui/aldeci/
```

### Quick Start

```bash
cd suite-ui/aldeci
npm install
npm run dev
# Opens at http://localhost:5173
```

### Configuration

Create a `.env.local` file (or use `.env.example` as a template):

```env
VITE_API_URL=http://localhost:8000
VITE_API_KEY=your-api-key  # optional
```

### Screen-to-API Mapping

See [suite-ui/aldeci/SCREEN_API_MAPPING.md](../suite-ui/aldeci/SCREEN_API_MAPPING.md) for the complete mapping of UI screens to backend API endpoints.

## What Was Deprecated

The following structure was moved from `web/` to `archive/web_mfe_legacy/`:

```
web/
├── apps/               # Individual MFE applications
├── packages/           # Shared packages
├── turbo.json          # Turborepo configuration
├── package.json        # Root package.json
└── frontend-details.md # Original frontend documentation
```

## Migration Guide

If you have custom integrations or extensions built on the legacy MFEs:

1. **Review ALdeci Components** - The new UI uses React + Vite + TypeScript + Tailwind CSS.
2. **Use Screen API Mapping** - Refer to `suite-ui/aldeci/SCREEN_API_MAPPING.md` for endpoint contracts.
3. **Migrate Custom Screens** - Port any custom screens to the new `suite-ui/aldeci/src/pages/` structure.
4. **Remove MFE References** - Update any CI/CD pipelines or scripts that reference `web/`.

## Archived Location

The legacy code is preserved at:

```
archive/web_mfe_legacy/
```

This archive is kept for reference only and will not receive updates. It should **not** be used for production deployments.

## Support

For questions about migration, open an issue on the FixOps repository or consult the development team.
