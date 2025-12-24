# Frontend Architecture

## Overview

The FixOps frontend is a monorepo containing 27 Micro Frontend (MFE) applications built with Next.js 14, plus shared packages for UI components and API client hooks.

## Repository Structure

```
web/
├── apps/                        # 27 MFE applications
│   ├── triage/                  # Security issue triage
│   ├── findings/                # Finding details
│   ├── risk-graph/              # Interactive risk graph
│   ├── compliance/              # Compliance management
│   ├── evidence/                # Evidence bundles
│   ├── policies/                # Policy management
│   ├── audit/                   # Audit logs
│   ├── inventory/               # Asset inventory
│   ├── iac/                     # IaC scanning
│   ├── secrets/                 # Secret detection
│   ├── reachability/            # Network reachability
│   ├── workflows/               # Workflow automation
│   ├── automations/             # Automation rules
│   ├── integrations/            # Third-party integrations
│   ├── users/                   # User management
│   ├── teams/                   # Team management
│   ├── sso/                     # SSO configuration
│   ├── settings/                # Organization settings
│   ├── dashboard/               # Executive dashboard
│   ├── reports/                 # Report generation
│   ├── saved-views/             # Saved filter views
│   ├── pentagi/                 # AI penetration testing
│   ├── micro-pentest/           # Quick pentest
│   ├── bulk/                    # Bulk operations
│   ├── marketplace/             # Security marketplace
│   ├── shell/                   # Empty wrapper
│   └── showcase/                # UI component demo
├── packages/                    # Shared packages
│   ├── ui/                      # @fixops/ui - Design system
│   └── api-client/              # @fixops/api-client - API hooks
├── package.json                 # Root package.json
├── pnpm-workspace.yaml          # pnpm workspace config
└── turbo.json                   # Turborepo config
```

## MFE Application Structure

Each MFE follows the Next.js 14 App Router structure:

```
apps/{mfe-name}/
├── app/
│   ├── layout.tsx               # Root layout with AppShell
│   ├── page.tsx                 # Main page component
│   └── globals.css              # Global styles
├── package.json                 # App dependencies
├── next.config.js               # Next.js configuration
├── tailwind.config.js           # Tailwind CSS config
└── tsconfig.json                # TypeScript config
```

## Shared Packages

### @fixops/ui

The design system package containing reusable UI components.

**Location:** `web/packages/ui/`

**Key Components:**

| Component | File | Purpose |
|-----------|------|---------|
| `AppShell` | `src/components/AppShell.tsx` | Main application shell with sidebar navigation |
| `Switch` | `src/components/Switch.tsx` | Toggle switch (demo mode) |
| `StatusBadge` | `src/components/StatusBadge.tsx` | Status indicators |
| `StatCard` | `src/components/StatCard.tsx` | Dashboard stat cards |
| `NavItem` | `src/components/NavItem.tsx` | Sidebar navigation items |
| `Surface` | `src/components/Surface.tsx` | Card/panel containers |

**Usage:**
```typescript
import { AppShell, Switch, StatusBadge } from '@fixops/ui';
```

### @fixops/api-client

The API client package containing React hooks for data fetching.

**Location:** `web/packages/api-client/`

**Key Files:**

| File | Purpose |
|------|---------|
| `src/hooks.ts` | React hooks for API endpoints |
| `src/config.ts` | API configuration |
| `src/index.ts` | Package exports |

**Key Hooks:**

| Hook | API Endpoint | Purpose |
|------|--------------|---------|
| `useApi<T>` | Generic | Base hook for API calls |
| `useTriage` | `/api/v1/triage` | Fetch triage data |
| `useGraph` | `/api/v1/graph` | Fetch risk graph |
| `useEvidence` | `/api/v1/evidence` | Fetch evidence bundles |
| `useCompliance` | `/api/v1/compliance/summary` | Fetch compliance data |
| `useReports` | `/api/v1/reports` | Fetch reports |
| `usePentagiRequests` | `/api/v1/pentagi/requests` | Fetch pentagi requests |
| `useMarketplaceBrowse` | `/api/v1/marketplace/browse` | Fetch marketplace items |

**Usage:**
```typescript
import { useTriage, useGraph, useDemoMode } from '@fixops/api-client';

function MyComponent() {
  const { data, loading, error } = useTriage();
  const { isDemoMode, toggleDemoMode } = useDemoMode();
  
  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  
  return <div>{data?.rows.length} issues</div>;
}
```

## AppShell Component

The `AppShell` component provides the main application layout with:

1. **Collapsible Sidebar** - Navigation grouped by category
2. **Top Bar** - Demo mode toggle, user menu
3. **Main Content Area** - Page content

**Navigation Groups:**

| Group | Items |
|-------|-------|
| Security | Triage, Findings, Risk Graph |
| Compliance | Compliance, Evidence, Policies, Audit |
| Assets | Inventory, IaC, Secrets, Reachability |
| Automation | Workflows, Automations, Integrations |
| Organization | Users, Teams, SSO, Settings |
| Reports | Dashboard, Reports, Saved Views |
| Specialized | Pentagi, Micro-Pentest, Bulk, Marketplace |

**Usage:**
```typescript
// app/layout.tsx
import { AppShell } from '@fixops/ui';

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
```

## Demo Mode

Demo mode allows the frontend to display sample data without a backend connection.

**Implementation:**

1. `useDemoMode()` hook manages demo state via localStorage
2. Each page checks demo mode and shows appropriate data
3. Status badge indicates when demo data is being used

**Usage:**
```typescript
import { useDemoMode } from '@fixops/api-client';

function MyPage() {
  const { isDemoMode, toggleDemoMode } = useDemoMode();
  const { data, loading, error } = useTriage();
  
  // If API fails and demo mode is on, show demo data
  const displayData = error && isDemoMode ? DEMO_DATA : data;
  
  return (
    <div>
      {isDemoMode && <StatusBadge status="demo">Demo Mode</StatusBadge>}
      {/* Render displayData */}
    </div>
  );
}
```

## Styling

### Tailwind CSS

All MFEs use Tailwind CSS with a shared configuration:

```javascript
// tailwind.config.js
module.exports = {
  content: [
    './app/**/*.{js,ts,jsx,tsx}',
    '../../packages/ui/src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // Custom colors
      },
    },
  },
  plugins: [],
};
```

### Dark Theme

The default theme is dark mode with:

- Background: `slate-950` (#020617)
- Text: `slate-100` (#f1f5f9)
- Accent: `indigo-600` (#4f46e5)

**globals.css:**
```css
:root {
  --background: #020617;
  --foreground: #f1f5f9;
}

body {
  background: var(--background);
  color: var(--foreground);
}
```

## Development

### Running a Single MFE

```bash
cd web/apps/triage
pnpm dev
```

### Running All MFEs

```bash
cd web
pnpm dev
```

### Building

```bash
cd web
pnpm build
```

### Type Checking

```bash
cd web
pnpm typecheck
```

### Linting

```bash
cd web
pnpm lint
```

## Adding a New MFE

1. Create directory: `web/apps/{mfe-name}/`

2. Create `package.json`:
```json
{
  "name": "@fixops/{mfe-name}",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "next dev -p 3001",
    "build": "next build",
    "start": "next start"
  },
  "dependencies": {
    "@fixops/ui": "workspace:*",
    "@fixops/api-client": "workspace:*",
    "next": "14.0.0",
    "react": "18.2.0",
    "react-dom": "18.2.0"
  }
}
```

3. Create `app/layout.tsx`:
```typescript
import { AppShell } from '@fixops/ui';
import './globals.css';

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
```

4. Create `app/page.tsx`:
```typescript
'use client';

import { useMyData } from '@fixops/api-client';

export default function MyPage() {
  const { data, loading, error } = useMyData();
  
  return (
    <div>
      <h1>My MFE</h1>
      {/* Page content */}
    </div>
  );
}
```

5. Add to navigation in `AppShell.tsx`

## Adding a New Hook

1. Open `web/packages/api-client/src/hooks.ts`

2. Add hook function:
```typescript
export function useMyData(options?: UseApiOptions) {
  return useApi<MyDataResponse>('/api/v1/my-endpoint', options);
}
```

3. Export from `index.ts`:
```typescript
export { useMyData } from './hooks';
```

4. Use in MFE:
```typescript
import { useMyData } from '@fixops/api-client';
```

## Integration Status

| MFE | API Integration | Notes |
|-----|-----------------|-------|
| triage | Fully integrated | `useTriage`, `useTriageExport` |
| findings | Fully integrated | `useFindingDetail` |
| risk-graph | Fully integrated | `useGraph` |
| compliance | Fully integrated | `useCompliance` |
| evidence | Fully integrated | `useEvidence` |
| reports | Fully integrated | `useReports`, `useReportDownload` |
| pentagi | Fully integrated | `usePentagiRequests`, `usePentagiResults` |
| marketplace | Fully integrated | `useMarketplaceBrowse`, `useMarketplaceStats` |
| dashboard | Partially integrated | Custom hook |
| policies | NOT integrated | Hook exists, not wired |
| audit | NOT integrated | Hook exists, not wired |
| inventory | NOT integrated | Hook exists, not wired |
| users | NOT integrated | Hook exists, not wired |
| teams | NOT integrated | Hook exists, not wired |
| workflows | NOT integrated | Hook exists, not wired |
| Others | NOT integrated | Demo data only |

## Troubleshooting

### "Module not found: @fixops/ui"
Run `pnpm install` from the `web/` directory.

### "API error - using demo data"
Backend API not running. Start with:
```bash
uvicorn apps.api.app:create_app --factory --reload
```

### Styles not applying
Ensure `globals.css` is imported in `layout.tsx` and Tailwind config includes package paths.

### TypeScript errors
Run `pnpm typecheck` to see all errors. Ensure `tsconfig.json` extends the base config.
