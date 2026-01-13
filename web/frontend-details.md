# FixOps/Aldeci Frontend Documentation

This document provides comprehensive documentation of all frontend screens, their purposes, layouts, components, API integrations, and deployment information.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Shared Packages](#shared-packages)
3. [Screen Catalog](#screen-catalog)
4. [API Integration Status](#api-integration-status)
5. [Deployment Information](#deployment-information)

---

## Architecture Overview

FixOps frontend is built as a monorepo with multiple Next.js applications sharing common packages.

### Directory Structure

```
/web
├── apps/                    # Individual Next.js applications (32 total)
│   ├── dashboard/          # Main dashboard
│   ├── triage/             # Vulnerability triage inbox
│   ├── scanners/           # Security scanner integrations (CTEM)
│   ├── prioritize/         # ML-based prioritization (CTEM)
│   ├── remediate/          # Remediation workflows (CTEM)
│   ├── validate/           # Attack path validation (CTEM)
│   ├── insight/            # Analytics dashboard (CTEM)
│   └── ... (27 more apps)
├── packages/
│   ├── ui/                 # Shared UI components (@fixops/ui)
│   └── api-client/         # API hooks and client (@fixops/api-client)
└── app-urls.json           # Deployment URL mappings
```

### Technology Stack

- **Framework**: Next.js 14+ with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **State Management**: React hooks (useState, useMemo, useCallback)
- **API Layer**: Custom hooks with fetch API
- **Theme**: Aldeci purple (#6B5AED) with dark slate backgrounds (#0F172A)

---

## Shared Packages

### @fixops/ui (packages/ui)

Shared UI components used across all applications.

#### Key Components

| Component | File | Purpose |
|-----------|------|---------|
| `AppShell` | `components/AppShell.tsx` | Main layout wrapper with sidebar navigation, top bar, demo mode toggle, and command palette |
| `Switch` | `components/Switch.tsx` | Toggle switch for demo/live mode |
| `StatusBadge` | `components/StatusBadge.tsx` | Status indicators (loading, error, demo, live) |
| `StatCard` | `components/StatCard.tsx` | Metric display cards |
| `DemoModeContext` | `components/AppShell.tsx` | React context for demo mode state |

#### AppShell Navigation Sections

The AppShell provides unified navigation organized into sections:

1. **OVERVIEW**: Dashboard, Triage Inbox
2. **ANALYSIS**: Risk Graph, Findings, Compliance, Evidence
3. **VIEWS**: Saved Views, Automations, Integrations
4. **CTEM**: Scanners, Prioritize, Remediate, Validate, Insight
5. **ADMIN**: Settings, Workflows, Users, Teams, Policies, Inventory, Reports, Audit Logs, SSO Config, Secrets, IaC Scanning, Bulk Operations, Pentagi, Shell, Showcase

### @fixops/api-client (packages/api-client)

API client and React hooks for data fetching.

#### Available Hooks

| Hook | API Endpoint | Purpose |
|------|--------------|---------|
| `useApi` | Generic | Base hook for API calls |
| `useSystemMode` | `/api/v1/system-mode` | Demo/enterprise mode management |
| `useDemoMode` | localStorage | Demo data toggle |
| `useReports` | `/api/v1/reports` | Report listing and management |
| `useReportDownload` | `/api/v1/reports/{id}/download` | Report file downloads |
| `usePentagiRequests` | `/api/v1/pentagi/requests` | Pentagi test requests |
| `usePentagiResults` | `/api/v1/pentagi/results` | Pentagi test results |
| `usePentagiStats` | `/api/v1/pentagi/stats` | Pentagi statistics |
| `useMarketplaceBrowse` | `/api/v1/marketplace/browse` | Marketplace content listing |
| `useMarketplaceStats` | `/api/v1/marketplace/stats` | Marketplace statistics |
| `useCompliance` | `/api/v1/compliance/summary` | Compliance framework data |
| `useFindings` | `/api/v1/findings` | Security findings |
| `useFindingDetail` | `/api/v1/findings/{id}` | Single finding details |
| `useInventory` | `/api/v1/inventory` | Asset inventory |
| `useUsers` | `/api/v1/users` | User management |
| `useTeams` | `/api/v1/teams` | Team management |
| `usePolicies` | `/api/v1/policies` | Security policies |
| `useWorkflows` | `/api/v1/workflows` | Automation workflows |
| `useAuditLogs` | `/api/v1/audit` | Audit log entries |
| `useTriage` | `/api/v1/triage` | Triage inbox data |
| `useTriageExport` | `/api/v1/triage/export` | Triage data export |
| `useGraph` | `/api/v1/graph` | Risk graph nodes/edges |
| `useEvidence` | `/api/v1/evidence` | Evidence bundles |
| `useIntegrations` | `/api/v1/integrations` | External integrations |

---

## Screen Catalog

### 1. Dashboard (`/web/apps/dashboard`)

**Purpose**: Main security posture overview with key metrics, trends, and quick actions.

**Layout**:
- Full-width responsive layout wrapped in AppShell
- Header with title, time range selector, team filter, export button
- 4-column metrics grid (responsive: 1 col mobile, 2 col tablet, 4 col desktop)
- 2-column MTTR/MTTD cards
- 3-column charts section (Issue Trend, Severity Distribution, Resolution Time)
- 2-column bottom section (Recent Findings, Top Affected Services)
- 4-column quick actions grid

**Key Components**:
- `MetricCard`: Displays Total Issues, Critical Issues, Avg Resolution, Compliance Score
- `TrendChart`: Recharts-based line/bar charts for trends
- `TeamPerformanceList`: Team-wise vulnerability stats
- `RecentFindingsList`: Latest critical findings
- `QuickActionButtons`: Navigation shortcuts

**API Integration**: `useDashboardData` custom hook (falls back to demo data)

**Code Location**: `/web/apps/dashboard/app/page.tsx`

---

### 2. Triage Inbox (`/web/apps/triage`)

**Purpose**: Main vulnerability management inbox for reviewing, filtering, and triaging security issues with SSVC decision support.

**Layout**:
- Left sidebar (280px): Summary stats, quick filters (New 7d, High/Critical, Exploitable, Internet Facing)
- Main content: Search bar, view mode toggle, data table with sortable columns
- Right panel (slide-out): Issue detail view with remediation guidance

**Key Components**:
- `FilterSidebar`: Quick filter buttons with counts
- `IssueTable`: Sortable, selectable data table with inline editing
- `IssueDetailPanel`: Full issue details, SSVC decision, evidence bundle info
- `BulkActionBar`: Actions for selected issues (assign, tag, snooze, ignore)
- `KeyboardShortcutHelp`: Modal showing keyboard navigation
- `ActivityDrawer`: Issue activity history

**Features**:
- Keyboard navigation (j/k for up/down, x to select, Enter to view)
- Column visibility/pinning customization
- Shareable view URLs with encoded filters
- Inline cell editing with undo support
- Context menu actions

**API Integration**: `useTriage`, `useTriageExport`

**Code Location**: `/web/apps/triage/app/page.tsx` (1746 lines)

---

### 3. Scanners (`/web/apps/scanners`) - CTEM

**Purpose**: Security scanner integrations management - connect, configure, and monitor vulnerability scanners.

**Layout**:
- Left sidebar (288px): Search, category filters (Infrastructure, Application, Cloud, CMDB)
- Main content: Scanner card grid (3 columns on desktop)
- Modal: Scanner configuration form

**Key Components**:
- `CategoryFilter`: Filter buttons with scanner counts
- `ScannerCard`: Scanner info, status badge, stats (assets, vulns, last sync)
- `ConfigurationModal`: URL and API key configuration form
- `SummaryStats`: Connected count, total assets, total vulnerabilities

**Scanner Categories**:
- **Infrastructure**: Qualys VM, Tenable Nessus/io, Rapid7 InsightVM, CrowdStrike Spotlight
- **Application (SAST/DAST)**: Checkmarx, Veracode, SonarQube, Burp Suite, GitHub Advanced Security
- **Cloud/Container**: AWS Inspector, Prisma Cloud, Wiz, Snyk, JFrog Xray
- **CMDB/Asset**: ServiceNow, BMC Remedy, Active Directory, AWS/Azure Cloud

**API Integration**: `useIntegrations`

**Code Location**: `/web/apps/scanners/app/page.tsx` (721 lines)

---

### 4. Prioritize (`/web/apps/prioritize`) - CTEM

**Purpose**: ML-based vulnerability prioritization with transparent risk scoring and threat intelligence correlation.

**Layout**:
- Left sidebar (288px): Summary stats, severity filters, source filters
- Main content: Vulnerability list with risk scores
- Right panel: Risk score breakdown showing factors

**Key Components**:
- `RiskScoreBreakdown`: Shows top 5 factors increasing/decreasing risk
- `ThreatIntelBadges`: KEV, EPSS, exploit kit indicators
- `VulnerabilityCard`: Vuln details with risk score, severity, threat intel
- `QueryBuilder`: Advanced filtering with AND/OR/NOT operators

**Risk Factors Displayed**:
- Severity weight
- EPSS score
- KEV status
- Internet exposure
- Asset criticality
- Compensating controls

**API Integration**: `useFindings`

**Code Location**: `/web/apps/prioritize/app/page.tsx`

---

### 5. Remediate (`/web/apps/remediate`) - CTEM

**Purpose**: Remediation workflow management with plans, SLA tracking, and ticket integration.

**Layout**:
- Left sidebar (288px): Plan list, status filters (Active, Pending, Completed, Overdue)
- Main content: Tabs (Plans, Exceptions, SLAs, Spotlight)
- Detail panel: Plan details with linked vulnerabilities

**Key Components**:
- `RemediationPlanCard`: Plan name, owner, assignee, progress bar, due date
- `SLATracker`: SLA status by severity (Critical: 7d, High: 30d, Medium: 90d, Low: 180d)
- `ExceptionManager`: Risk acceptance records with expiration
- `SpotlightSection`: Celebrity vulnerabilities (Log4Shell, etc.)
- `TicketIntegration`: Jira/ServiceNow ticket links

**API Integration**: `useWorkflows`

**Code Location**: `/web/apps/remediate/app/page.tsx`

---

### 6. Validate (`/web/apps/validate`) - CTEM

**Purpose**: Attack path visualization and security control validation.

**Layout**:
- Left sidebar (288px): Path list, risk filters
- Main content: Attack path visualization graph
- Detail panel: Path details with control effectiveness

**Key Components**:
- `AttackPathGraph`: Visual network showing paths from Internet to Crown Jewels
- `PathRiskScore`: Calculated risk for each attack path
- `ControlEffectiveness`: Shows where security controls block paths
- `AssetDetailPanel`: Vulnerabilities, ports, interfaces for selected node

**API Integration**: `useGraph`

**Code Location**: `/web/apps/validate/app/page.tsx`

---

### 7. Insight (`/web/apps/insight`) - CTEM

**Purpose**: Full-stack security analytics dashboard with customizable KPIs and reporting.

**Layout**:
- Left sidebar (288px): Dashboard selector, time range, business unit filter
- Main content: Widget grid (customizable)
- Export options: PDF, CSV, scheduled reports

**Key Components**:
- `RiskScoreTrend`: Risk score over time chart
- `RemediationVelocity`: Vulns fixed per week/month
- `ScannerCoverage`: % of assets covered by scanner type
- `SeverityDistribution`: Pie/donut chart of severity breakdown
- `TopVulnerableAssets`: Ranked list of most vulnerable assets

**API Integration**: `useFindings`, `useCompliance`

**Code Location**: `/web/apps/insight/app/page.tsx`

---

### 8. Compliance (`/web/apps/compliance`)

**Purpose**: Compliance framework coverage dashboard with control gap analysis.

**Layout**:
- Left sidebar (320px): Framework list with coverage bars, demo mode toggle
- Main content: Framework overview grid or detail view
- Detail view: Control stats, gap list, audit timeline

**Key Components**:
- `FrameworkCard`: Framework name, coverage %, controls passing/failing
- `CoverageBar`: Visual progress bar with color coding
- `ControlGapList`: List of failing controls with severity and remediation
- `AuditTimeline`: Last/next audit dates

**Frameworks Tracked**:
- SOC 2 Type II
- ISO 27001:2022
- PCI-DSS 4.0
- GDPR

**API Integration**: `useCompliance`

**Code Location**: `/web/apps/compliance/app/page.tsx` (629 lines)

---

### 9. Evidence (`/web/apps/evidence`)

**Purpose**: Cryptographic evidence bundle management with signature verification.

**Layout**:
- Left sidebar: Severity filters, date range
- Main content: Evidence bundle list/grid
- Detail panel: Bundle contents, signature verification

**Key Components**:
- `EvidenceBundleCard`: Bundle ID, issue, severity, signature status
- `SignatureVerifier`: Verify bundle integrity
- `RetentionInfo`: Retention mode, days, expiration date
- `ChecksumDisplay`: SHA256 checksum for verification

**API Integration**: `useEvidence`

**Code Location**: `/web/apps/evidence/app/page.tsx`

---

### 10. Risk Graph (`/web/apps/risk-graph`)

**Purpose**: Cytoscape-based visualization of Service -> Component -> CVE relationships.

**Layout**:
- Left sidebar: Node type filters, severity filters
- Main content: Interactive graph visualization
- Detail panel: Selected node information

**Key Components**:
- `CytoscapeGraph`: Interactive node-edge graph
- `NodeTypeFilter`: Filter by service, component, CVE
- `SeverityFilter`: Filter by severity level
- `NodeDetailPanel`: Full details for selected node

**API Integration**: `useGraph`

**Code Location**: `/web/apps/risk-graph/app/page.tsx`

---

### 11. Findings (`/web/apps/findings`)

**Purpose**: Detailed vulnerability analysis with SSVC decisions.

**Layout**:
- Left sidebar: Severity/status filters
- Main content: Findings list
- Detail panel: Full finding details, CVSS, remediation

**API Integration**: `useFindings`, `useFindingDetail`

**Code Location**: `/web/apps/findings/app/page.tsx`

---

### 12. Users (`/web/apps/users`)

**Purpose**: User management - create, edit, delete users and manage roles.

**Layout**:
- Left sidebar (288px): Summary stats, role filters, status filters
- Main content: User table with search
- Modals: Create/edit user forms

**Key Components**:
- `UserTable`: Sortable table with avatar, email, role, status, teams, last login
- `RoleFilter`: Filter by admin, security_analyst, developer, viewer
- `StatusFilter`: Filter by active, inactive, suspended
- `CreateUserModal`: Form for new user creation
- `EditUserModal`: Form for user editing

**API Integration**: `useUsers`

**Code Location**: `/web/apps/users/app/page.tsx` (638 lines)

---

### 13. Teams (`/web/apps/teams`)

**Purpose**: Team management and member assignment.

**Layout**:
- Left sidebar: Team list with member counts
- Main content: Team details, member list
- Modals: Create/edit team forms

**API Integration**: `useTeams`

**Code Location**: `/web/apps/teams/app/page.tsx`

---

### 14. Policies (`/web/apps/policies`)

**Purpose**: Security policy management and evaluation.

**Layout**:
- Left sidebar: Policy type filters, status filters
- Main content: Policy list with evaluation status
- Detail panel: Policy rules and affected resources

**API Integration**: `usePolicies`

**Code Location**: `/web/apps/policies/app/page.tsx`

---

### 15. Workflows (`/web/apps/workflows`)

**Purpose**: Automation workflow management.

**Layout**:
- Left sidebar: Status filters, trigger type filters
- Main content: Workflow list with run history
- Detail panel: Workflow configuration, execution logs

**API Integration**: `useWorkflows`

**Code Location**: `/web/apps/workflows/app/page.tsx`

---

### 16. Inventory (`/web/apps/inventory`)

**Purpose**: Asset inventory with vulnerability counts.

**Layout**:
- Left sidebar: Asset type filters
- Main content: Asset table with risk scores
- Detail panel: Asset details, vulnerabilities

**API Integration**: `useInventory`

**Code Location**: `/web/apps/inventory/app/page.tsx`

---

### 17. Reports (`/web/apps/reports`)

**Purpose**: Report generation and download.

**Layout**:
- Left sidebar: Report type filters
- Main content: Report list with status
- Actions: Generate new report, download existing

**API Integration**: `useReports`, `useReportDownload`

**Code Location**: `/web/apps/reports/app/page.tsx`

---

### 18. Audit Logs (`/web/apps/audit`)

**Purpose**: System audit trail and activity logging.

**Layout**:
- Left sidebar: Action type filters, user filters
- Main content: Audit log table with timestamps
- Detail panel: Full event details

**API Integration**: `useAuditLogs`

**Code Location**: `/web/apps/audit/app/page.tsx`

---

### 19. Integrations (`/web/apps/integrations`)

**Purpose**: External tool connections (Jira, GitHub, Slack, etc.).

**Layout**:
- Left sidebar: Integration category filters
- Main content: Integration card grid
- Modal: Configuration forms

**API Integration**: `useIntegrations`

**Code Location**: `/web/apps/integrations/app/page.tsx`

---

### 20. Marketplace (`/web/apps/marketplace`)

**Purpose**: Browse and purchase compliance packs, policy templates, attack scenarios.

**Layout**:
- Left sidebar: Content type filters, framework filters, pricing filters
- Main content: Content card grid with ratings
- Detail panel: Content details, purchase options

**API Integration**: `useMarketplaceBrowse`, `useMarketplaceStats`

**Code Location**: `/web/apps/marketplace/app/page.tsx`

---

### 21. Settings (`/web/apps/settings`)

**Purpose**: Organization configuration, API keys, notifications.

**Layout**:
- Left sidebar: Settings category navigation
- Main content: Settings forms by category

**Categories**:
- Organization
- API Keys
- Notifications
- Security
- Appearance

**API Integration**: Custom settings hooks

**Code Location**: `/web/apps/settings/app/page.tsx`

---

### 22. Pentagi (`/web/apps/pentagi`)

**Purpose**: AI-powered penetration testing requests and results.

**Layout**:
- Left sidebar: Request status filters
- Main content: Request list, results view
- Detail panel: Test execution details, evidence

**API Integration**: `usePentagiRequests`, `usePentagiResults`, `usePentagiStats`

**Code Location**: `/web/apps/pentagi/app/page.tsx`

---

### 23-32. Additional Apps

| App | Purpose | API Hook |
|-----|---------|----------|
| `automations` | Automation rule management | `useWorkflows` |
| `bulk` | Bulk operations on findings | `useFindings` |
| `iac` | Infrastructure as Code scanning | `useFindings` |
| `micro-pentest` | Micro penetration testing | `usePentagiRequests` |
| `reachability` | Network reachability analysis | `useGraph` |
| `saved-views` | Saved filter configurations | `useFindings` |
| `secrets` | Secrets scanning results | `useFindings` |
| `shell` | Interactive shell interface | Custom |
| `showcase` | Feature showcase/demo | Demo data |
| `sso` | SSO configuration | `useUsers` |

---

## API Integration Status

### Apps with Real API Integration (8)

These apps properly use API hooks with demo data fallback:

| App | Primary Hook | Status |
|-----|--------------|--------|
| `compliance` | `useCompliance` | Fully integrated |
| `evidence` | `useEvidence` | Fully integrated |
| `findings` | `useFindings` | Fully integrated |
| `marketplace` | `useMarketplaceBrowse` | Fully integrated |
| `pentagi` | `usePentagiRequests` | Fully integrated |
| `reports` | `useReports` | Fully integrated |
| `risk-graph` | `useGraph` | Fully integrated |
| `triage` | `useTriage` | Fully integrated |

### Apps Updated with API Hooks (24)

These apps were updated to use real API hooks with demo data fallback:

| App | Hook Added | Demo Data Constant |
|-----|------------|-------------------|
| `audit` | `useAuditLogs` | `DEMO_AUDIT_LOGS` |
| `automations` | `useWorkflows` | `DEMO_AUTOMATIONS` |
| `bulk` | `useFindings` | `DEMO_BULK_ITEMS` |
| `dashboard` | `useDashboardData` | `DEMO_METRICS` |
| `iac` | `useFindings` | `DEMO_IAC_FINDINGS` |
| `insight` | `useFindings` | `DEMO_INSIGHTS` |
| `integrations` | `useIntegrations` | `DEMO_INTEGRATIONS` |
| `inventory` | `useInventory` | `DEMO_INVENTORY` |
| `micro-pentest` | `usePentagiRequests` | `DEMO_TESTS` |
| `policies` | `usePolicies` | `DEMO_POLICIES` |
| `prioritize` | `useFindings` | `DEMO_VULNERABILITIES` |
| `reachability` | `useGraph` | `DEMO_PATHS` |
| `remediate` | `useWorkflows` | `DEMO_PLANS` |
| `saved-views` | `useFindings` | `DEMO_VIEWS` |
| `scanners` | `useIntegrations` | `DEMO_SCANNERS` |
| `secrets` | `useFindings` | `DEMO_SECRETS` |
| `settings` | Custom | `DEMO_SETTINGS` |
| `shell` | Custom | N/A |
| `showcase` | N/A | Demo only |
| `sso` | `useUsers` | `DEMO_SSO_CONFIG` |
| `teams` | `useTeams` | `DEMO_TEAMS` |
| `users` | `useUsers` | `DEMO_USERS` |
| `validate` | `useGraph` | `DEMO_ATTACK_PATHS` |
| `workflows` | `useWorkflows` | `DEMO_WORKFLOWS` |

### Demo/Enterprise Mode Pattern

All apps follow this pattern for data loading:

```typescript
const { demoEnabled } = useDemoModeContext()
const { data: apiData, loading, error } = useApiHook()

const displayData = useMemo(() => {
  if (demoEnabled || !apiData?.items) {
    return DEMO_DATA
  }
  return transformApiData(apiData.items)
}, [demoEnabled, apiData])
```

---

## Deployment Information

### Current Deployments

The dashboard app is deployed to a public URL. Other apps have placeholder URLs in `app-urls.json`.

| App | Deployment URL | Status |
|-----|----------------|--------|
| `dashboard` | https://fixops-screen-app-22u9mhwf.devinapps.com | Deployed |
| `users` | https://compliance-testing-app-hqfjw04i.devinapps.com | Deployed |
| `triage` | https://compliance-testing-app-fbmxagxb.devinapps.com | Deployed |
| `compliance` | https://compliance-testing-app-opsmztd0.devinapps.com | Deployed |
| `scanners` | (not deployed) | Pending |
| `prioritize` | (not deployed) | Pending |
| `remediate` | (not deployed) | Pending |
| `validate` | (not deployed) | Pending |
| `insight` | (not deployed) | Pending |

### Deployment Process

Apps are deployed as static Next.js exports:

1. **Build**: `npm run build` in the app directory
2. **Export**: Next.js generates static files in `/out` directory
3. **Deploy**: Static files deployed to Devin Apps hosting

### URL Configuration

Deployment URLs are configured in `/web/app-urls.json`:

```json
{
  "dashboard": "https://fixops-screen-app-22u9mhwf.devinapps.com",
  "users": "https://compliance-testing-app-hqfjw04i.devinapps.com",
  "scanners": "",
  "prioritize": "",
  ...
}
```

The AppShell component reads these URLs to generate navigation links between apps.

---

## Backend API Endpoints

The frontend expects these API endpoints from the FixOps backend:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/triage` | GET | Triage inbox data |
| `/api/v1/triage/export` | GET | Export triage data |
| `/api/v1/findings` | GET | Security findings list |
| `/api/v1/findings/{id}` | GET | Single finding details |
| `/api/v1/compliance/summary` | GET | Compliance framework data |
| `/api/v1/evidence` | GET | Evidence bundles |
| `/api/v1/graph` | GET | Risk graph nodes/edges |
| `/api/v1/reports` | GET | Reports list |
| `/api/v1/reports/{id}/download` | GET | Download report |
| `/api/v1/users` | GET | User list |
| `/api/v1/teams` | GET | Team list |
| `/api/v1/policies` | GET | Policy list |
| `/api/v1/workflows` | GET | Workflow list |
| `/api/v1/audit` | GET | Audit logs |
| `/api/v1/inventory` | GET | Asset inventory |
| `/api/v1/integrations` | GET | Integration list |
| `/api/v1/marketplace/browse` | GET | Marketplace content |
| `/api/v1/marketplace/stats` | GET | Marketplace statistics |
| `/api/v1/pentagi/requests` | GET | Pentagi requests |
| `/api/v1/pentagi/results` | GET | Pentagi results |
| `/api/v1/pentagi/stats` | GET | Pentagi statistics |
| `/api/v1/system-mode/toggle` | POST | Toggle demo/enterprise mode |

---

## Development Guide

### Running an App Locally

```bash
cd /home/ubuntu/repos/Fixops/web/apps/{app-name}
npm install
npm run dev
```

### Building for Production

```bash
cd /home/ubuntu/repos/Fixops/web/apps/{app-name}
npm run build
```

### Adding a New Screen

1. Create new directory in `/web/apps/{new-app}/`
2. Copy structure from existing app (package.json, tsconfig.json, next.config.js, etc.)
3. Create `app/page.tsx` with:
   - `'use client'` directive
   - Import `AppShell` and `useDemoModeContext` from `@fixops/ui`
   - Import relevant API hook from `@fixops/api-client`
   - Define `DEMO_*` constant for demo data
   - Implement demo/enterprise mode pattern
4. Add app to `NAV_SECTIONS` in `AppShell.tsx`
5. Add deployment URL to `app-urls.json`

---

## PR and Changes

**PR**: https://github.com/DevOpsMadDog/Fixops/pull/237

**Branch**: `devin/1768128342-nopsec-style-screens`

**Key Changes**:
- Added 5 new CTEM screens (scanners, prioritize, remediate, validate, insight)
- Updated 24 apps with real API hooks and demo data fallback
- Integrated all screens into unified AppShell navigation
- Fixed mobile responsiveness for dashboard and AppShell sidebar
