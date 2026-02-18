# ALdeci Implementation Guide — Multi-AI Team Orchestration
## Generated: 2026-02-15 | Backend: 539 APIs | UI: 8 Screens to Build

---

# EXECUTIVE SUMMARY

## Current State
| Layer | Status | Details |
|-------|--------|---------|
| **Backend APIs** | ✅ 99% Complete | 539 endpoints implemented (spec: 526) |
| **MCP Server** | ✅ Complete | 8 MCP endpoints + tools/resources/prompts |
| **UI Framework** | ✅ Ready | React 18 + Vite + Tailwind + shadcn/ui |
| **UI Pages** | ✅ Complete | 8 pages implemented |
| **Components** | ✅ Complete | 12 shadcn/ui primitives + 12 ALdeci custom + 3 charts |
| **CLI Wrapper** | ✅ Complete | aldeci CLI with 10 command groups |
| **State Management** | ✅ Complete | zustand stores + SSE hooks |

## What Has Been Built
**8 screens + 12 custom components + 3 chart components + MCP server + CLI wrapper**

---

# PART 1: VERIFIED BACKEND API COVERAGE

## API Endpoint Testing Results
- **Server Status**: Running on port 8000
- **Total Endpoints**: 539 (OpenAPI verified)
- **Health Endpoint**: `GET /api/v1/health` → `{"status":"healthy"}`
- **Auth Required**: Yes (X-API-Key header, token strategy)

## Endpoint Distribution by Domain

| Domain | Count | Key Endpoints |
|--------|-------|---------------|
| **Analytics/Dashboard** | 32 | `/api/v1/analytics/*`, `/api/v1/analytics/dashboard/*` |
| **Copilot + Agents** | 48 | `/api/v1/copilot/*`, `/api/v1/copilot/agents/*` |
| **Brain/Knowledge Graph** | 24 | `/api/v1/brain/*`, `/api/v1/brain/pipeline/*` |
| **Attack/Pentest** | 42 | `/api/v1/attack-sim/*`, `/api/v1/micro-pentest/*` |
| **Evidence/Compliance** | 18 | `/api/v1/evidence/*`, `/api/v1/audit/compliance/*` |
| **Integrations** | 12 | `/api/v1/integrations/*`, `/api/v1/webhooks/*` |
| **AutoFix/Remediation** | 16 | `/api/v1/autofix/*`, `/api/v1/remediation/*` |
| **Deduplication** | 8 | `/api/v1/dedup/*` |
| **Feeds (NVD/EPSS/KEV)** | 12 | `/api/v1/feeds/*` |
| **Users/Teams/Auth** | 24 | `/api/v1/users/*`, `/api/v1/teams/*`, `/api/v1/auth/*` |
| **Other (inventory, policies, etc.)** | ~300 | Various |

## Spec-to-Implementation API Mapping

### S1: Command Center (`/`) — APIs AVAILABLE
| Spec Endpoint | Implemented Endpoint | Status |
|--------------|---------------------|--------|
| `GET /api/v1/dashboard/overview` | `/api/v1/analytics/dashboard/overview` | ✅ Different path |
| `GET /api/v1/dashboard/metrics` | `/api/v1/analytics/mttr`, `/api/v1/analytics/roi` | ✅ Split |
| `GET /api/v1/dashboard/trends` | `/api/v1/analytics/dashboard/trends` | ✅ |
| `GET /api/v1/dashboard/top-risks` | `/api/v1/analytics/dashboard/top-risks` | ✅ |
| `GET /api/v1/nerve-center/pulse` | `/api/v1/nerve-center/pulse` | ✅ |
| `GET /api/v1/brain-pipeline/status` | `/api/v1/brain/pipeline/runs` | ✅ |
| `GET /api/v1/integrations/status` | `/api/v1/integrations` | ✅ |
| `GET /api/v1/copilot/insight` | `/api/v1/copilot/suggestions` | ✅ |

### S2: Findings Hub (`/findings`) — APIs AVAILABLE
| Spec Endpoint | Implemented Endpoint | Status |
|--------------|---------------------|--------|
| `GET /api/v1/findings` | `/api/v1/analytics/findings` | ✅ |
| `GET /api/v1/findings/:id` | `/api/v1/analytics/findings/{id}` | ✅ |
| `POST /api/v1/findings/bulk` | `/api/v1/bulk/findings/*` | ✅ Multiple |
| `GET /api/v1/dedup/status` | `/api/v1/dedup/status` | ✅ |
| `GET /api/v1/dedup/clusters` | `/api/v1/dedup/clusters` | ✅ |
| `POST /api/v1/multi-llm/consensus` | `/api/v1/llm/consensus` | ✅ |
| `GET /api/v1/feeds/nvd/lookup` | `/api/v1/feeds/nvd/*` | ✅ |
| `GET /api/v1/feeds/epss/score` | `/api/v1/feeds/epss/*` | ✅ |
| `GET /api/v1/feeds/kev/check` | `/api/v1/feeds/kev/*` | ✅ |
| `GET /api/v1/exposure-cases` | `/api/v1/exposure-cases` | ✅ |
| `GET /api/v1/gnn/graph` | `/api/v1/algorithms/gnn/*` | ✅ |

### S3: Attack Lab (`/attack`) — APIs AVAILABLE
| Spec Endpoint | Implemented Endpoint | Status |
|--------------|---------------------|--------|
| `POST /api/v1/micro-pentest/run` | `/api/v1/micro-pentest/*` | ✅ Multiple |
| `GET /api/v1/micro-pentest/sessions` | `/api/v1/micro-pentest/sessions` | ✅ |
| `POST /api/v1/attack-simulation/run` | `/api/v1/attack-sim/campaigns/run` | ✅ |
| `GET /api/v1/reachability/analyze` | `/api/v1/reachability/analyze` | ✅ |
| `POST /api/v1/dast/scan` | `/api/v1/dast/scan` | ✅ |
| `POST /api/v1/api-fuzzer/run` | `/api/v1/api-fuzzer/fuzz` | ✅ |

### S4: Connect (`/connect`) — APIs AVAILABLE
| Spec Endpoint | Implemented Endpoint | Status |
|--------------|---------------------|--------|
| `GET /api/v1/integrations` | `/api/v1/integrations` | ✅ |
| `POST /api/v1/integrations` | `/api/v1/integrations` | ✅ |
| `GET /api/v1/webhooks` | `/api/v1/webhooks/endpoints` | ✅ |
| `POST /api/v1/webhooks` | `/api/v1/webhooks/endpoints` | ✅ |
| `POST /api/v1/code/sbom/upload` | `/api/v1/sbom/upload` | ✅ |
| `POST /api/v1/code/scan/upload` | `/api/v1/sarif/upload` | ✅ |

### S5: Evidence (`/evidence`) — APIs AVAILABLE
| Spec Endpoint | Implemented Endpoint | Status |
|--------------|---------------------|--------|
| `GET /api/v1/evidence/bundles` | `/api/v1/evidence/`, `/api/v1/brain/evidence/packs` | ✅ |
| `POST /api/v1/evidence/bundles` | `/api/v1/brain/evidence/generate` | ✅ |
| `GET /api/v1/compliance/soc2` | `/api/v1/audit/compliance/frameworks/{id}/status` | ✅ |
| `GET /api/v1/provenance/verify` | `/api/v1/evidence/verify` | ✅ |
| `GET /api/v1/audit/log` | `/api/v1/audit/logs` | ✅ |

### S6: Pipeline (`/pipeline`) — APIs AVAILABLE
| Spec Endpoint | Implemented Endpoint | Status |
|--------------|---------------------|--------|
| `POST /api/v1/brain-pipeline/run` | `/api/v1/brain/pipeline/run` | ✅ |
| `GET /api/v1/brain-pipeline/runs` | `/api/v1/brain/pipeline/runs` | ✅ |
| `GET /api/v1/remediation/queue` | `/api/v1/remediation/queue` | ✅ |
| `POST /api/v1/remediation/autofix` | `/api/v1/autofix/apply` | ✅ |
| `GET /api/v1/workflows` | `/api/v1/workflows` | ✅ |
| `GET /api/v1/policies` | `/api/v1/policies` | ✅ |

### S7: The Brain (`/brain`) — APIs AVAILABLE
| Spec Endpoint | Implemented Endpoint | Status |
|--------------|---------------------|--------|
| `POST /api/v1/copilot/sessions` | `/api/v1/copilot/sessions` | ✅ |
| `POST /api/v1/copilot/sessions/:id/message` | `/api/v1/copilot/sessions/{session_id}/messages` | ✅ |
| `GET /api/v1/copilot/agents` | `/api/v1/copilot/agents/*` | ✅ |
| `POST /api/v1/multi-llm/consensus` | `/api/v1/llm/consensus` | ✅ |
| `GET /api/v1/nerve-center/intelligence-map` | `/api/v1/nerve-center/intelligence` | ✅ |

### S8: Settings (`/settings`) — APIs AVAILABLE
| Spec Endpoint | Implemented Endpoint | Status |
|--------------|---------------------|--------|
| `GET /api/v1/users` | `/api/v1/users` | ✅ |
| `POST /api/v1/users` | `/api/v1/users` | ✅ |
| `GET /api/v1/teams` | `/api/v1/teams` | ✅ |
| `GET /api/v1/health` | `/api/v1/health` | ✅ |
| `GET /api/v1/health/detailed` | `/api/v1/health/detailed` | ✅ |

---

# PART 2: UI IMPLEMENTATION TASKS

## File Structure to Create

```
suite-ui1/aldeci/src/
├── components/
│   ├── ui/                     # ✅ COMPLETE (12 primitives)
│   │   ├── avatar.tsx          # ✅
│   │   ├── badge.tsx           # ✅ Has severity variants
│   │   ├── button.tsx          # ✅ Has 6 variants
│   │   ├── card.tsx            # ✅
│   │   ├── checkbox.tsx        # ✅
│   │   ├── input.tsx           # ✅
│   │   ├── progress.tsx        # ✅
│   │   ├── scroll-area.tsx     # ✅
│   │   ├── separator.tsx       # ✅
│   │   ├── switch.tsx          # ✅
│   │   ├── tabs.tsx            # ✅
│   │   └── tooltip.tsx         # ✅
│   ├── aldeci/                 # ✅ COMPLETE (12 components)
│   │   ├── finding-card.tsx    # ✅
│   │   ├── severity-badge.tsx  # ✅
│   │   ├── connector-card.tsx  # ✅
│   │   ├── pipeline-step.tsx   # ✅
│   │   ├── metric-card.tsx     # ✅
│   │   ├── chat-message.tsx    # ✅
│   │   ├── approval-card.tsx   # ✅
│   │   ├── compliance-bar.tsx  # ✅
│   │   ├── data-table.tsx      # ✅
│   │   ├── status-dot.tsx      # ✅
│   │   ├── command-palette.tsx # ✅
│   │   └── global-sidebar.tsx  # ✅
│   ├── charts/                 # ✅ COMPLETE (3 components)
│   │   ├── severity-donut.tsx  # ✅
│   │   ├── trend-line.tsx      # ✅
│   │   └── sparkline.tsx       # ✅
│   └── layout/                 # ✅ COMPLETE
│       └── main-layout.tsx     # ✅
├── pages/                      # ✅ COMPLETE (8 pages)
│   ├── command-center/         # S1 ✅
│   │   └── index.tsx           # ✅
│   ├── findings/               # S2 ✅
│   │   └── index.tsx           # ✅
│   ├── attack-lab/             # S3 ✅
│   │   └── index.tsx           # ✅
│   ├── connect/                # S4 ✅
│   │   └── index.tsx           # ✅
│   ├── evidence/               # S5 ✅
│   │   └── index.tsx           # ✅
│   ├── pipeline/               # S6 ✅
│   │   └── index.tsx           # ✅
│   ├── brain/                  # S7 ✅
│   │   └── index.tsx           # ✅
│   └── settings/               # S8 ✅
│       └── index.tsx           # ✅
├── hooks/                      # ✅ COMPLETE
│   └── use-sse.ts              # ✅ SSE streaming hook
│   └── use-pagination.ts
├── stores/                     # ✅ COMPLETE (zustand)
│   └── index.ts                # ✅ auth, findings, ui, notifications stores
├── lib/
│   ├── api.ts                  # ✅ COMPLETE (1190 lines, typed API client)
│   └── utils.ts                # ✅ EXISTS
└── App.tsx                     # ✅ COMPLETE (router setup)
```

---

# ADDITIONAL IMPLEMENTATIONS (COMPLETED)

## MCP Server Backend
**File:** `suite-integrations/api/mcp_router.py` (15KB)

**Endpoints:**
- `GET /api/v1/mcp/status` - MCP server status
- `GET /api/v1/mcp/clients` - Connected clients
- `GET /api/v1/mcp/tools` - Available MCP tools
- `GET /api/v1/mcp/resources` - Available MCP resources
- `GET /api/v1/mcp/prompts` - Available MCP prompts
- `GET /api/v1/mcp/config` - MCP configuration
- `POST /api/v1/mcp/configure` - Update MCP config
- `GET /api/v1/mcp/manifest` - Full MCP manifest

**MCP Tools (8):**
- `fixops_list_findings` - List security findings
- `fixops_get_finding` - Get finding details
- `fixops_run_scan` - Run security scan
- `fixops_check_epss` - Check EPSS score
- `fixops_check_kev` - Check KEV status
- `fixops_list_connectors` - List integrations
- `fixops_run_pipeline` - Run brain pipeline
- `fixops_chat` - Chat with copilot

**MCP Resources (4):**
- Critical findings summary
- Risk score snapshot
- Connector status
- Pipeline status

**MCP Prompts (3):**
- Analyze finding
- Explain CVE
- Suggest remediation

## CLI Wrapper
**File:** `suite-core/cli/aldeci.py` (27KB)
**Executable:** `scripts/aldeci`

**Commands:**
- `aldeci scan` - Security scanning
- `aldeci attack` - Micro-pentest execution
- `aldeci findings` - Finding management
- `aldeci connect` - Integration management
- `aldeci evidence` - Evidence generation
- `aldeci brain` - AI copilot
- `aldeci mcp` - MCP server management
- `aldeci pipeline` - Automation pipeline
- `aldeci auth` - Authentication

---

# PART 3: MULTI-AI TEAM TASK BREAKDOWN (COMPLETED)

## Team Structure

| Agent | Responsibility | Files | Status |
|-------|---------------|-------|--------|
| **Agent-Layout** | Main layout, sidebar, routing | `layout/`, `App.tsx` | ✅ |
| **Agent-Components** | shadcn/ui + custom ALdeci components | `components/aldeci/` | ✅ |
| **Agent-S1** | Command Center page | `pages/command-center/` | ✅ |
| **Agent-S2** | Findings Hub (most complex) | `pages/findings/` | ✅ |
| **Agent-S3** | Attack Lab | `pages/attack-lab/` | ✅ |
| **Agent-S4** | Connect | `pages/connect/` | ✅ |
| **Agent-S5** | Evidence | `pages/evidence/` | ✅ |
| **Agent-S6** | Pipeline | `pages/pipeline/` | ✅ |
| **Agent-S7** | The Brain (chat UI) | `pages/brain/` | ✅ |
| **Agent-S8** | Settings | `pages/settings/` | ✅ |
| **Agent-Hooks** | API hooks, SSE, state | `hooks/`, `stores/` | ✅ |
| **Agent-Charts** | SVG chart wrappers | `components/charts/` | ✅ |
| **Agent-MCP** | MCP server backend | `suite-integrations/api/` | ✅ |
| **Agent-CLI** | CLI wrapper | `suite-core/cli/` | ✅ |

---

## Phase 1 Task Queue — ALL COMPLETE

### Week 1-2: Foundation (Agent-Layout + Agent-Hooks)

**Task 1.1: Router Setup**
```typescript
// App.tsx - Create with react-router-dom
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { MainLayout } from './layouts/main-layout'

// Routes:
// /                 → CommandCenter
// /findings         → FindingsHub
// /findings/:id     → FindingDetail (Sheet)
// /attack           → AttackLab
// /attack/:id       → AttackDetail
// /connect          → Connect
// /evidence         → Evidence
// /evidence/:id     → EvidenceDetail
// /pipeline         → Pipeline
// /brain            → TheBrain
// /settings         → Settings
```

**Task 1.2: Main Layout**
```typescript
// layouts/main-layout.tsx
// - GlobalSidebar (collapsible, 8 nav items)
// - Main content area with ScrollArea
// - CommandPalette (⌘K trigger)
// - Toast provider (sonner)
```

**Task 1.3: API Client Setup**
```typescript
// lib/api.ts - Extend with typed endpoints
// hooks/use-api.ts - TanStack Query wrapper
const API_BASE = 'http://localhost:8000'
// All requests need X-API-Key header
```

**Task 1.4: SSE Hook**
```typescript
// hooks/use-sse.ts
// For: /api/v1/stream/pipeline, /api/v1/stream/copilot
```

---

### Week 3-4: S1 Command Center + S8 Settings (Agent-S1 + Agent-S8)

**Task 2.1: Command Center Page**
- MetricCard grid (Critical, High, Medium, Low counts)
- Sparkline for MTTR trend
- Top 5 Risky Assets list
- Pipeline status indicator
- Connector health summary
- AI Insight banner

**APIs to consume:**
```
GET /api/v1/analytics/dashboard/overview
GET /api/v1/analytics/dashboard/trends
GET /api/v1/analytics/dashboard/top-risks
GET /api/v1/analytics/mttr
GET /api/v1/brain/pipeline/runs
GET /api/v1/integrations
GET /api/v1/copilot/suggestions
```

**Task 2.2: Settings Page**
- Tabs: General, Users & Teams, API Keys, Notifications, System
- Users/Teams CRUD
- System health display

**APIs to consume:**
```
GET /api/v1/users
GET /api/v1/teams
GET /api/v1/health/detailed
GET /api/v1/system/config
```

---

### Week 5-6: S2 Findings Hub (Agent-S2) — CRITICAL

**Task 3.1: Findings List Page**
- DataTable with columns: CVE-ID, Severity, Asset, Source, Status, AI Triage
- Tabs: All, Code, Secrets, IaC, Container, Cloud, Cases, Graph
- Filters: Severity, Source, Asset, Status, Exploitable
- Bulk actions dropdown
- Export button
- Pagination

**Task 3.2: Finding Detail Sheet**
- Slide-out Sheet (not separate page)
- Multi-LLM consensus display
- EPSS/KEV/NVD enrichment badges
- Action buttons: Attack, Evidence, Fix Now, Create Case, Add to Pipeline

**APIs to consume:**
```
GET /api/v1/analytics/findings (paginated, filtered)
GET /api/v1/analytics/findings/{id}
POST /api/v1/bulk/findings/update
GET /api/v1/dedup/clusters
GET /api/v1/llm/consensus
GET /api/v1/feeds/epss/{cve_id}
GET /api/v1/feeds/kev/{cve_id}
GET /api/v1/exposure-cases
```

---

### Week 7-8: S4 Connect (Agent-S4)

**Task 4.1: Integrations Page**
- Tabs: CI/CD, Webhooks, Manual Upload
- ConnectorCard grid (GitHub, GitLab, Jenkins, etc.)
- Webhook list with test button
- File upload dropzone for SBOM/SARIF

**APIs to consume:**
```
GET /api/v1/integrations
POST /api/v1/integrations
DELETE /api/v1/integrations/{id}
GET /api/v1/webhooks/endpoints
POST /api/v1/webhooks/endpoints
POST /api/v1/sbom/upload
POST /api/v1/sarif/upload
```

---

### Week 9-10: S6 Pipeline (Agent-S6)

**Task 5.1: Pipeline Page**
- Tabs: Active Runs, Remediation, Workflows, Policies, History
- PipelineStep component (7-step visualization)
- Progress bar with live updates (SSE)
- Remediation queue table

**APIs to consume:**
```
GET /api/v1/brain/pipeline/runs
POST /api/v1/brain/pipeline/run
GET /api/v1/remediation/queue
GET /api/v1/workflows
GET /api/v1/policies
SSE /api/v1/stream/pipeline
```

---

### Week 11-12: S3 Attack Lab (Agent-S3)

**Task 6.1: Attack Lab Page**
- Tabs: Micro-Pentest, Attack Simulation, Reachability, DAST
- Active sessions table
- Attack stage visualization (5-step)
- Live terminal output component
- AI analysis panel

**APIs to consume:**
```
GET /api/v1/micro-pentest/sessions
POST /api/v1/micro-pentest/run
GET /api/v1/attack-sim/campaigns
POST /api/v1/attack-sim/campaigns/run
GET /api/v1/reachability/paths
SSE /api/v1/stream/attack
```

---

### Week 13: S5 Evidence + S7 Brain (Agent-S5 + Agent-S7)

**Task 7.1: Evidence Page**
- Evidence bundles table
- Compliance dashboard (SOC2, ISO27001, PCI-DSS bars)
- Bundle detail with artifact list
- Generate/Sign buttons

**APIs to consume:**
```
GET /api/v1/evidence/
GET /api/v1/brain/evidence/packs
POST /api/v1/brain/evidence/generate
GET /api/v1/audit/compliance/frameworks
GET /api/v1/audit/logs
```

**Task 7.2: The Brain Page (Phase 1 Copilot)**
- Chat interface (ChatMessage components)
- Session management
- Suggestion cards
- Activity feed (later phases)

**APIs to consume:**
```
GET /api/v1/copilot/sessions
POST /api/v1/copilot/sessions
POST /api/v1/copilot/sessions/{id}/messages
GET /api/v1/copilot/suggestions
SSE /api/v1/stream/copilot
```

---

### Week 14: Integration + Polish

- Cross-screen navigation testing
- URL state persistence
- Error states and loading skeletons
- Dark mode verification
- Accessibility audit
- Performance optimization

---

# PART 4: COMPONENT SPECIFICATIONS

## shadcn/ui Components to Add

Run this command in `suite-ui1/aldeci/`:
```bash
npx shadcn-ui@latest add accordion alert-dialog avatar checkbox \
  command dialog dropdown-menu hover-card label popover select \
  separator sheet skeleton switch table textarea toast toggle \
  toggle-group
```

## Custom Component Specs

### `<MetricCard />`
```typescript
interface MetricCardProps {
  title: string
  value: number | string
  trend?: 'up' | 'down' | 'flat'
  trendValue?: string
  sparkData?: number[]
  onClick?: () => void
}
```

### `<FindingCard />`
```typescript
interface FindingCardProps {
  finding: Finding
  compact?: boolean
  onClick?: (finding: Finding) => void
  selected?: boolean
}
```

### `<SeverityBadge />`
```typescript
interface SeverityBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  showIcon?: boolean
}
```

### `<ConnectorCard />`
```typescript
interface ConnectorCardProps {
  connector: Connector
  onToggle: (id: string, enabled: boolean) => void
  onConfigure: (id: string) => void
}
```

### `<PipelineStep />`
```typescript
interface PipelineStepProps {
  step: {
    name: string
    status: 'pending' | 'running' | 'completed' | 'failed'
    progress?: number
    message?: string
  }
  expanded?: boolean
}
```

### `<ChatMessage />`
```typescript
interface ChatMessageProps {
  message: string
  role: 'user' | 'ai'
  timestamp: Date
  actions?: { label: string; onClick: () => void }[]
  isLoading?: boolean
}
```

---

# PART 5: API CLIENT CONFIGURATION

## Base API Client

```typescript
// lib/api.ts
import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Interceptor for API key
api.interceptors.request.use((config) => {
  const apiKey = localStorage.getItem('fixops_api_key')
  if (apiKey) {
    config.headers['X-API-Key'] = apiKey
  }
  return config
})

export default api
```

## TanStack Query Setup

```typescript
// main.tsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000, // 30 seconds
      refetchOnWindowFocus: false,
    },
  },
})

// Wrap App with QueryClientProvider
```

## SSE Hook

```typescript
// hooks/use-sse.ts
import { useEffect, useState } from 'react'

export function useSSE<T>(url: string) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    const eventSource = new EventSource(url)
    
    eventSource.onmessage = (event) => {
      setData(JSON.parse(event.data))
    }
    
    eventSource.onerror = (e) => {
      setError(new Error('SSE connection failed'))
      eventSource.close()
    }
    
    return () => eventSource.close()
  }, [url])

  return { data, error }
}
```

---

# PART 6: DESIGN TOKENS

Add to `tailwind.config.js`:

```javascript
module.exports = {
  theme: {
    extend: {
      colors: {
        severity: {
          critical: 'hsl(0 84% 60%)',    // red
          high: 'hsl(25 95% 53%)',        // orange
          medium: 'hsl(48 96% 53%)',      // yellow
          low: 'hsl(217 91% 60%)',        // blue
          info: 'hsl(220 9% 46%)',        // gray
        },
        status: {
          healthy: 'hsl(142 71% 45%)',    // green
          degraded: 'hsl(48 96% 53%)',    // yellow
          failed: 'hsl(0 84% 60%)',       // red
          unknown: 'hsl(220 9% 46%)',     // gray
        },
      },
    },
  },
}
```

---

# PART 7: ROUTING CONFIGURATION

```typescript
// App.tsx
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import { MainLayout } from './layouts/main-layout'
import CommandCenter from './pages/command-center'
import FindingsHub from './pages/findings'
import FindingDetail from './pages/findings/[id]'
import AttackLab from './pages/attack'
import Connect from './pages/connect'
import Evidence from './pages/evidence'
import Pipeline from './pages/pipeline'
import TheBrain from './pages/brain'
import Settings from './pages/settings'

const router = createBrowserRouter([
  {
    path: '/',
    element: <MainLayout />,
    children: [
      { index: true, element: <CommandCenter /> },
      { path: 'findings', element: <FindingsHub /> },
      { path: 'findings/:id', element: <FindingDetail /> },
      { path: 'attack', element: <AttackLab /> },
      { path: 'attack/:id', element: <AttackLab /> },
      { path: 'connect', element: <Connect /> },
      { path: 'evidence', element: <Evidence /> },
      { path: 'evidence/:id', element: <Evidence /> },
      { path: 'pipeline', element: <Pipeline /> },
      { path: 'brain', element: <TheBrain /> },
      { path: 'settings', element: <Settings /> },
    ],
  },
])

export default function App() {
  return <RouterProvider router={router} />
}
```

---

# PART 8: AGENT COORDINATION PROTOCOL

## Communication Format

Each agent should report progress using this format:

```
AGENT: Agent-S2
TASK: Findings Hub - DataTable implementation
STATUS: IN_PROGRESS | COMPLETED | BLOCKED
FILES_CREATED: [list of files]
FILES_MODIFIED: [list of files]
APIS_INTEGRATED: [list of endpoints]
BLOCKERS: [list of blockers, if any]
DEPENDENCIES: [what it needs from other agents]
NEXT_STEPS: [upcoming work]
```

## Dependencies Graph

```
Agent-Layout → Agent-Hooks → ALL SCREEN AGENTS
Agent-Components → ALL SCREEN AGENTS
Agent-Charts → Agent-S1 (MetricCard needs Sparkline)

Agent-S1 (Command Center) - No screen dependencies
Agent-S2 (Findings Hub) - Depends on Agent-Components
Agent-S3 (Attack Lab) - Can work in parallel
Agent-S4 (Connect) - Can work in parallel
Agent-S5 (Evidence) - Can work in parallel
Agent-S6 (Pipeline) - Can work in parallel
Agent-S7 (Brain) - Can work in parallel
Agent-S8 (Settings) - Can work in parallel
```

## Integration Points

| Screen A | Screen B | Trigger | Navigation |
|----------|----------|---------|------------|
| S1 | S2 | Click severity count | `/?severity=critical` → `/findings?severity=critical` |
| S2 | S3 | Click "Attack" button | Finding ID passed as state |
| S2 | S5 | Click "Evidence" button | Finding ID passed as state |
| S2 | S6 | Click "Fix Now" button | Opens pipeline modal |
| S3 | S5 | Click "Generate Evidence" | Attack session ID |
| S6 | S5 | View generated evidence | Bundle ID |
| S7 | S2 | Click finding in chat | `/findings/:id` |
| S7 | S6 | Execute remediation | Opens pipeline |

---

# PART 9: QUICK START COMMANDS

```bash
# 1. Start backend
cd /Users/devops.ai/developement/fixops/Fixops/suite-api
export PYTHONPATH="/Users/devops.ai/developement/fixops/Fixops:/Users/devops.ai/developement/fixops/Fixops/suite-api:/Users/devops.ai/developement/fixops/Fixops/suite-core:/Users/devops.ai/developement/fixops/Fixops/suite-attack:/Users/devops.ai/developement/fixops/Fixops/suite-feeds:/Users/devops.ai/developement/fixops/Fixops/suite-evidence-risk:/Users/devops.ai/developement/fixops/Fixops/suite-integrations"
source ../.venv/bin/activate
python -m uvicorn backend.app:create_app --factory --port 8000

# 2. Add missing shadcn components
cd /Users/devops.ai/developement/fixops/Fixops/suite-ui1/aldeci
npx shadcn-ui@latest add accordion alert-dialog avatar checkbox \
  command dialog dropdown-menu hover-card label popover select \
  separator sheet skeleton switch table textarea toast toggle toggle-group

# 3. Start UI development
cd /Users/devops.ai/developement/fixops/Fixops/suite-ui1/aldeci
npm install
npm run dev
```

---

# APPENDIX A: ALL 539 API ENDPOINTS (Reference)

The full list of endpoints is available at:
```
GET http://localhost:8000/openapi.json
```

Or run:
```bash
curl -s http://localhost:8000/openapi.json | python3 -c "import json, sys; d = json.load(sys.stdin); print('\n'.join(sorted(d['paths'].keys())))"
```

---

# APPENDIX B: FIGMA SPEC REFERENCE

See: `/Users/devops.ai/developement/fixops/Fixops/docs/FIGMA_ADVANCED_SPECS_V1.md`

Key sections:
- Part 3: Screen Specifications (lines 168-850)
- Part 7: Implementation Roadmap (lines 1100-1200)
- Part 8: Design System (lines 1200-1500)
- Part 9: Data Architecture (lines 1500+)

---

**Document Version**: 1.0
**Generated By**: GitHub Copilot
**Last Updated**: 2026-02-15
