# PRD — Community 437: Security Workflows Page (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Security automation workflow management — create, trigger, pause, monitor automated security workflows
- **Persona**: Security Engineer, SOAR Operator, SOC Analyst
- **ALDECI Pillar**: Security Automation / SOAR (Legacy)
- **Backend**: `workflow_router.py` → `/api/v1/workflows`

## Architecture Diagram
```mermaid
graph TD
    A[Route: /protect/workflows] --> B[Workflows.tsx]
    B --> C[useQuery: workflow list]
    B --> D[useMutation: create/trigger/pause]
    B --> E[useQueryClient: optimistic updates]
    B --> F[AnimatePresence: workflow cards]
    B --> G[Workflow card: trigger_count / last_run / status]
    B --> H[Search + filter by status]
    C --> I[GET /api/v1/workflows]
    D --> J[POST /api/v1/workflows/{id}/trigger]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/pages/protect/Workflows.tsx:1-70+`
- **Hooks**: useState, useMemo, useCallback, useQuery, useMutation, useQueryClient, motion, AnimatePresence
- **Icons**: Workflow, Plus, RefreshCw, Play, Pause, CheckCircle2, AlertTriangle, Clock, Search, Filter, Zap, Loader2, ArrowRight, BarChart3, Shield, Bug

## Inter-Dependencies
- **Backend**: workflow_router, security_automation_engine.py (32 tests)
- **Router**: `/api/v1/workflows`
- **Related**: Playbooks, Remediation, SOAR

## Data Flow
```
GET /api/v1/workflows → useMemo filter by search/status →
AnimatePresence card list → trigger → useMutation →
useQueryClient.invalidate → optimistic update →
toast.success/error
```

## Acceptance Criteria
- [ ] Workflow list with trigger count and last run
- [ ] Create new workflow form
- [ ] Trigger/pause per workflow
- [ ] Optimistic UI update on trigger
- [ ] Status filter (active/paused/error)
- [ ] BarChart3 for trigger frequency sparkline

## Effort Estimate
**M** — 2 days (complete, frozen)

## Status
**DONE** — Frozen legacy workflow page
