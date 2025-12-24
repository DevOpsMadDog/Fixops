# File-to-Feature Mapping

This appendix provides a comprehensive mapping of every file to its associated feature, API endpoint, CLI command, and frontend hook.

## Frontend MFE Apps

| MFE App | Page File | Hook(s) Used | API Endpoint(s) | CLI Command | Integration Status |
|---------|-----------|--------------|-----------------|-------------|-------------------|
| triage | `web/apps/triage/app/page.tsx` | `useTriage`, `useSystemMode`, `useDemoModeContext` | `GET /api/v1/triage`, `POST /api/v1/triage/export` | `python -m core.cli run` | Fully Integrated |
| findings | `web/apps/findings/app/page.tsx` | `useFindingDetail`, `useDemoMode`, `useSystemMode` | `GET /api/v1/findings/{id}` | `python -m core.cli analyze` | Fully Integrated |
| risk-graph | `web/apps/risk-graph/app/page.tsx` | `useGraph`, `useDemoMode`, `useSystemMode` | `GET /api/v1/graph` | `python -m core.cli run` | Fully Integrated |
| compliance | `web/apps/compliance/app/page.tsx` | `useCompliance`, `useDemoMode`, `useSystemMode` | `GET /api/v1/compliance/summary` | `python -m core.cli compliance` | Fully Integrated |
| evidence | `web/apps/evidence/app/page.tsx` | `useEvidence`, `useDemoMode`, `useSystemMode` | `GET /api/v1/evidence` | `python -m core.cli get-evidence` | Fully Integrated |
| policies | `web/apps/policies/app/page.tsx` | `useState` (demo only) | `GET /api/v1/policies` | `python -m core.cli policies` | NOT Integrated |
| audit | `web/apps/audit/app/page.tsx` | `useState` (demo only) | `GET /api/v1/audit` | `python -m core.cli audit` | NOT Integrated |
| inventory | `web/apps/inventory/app/page.tsx` | `useState` (demo only) | `GET /api/v1/inventory` | `python -m core.cli inventory` | NOT Integrated |
| iac | `web/apps/iac/app/page.tsx` | `useState` (demo only) | `GET /api/v1/iac/findings` | N/A | NOT Integrated |
| secrets | `web/apps/secrets/app/page.tsx` | `useState` (demo only) | `GET /api/v1/secrets` | N/A | NOT Integrated |
| reachability | `web/apps/reachability/app/page.tsx` | `useState`, `useEffect`, `useMemo` | `GET /api/v1/reachability/analyze` | `python -m core.cli reachability` | NOT Integrated |
| workflows | `web/apps/workflows/app/page.tsx` | `useState` (demo only) | `GET /api/v1/workflows` | `python -m core.cli workflows` | NOT Integrated |
| automations | `web/apps/automations/app/page.tsx` | `useState` (demo only) | N/A | N/A | NOT Implemented |
| integrations | `web/apps/integrations/app/page.tsx` | `useState` (demo only) | `GET /api/v1/integrations` | `python -m core.cli integrations` | NOT Integrated |
| users | `web/apps/users/app/page.tsx` | `useState` (demo only) | `GET /api/v1/users` | `python -m core.cli users` | NOT Integrated |
| teams | `web/apps/teams/app/page.tsx` | `useState` (demo only) | `GET /api/v1/teams` | `python -m core.cli teams` | NOT Integrated |
| sso | `web/apps/sso/app/page.tsx` | `useState` (demo only) | `GET /api/v1/auth/sso` | N/A | NOT Integrated |
| settings | `web/apps/settings/app/page.tsx` | `useState` (demo only) | N/A | N/A | NOT Implemented |
| dashboard | `web/apps/dashboard/app/page.tsx` | `useDashboardData`, `useState` | `GET /api/v1/analytics/dashboard` | `python -m core.cli analytics` | Partially Integrated |
| reports | `web/apps/reports/app/page.tsx` | `useReports`, `useReportDownload`, `useApi`, `useSystemMode` | `GET /api/v1/reports` | `python -m core.cli reports` | Fully Integrated |
| saved-views | `web/apps/saved-views/app/page.tsx` | `useState` (demo only) | N/A | N/A | NOT Implemented |
| pentagi | `web/apps/pentagi/app/page.tsx` | `usePentagiData`, `useSystemMode` | `GET /api/v1/pentagi/requests` | `python -m core.cli pentagi` | Fully Integrated |
| micro-pentest | `web/apps/micro-pentest/app/page.tsx` | `useState`, `useEffect` | `GET /api/v1/pentagi/quick` | `python -m core.cli advanced-pentest` | Partially Integrated |
| bulk | `web/apps/bulk/app/page.tsx` | `useState` (demo only) | `POST /api/v1/bulk/*` | N/A | NOT Integrated |
| marketplace | `web/apps/marketplace/app/page.tsx` | `useMarketplaceBrowse`, `useMarketplaceStats`, `useSystemMode` | `GET /api/v1/marketplace/browse` | N/A | Fully Integrated |
| shell | `web/apps/shell/app/page.tsx` | `useEffect` | N/A | N/A | Utility |
| showcase | `web/apps/showcase/app/page.tsx` | `useState`, `useEffect` | N/A | N/A | Utility |

## Backend API Routers

| Router File | Prefix | Endpoints | Database | Core Module | Frontend Hook |
|-------------|--------|-----------|----------|-------------|---------------|
| `apps/api/app.py` | `/api/v1` | 18 | `app.state.*` | `pipeline.py` | `useTriage`, `useGraph` |
| `apps/api/analytics_router.py` | `/api/v1/analytics` | 16 | `analytics_db.py` | `analytics.py` | `useDashboardData` |
| `apps/api/inventory_router.py` | `/api/v1/inventory` | 15 | `inventory_db.py` | `inventory_models.py` | `useInventory` |
| `apps/api/pentagi_router_enhanced.py` | `/api/v1/pentagi` | 14 | `pentagi_db.py` | `pentagi_advanced.py` | `usePentagiRequests` |
| `apps/api/marketplace_router.py` | `/api/v1/marketplace` | 12 | In-memory | N/A | `useMarketplaceBrowse` |
| `apps/api/reports_router.py` | `/api/v1/reports` | 10 | `report_db.py` | `report_models.py` | `useReports` |
| `apps/api/audit_router.py` | `/api/v1/audit` | 10 | `audit_db.py` | `audit_models.py` | `useAuditLogs` |
| `apps/api/teams_router.py` | `/api/v1/teams` | 8 | `user_db.py` | `user_models.py` | `useTeams` |
| `apps/api/policies_router.py` | `/api/v1/policies` | 8 | `policy_db.py` | `policy_models.py` | `usePolicies` |
| `apps/api/integrations_router.py` | `/api/v1/integrations` | 8 | `integration_db.py` | `integration_models.py` | N/A |
| `apps/api/workflows_router.py` | `/api/v1/workflows` | 7 | `workflow_db.py` | `workflow_models.py` | `useWorkflows` |
| `apps/api/users_router.py` | `/api/v1/users` | 6 | `user_db.py` | `user_models.py` | `useUsers` |
| `apps/api/secrets_router.py` | `/api/v1/secrets` | 5 | `secrets_db.py` | `secrets_models.py` | N/A |
| `apps/api/iac_router.py` | `/api/v1/iac` | 5 | `iac_db.py` | `iac_models.py` | N/A |
| `apps/api/bulk_router.py` | `/api/v1/bulk` | 5 | N/A | N/A | N/A |
| `apps/api/auth_router.py` | `/api/v1/auth` | 4 | `auth_db.py` | `auth_models.py` | N/A |
| `apps/api/ide_router.py` | `/api/v1/ide` | 3 | N/A | N/A | N/A |
| `apps/api/health_router.py` | `/health` | 1 | N/A | N/A | N/A |
| `backend/api/evidence/router.py` | `/api/v1/evidence` | 3 | Filesystem | `evidence.py` | `useEvidence` |
| `backend/api/graph/router.py` | `/api/v1/graph` | 4 | `app.state.*` | `processing_layer.py` | `useGraph` |
| `backend/api/risk/router.py` | `/api/v1/risk` | 3 | `app.state.*` | `probabilistic.py` | N/A |
| `backend/api/provenance/router.py` | `/api/v1/provenance` | 2 | Filesystem | N/A | N/A |

## Core Module Files

| Core File | Feature | CLI Command | API Router | Frontend |
|-----------|---------|-------------|------------|----------|
| `core/cli.py` | CLI entry point | All commands | N/A | N/A |
| `core/configuration.py` | Overlay config | `show-overlay` | All routers | N/A |
| `core/evidence.py` | Evidence bundles | `get-evidence`, `copy-evidence` | `evidence/router.py` | Evidence MFE |
| `core/analytics.py` | Analytics store | `analytics` | `analytics_router.py` | Dashboard MFE |
| `core/enhanced_decision.py` | Multi-LLM decisions | `run`, `make-decision` | `app.py` | Triage MFE |
| `core/probabilistic.py` | Risk forecasting | `run`, `train-forecast` | `risk/router.py` | Risk Graph MFE |
| `core/processing_layer.py` | Data processing | `run` | `graph/router.py` | Risk Graph MFE |
| `core/storage.py` | Artifact archive | `run` | All routers | N/A |
| `core/compliance.py` | Compliance mapping | `compliance` | `app.py` | Compliance MFE |
| `core/pentagi_db.py` | Pentagi database | `pentagi` | `pentagi_router.py` | Pentagi MFE |
| `core/pentagi_models.py` | Pentagi models | `pentagi` | `pentagi_router.py` | Pentagi MFE |
| `core/pentagi_advanced.py` | Advanced pentest | `advanced-pentest` | `pentagi_router.py` | Micro-pentest MFE |
| `core/policy_db.py` | Policy database | `policies` | `policies_router.py` | Policies MFE |
| `core/policy_models.py` | Policy models | `policies` | `policies_router.py` | Policies MFE |
| `core/policy.py` | Policy engine | `policies` | `policies_router.py` | Policies MFE |
| `core/report_db.py` | Report database | `reports` | `reports_router.py` | Reports MFE |
| `core/report_models.py` | Report models | `reports` | `reports_router.py` | Reports MFE |
| `core/user_db.py` | User database | `users`, `teams` | `users_router.py`, `teams_router.py` | Users/Teams MFE |
| `core/user_models.py` | User models | `users`, `teams` | `users_router.py`, `teams_router.py` | Users/Teams MFE |
| `core/audit_db.py` | Audit database | `audit` | `audit_router.py` | Audit MFE |
| `core/audit_models.py` | Audit models | `audit` | `audit_router.py` | Audit MFE |
| `core/inventory_db.py` | Inventory database | `inventory` | `inventory_router.py` | Inventory MFE |
| `core/inventory_models.py` | Inventory models | `inventory` | `inventory_router.py` | Inventory MFE |
| `core/integration_db.py` | Integration database | `integrations` | `integrations_router.py` | Integrations MFE |
| `core/integration_models.py` | Integration models | `integrations` | `integrations_router.py` | Integrations MFE |
| `core/workflow_db.py` | Workflow database | `workflows` | `workflows_router.py` | Workflows MFE |
| `core/workflow_models.py` | Workflow models | `workflows` | `workflows_router.py` | Workflows MFE |
| `core/secrets_db.py` | Secrets database | N/A | `secrets_router.py` | Secrets MFE |
| `core/secrets_models.py` | Secrets models | N/A | `secrets_router.py` | Secrets MFE |
| `core/iac_db.py` | IaC database | N/A | `iac_router.py` | IaC MFE |
| `core/iac_models.py` | IaC models | N/A | `iac_router.py` | IaC MFE |
| `core/iac.py` | IaC scanning | N/A | `iac_router.py` | IaC MFE |
| `core/exploit_signals.py` | KEV/EPSS enrichment | `run` | `app.py` | Triage MFE |
| `core/severity_promotion.py` | Severity adjustment | `run` | `app.py` | Triage MFE |
| `core/demo_runner.py` | Demo mode | `demo` | N/A | All MFEs |
| `core/connectors.py` | External connectors | `integrations` | `integrations_router.py` | Integrations MFE |
| `core/llm_providers.py` | LLM providers | `run` | `enhanced.py` | N/A |
| `core/ai_agents.py` | AI agents | `run` | N/A | N/A |
| `core/hallucination_guards.py` | LLM validation | `run` | N/A | N/A |
| `core/feedback.py` | Feedback recording | `run` | `app.py` | N/A |
| `core/business_context.py` | Business context | `run` | `app.py` | N/A |
| `core/ssdlc.py` | Secure SDLC | `run` | N/A | N/A |
| `core/continuous_validation.py` | Validation | `run` | N/A | N/A |
| `core/onboarding.py` | User onboarding | N/A | N/A | N/A |
| `core/tenancy.py` | Multi-tenancy | N/A | All routers | N/A |
| `core/performance.py` | Performance metrics | N/A | N/A | N/A |

## Shared UI Components

| Component File | Export | Used By |
|----------------|--------|---------|
| `web/packages/ui/src/components/AppShell.tsx` | `AppShell` | All MFEs |
| `web/packages/ui/src/components/Switch.tsx` | `Switch` | Demo mode toggle |
| `web/packages/ui/src/components/StatusBadge.tsx` | `StatusBadge` | Status indicators |
| `web/packages/ui/src/components/StatCard.tsx` | `StatCard` | Dashboard stats |
| `web/packages/ui/src/components/NavItem.tsx` | `NavItem` | Sidebar navigation |
| `web/packages/ui/src/components/Surface.tsx` | `Surface` | Card containers |

## API Client Hooks

| Hook | File | API Endpoint | Used By MFE |
|------|------|--------------|-------------|
| `useApi` | `hooks.ts:14` | Generic | All |
| `useSystemMode` | `hooks.ts:64` | `/api/v1/system-mode` | All |
| `useReports` | `hooks.ts:97` | `/api/v1/reports` | Reports |
| `useReportDownload` | `hooks.ts:125` | `/api/v1/reports/{id}/download` | Reports |
| `usePentagiRequests` | `hooks.ts:159` | `/api/v1/pentagi/requests` | Pentagi |
| `usePentagiResults` | `hooks.ts:192` | `/api/v1/pentagi/results` | Pentagi |
| `usePentagiStats` | `hooks.ts:226` | `/api/v1/pentagi/stats` | Pentagi |
| `useMarketplaceBrowse` | `hooks.ts:239` | `/api/v1/marketplace/browse` | Marketplace |
| `useMarketplaceStats` | `hooks.ts:285` | `/api/v1/marketplace/stats` | Marketplace |
| `useCompliance` | `hooks.ts:301` | `/api/v1/compliance/summary` | Compliance |
| `useFindings` | `hooks.ts:329` | `/api/v1/findings` | Findings |
| `useInventory` | `hooks.ts:364` | `/api/v1/inventory` | Inventory |
| `useUsers` | `hooks.ts:391` | `/api/v1/users` | Users |
| `useTeams` | `hooks.ts:416` | `/api/v1/teams` | Teams |
| `usePolicies` | `hooks.ts:439` | `/api/v1/policies` | Policies |
| `useWorkflows` | `hooks.ts:464` | `/api/v1/workflows` | Workflows |
| `useAuditLogs` | `hooks.ts:490` | `/api/v1/audit` | Audit |
| `useTriage` | `hooks.ts:524` | `/api/v1/triage` | Triage |
| `useTriageExport` | `hooks.ts:574` | `/api/v1/triage/export` | Triage |
| `useGraph` | `hooks.ts:601` | `/api/v1/graph` | Risk Graph |
| `useEvidence` | `hooks.ts:636` | `/api/v1/evidence` | Evidence |
| `useFindingDetail` | `hooks.ts:680` | `/api/v1/findings/{id}` | Findings |
| `useDemoMode` | `hooks.ts:759` | N/A (localStorage) | All |

## End-to-End Feature Flows

### Security Triage Flow
```
User Action: View triage dashboard
Files Involved:
  - web/apps/triage/app/page.tsx (UI)
  - web/packages/api-client/src/hooks.ts:useTriage (Hook)
  - apps/api/app.py:get_triage (API Handler)
  - apps/api/pipeline.py:PipelineOrchestrator (Processing)
  - core/enhanced_decision.py:EnhancedDecisionEngine (Decision)
  - core/evidence.py:EvidenceHub (Evidence)
Data Flow:
  1. page.tsx renders -> calls useTriage()
  2. useTriage() -> HTTP GET /api/v1/triage
  3. get_triage() -> reads app.state.last_pipeline_result
  4. Returns JSON -> hook state -> React render
```

### Risk Graph Flow
```
User Action: View risk graph
Files Involved:
  - web/apps/risk-graph/app/page.tsx (UI)
  - web/packages/api-client/src/hooks.ts:useGraph (Hook)
  - apps/api/app.py:get_graph (API Handler)
  - backend/api/graph/router.py (Graph Generation)
  - core/processing_layer.py:ProcessingLayer (Processing)
Data Flow:
  1. page.tsx renders -> calls useGraph()
  2. useGraph() -> HTTP GET /api/v1/graph
  3. get_graph() -> builds nodes/edges from pipeline data
  4. Returns JSON -> Cytoscape.js render
```

### Evidence Bundle Flow
```
User Action: Download evidence bundle
Files Involved:
  - web/apps/evidence/app/page.tsx (UI)
  - web/packages/api-client/src/hooks.ts:useEvidence (Hook)
  - backend/api/evidence/router.py (API Handler)
  - core/evidence.py:EvidenceHub (Bundle Generation)
Data Flow:
  1. page.tsx renders -> calls useEvidence()
  2. useEvidence() -> HTTP GET /api/v1/evidence
  3. Router reads evidence_bundle_dir
  4. User clicks download -> HTTP GET /api/v1/evidence/{id}/download
  5. Returns binary file
```

### Report Generation Flow
```
User Action: Generate report
Files Involved:
  - web/apps/reports/app/page.tsx (UI)
  - web/packages/api-client/src/hooks.ts:useReports (Hook)
  - apps/api/reports_router.py (API Handler)
  - core/report_db.py:ReportDB (Database)
  - core/report_models.py (Models)
Data Flow:
  1. page.tsx renders -> calls useReports()
  2. User clicks "Generate" -> HTTP POST /api/v1/reports
  3. reports_router creates report job
  4. Background task generates PDF/CSV
  5. User downloads via useReportDownload()
```

### Pentagi Flow
```
User Action: Request AI pentest
Files Involved:
  - web/apps/pentagi/app/page.tsx (UI)
  - web/packages/api-client/src/hooks.ts:usePentagiRequests (Hook)
  - apps/api/pentagi_router_enhanced.py (API Handler)
  - core/pentagi_db.py:PentagiDB (Database)
  - core/pentagi_advanced.py (Pentest Logic)
Data Flow:
  1. page.tsx renders -> calls usePentagiRequests()
  2. User clicks "Run Pentest" -> HTTP POST /api/v1/pentagi/requests
  3. pentagi_router creates request
  4. Background task executes pentest
  5. Results stored in pentagi_db
  6. User views results via usePentagiResults()
```

## Integration Gaps

| MFE | Hook Exists | Hook Wired | Missing |
|-----|-------------|------------|---------|
| policies | Yes (`usePolicies`) | No | Wire hook to page.tsx |
| audit | Yes (`useAuditLogs`) | No | Wire hook to page.tsx |
| inventory | Yes (`useInventory`) | No | Wire hook to page.tsx |
| users | Yes (`useUsers`) | No | Wire hook to page.tsx |
| teams | Yes (`useTeams`) | No | Wire hook to page.tsx |
| workflows | Yes (`useWorkflows`) | No | Wire hook to page.tsx |
| iac | No | No | Create hook + wire |
| secrets | No | No | Create hook + wire |
| integrations | No | No | Create hook + wire |
| bulk | No | No | Create hook + wire |
| sso | No | No | Create hook + wire |
| settings | No | No | Create hook + wire |
| automations | No | No | Create hook + wire |
| saved-views | No | No | Create hook + wire |
| reachability | No | No | Create hook + wire |
