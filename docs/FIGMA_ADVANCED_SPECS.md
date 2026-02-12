# FixOps — Advanced Figma Screen Specifications v2
## Cross-Linked Data Architecture · 526 APIs · 68 Routes · 45+ Screens

> Every screen has: wireframe, API map, **data-in** (what feeds it), **data-out** (what it feeds),
> state machines, deep-link targets, SSE streams, and Zustand store bindings.

---

# PART 1: GLOBAL DATA ARCHITECTURE

## 1.1 Master Entity Relationship Model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FixOps Entity Graph                              │
│                                                                         │
│  ┌──────────┐    contains    ┌──────────┐    grouped     ┌──────────┐  │
│  │  Asset    ├──────────────►│ Finding  ├───────────────►│ Cluster  │  │
│  │ (inventory)│              │(SARIF/SBOM│               │ (dedup)  │  │
│  └─────┬────┘               │ /CNAPP)   │               └────┬─────┘  │
│        │                    └─────┬────┘                     │        │
│        │ mapped-to                │ enriched-by              │ forms  │
│        ▼                         ▼                          ▼        │
│  ┌──────────┐    ┌──────────┐  ┌──────────┐          ┌──────────┐   │
│  │Code-to-  │    │ EPSS/KEV │  │ MPTE     │          │ Exposure │   │
│  │Cloud Map │    │ Feeds    │  │ Result   │          │ Case     │   │
│  └──────────┘    └──────────┘  └─────┬────┘          └────┬─────┘   │
│                                      │ validates          │ tracks  │
│                                      ▼                    ▼         │
│                                ┌──────────┐         ┌──────────┐    │
│                                │Reachabilty│        │ Remed.   │    │
│                                │ Analysis  │        │ Task     │    │
│                                └──────────┘         └────┬─────┘    │
│                                                          │ creates  │
│                                                          ▼          │
│                                                    ┌──────────┐     │
│                                                    │ PR/Ticket│     │
│                                                    │ (ALM)    │     │
│                                                    └──────────┘     │
│                                                                      │
│  Cross-cutting: Copilot Session ←→ Any Entity (finding, case, asset) │
│  Cross-cutting: Evidence Bundle ←→ Any Entity (provenance chain)     │
│  Cross-cutting: SSE Stream ←→ Any long-running operation             │
└─────────────────────────────────────────────────────────────────────────┘
```

## 1.2 Shared Data Objects (TypeScript Interfaces)

These objects flow between screens. Every screen that displays or mutates one is linked.

| Object | Primary Key | Created At | Consumed At | Mutated At |
|--------|------------|-----------|-------------|------------|
| `Finding` | `id` + `cve_id` | Code Scanning, Cloud Posture | Dashboard, Findings View, Correlation, MPTE, Copilot, Reachability, Decision Engine | Bulk Ops, Remediation |
| `Cluster` | `id` + `canonical_cve` | Correlation Engine (auto) | Dashboard, Exposure Cases, Remediation, Bulk Ops | Exposure Cases (add to case) |
| `ExposureCase` | `case_id` | Exposure Cases, Brain Pipeline (auto) | Dashboard (count), Remediation (linked), Copilot | Exposure Cases (transition) |
| `MPTEResult` | `id` + `request_id` | MPTE Console | Findings View (evidence badge), Copilot, Reachability | — |
| `RemediationTask` | `id` | Remediation Center | Dashboard (MTTR), Bulk Ops, Copilot | Remediation Center, AutoFix |
| `EvidenceBundle` | `release` | Evidence Vault, Brain Pipeline | Compliance Reports, SOC2 Evidence, Audit Logs | — |
| `Workflow` | `id` | Workflows page | Playbooks, Nerve Center (triggers) | Workflow Editor |
| `Integration` | `id` | Integrations Hub | Webhooks (connector), Remediation (PR target) | Integrations Settings |
| `CopilotSession` | `session_id` | Copilot Chat | — (self-contained) | Copilot Chat |
| `AttackPath` | computed | Attack Paths (GNN) | Dashboard (top risks), Attack Sim, Copilot | — |
| `Policy` | `id` | Policies page | Decision Engine (rules), Nerve Center | Policies page |
| `BusinessContext` | `asset_id` | Data Fabric | Decision Engine (weighting), Copilot | Data Fabric |

## 1.3 Zustand Stores ↔ Screen Mapping

| Store | Persisted? | Screens Reading | Screens Writing |
|-------|-----------|----------------|----------------|
| `useUIStore` | ✅ `aldeci-ui` | All (sidebar state, theme) | MainLayout, Settings |
| `useAuthStore` | ✅ `aldeci-auth` | API interceptor (every call) | Settings (API key) |
| `useChatStore` | ❌ | Copilot Chat | Copilot Chat |
| `useDashboardStore` | ❌ | Dashboard | Dashboard (on fetch) |
| `useSelectionStore` | ❌ | Bulk Ops, Findings View | Bulk Ops, Findings View |
| `useFindingsStore` | ❌ | Findings View, Correlation | Code Scanning (on ingest), Bulk Ops |
| `useAssetsStore` | ❌ | Inventory, Data Fabric | Code Scanning (SBOM ingest) |
| `usePipelineStore` | ❌ | Brain Pipeline, Nerve Center | Brain Pipeline (on run) |
| `useNotificationsStore` | ❌ | TopBar (bell icon), Collaboration | SSE events, Webhook events |
| `useRuntimeConfigStore` | ❌ | GlobalStatusBar | Overlay Config |

## 1.4 SSE Real-Time Streams

| Stream | Endpoint | Events | Subscribed By |
|--------|---------|--------|--------------|
| Pipeline Progress | `/api/v1/stream/pipeline/{runId}` | `progress`, `complete`, `error` | Brain Pipeline, Nerve Center |
| Live Events | `/api/v1/stream/events` | `finding.created`, `case.transitioned`, `scan.complete` | TopBar notifications, Dashboard activity feed |
| Pentest Live | `/api/v1/stream/pentest/{flowId}` | `test.started`, `test.result`, `test.complete` | Micro Pentest results |
| Copilot Stream | `/api/v1/copilot/sessions/{id}/stream` | `token`, `complete` | Copilot Chat (streaming response) |

---

# PART 2: CROSS-SCREEN DATA FLOW DIAGRAMS

## 2.1 The Finding Lifecycle (master flow)

```
 INGEST                CORRELATE              VERIFY               DECIDE              REMEDIATE             EVIDENCE
┌─────────┐          ┌─────────────┐        ┌──────────┐        ┌──────────┐        ┌───────────┐        ┌──────────┐
│ Code    │ finding  │ Correlation │cluster │ MPTE     │result  │ Decision │action  │ Remed.   │ticket  │ Evidence │
│Scanning ├─────────►│  Engine     ├───────►│ Console  ├───────►│  Engine  ├───────►│  Center  ├───────►│  Vault   │
│         │          │  (dedup)    │        │          │        │          │        │          │        │          │
│ Cloud   │ finding  │  + Fuzzy    │        │ Micro    │        │ SSVC     │        │ AutoFix  │        │ SOC2     │
│Posture  ├─────────►│  Identity   │        │ Pentest  │        │ + CVSS   │        │ + PR     │        │ Packs    │
│         │          │             │        │          │        │ + EPSS   │        │          │        │          │
│ DAST    │ finding  │             │        │ Reachab. │        │ + KEV    │        │ Playbook │        │ SLSA     │
│ Scan    ├─────────►│             │        │ Analysis │        │          │        │ Execute  │        │ Provenance│
└─────────┘          └──────┬──────┘        └──────────┘        └──────────┘        └──────────┘        └──────────┘
                            │                                                              │
                            │ case                                                         │ comment
                            ▼                                                              ▼
                     ┌─────────────┐                                                ┌──────────┐
                     │  Exposure   │                                                │ Collab.  │
                     │  Case Center│◄───────────────────────────────────────────────►│ Panel    │
                     │  (Kanban)   │                                                │          │
                     └─────────────┘                                                └──────────┘
```

### Deep-Link Triggers (click actions that navigate between screens)

| From Screen | User Action | Target Screen | Data Passed |
|------------|------------|--------------|-------------|
| **Dashboard** → Top Risk row click | Click CVE-2025-1234 | **Findings View** | `?cve_id=CVE-2025-1234` |
| **Dashboard** → Critical findings count | Click "12" | **Findings View** | `?severity=critical` |
| **Dashboard** → MTTR card | Click | **Remediation Center** | `?view=metrics` |
| **Dashboard** → Compliance bar | Click "PCI-DSS 82%" | **Compliance Reports** | `?framework=pci-dss` |
| **Dashboard** → Quick Action "Ingest" | Click | **Code Scanning** | — |
| **Dashboard** → Quick Action "Pentest" | Click | **Micro Pentest** | — |
| **Dashboard** → Quick Action "Brain Pipeline" | Click | **Brain Pipeline** | — |
| **Dashboard** → Activity Feed item | Click "SBOM ingested" | **Code Scanning** | `?tab=history` |
| **Findings View** → Row click | Click finding | **Finding Detail (slide-over)** | `finding.id` |
| **Finding Detail** → "AutoFix" button | Click | **AutoFix Dashboard** | `cve_id` |
| **Finding Detail** → "Create Case" | Click | **Exposure Cases** | `finding_ids[]` pre-filled |
| **Finding Detail** → "Pentest" | Click | **MPTE Console** | `finding_id`, `target_url`, `vuln_type` |
| **Finding Detail** → "View Cluster" | Click cluster badge | **Correlation Engine** | `cluster_id` |
| **Finding Detail** → "Reachability" | Click | **Reachability Analysis** | `cve_id`, `component_name` |
| **Finding Detail** → CVE link | Click CVE-ID | **Intelligence Hub** | `cve_id` in search |
| **Correlation Engine** → Cluster row | Click | **Cluster Detail (expand)** | `cluster_id` |
| **Cluster Detail** → "Create Case" | Click | **Exposure Cases** | `cluster_ids[]` |
| **Cluster Detail** → Finding row | Click | **Finding Detail** | `finding.id` |
| **Exposure Cases** → Case card (Kanban) | Click | **Case Detail tab** | `case_id` |
| **Case Detail** → "View Findings" | Click | **Findings View** | `?finding_ids=f1,f2,f3` |
| **Case Detail** → "Remediate" | Click | **Remediation Center** | `case_id, cluster_ids[]` |
| **MPTE Console** → Result row | Click | **MPTE Result Detail** | `request_id` |
| **MPTE Result** → "Generate Fix" | Click | **AutoFix Dashboard** | `cve_id, evidence` |
| **MPTE Result** → "Create Ticket" | Click | **Remediation Center** → Create Task | `finding_id, cve_id` |
| **Remediation Center** → Task row | Click | **Task Detail (expand)** | `task_id` |
| **Task Detail** → "View Finding" | Click | **Finding Detail** | `finding_id` |
| **Task Detail** → "View PR" | Click | **External** (GitHub/Jira) | `pr_url` (new tab) |
| **Micro Pentest** → Live result row | Click CVE | **Finding Detail** | `cve_id` |
| **Attack Paths** → Node click | Click critical node | **Inventory** | `asset_id` |
| **Attack Paths** → Path click | Click path | **Attack Simulation** | `path_data` |
| **Threat Feeds** → KEV entry | Click CVE | **Intelligence Hub** | `cve_id` |
| **Threat Feeds** → EPSS row | Click CVE | **Finding Detail** | `cve_id` |
| **Copilot** → "View Evidence" | Click in AI response | **Evidence Vault** | `bundle_id` or `cve_id` |
| **Copilot** → "Create Ticket" | Click in AI response | **Remediation Center** | `cve_id, recommendation` |
| **Copilot** → "AutoFix" | Click in AI response | **AutoFix Dashboard** | `cve_id` |
| **Brain Pipeline** → Run result | Click run | **Exposure Cases** | `?org_id=X` (cases created) |
| **Nerve Center** → Playbook row | Click | **Playbook Editor** | `playbook_id` |
| **Compliance Reports** → Framework row | Click | **Evidence Vault** | `?framework=pci-dss` |
| **Evidence Vault** → Bundle row | Click | **Bundle Detail** | `release` |
| **Integrations Hub** → Connector card | Click | **Integration Config (modal)** | `integration_id` |
| **Webhooks** → Event row | Click | **Event Detail (expand)** | `event_id` |
| **Webhooks** → Work Item row | Click | **External** (Jira/GH) | `work_item_url` (new tab) |

## 2.2 The Attack Verification Flow (unique to FixOps)

```
 DISCOVER                                VERIFY                                VALIDATE
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Code Scanning│    │ Threat Feeds │    │ MPTE Console │    │ Reachability │    │ Micro Pentest│
│              │    │              │    │              │    │              │    │              │
│ Finding:     │    │ EPSS: 0.94   │    │ Verify:      │    │ Call Graph:  │    │ Live Attack: │
│ CVE-2025-1234├───►│ KEV: ✅      ├───►│ Exploitable? ├───►│ Reachable?   ├───►│ Confirmed?   │
│ express 4.17 │    │ Exploits: 3  │    │ Evidence?    │    │ Code Path?   │    │ Impact?      │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
        │                   │                   │                   │                   │
        │                   │                   │                   │                   │
        ▼                   ▼                   ▼                   ▼                   ▼
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │                          FINDING DETAIL (slide-over)                                    │
  │  ┌─────┐ ┌──────┐ ┌────────┐ ┌────────────┐ ┌─────────┐ ┌──────────┐ ┌─────────────┐ │
  │  │CVSS │ │ EPSS │ │ KEV    │ │ MPTE       │ │Reachable│ │ Pentest  │ │ SSVC        │ │
  │  │ 9.8 │ │ 0.94 │ │ ✅ Yes │ │ ⚠️ EXPLOIT │ │ ✅ Yes  │ │ 🔴 CONF  │ │ ACT         │ │
  │  └─────┘ └──────┘ └────────┘ └────────────┘ └─────────┘ └──────────┘ └─────────────┘ │
  │                                                                                        │
  │  Evidence Chain: SBOM → Cluster → EPSS(0.94) → KEV(✅) → MPTE(exploitable)            │
  │                  → Reachable(4 call depths) → Pentest(confirmed RCE)                   │
  │                  → SSVC Decision: ACT IMMEDIATELY                                      │
  │                                                                                        │
  │  [AutoFix] [Create Case] [Create Ticket] [Suppress] [Ask Copilot]                     │
  └────────────────────────────────────────────────────────────────────────────────────────┘
```

### Data Enrichment Pipeline (per finding, across screens)

| Step | Screen | API | Adds to Finding Object |
|------|--------|-----|----------------------|
| 1 | Code Scanning | `/inputs/sbom` or `/inputs/sarif` | `id`, `cve_id`, `severity`, `source`, `asset` |
| 2 | Correlation Engine | `/api/v1/deduplication/process` | `cluster_id`, `canonical_cve`, `finding_count` |
| 3 | Threat Feeds | `/api/v1/feeds/epss` | `epss_score`, `epss_percentile` |
| 4 | Threat Feeds | `/api/v1/feeds/kev` | `kev: true/false`, `kev_date_added` |
| 5 | MPTE Console | `/api/v1/mpte/verify` | `exploitability`, `evidence`, `risk_score` |
| 6 | Reachability | `/api/v1/reachability/analyze` | `reachable: true/false`, `call_depth`, `code_paths[]` |
| 7 | Micro Pentest | `/api/v1/micro-pentest/run` | `pentest_confirmed`, `attack_vector`, `impact` |
| 8 | Decision Engine | `/api/v1/copilot/agents/analyst/prioritize` | `ssvc_decision`, `priority_rank` |
| 9 | Business Context | `/api/v1/business-context-enhanced/analyze` | `asset_criticality`, `data_sensitivity`, `revenue_impact` |
| 10 | Monte Carlo | `/api/v1/algorithms/monte-carlo/quantify` | `expected_loss_$`, `95th_percentile_$` |

---

# PART 3: SCREEN SPECIFICATIONS (with cross-links)

## S01: HOME DASHBOARD
**Route:** `/` or `/dashboard` | **Frame:** 1440×900

### Wireframe
```
┌──────────────────────────────────────────────────────────────────┐
│  ┌─ SECURITY POSTURE ─┐  ┌─ QUICK ACTIONS ─────────────────┐   │
│  │     ╭───╮           │  │ [→ Ingest]  [→ Scan]  [→ Brain] │   │
│  │    ╱ 78 ╲  /100     │  │ [→ Pentest] [→ Multi-LLM]       │   │
│  │   ╰─────╯           │  │ [→ SOC2]    [→ Attack Sim]      │   │
│  │  Critical: 12 ━━━   │  └──────────────────────────────────┘   │
│  │  High:     34 ━━━━  │                                        │
│  │  Medium:   89 ━━━━━ │  ← Click counts → /findings?severity=X │
│  │  Low:     156 ━━━━━━│                                        │
│  └──────────────────────┘                                        │
├──────────────────────────────────────────────────────────────────┤
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐        │
│  │MTTR  │ │Noise │ │Cover │ │ROI   │ │Cases │ │Tasks │        │
│  │ 4.2d │ │ -67% │ │ 89%  │ │ 340% │ │ 23   │ │ 156  │        │
│  │→Remed│ │→Corr │ │→Inv  │ │→Rept │ │→Cases│ │→Remed│        │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘        │
│  ↑ Each card click navigates to its detail screen               │
├──────────────────────────────────────────────────────────────────┤
│  ┌─ SEVERITY TREND (30d) ──────┐  ┌─ TOP 10 RISKS ───────────┐ │
│  │  ▁▂▃▄▅▆▇█▇▆▅▄ area chart   │  │  1. CVE-2025-1234  🔴 9.8│ │
│  │  x: date, y: count         │  │     → click → /findings    │ │
│  │  series: crit/high/med/low  │  │  2. CVE-2025-5678  🔴 9.1│ │
│  │  → click date → /findings   │  │  3. CVE-2025-9012  🟠 8.7│ │
│  │    ?created_after=2026-01-X  │  │  → click → enriched view │ │
│  └──────────────────────────────┘  └───────────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│  ┌─ COMPLIANCE ────────────────┐  ┌─ ACTIVITY FEED (SSE) ─────┐ │
│  │  PCI-DSS  ████░ 82%  →     │  │  ● SBOM ingested     2m   │ │
│  │  SOC2     ██████ 95%  →     │  │  ● Case CASE-007 → fixing │ │
│  │  ISO27001 ███░░░ 61%  →     │  │  ● AutoFix PR merged      │ │
│  │  ↑ click → /evidence/       │  │  ● Pentest completed       │ │
│  │    compliance?fw=X           │  │  ↑ SSE: /api/v1/stream/   │ │
│  └──────────────────────────────┘  │    events                  │ │
│                                    │  ↑ click item → source pg  │ │
│  ┌─ MULTI-LLM PANEL ──────────┐   └───────────────────────────┘ │
│  │  Consensus: 94%  3 providers│                                 │
│  │  Last: "CVE-2025-1234 is..." │                                │
│  │  → click → /ai-engine/       │                                │
│  │    multi-llm                  │                                │
│  └───────────────────────────────┘                                │
└──────────────────────────────────────────────────────────────────┘
```

### API Map
| Component | Endpoint | Method | Response → |
|-----------|---------|--------|-----------|
| Posture Ring | `/api/v1/analytics/dashboard/overview` | GET | `{score, severity_breakdown}` |
| Trend Chart | `/api/v1/analytics/dashboard/trends` | GET | `{dates[], critical[], high[]}` |
| Top Risks | `/api/v1/analytics/dashboard/top-risks` | GET | `{risks[{cve_id, score, title}]}` |
| Compliance | `/api/v1/analytics/dashboard/compliance-status` | GET | `{frameworks[{name, pct}]}` |
| MTTR Card | `/api/v1/analytics/mttr` | GET | `{mttr_days, mttr_by_severity}` |
| Noise Card | `/api/v1/analytics/noise-reduction` | GET | `{reduction_percent}` |
| ROI Card | `/api/v1/analytics/roi` | GET | `{roi_percent}` |
| Coverage | `/api/v1/analytics/coverage` | GET | `{coverage_percent}` |
| Activity | `/api/v1/nerve-center/pulse` | GET | `{events[]}` |
| Activity SSE | `/api/v1/stream/events` | SSE | `event: {type, data}` |
| Cases Count | `/api/v1/cases/stats/summary` | GET | `{total, by_status}` |
| Tasks Count | `/api/v1/remediation/metrics` | GET | `{total_tasks}` |
| Multi-LLM | `/api/v1/enhanced/analysis` | POST | `{consensus, confidence}` |
| Custom Query | `/api/v1/analytics/custom-query` | POST | `{results[]}` |

### State Machine
```
Dashboard Load
  │
  ├─► Fetch 10 APIs in parallel (React Query, stale: 5min)
  │     ├─► overview → posture ring
  │     ├─► trends → chart
  │     ├─► top-risks → table
  │     ├─► compliance → bars
  │     ├─► mttr → card
  │     ├─► noise → card
  │     ├─► roi → card
  │     ├─► coverage → card
  │     ├─► pulse → activity feed
  │     └─► cases/stats → case count
  │
  ├─► Connect SSE stream → update activity feed in real-time
  │
  ├─► On click severity count → navigate(/findings?severity=X)
  ├─► On click top risk → navigate(/findings?cve_id=X)
  ├─► On click compliance bar → navigate(/evidence/compliance?fw=X)
  ├─► On click MTTR card → navigate(/protect/remediation)
  ├─► On click quick action → navigate(target)
  └─► On click activity item → navigate(source page of event)
```

### Data In / Data Out
| Direction | Source Screen | Data | Link Type |
|-----------|-------------|------|-----------|
| **IN** | Code Scanning | Finding counts (via analytics API) | API aggregation |
| **IN** | Correlation Engine | Cluster counts, noise reduction | API aggregation |
| **IN** | Remediation | MTTR, task counts | API aggregation |
| **IN** | Exposure Cases | Case counts by status | API aggregation |
| **IN** | SSE Stream | Real-time events | WebSocket-like |
| **OUT** | → Findings View | Severity filter, CVE filter | URL params |
| **OUT** | → Compliance Reports | Framework filter | URL params |
| **OUT** | → Remediation Center | — | Navigation |
| **OUT** | → Code Scanning | — | Navigation |
| **OUT** | → Brain Pipeline | — | Navigation |
| **OUT** | → Multi-LLM | — | Navigation |

---

## S02: NERVE CENTER
**Route:** `/nerve-center` | **Frame:** 1440×900

### Wireframe
```
┌──────────────────────────────────────────────────────────────────┐
│  🧠 FixOps Nerve Center                    [Auto-Remediate ▶]   │
├──────────────────────────────────────────────────────────────────┤
│  ┌─ SYSTEM PULSE ──────────────┐  ┌─ INTELLIGENCE MAP ────────┐ │
│  │                              │  │                            │ │
│  │  Engine: ● Healthy           │  │    ┌───┐    ┌───┐         │ │
│  │  Alerts: 7 active            │  │    │CVE├────┤AST│         │ │
│  │  Pipeline: 42 runs           │  │    └─┬─┘    └─┬─┘         │ │
│  │  Confidence: 94%             │  │      │  ┌───┐ │           │ │
│  │  Last Run: 3m ago            │  │      └──┤FIX├─┘           │ │
│  │                              │  │         └───┘             │ │
│  │  Health: ████████████░░ 87%  │  │  (D3 force graph)         │ │
│  │                              │  │  → click node → detail    │ │
│  │  → feeds from:               │  │  → click CVE node →       │ │
│  │    • /nerve-center/pulse     │  │    /findings?cve_id=X     │ │
│  │    • /nerve-center/state     │  │  → click AST node →       │ │
│  │                              │  │    /code/inventory?id=X   │ │
│  └──────────────────────────────┘  └────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│  ┌─ PLAYBOOKS ──────────────────────────────────────────────────┐│
│  │  Name              Triggers      Last      Status  Actions   ││
│  │  Auto-Triage       on_ingest     2m ✅     Active  [▶][✎][🗑]││
│  │  KEV-Escalate      kev_match     1h ✅     Active  [▶][✎][🗑]││
│  │  SLA-Breach        sla_due       15m ✅    Active  [▶][✎][🗑]││
│  │  [+ New Playbook]                                            ││
│  │                                                              ││
│  │  → [✎] click → /protect/playbook-editor?id=X                ││
│  │  → [▶] click → POST /nerve-center/playbooks/execute/{id}    ││
│  │  → [+ New] → /protect/playbook-editor (new)                 ││
│  └──────────────────────────────────────────────────────────────┘│
├──────────────────────────────────────────────────────────────────┤
│  ┌─ OVERLAY CONFIGURATION ──────────────────────────────────────┐│
│  │  Mode: [demo ▾]   Auth: [token ▾]                           ││
│  │  Feature Flags:                                              ││
│  │    [☑ capture_feedback] [☑ auto_triage] [☐ ml_learning]     ││
│  │  → reads: /nerve-center/overlay                              ││
│  │  → writes: PUT /nerve-center/overlay                          ││
│  │  → also shown at: /settings/overlay-config                   ││
│  │  [Save Config] [Reset]                                       ││
│  └──────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

### API Map (8 endpoints)
| Component | Endpoint | Method |
|-----------|---------|--------|
| Pulse Panel | `/api/v1/nerve-center/pulse` | GET |
| State Panel | `/api/v1/nerve-center/state` | GET |
| Intel Map | `/api/v1/nerve-center/intelligence-map` | GET |
| Auto-Remediate | `/api/v1/nerve-center/auto-remediate` | POST |
| Playbooks List | `/api/v1/nerve-center/playbooks` | GET |
| Validate Playbook | `/api/v1/nerve-center/playbooks/validate` | POST |
| Execute Playbook | `/api/v1/nerve-center/playbooks/execute/{id}` | POST |
| Overlay Config | `/api/v1/nerve-center/overlay` | GET/PUT |

### Cross-Links
| From | Action | To | Data |
|------|--------|----|------|
| Intel Map CVE node | Click | Findings View | `cve_id` |
| Intel Map Asset node | Click | Inventory | `asset_id` |
| Playbook edit icon | Click | Playbook Editor | `playbook_id` |
| Playbook execute | Click | — (inline result) | `playbook_id` |
| Auto-Remediate | Click | — (SSE progress) | `finding_ids[]` |
| Overlay Config | Shared with | Settings → Overlay | Same API |

---

## S03: GLOBAL FINDINGS VIEW
**Route:** `/findings` | **Frame:** 1440×900

> **This is the most cross-linked screen.** Every suite feeds data here, and this screen links out to every suite.

### Wireframe
```
┌──────────────────────────────────────────────────────────────────┐
│  📊 Findings                [Export ▾] [Bulk ▾] [🔍 Search____] │
├──────────────────────────────────────────────────────────────────┤
│  FILTERS: [Severity ▾] [Source ▾] [Status ▾] [KEV ▾] [EPSS ▾] │
│           [Cluster ▾] [Asset ▾] [Date Range ▾] [Clear All]      │
│  → URL params: ?severity=critical&kev=true&epss_min=0.5         │
├──────────────────────────────────────────────────────────────────┤
│  ☐ │ CVE            │ Title          │ Sev  │ EPSS │ KEV │ Src │
│  ──┼────────────────┼────────────────┼──────┼──────┼─────┼─────│
│  ☐ │ CVE-2025-1234  │ RCE in Express │ 🔴   │ 0.94 │ ✅  │SARIF│
│  ☐ │ CVE-2025-5678  │ XSS in React   │ 🟡   │ 0.42 │ ❌  │SBOM │
│  ☐ │ CVE-2025-9012  │ SQLi in API    │ 🔴   │ 0.88 │ ✅  │DAST │
│  ☐ │ GHSA-xxxx-yyyy │ Prototype Poll │ 🟠   │ 0.31 │ ❌  │SARIF│
│                                                                  │
│  Pagination: [← Prev] 1 2 3 ... 12 [Next →]  (500 total)       │
│  Selected: 3 → [Bulk Update ▾] [Assign ▾] [Create Case]        │
│                                                                  │
│  ► ENRICHMENT BADGES per row:                                    │
│    [CVSS 9.8] [EPSS 94%] [KEV ✅] [MPTE: Exploitable]          │
│    [Reachable ✅] [Cluster: CLU-001] [Case: CASE-007]           │
│    → each badge clickable → navigates to that screen             │
├──────────────────────────────────────────────────────────────────┤
│  ┌─ SLIDE-OVER: FINDING DETAIL ────────────────────────────────┐│
│  │                                                              ││
│  │  CVE-2025-1234 │ express@4.17.1 │ RCE                       ││
│  │                                                              ││
│  │  ┌────────────────────────────────────────────────────────┐  ││
│  │  │ EVIDENCE CHAIN (horizontal pipeline)                   │  ││
│  │  │                                                        │  ││
│  │  │ [SBOM]→[Cluster]→[EPSS 0.94]→[KEV✅]→[MPTE⚠️]→      │  ││
│  │  │ [Reachable✅]→[Pentest🔴]→[SSVC: ACT]                │  ││
│  │  │                                                        │  ││
│  │  │ Each node: click → navigates to source screen          │  ││
│  │  └────────────────────────────────────────────────────────┘  ││
│  │                                                              ││
│  │  Description: Remote code execution vulnerability in...      ││
│  │  Component: express@4.17.1 → [View in SBOM]                 ││
│  │  Asset: payment-service → [View in Inventory]                ││
│  │  Cluster: CLU-001 (12 findings) → [View Cluster]            ││
│  │  Case: CASE-007 → [View Case]                               ││
│  │                                                              ││
│  │  ┌─ COMMENTS (Collaboration) ─────────────────────────────┐ ││
│  │  │  user-a: "Confirmed exploitable in staging"    2h ago  │ ││
│  │  │  user-b: "PR #342 fixes this"                  1h ago  │ ││
│  │  │  [Type comment...________________________] [Send]      │ ││
│  │  └────────────────────────────────────────────────────────┘ ││
│  │                                                              ││
│  │  [AutoFix] [Create Case] [Run Pentest] [Ask Copilot]        ││
│  │  [Suppress] [Accept Risk] [Assign ▾]                        ││
│  └──────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

### APIs Consumed (15 endpoints across 6 suites)
| Component | Endpoint | Method | Suite |
|-----------|---------|--------|-------|
| Finding list | `/api/v1/analytics/findings` | GET | Analytics |
| Global search | `/api/v1/search` | GET | Core |
| EPSS enrichment | `/api/v1/feeds/epss` | GET | Feeds |
| KEV enrichment | `/api/v1/feeds/kev` | GET | Feeds |
| Cluster lookup | `/api/v1/deduplication/clusters/{id}` | GET | Correlation |
| MPTE results | `/api/v1/mpte/results` | GET | Attack |
| Reachability | `/api/v1/reachability/results/{cve}` | GET | Attack |
| Business ctx | `/api/v1/business-context/assets` | GET | Evidence-Risk |
| Comments | `/api/v1/collaboration/comments` | GET | Protect |
| Add comment | `/api/v1/collaboration/comments` | POST | Protect |
| Bulk update | `/api/v1/bulk/findings/update` | POST | Protect |
| Create case | `/api/v1/cases` | POST | Core |
| Create task | `/api/v1/remediation/tasks` | POST | Protect |
| AutoFix | `/api/v1/autofix/generate` | POST | Core |
| Copilot analyze | `/api/v1/copilot/quick/analyze` | POST | Core |

### Cross-Link Map (this screen is the hub)
```
                    ┌──────────────┐
                    │   Dashboard  │
                    │  (severity   │
        ┌───────────┤   filter)    │
        │           └──────────────┘
        │
        │    ┌──────────────┐         ┌──────────────┐
        │    │ Code Scanning│         │ Threat Feeds │
        │    │ (new findings)├────────►│ (EPSS/KEV)   │
        │    └──────────────┘         └──────┬───────┘
        │                                    │
        ▼                                    ▼
  ┌─────────────────────────────────────────────────┐
  │              FINDINGS VIEW (HUB)                 │
  │                                                   │
  │  Evidence Chain per finding links to:             │
  │  • SBOM → /code/sbom-generation                   │
  │  • Cluster → /cloud/correlation?id=CLU-001        │
  │  • EPSS → /cloud/threat-feeds?tab=epss            │
  │  • KEV → /cloud/threat-feeds?tab=kev              │
  │  • MPTE → /attack/mpte?result=REQ-001             │
  │  • Reachability → /attack/reachability?cve=X      │
  │  • Pentest → /attack/micro-pentest?cve=X          │
  │  • SSVC → /decisions?finding=X                    │
  │                                                   │
  │  Action buttons link to:                          │
  │  • AutoFix → /protect/autofix?cve=X               │
  │  • Create Case → /core/exposure-cases (modal)     │
  │  • Create Ticket → /protect/remediation (modal)   │
  │  • Ask Copilot → /copilot?context=finding:X       │
  └───────┬──────────┬──────────┬──────────┬──────────┘
          │          │          │          │
          ▼          ▼          ▼          ▼
   ┌──────────┐ ┌──────────┐ ┌────────┐ ┌────────┐
   │ Exposure │ │ Remed.   │ │AutoFix │ │Copilot │
   │ Cases    │ │ Center   │ │        │ │ Chat   │
   └──────────┘ └──────────┘ └────────┘ └────────┘
```

---

## S04–S08: CODE SUITE SCREENS

### S04: Code Scanning (/code/code-scanning)
| API | Cross-Links To | Cross-Links From |
|-----|---------------|-----------------|
| `POST /inputs/sbom` | → Findings View (new findings), → Correlation (auto-dedup) | ← Dashboard quick action |
| `POST /inputs/sarif` | → Findings View, → Correlation | ← Dashboard quick action |
| `POST /inputs/cnapp` | → Cloud Posture, → Findings View | — |
| `POST /api/v1/validate/input` | — | — |
| `POST /api/v1/uploads/chunk` | — | — |
| `GET /api/v1/inventory/applications` | → SBOM page, → Inventory | — |
| `GET /api/v1/deduplication/stats` | displays noise reduction | ← Correlation Engine |

### S05: Secrets Detection (/code/secrets-detection)
| API | Links To |
|-----|---------|
| `GET /api/v1/secrets` | → Findings View (secret findings appear as findings) |
| `POST /api/v1/secrets/{id}/resolve` | → Audit Logs (resolution recorded) |
| `POST /api/v1/secrets/scan/content` | — (inline result) |

### S06: IaC Scanning (/code/iac-scanning)
| API | Links To |
|-----|---------|
| `GET /api/v1/iac` | → Findings View (IaC findings), → Cloud Posture (infra misconfigs) |
| `POST /api/v1/iac/scan/content` | — (inline result) |
| `POST /api/v1/iac/{id}/remediate` | → Remediation Center (fix task created) |

### S07: SBOM Generation (/code/sbom-generation)
| API | Links To |
|-----|---------|
| `POST /inputs/sbom` | → Findings View, → Correlation |
| `GET /api/v1/inventory/applications` | → Inventory |

### S08: Inventory (/code/inventory)
| API | Links To |
|-----|---------|
| `GET /api/v1/inventory/search` | → Finding Detail (click asset) |
| `GET /api/v1/inventory/applications` | → Code-to-Cloud Map |
| `GET /api/v1/code-to-cloud/map` | → Data Fabric |

---

## S09–S13: CLOUD SUITE SCREENS

### S09: Cloud Posture (/cloud/cloud-posture)
| API | Cross-Links To |
|-----|---------------|
| `POST /inputs/cnapp` | → Findings View (cloud findings) |
| `GET /api/v1/analytics/findings?source=cnapp` | ← Findings View (filtered) |
| `GET /api/v1/inventory/applications` | → Inventory |
| `POST /api/v1/iac/scan/content` | → IaC Scanning (shared API) |

### S10: Container Security (/cloud/container-security)
| API | Cross-Links To |
|-----|---------------|
| `POST /api/v1/container/scan` | → Findings View |
| `GET /api/v1/container/images` | → SBOM Generation (image SBOM) |
| `GET /api/v1/container/runtime` | → Runtime Protection |

### S11: Threat Feeds (/cloud/threat-feeds)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/feeds/epss` | → Finding Detail (EPSS badge) |
| `GET /api/v1/feeds/kev` | → Finding Detail (KEV badge), → Nerve Center (KEV playbook trigger) |
| `GET /api/v1/feeds/exploits` | → MPTE Console (known exploits) |
| `GET /api/v1/feeds/threat-actors` | → Attack Simulation (actor-based scenarios) |
| `GET /api/v1/feeds/health` | → Settings/System Health |
| `GET /api/v1/feeds/stats` | → Dashboard (feed counts) |

### S12: Correlation Engine (/cloud/correlation)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/deduplication/clusters` | → Exposure Cases (cluster → case), → Findings View (cluster badge) |
| `GET /api/v1/deduplication/clusters/{id}` | → Finding Detail (expand cluster) |
| `POST /api/v1/deduplication/process` | ← Code Scanning (auto on ingest) |
| `GET /api/v1/deduplication/stats` | → Dashboard (noise reduction card) |
| `POST /api/v1/fuzzy-identity/match` | — (inline enrichment) |

### S13: Runtime Protection (/cloud/runtime-protection)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/container/runtime` | → Findings View (runtime findings) |
| SSE: `/api/v1/stream/events?types=runtime` | → TopBar notifications |

---

## S14–S20: ATTACK SUITE SCREENS

### S14: MPTE Console (/attack/mpte)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/mpte/requests` | — |
| `POST /api/v1/mpte/requests` | ← Finding Detail ("Run Pentest" button) |
| `GET /api/v1/mpte/results` | → Finding Detail (MPTE badge) |
| `POST /api/v1/mpte/verify` | → Finding Detail (exploitability evidence) |
| `GET /api/v1/mpte/configs` | — |

**Data In:** finding_id, target_url, vulnerability_type from Findings View
**Data Out:** exploitability result → Finding Detail evidence chain, → Remediation (priority)

### S15: Micro Pentest (/attack/micro-pentest)
| API | Cross-Links To |
|-----|---------------|
| `POST /api/v1/micro-pentest/run` | → Finding Detail (pentest badge) |
| `GET /api/v1/micro-pentest/status/{flowId}` | — |
| `POST /api/v1/micro-pentest/enterprise/scan` | — |
| SSE: `/api/v1/stream/pentest/{flowId}` | real-time results in-page |

**Data In:** cve_ids[], target_urls[] from Findings View / Copilot
**Data Out:** test results → Finding Detail pentest badge

### S16: Attack Simulation (/attack/attack-simulation)
| API | Cross-Links To |
|-----|---------------|
| `POST /api/v1/predictions/simulate-attack` | → Dashboard (risk update) |
| `POST /api/v1/predictions/attack-chain` | → Attack Paths (chain visualization) |
| `POST /api/v1/predictions/risk-trajectory` | → Dashboard (trend line) |
| `POST /api/v1/vulns/discovered` | → Findings View (new vuln) |

### S17: Reachability Analysis (/attack/reachability)
| API | Cross-Links To |
|-----|---------------|
| `POST /api/v1/reachability/analyze` | → Finding Detail (reachability badge) |
| `GET /api/v1/reachability/results/{cve}` | ← Finding Detail ("Check Reachability") |
| `GET /api/v1/reachability/metrics` | → Dashboard (reachability stats) |

**Data In:** cve_id, component_name from Finding Detail
**Data Out:** reachable: true/false → Finding evidence chain

### S18: Attack Paths GNN (/attack/attack-paths)
| API | Cross-Links To |
|-----|---------------|
| `POST /api/v1/algorithms/gnn/attack-surface` | → Dashboard (top risk paths) |
| `POST /api/v1/algorithms/gnn/critical-nodes` | → Inventory (critical assets) |
| `GET /api/v1/graph/data` | → Knowledge Graph (shared data) |

**Node Click:** → Inventory (asset detail) or → Finding Detail (CVE node)
**Path Click:** → Attack Simulation (pre-fill scenario)

### S19: DAST (/attack/dast) — 3 APIs
### S20: API Fuzzer (/attack/api-fuzzer) — 3 APIs
### S20b: Malware Analysis (/attack/malware) — 3 APIs

All feed results → Findings View as new findings.

---

## S21–S27: AI SUITE SCREENS

### S21: Copilot Chat (/copilot)
**The universal connector. Can invoke ANY other screen's API.**

| API | Cross-Links To |
|-----|---------------|
| `POST /api/v1/copilot/sessions` | — |
| `POST /api/v1/copilot/sessions/{id}/messages` | — |
| `POST /api/v1/copilot/agents/analyst/analyze` | → Finding Detail (enriched analysis) |
| `POST /api/v1/copilot/agents/analyst/threat-intel` | → Threat Feeds (intel enrichment) |
| `POST /api/v1/copilot/agents/analyst/prioritize` | → Decision Engine (SSVC result) |
| `POST /api/v1/copilot/agents/analyst/attack-path` | → Attack Paths (graph) |
| `POST /api/v1/copilot/agents/pentest/validate` | → MPTE Console (validation) |
| `POST /api/v1/copilot/agents/pentest/generate-poc` | — (inline code block) |
| `POST /api/v1/copilot/agents/pentest/schedule` | → Micro Pentest (scheduled) |
| `POST /api/v1/copilot/agents/compliance/map-findings` | → Compliance Reports |
| `POST /api/v1/copilot/agents/compliance/gap-analysis` | → Compliance Reports |
| `POST /api/v1/copilot/agents/compliance/regulatory-alerts` | → Compliance Reports |
| `POST /api/v1/copilot/quick/analyze` | — (inline result) |
| `GET /api/v1/copilot/health` | → Settings/System Health |

**Inline Action Buttons in AI Response:**
- `[View Evidence]` → /evidence/bundles?cve=X
- `[Create Ticket]` → /protect/remediation (pre-filled)
- `[AutoFix]` → /protect/autofix?cve=X
- `[Show Attack Path]` → /attack/attack-paths
- `[View in Findings]` → /findings?cve_id=X

### S22: Decision Engine (/decisions)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/algorithms/capabilities` | — |
| `GET /api/v1/algorithms/status` | → Settings/System Health |
| `POST /api/v1/copilot/agents/analyst/prioritize` | → Findings View (priority ranking) |

**Data In:** Finding objects from Findings View, Business Context from Data Fabric
**Data Out:** SSVC decision → Finding Detail evidence chain, → Exposure Cases (priority)

### S23: Algorithmic Lab (/ai-engine/algorithmic-lab)
| API | Cross-Links To |
|-----|---------------|
| `POST /api/v1/algorithms/monte-carlo/quantify` | → Dashboard (risk dollar amount) |
| `POST /api/v1/algorithms/causal/analyze` | → Copilot (root cause explanation) |

### S24: Multi-LLM Consensus (/ai-engine/multi-llm)
| API | Cross-Links To |
|-----|---------------|
| `POST /api/v1/enhanced/analysis` | → Dashboard (consensus panel) |
| `POST /api/v1/enhanced/compare-llms` | — (inline comparison) |
| `GET /api/v1/llm/status` | → Settings/System Health |
| `GET /api/v1/llm/providers` | → Settings/System Health |
| `GET /api/v1/enhanced/capabilities` | — |

### S25: LLM Monitor (/ai-engine/ml-dashboard)
### S26: Predictions (/ai-engine/predictions)
### S27: Policies (/ai-engine/policies)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/policies` | → Decision Engine (policy rules), → Nerve Center (policy triggers) |
| `POST /api/v1/policies` | — |
| `POST /api/v1/policies/{id}/validate` | — |

---

## S28–S31: CONNECTORS SCREENS

### S28: Integrations Hub (/protect/integrations + /settings/integrations)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/integrations` | → Webhooks (connector source), → Remediation (PR target) |
| `POST /api/v1/integrations/{id}/test` | — (inline status) |
| `POST /api/v1/integrations` | — |
| `PUT /api/v1/integrations/{id}` | — |
| `DELETE /api/v1/integrations/{id}` | — |
| `POST /api/v1/integrations/{id}/sync` | → Webhooks (trigger sync) |

### S29: Webhooks (/settings/webhooks)
**14 endpoints — most connected connector screen**

| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/webhooks/mappings` | → Integrations (connector config) |
| `POST /api/v1/webhooks/mappings` | — |
| `PUT /api/v1/webhooks/mappings/{id}/sync` | → Integrations (sync status) |
| `GET /api/v1/webhooks/drift` | → Integrations (drift alert badge) |
| `PUT /api/v1/webhooks/drift/{id}/resolve` | — |
| `GET /api/v1/webhooks/events` | → TopBar (notification feed via SSE) |
| `GET /api/v1/webhooks/outbox` | — |
| `GET /api/v1/webhooks/outbox/stats` | → Dashboard (pending items count) |
| `POST /api/v1/webhooks/outbox` | — |
| `POST /api/v1/webhooks/outbox/{id}/execute` | — |
| `POST /api/v1/webhooks/outbox/{id}/retry` | — |
| `POST /api/v1/webhooks/outbox/process-pending` | — |
| `GET /api/v1/webhooks/alm/work-items` | → Remediation Center (linked tickets) |
| `POST /api/v1/webhooks/alm/work-items` | ← Remediation Center ("Create PR"), ← Finding Detail ("Create Ticket") |

### S30: Marketplace (/settings/marketplace)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/marketplace/browse` | → Integrations (installed items) |
| `POST /api/v1/marketplace/purchase/{id}` | → Integrations (new connector) |

### S31: MCP Connectors (/connect/mcp)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/oss-tools/status` | — |
| `POST /api/v1/oss-tools/run` | → Findings View (tool results as findings) |
| SSE: `/api/v1/stream/events` | → TopBar, → Dashboard activity |
| `GET /api/v1/ide/tools` | — |

---

## S32–S39: GOVERNANCE SCREENS

### S32: Evidence Vault (/evidence/bundles)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/evidence/` | → Compliance Reports (evidence per framework) |
| `GET /api/v1/evidence/{release}` | → SLSA Provenance (attestation chain) |
| `POST /api/v1/evidence/verify` | → Audit Logs (verification event) |
| `GET /api/v1/evidence/stats` | → Dashboard (evidence counts) |
| `POST /api/v1/brain/evidence/generate` | ← Brain Pipeline (auto-generate) |
| `GET /api/v1/brain/evidence/packs` | → SOC2 Evidence |
| `GET /api/v1/brain/evidence/packs/{id}` | → SOC2 Evidence (detail) |

### S33: Compliance Reports (/evidence/compliance)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/audit/compliance/frameworks` | → Dashboard (compliance bars) |
| `GET /api/v1/analytics/dashboard/compliance-status` | ← Dashboard (shared API) |
| `POST /api/v1/reports` | → Reports list, → Evidence Vault (report artifact) |
| `GET /api/v1/reports` | — |
| `GET /api/v1/reports/templates/list` | — |
| `GET /api/v1/analytics/export` | — (file download) |

### S34: Audit Logs (/evidence/audit-trail)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/audit/logs` | → Evidence Vault (audit events as evidence) |
| `GET /api/v1/audit/compliance/frameworks` | → Compliance Reports |

### S35: Exposure Cases (/core/exposure-cases)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/cases` | → Dashboard (case counts) |
| `GET /api/v1/cases/{id}` | — |
| `POST /api/v1/cases` | ← Finding Detail ("Create Case"), ← Brain Pipeline (auto) |
| `PATCH /api/v1/cases/{id}` | — |
| `POST /api/v1/cases/{id}/transition` | → Audit Logs (transition event), → SSE (case.transitioned) |
| `POST /api/v1/cases/{id}/clusters` | ← Correlation Engine ("Add to Case") |
| `GET /api/v1/cases/stats/summary` | → Dashboard (case stats) |
| `GET /api/v1/cases/{id}/transitions` | — (timeline in detail view) |

**State Machine:**
```
  open ──→ triaging ──→ fixing ──→ resolved ──→ closed
    │          │           │           │           │
    │          ▼           ▼           │           │
    │     accepted_risk    │           │           │
    │          │       false_positive  │           │
    │          │           │           │           │
    └──────────┴───────────┴───────────┴───────────┘
                      (reopen to 'open')
```

### S36: Remediation Center (/protect/remediation)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/remediation/tasks` | → Dashboard (MTTR, task counts) |
| `POST /api/v1/remediation/tasks` | ← Finding Detail, ← MPTE Console ("Create Task") |
| `PUT /api/v1/remediation/tasks/{id}/assign` | → Collaboration (notification) |
| `GET /api/v1/remediation/metrics` | → Dashboard (MTTR card), → Compliance Reports |
| `POST /api/v1/enhanced/analysis` (fix gen) | → AutoFix Dashboard |
| `POST /api/v1/webhooks/alm/work-items` | → External Jira/GitHub (new tab) |
| `POST /api/v1/autofix/generate` | → AutoFix Dashboard |

### S37: Brain Pipeline (/core/brain-pipeline)
| API | Cross-Links To |
|-----|---------------|
| `POST /api/v1/brain/pipeline/run` | → Exposure Cases (auto-created), → Findings View (enriched), → Correlation (reclustered) |
| `GET /api/v1/brain/pipeline/runs` | — |
| `GET /api/v1/brain/pipeline/runs/{id}` | — |
| SSE: `/api/v1/stream/pipeline/{runId}` | real-time progress bar |

**This is the orchestrator.** One pipeline run triggers:
1. Deduplication → clusters created
2. Enrichment → EPSS/KEV added to findings
3. Prioritization → SSVC decisions applied
4. Case creation → exposure cases auto-generated
5. Evidence → audit trail recorded

### S38: Workflows (/protect/workflows + /protect/playbooks)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/workflows` | → Nerve Center (playbook triggers) |
| `POST /api/v1/workflows` | — |
| `POST /api/v1/workflows/{id}/execute` | → Audit Logs (execution event), → SSE (workflow event) |

### S39: Collaboration (/protect/collaboration)
| API | Cross-Links To |
|-----|---------------|
| `GET /api/v1/collaboration/comments` | → Finding Detail (comments tab) |
| `POST /api/v1/collaboration/comments` | → Finding Detail, → Exposure Cases |
| `GET /api/v1/collaboration/notifications/pending` | → TopBar (notification bell) |

---

## S40–S43: SETTINGS SCREENS

### S40: Users (/settings/users) — 2 APIs → Auth flows
### S41: Teams (/settings/teams) — 1 API → Assignment dropdowns across all screens
### S42: System Health (/settings/system-health) — 4 APIs → Status indicators everywhere
### S43: Overlay Config (/settings/overlay-config) — shared with Nerve Center

---

# PART 4: INTERACTION STATE MACHINES

## 4.1 Finding Lifecycle State Machine

```
                    ┌──────────────────────────────────────────┐
                    │           FINDING STATES                  │
                    │                                          │
  Ingest ──────►   new ──────► triaged ──────► verified       │
  (Code Scanning)   │            │               │             │
                    │            │               │             │
                    ▼            ▼               ▼             │
                  ignored    in_progress    exploitable        │
                    │            │          │         │         │
                    │            │          │         │         │
                    │            ▼          ▼         ▼         │
                    │         fixing    not_exploitable        │
                    │            │                             │
                    │            ▼                             │
                    │         fixed ──────► evidence_collected │
                    │                                          │
                    └──────────(suppress / accept_risk)────────┘
```

| State | Set By Screen | Visible At |
|-------|--------------|-----------|
| `new` | Code Scanning (auto) | Findings View, Dashboard |
| `triaged` | Decision Engine, Copilot | Findings View |
| `verified` | MPTE Console | Finding Detail |
| `exploitable` | Micro Pentest, Reachability | Finding Detail (red badge) |
| `not_exploitable` | Micro Pentest, MPTE | Finding Detail (green badge) |
| `in_progress` | Remediation Center | Findings View, Dashboard |
| `fixing` | Remediation Center | Findings View |
| `fixed` | Remediation/AutoFix | Findings View, Dashboard (counts down) |
| `ignored` | Bulk Ops, Finding Detail | Findings View (filtered out by default) |
| `evidence_collected` | Evidence Vault | Compliance Reports |

## 4.2 Case Lifecycle State Machine (mirrors ExposureCaseCenter.tsx)

```
  open ←──────────────────────────────────────────┐
    │                                              │
    ├──→ triaging ──→ fixing ──→ resolved ──→ closed
    │        │          │          │
    │        ▼          │          │
    ├──→ accepted_risk ─┘          │
    │                              │
    └──→ false_positive ───────────┘
```

| Transition | Triggered By | Side Effects |
|-----------|-------------|-------------|
| open → triaging | Nerve Center playbook, Manual | SSE event, Audit log |
| triaging → fixing | Remediation task created | Task created, SSE event |
| fixing → resolved | All tasks completed | SSE event, Audit log |
| resolved → closed | Manual or auto (SLA) | Evidence bundle updated |
| any → accepted_risk | Manual | Audit log, Risk register |
| any → false_positive | Manual | Findings suppressed |
| any → open | Reopen | SSE event |

## 4.3 Pipeline Orchestration State Machine

```
  idle ──► ingesting ──► deduplicating ──► enriching ──► prioritizing ──► complete
    ▲          │               │               │              │              │
    │          ▼               ▼               ▼              ▼              │
    │        error           error           error          error           │
    │          │               │               │              │              │
    └──────────┴───────────────┴───────────────┴──────────────┘              │
              (retry from failed stage)                                       │
                                                                              │
    SSE events at each transition:                                            │
    stream/pipeline/{runId} → {stage, progress%, findings_count, errors[]}  │
    ← consumed by Brain Pipeline screen + Nerve Center                       │
```

---

# PART 5: COMPONENT DESIGN SYSTEM

## 5.1 Shared Components Across Screens

| Component | Screens Using | Props |
|-----------|--------------|-------|
| `<SeverityBadge>` | ALL screens with findings | `severity: 'critical'\|'high'\|'medium'\|'low'` |
| `<CVELink>` | Findings, Intel Hub, Feeds, Copilot | `cveId: string` → click opens Finding Detail |
| `<EvidenceChain>` | Finding Detail, Copilot response | `steps: {type, label, value, link}[]` |
| `<KanbanBoard>` | Exposure Cases, Remediation | `columns: Column[], items: Item[], onDrop` |
| `<ForceGraph>` | Attack Paths, Knowledge Graph, Intel Map | `nodes: Node[], edges: Edge[], onClick` |
| `<StreamingText>` | Copilot Chat, AutoFix | `stream: SSE, onToken` |
| `<MetricCard>` | Dashboard (×6), Remediation (×4) | `label, value, trend, onClick → navigate()` |
| `<FindingTable>` | Findings View, Correlation, Bulk Ops | `findings: Finding[], selectable, onRowClick` |
| `<TimelineView>` | Exposure Cases, Audit Logs | `events: {at, from, to, actor}[]` |
| `<CodeDiff>` | AutoFix, Remediation | `before: string, after: string` |
| `<CommentThread>` | Finding Detail, Exposure Cases | `entityType, entityId` → `/api/v1/collaboration/comments` |

## 5.2 Design Tokens

```
Dark Theme (Primary):
  --bg-base:        #09090B    (zinc-950)
  --bg-card:        #18181B    (zinc-900)
  --bg-elevated:    #27272A    (zinc-800)
  --bg-hover:       #3F3F46    (zinc-700)
  --border:         #27272A    (zinc-800)
  --border-focus:   #3B82F6    (blue-500)
  --text-primary:   #FAFAFA    (zinc-50)
  --text-secondary: #A1A1AA    (zinc-400)
  --text-muted:     #71717A    (zinc-500)

Severity Colors:
  --critical:       #EF4444    (red-500)
  --critical-bg:    #450A0A    (red-950)
  --high:           #F97316    (orange-500)
  --high-bg:        #431407    (orange-950)
  --medium:         #EAB308    (yellow-500)
  --medium-bg:      #422006    (yellow-950)
  --low:            #3B82F6    (blue-500)
  --low-bg:         #172554    (blue-950)
  --info:           #6B7280    (gray-500)

Accent & Actions:
  --accent:         #8B5CF6    (violet-500)
  --success:        #22C55E    (green-500)
  --warning:        #F59E0B    (amber-500)
  --error:          #EF4444    (red-500)

Typography (Inter + JetBrains Mono):
  --text-h1:        30px / 700 / -0.025em
  --text-h2:        24px / 600 / -0.02em
  --text-h3:        18px / 600 / -0.015em
  --text-body:      14px / 400 / 0
  --text-small:     12px / 400 / 0
  --text-mono:      13px / JetBrains Mono / 400

Spacing: 4 / 8 / 12 / 16 / 20 / 24 / 32 / 40 / 48 / 64
Radius: 6 (sm) / 8 (md) / 12 (lg) / 9999 (full)

Animation (Framer Motion):
  --transition-fast:    150ms ease-out
  --transition-normal:  200ms ease-out
  --transition-slow:    350ms ease-in-out
  --spring-bounce:      { type: "spring", stiffness: 300, damping: 20 }
```

---

# PART 6: API COVERAGE AUDIT

## Total: 526 endpoints in backend

| Category | Endpoints | Screens Covering | Gap |
|----------|----------|-----------------|-----|
| Dashboard/Analytics | 14 | Dashboard, Findings View | ✅ Full |
| Copilot + Agents | 17 | Copilot Chat | ✅ Full |
| Code Scanning (Ingest) | 8 | Code Scanning, SBOM, Validation | ✅ Full |
| Secrets | 6 | Secrets Detection | ✅ Full |
| IaC | 5 | IaC Scanning | ✅ Full |
| Inventory | 3 | Inventory, Cloud Posture | ✅ Full |
| Feeds (EPSS/KEV) | 6 | Threat Feeds | ✅ Full |
| Deduplication | 4 | Correlation Engine | ✅ Full |
| MPTE | 5 | MPTE Console | ✅ Full |
| Micro Pentest | 4 | Micro Pentest | ✅ Full |
| Attack Sim/Predictions | 4 | Attack Simulation, Predictions | ✅ Full |
| Reachability | 3 | Reachability Analysis | ✅ Full |
| GNN/Graph | 3 | Attack Paths | ✅ Full |
| Decision/Algorithms | 6 | Decision Engine, Algo Lab | ✅ Full |
| Enhanced/Multi-LLM | 5 | Multi-LLM | ✅ Full |
| LLM | 2 | Multi-LLM, Settings | ✅ Full |
| Nerve Center | 8 | Nerve Center | ✅ Full |
| Brain Pipeline | 4 | Brain Pipeline | ✅ Full |
| Exposure Cases | 8 | Exposure Cases | ✅ Full |
| Remediation | 6 | Remediation Center | ✅ Full |
| Workflows | 6 | Workflows, Playbooks | ✅ Full |
| Policies | 3 | Policies | ✅ Full |
| Bulk | 2 | Bulk Operations | ✅ Full |
| Collaboration | 3 | Collaboration, Finding Detail | ✅ Full |
| Evidence | 7 | Evidence Vault, SOC2 | ✅ Full |
| Compliance/Reports | 6 | Compliance Reports, Reports | ✅ Full |
| Audit | 2 | Audit Logs | ✅ Full |
| Integrations | 6 | Integrations Hub | ✅ Full |
| Webhooks | 14 | Webhooks | ✅ Full |
| Marketplace | 2 | Marketplace | ✅ Full |
| Auth/Users/Teams | 4 | Settings | ✅ Full |
| Health/System | 4 | System Health | ✅ Full |
| Streaming/SSE | 3 | Global (TopBar, Pipeline, Pentest) | ✅ Full |
| Code-to-Cloud | 2 | Data Fabric, Inventory | ✅ Full |
| Business Context | 3 | Data Fabric | ✅ Full |
| **SAST** | 3 | ❌ **MISSING SCREEN** | Add /code/sast |
| **DAST** | 3 | ⚠️ Basic | Enhance /attack/dast |
| **API Fuzzer** | 3 | ⚠️ Basic | Enhance /attack/api-fuzzer |
| **Malware** | 3 | ⚠️ Basic | Enhance /attack/malware |
| **Container (suite-attack)** | 3 | Cloud/Container | ✅ Covered |
| **CSPM** | 3 | Cloud Posture | ✅ Covered |
| **AutoFix** | 3 | AutoFix Dashboard | ✅ Covered |
| **Fuzzy Identity** | 2 | Correlation (inline) | ✅ Covered |
| **LLM Monitor** | 3 | ❌ **MISSING SCREEN** | Add /ai/llm-monitor |
| **Intelligent Engine** | 4 | ❌ **MISSING SCREEN** | Add /ai/intelligent-engine |
| **Provenance** | 3 | SLSA Provenance | ✅ Covered |
| **Risk** | 3 | Data Fabric (inline) | ✅ Covered |
| **OSS Tools** | 3 | MCP Connectors | ✅ Covered |
| **IDE** | 2 | MCP Connectors | ✅ Covered |
| **Logs (detailed)** | 3 | Settings/Log Viewer | ✅ Covered |
| **Learning Middleware** | 2 | ❌ **MISSING SCREEN** | Add /ai/anomaly-detection |

### Missing Screens to Add (4):
1. **`/code/sast`** — SAST Analysis (3 endpoints from sast_router)
2. **`/ai/llm-monitor`** — LLM Usage & Cost Monitor (3 endpoints from llm_monitor_router)
3. **`/ai/intelligent-engine`** — Intelligent Engine Dashboard (4 endpoints)
4. **`/ai/anomaly-detection`** — API Anomaly Detection from ML Learning Middleware (2 endpoints)

---

# PART 7: COMPLETE ROUTE TABLE (68 routes → 45 screens)

| Route | Screen | Suite | Status |
|-------|--------|-------|--------|
| `/` | Dashboard | Home | ✅ |
| `/dashboard` | Dashboard | Home | ✅ alias |
| `/nerve-center` | Nerve Center | Home | ✅ |
| `/findings` | Findings View | Global | ✅ NEW |
| `/copilot` | Copilot Chat | AI | ✅ |
| `/code/code-scanning` | Code Scanning | Code | ✅ |
| `/code/secrets-detection` | Secrets Detection | Code | ✅ |
| `/code/iac-scanning` | IaC Scanning | Code | ✅ |
| `/code/sbom-generation` | SBOM Generation | Code | ✅ |
| `/code/inventory` | Inventory | Code | ✅ |
| `/code/sast` | SAST Analysis | Code | 🆕 ADD |
| `/cloud/cloud-posture` | Cloud Posture | Cloud | ✅ |
| `/cloud/container-security` | Container Security | Cloud | ✅ |
| `/cloud/runtime-protection` | Runtime Protection | Cloud | ✅ |
| `/cloud/threat-feeds` | Threat Feeds | Cloud | ✅ |
| `/cloud/correlation` | Correlation Engine | Cloud | ✅ |
| `/attack/mpte` | MPTE Console | Attack | ✅ |
| `/attack/micro-pentest` | Micro Pentest | Attack | ✅ |
| `/attack/attack-simulation` | Attack Simulation | Attack | ✅ |
| `/attack/reachability` | Reachability Analysis | Attack | ✅ |
| `/attack/attack-paths` | Attack Paths GNN | Attack | ✅ |
| `/attack/dast` | DAST Scanner | Attack | ✅ |
| `/attack/api-fuzzer` | API Fuzzer | Attack | ✅ |
| `/attack/malware` | Malware Analysis | Attack | ✅ |
| `/attack/exploit-research` | Attack Lab | Attack | ✅ |
| `/decisions` | Decision Engine | AI | ✅ |
| `/ai-engine/algorithmic-lab` | Algorithmic Lab | AI | ✅ |
| `/ai-engine/multi-llm` | Multi-LLM | AI | ✅ |
| `/ai-engine/predictions` | Predictions | AI | ✅ |
| `/ai-engine/policies` | Policies | AI | ✅ |
| `/ai-engine/ml-dashboard` | ML Dashboard | AI | ✅ |
| `/ai/llm-monitor` | LLM Monitor | AI | 🆕 ADD |
| `/ai/intelligent-engine` | Intelligent Engine | AI | 🆕 ADD |
| `/ai/anomaly-detection` | Anomaly Detection | AI | 🆕 ADD |
| `/protect/remediation` | Remediation Center | Govern | ✅ |
| `/protect/autofix` | AutoFix Dashboard | Govern | ✅ |
| `/protect/playbooks` | Playbooks | Govern | ✅ |
| `/protect/playbook-editor` | Playbook Editor | Govern | ✅ |
| `/protect/bulk-operations` | Bulk Operations | Govern | ✅ |
| `/protect/workflows` | Workflows | Govern | ✅ |
| `/protect/collaboration` | Collaboration | Govern | ✅ |
| `/protect/integrations` | Integrations Hub | Connect | ✅ |
| `/core/exposure-cases` | Exposure Cases | Govern | ✅ |
| `/core/brain-pipeline` | Brain Pipeline | Govern | ✅ |
| `/core/knowledge-graph` | Knowledge Graph | Govern | ✅ |
| `/evidence/bundles` | Evidence Vault | Evidence | ✅ |
| `/evidence/compliance` | Compliance Reports | Evidence | ✅ |
| `/evidence/audit-trail` | Audit Logs | Evidence | ✅ |
| `/evidence/reports` | Reports | Evidence | ✅ |
| `/evidence/analytics` | Evidence Analytics | Evidence | ✅ |
| `/evidence/soc2` | SOC2 Evidence | Evidence | ✅ |
| `/evidence/slsa-provenance` | SLSA Provenance | Evidence | ✅ |
| `/data-fabric` | Data Fabric | Core | ✅ |
| `/feeds/live` | Live Feed Dashboard | Feeds | ✅ |
| `/settings` | Settings | Settings | ✅ |
| `/settings/users` | Users | Settings | ✅ |
| `/settings/teams` | Teams | Settings | ✅ |
| `/settings/integrations` | Integrations Settings | Settings | ✅ |
| `/settings/marketplace` | Marketplace | Settings | ✅ |
| `/settings/system-health` | System Health | Settings | ✅ |
| `/settings/webhooks` | Webhooks | Settings | ✅ |
| `/settings/overlay-config` | Overlay Config | Settings | ✅ |
| `/settings/logs` | Log Viewer | Settings | ✅ |
