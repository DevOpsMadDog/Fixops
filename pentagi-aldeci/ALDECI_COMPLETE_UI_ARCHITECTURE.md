# ALdeci Intelligence Hub - Complete UI Architecture

## 🎯 Overview

**ALdeci** (Algorithmic Vulnerability Management) built on **PentAGI** with comprehensive coverage of **363 API endpoints** mapped to **5 Product Suites** following the **6-Step CTEM Framework**.

### 6-Step Framework → 5 Product Suites Mapping

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    6-STEP CTEM FRAMEWORK                                │
├─────────────────────────────────────────────────────────────────────────┤
│  1.INGEST → 2.CORRELATE → 3.DECIDE → 4.VERIFY → 5.REMEDIATE → 6.EVIDENCE│
│     ↓            ↓           ↓          ↓           ↓            ↓      │
│  ┌──────┐    ┌──────┐    ┌──────┐   ┌──────┐    ┌──────┐    ┌──────┐   │
│  │ CODE │    │CLOUD │    │  AI  │   │ATTACK│    │PROTECT│   │EVID- │   │
│  │SUITE │    │SUITE │    │ENGINE│   │SUITE │    │ SUITE │   │ ENCE │   │
│  └──────┘    └──────┘    └──────┘   └──────┘    └──────┘    └──────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

| Product Suite | CTEM Steps | PRD Codes | APIs | Description |
|---------------|------------|-----------|------|-------------|
| **🔍 CODE** | Ingest (code) | FR-ING | 15 | SAST, SCA, Secrets, IaC, Validation |
| **☁️ CLOUD** | Ingest + Correlate | FR-ING + FR-COR | 56 | CSPM, Feeds, Dedup, Inventory, Attack Paths |
| **⚔️ ATTACK** | Verify | FR-VER | 62 | PentAGI, Micro-Pentest, Intelligent Engine |
| **🛡️ PROTECT** | Remediate | FR-REM + FR-AUT | 84 | Remediation, Workflows, Bulk Ops, Webhooks, Collaboration |
| **🧠 AI ENGINE** | Decide | FR-DEC | 37 | Multi-LLM, Monte Carlo, Causal, Predictions, Policies |
| **📦 EVIDENCE** | Evidence | FR-EVD + FR-VIZ | 52 | Audit, Reports, Analytics, Provenance, Graph, Risk |
| **⚙️ SETTINGS** | - | - | 32 | Users, Teams, Auth, Integrations, IDE, Health |
| **💬 COPILOT** | All Steps | - | 25 | App.py Ingestion + Health endpoints |
| **TOTAL** | | | **363** | |

---

## 🏗️ UI Architecture - 5 Product Suites + AI Copilot

### Navigation Structure (Left Sidebar Icons)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  🛡️ ALdeci Intelligence Hub      [Dashboard] [Inbox] [Settings] 🔔 👤  │
├───────┬─────────────────────────────────────────────────────────────────┤
│       │                                                                 │
│  📊   │  DASHBOARD (Overview - CTEM Progress Ring)                      │
│  💬   │  COPILOT (AI Chat - like Aikido's agent reasoning)              │
│       │                                                                 │
│  ──   │  ═══════════ CODE SUITE (FR-ING: Ingest) ═══════════           │
│  🔍   │  Code Scanning (SAST/SCA) - /inputs/sbom, /sarif                │
│  🔑   │  Secrets Detection - /api/v1/secrets/*                          │
│  🏗️   │  Infrastructure as Code - /api/v1/iac/*                         │
│  📜   │  License & SBOM - /inputs/sbom, /api/v1/inventory/*             │
│       │                                                                 │
│  ──   │  ═══════════ CLOUD SUITE (FR-COR: Correlate) ═══════════       │
│  ☁️   │  Cloud Posture (CSPM) - /inputs/cnapp, /api/v1/feeds/*          │
│  📦   │  Container & VM Scanning - /api/v1/inventory/components         │
│  🔗   │  Finding Correlation - /api/v1/deduplication/*                  │
│  🕸️   │  Attack Paths (GNN) - /api/v1/algorithms/gnn/*                  │
│       │                                                                 │
│  ──   │  ═══════════ ATTACK SUITE (FR-VER: Verify) ═══════════         │
│  ⚔️   │  AI Pentesting (PentAGI) - /api/v1/pentagi/*                    │
│  🎯   │  Attack Simulation - /api/v1/predictions/simulate-attack        │
│  📋   │  Playbooks & Campaigns - /api/v1/micro-pentest/*                │
│  🌐   │  Surface Monitoring (DAST) - /api/v1/reachability/*             │
│       │                                                                 │
│  ──   │  ═══════════ PROTECT SUITE (FR-REM: Remediate) ═══════════     │
│  🛡️   │  Remediation Center - /api/v1/remediation/*                     │
│  ⚡   │  Bulk Operations - /api/v1/bulk/*                               │
│  🤝   │  Collaboration - /api/v1/collaboration/*                        │
│  🔄   │  Workflows & Automation - /api/v1/workflows/*                   │
│  🎫   │  Ticket Integrations - /api/v1/webhooks/*                       │
│       │                                                                 │
│  ──   │  ═══════════ AI ENGINE (FR-DEC: Decide) ═══════════            │
│  📈   │  Algorithmic Lab - /api/v1/algorithms/*                         │
│       │    ├── Monte Carlo FAIR (Risk Quantification)                   │
│       │    ├── Causal Inference (Impact Analysis)                       │
│       │    └── GNN Attack Graph (Critical Nodes)                        │
│  🤖   │  Multi-LLM Consensus - /api/v1/enhanced/*                       │
│       │    ├── GPT-5, Claude-3, Gemini-2, Sentinel-Cyber               │
│       │    └── Weighted voting + Expert override                        │
│  📊   │  Predictions - /api/v1/predictions/*                            │
│       │    ├── Markov Chain (State Transitions)                         │
│       │    └── Bayesian Network (Probability Updates)                   │
│  📏   │  Policy Engine - /api/v1/policies/*                             │
│       │                                                                 │
│  ──   │  ═══════════ EVIDENCE (FR-EVD: Evidence) ═══════════           │
│  📦   │  Evidence Bundles - /api/v1/evidence/*                          │
│  🔏   │  SLSA Provenance - /api/v1/provenance/*                         │
│  📑   │  Compliance Reports - /api/v1/compliance/*                      │
│  📝   │  Audit Trail - /api/v1/audit/*                                  │
│  📊   │  Analytics Dashboard - /api/v1/analytics/*                      │
│       │                                                                 │
│  ──   │  ═══════════════════════════════════════════════════           │
│  ⚙️   │  Settings & Integrations - /api/v1/users/*, /teams/*, /llm/*   │
│       │                                                                 │
└───────┴─────────────────────────────────────────────────────────────────┘
```

---

## � CTEM 6-Step Framework → Product Suite Mapping

### How ALdeci Maps the CTEM Continuous Threat Exposure Management Cycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     CTEM 6-STEP CONTINUOUS CYCLE                            │
│                                                                             │
│     ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐              │
│     │1.INGEST │───▶│2.CORREL-│───▶│3.DECIDE │───▶│4.VERIFY │              │
│     │(Discover)│    │  ATE    │    │(Priorit.)   │(Validate)│              │
│     └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘              │
│          │              │              │              │                     │
│     ┌────▼────┐    ┌────▼────┐    ┌────▼────┐    ┌────▼────┐              │
│     │  CODE   │    │  CLOUD  │    │   AI    │    │ ATTACK  │              │
│     │  SUITE  │    │  SUITE  │    │ ENGINE  │    │  SUITE  │              │
│     │ 18 APIs │    │ 29 APIs │    │ 32 APIs │    │ 40 APIs │              │
│     └─────────┘    └─────────┘    └─────────┘    └─────────┘              │
│                                                                             │
│                    ┌─────────┐    ┌─────────┐                              │
│                    │5.REMEDI-│◀───│6.EVIDENCE│◀──────────────────┐        │
│                    │  ATE    │    │(Measure) │                    │        │
│                    └────┬────┘    └────┬────┘                    │        │
│                         │              │                          │        │
│                    ┌────▼────┐    ┌────▼────┐                    │        │
│                    │ PROTECT │    │EVIDENCE │                    │        │
│                    │  SUITE  │    │  VAULT  │────────────────────┘        │
│                    │ 51 APIs │    │ 35 APIs │    (Feedback Loop)          │
│                    └─────────┘    └─────────┘                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Detailed Suite → CTEM Step Mapping

| Product Suite | CTEM Step | PRD Codes | What Happens | APIs |
|---------------|-----------|-----------|--------------|------|
| **🔍 CODE SUITE** | 1. Ingest (Code) | FR-ING | SBOM/SARIF/Secrets/IaC ingestion | 18 |
| **☁️ CLOUD SUITE** | 1. Ingest + 2. Correlate | FR-ING + FR-COR | CNAPP + Deduplication + GNN Paths | 29 |
| **🧠 AI ENGINE** | 3. Decide (Prioritize) | FR-DEC | Multi-LLM + Monte Carlo + Bayesian | 32 |
| **⚔️ ATTACK SUITE** | 4. Verify (Validate) | FR-VER | PentAGI + Micro-Pentest + DAST | 40 |
| **🛡️ PROTECT SUITE** | 5. Remediate | FR-REM + FR-AUT | Workflows + Bulk Ops + Tickets | 51 |
| **📦 EVIDENCE** | 6. Evidence (Measure) | FR-EVD + FR-VIZ | Bundles + SLSA + Compliance | 35 |

### CTEM Progress Visualization in Dashboard

The Dashboard shows real-time CTEM cycle completion:

```
┌─────────────────────────────────────────────────────────────┐
│  CTEM CYCLE PROGRESS                        Overall: 78%   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. INGEST     ████████████████████ 100%  ✓ CODE SUITE     │
│     └── 24 SBOMs, 12 SARIF, 8 CNAPP files ingested         │
│                                                             │
│  2. CORRELATE  ████████████░░░░░░░░  60%  ↻ CLOUD SUITE    │
│     └── 4,567 findings → 1,234 clusters (73% dedup)        │
│                                                             │
│  3. DECIDE     ███████████████░░░░░  75%  ↻ AI ENGINE      │
│     └── 4 LLMs: 81.5% consensus ALLOW                      │
│                                                             │
│  4. VERIFY     ██████████████████░░  90%  ✓ ATTACK SUITE   │
│     └── 45/50 CVEs verified, 12 exploited                  │
│                                                             │
│  5. REMEDIATE  █████████░░░░░░░░░░░  45%  ↻ PROTECT SUITE  │
│     └── 234 tasks open, MTTR: 4.2 days                     │
│                                                             │
│  6. EVIDENCE   ████████████████░░░░  80%  ✓ EVIDENCE VAULT │
│     └── 12 bundles signed, SLSA L3                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## �📊 PAGE 1: Dashboard (Home) + CTEM Progress

### APIs Consumed (20 endpoints)

```javascript
// FR-VIZ: Visualization APIs
const dashboardApis = {
  overview: 'GET /api/v1/analytics/dashboard',
  trends: 'GET /api/v1/analytics/trends',
  topRisks: 'GET /api/v1/analytics/top-risks',
  compliance: 'GET /api/v1/analytics/compliance',
  mttr: 'GET /api/v1/analytics/mttr',
  coverage: 'GET /api/v1/analytics/coverage',
  roi: 'GET /api/v1/analytics/roi',
  noiseReduction: 'GET /api/v1/analytics/noise-reduction',
  
  // Graph APIs
  graphSummary: 'GET /api/v1/graph',
  lineage: 'GET /api/v1/graph/lineage',
  kev: 'GET /api/v1/graph/kev',
  anomalies: 'GET /api/v1/graph/anomalies',
  
  // Multi-LLM Status
  llmStatus: 'GET /api/v1/llm/status',
  enhancedSignals: 'GET /api/v1/enhanced/signals',
  
  // Algorithm Status
  algorithmStatus: 'GET /api/v1/algorithms/status',
  algorithmCaps: 'GET /api/v1/algorithms/capabilities'
};
```

### Layout

```
┌────────────────────────────────────────────────────────────────────────┐
│ 📊 ALdeci Dashboard                                    🔔 ⚙️ 👤       │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌──────────────────────────┐  ┌──────────────────────────────────┐   │
│  │   CTEM PROGRESS RING     │  │  MULTI-LLM CONSENSUS PANEL       │   │
│  │                          │  │                                   │   │
│  │     ┌─────────────┐      │  │  GPT-5 ████████░░ 82% ✓          │   │
│  │     │  6-STEP     │      │  │  Claude ████████░░ 85% ✓         │   │
│  │     │  FRAMEWORK  │      │  │  Gemini ███████░░░ 78% ✓         │   │
│  │     │             │      │  │  Sentinel ████████░░ 81% ✓       │   │
│  │     │   78%       │      │  │  ─────────────────────────       │   │
│  │     │  Overall    │      │  │  Consensus: 81.5% ALLOW          │   │
│  │     └─────────────┘      │  │  Method: Weighted Voting          │   │
│  │                          │  │  Expert Override: Not Required    │   │
│  │  1.Ingest ██████████ 100%│  └──────────────────────────────────┘   │
│  │  2.Correlate █████░░░ 60%│                                         │
│  │  3.Decide ███████░░░ 75% │  ┌──────────────────────────────────┐   │
│  │  4.Verify █████████░ 90% │  │  ALGORITHMIC ENGINES STATUS      │   │
│  │  5.Remediate ████░░░ 45% │  │                                   │   │
│  │  6.Evidence ███████░ 80% │  │  Monte Carlo FAIR    🟢 Active    │   │
│  └──────────────────────────┘  │  Causal DAG          🟢 Active    │   │
│                                │  GNN Attack Graph    🟢 Active    │   │
│  ┌──────────────────────────┐  │  Markov Chain        🟢 Active    │   │
│  │   RISK METRICS           │  │  Bayesian Network    🟢 Active    │   │
│  │                          │  │  MindsDB (ML)        🟢 47334     │   │
│  │  Critical: 12 (-3 today) │  └──────────────────────────────────┘   │
│  │  High: 45 (+7 today)     │                                         │
│  │  Medium: 234             │  ┌──────────────────────────────────┐   │
│  │  Low: 890                │  │  LIVE ALERT FEED                 │   │
│  │  ───────────────────     │  │                                   │   │
│  │  MTTR: 4.2 days          │  │  🔴 CVE-2024-1234 Exploited      │   │
│  │  False Positive: 62%↓    │  │  🟡 New SBOM ingested (APP3)     │   │
│  │  Coverage: 89%           │  │  🟢 Pentest completed (task-42)  │   │
│  └──────────────────────────┘  │  🔵 Evidence bundle signed       │   │
│                                └──────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📥 PAGE 2: Data Fabric (Ingest - FR-ING)

### APIs Consumed (24 endpoints)

```javascript
const ingestApis = {
  // Direct Ingestion
  design: 'POST /inputs/design',
  sbom: 'POST /inputs/sbom',
  sarif: 'POST /inputs/sarif',
  cve: 'POST /inputs/cve',
  vex: 'POST /inputs/vex',
  cnapp: 'POST /inputs/cnapp',
  context: 'POST /inputs/context',
  
  // Scanner-Agnostic
  multipart: 'POST /api/v1/ingest/multipart',
  
  // Assets & Formats
  assets: 'GET /api/v1/ingest/assets',
  formats: 'GET /api/v1/ingest/formats',
  
  // Chunked Upload
  chunksStart: 'POST /inputs/{stage}/chunks/start',
  chunksUpload: 'PUT /inputs/{stage}/chunks/{upload_id}/{chunk_index}',
  chunksComplete: 'POST /inputs/{stage}/chunks/{upload_id}/complete',
  chunksStatus: 'GET /inputs/{stage}/chunks/{upload_id}/status',
  
  // Vulnerability Feeds
  epss: 'GET /api/v1/feeds/epss',
  epssRefresh: 'POST /api/v1/feeds/epss/refresh',
  kev: 'GET /api/v1/feeds/kev',
  kevRefresh: 'POST /api/v1/feeds/kev/refresh',
  feedStats: 'GET /api/v1/feeds/stats',
  feedCategories: 'GET /api/v1/feeds/categories',
  feedSources: 'GET /api/v1/feeds/sources',
  feedHealth: 'GET /api/v1/feeds/health',
  feedScheduler: 'GET /api/v1/feeds/scheduler',
  
  // Validation
  validate: 'POST /api/v1/validation/check'
};
```

### Layout

```
┌────────────────────────────────────────────────────────────────────────┐
│ 📥 Data Fabric - Universal Security Artifact Ingestion                │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │ DRAG & DROP ZONE                                              │    │
│  │                                                               │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │    │
│  │  │  SBOM   │ │  SARIF  │ │  CVE    │ │  VEX    │ │  CNAPP  │ │    │
│  │  │CycloneDX│ │ 2.1+    │ │  Feed   │ │OpenVEX  │ │ Wiz/Orca│ │    │
│  │  │  SPDX   │ │ Snyk    │ │  NVD    │ │CycloneDX│ │ AWS Hub │ │    │
│  │  │  Syft   │ │ Trivy   │ │  KEV    │ │         │ │ Azure   │ │    │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ │    │
│  │                                                               │    │
│  │  📄 Drop files or click to browse (max 50MB)                 │    │
│  │     Supported: JSON, XML, CSV, SARIF                         │    │
│  └───────────────────────────────────────────────────────────────┘    │
│                                                                        │
│  ┌──────────────────────────┐  ┌──────────────────────────────────┐   │
│  │  INTELLIGENCE FEEDS      │  │  RECENT INGESTIONS               │   │
│  │                          │  │                                   │   │
│  │  EPSS Scores             │  │  ✓ app3-sbom.cdx.json  3 min ago │   │
│  │  Last: 2024-01-15 08:00  │  │  ✓ snyk-results.sarif  15 min    │   │
│  │  Coverage: 234,567 CVEs  │  │  ✓ wiz-findings.json   1 hour    │   │
│  │  [🔄 Refresh]            │  │  ✓ kev-feed.json       2 hours   │   │
│  │                          │  │  ─────────────────────────────   │   │
│  │  KEV (Known Exploited)   │  │  Total Today: 24 files           │   │
│  │  Last: 2024-01-15 06:00  │  │  Success Rate: 98.2%             │   │
│  │  Active: 1,127 CVEs      │  │  Findings Extracted: 4,567       │   │
│  │  [🔄 Refresh]            │  └──────────────────────────────────┘   │
│  └──────────────────────────┘                                         │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  SCANNER-AGNOSTIC MULTIPART INGESTION                            │ │
│  │                                                                   │ │
│  │  POST /api/v1/ingest/multipart                                   │ │
│  │                                                                   │ │
│  │  Upload any security scanner output - ALdeci auto-detects:       │ │
│  │  • Snyk, Trivy, Grype, Semgrep, Dependabot                      │ │
│  │  • AWS Security Hub, Azure Defender, GCP SCC                     │ │
│  │  • GitHub GHAS, GitLab SAST/DAST                                 │ │
│  │                                                                   │ │
│  │  [📤 Upload Scan Results]                                        │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔗 PAGE 3: Intelligence Hub (Correlate - FR-COR)

### APIs Consumed (23 endpoints)

```javascript
const correlateApis = {
  // Deduplication
  processFinding: 'POST /api/v1/deduplication/process',
  processBatch: 'POST /api/v1/deduplication/batch',
  listClusters: 'GET /api/v1/deduplication/clusters',
  getCluster: 'GET /api/v1/deduplication/clusters/{id}',
  updateCluster: 'PUT /api/v1/deduplication/clusters/{id}/status',
  assignCluster: 'PUT /api/v1/deduplication/clusters/{id}/assign',
  linkTicket: 'PUT /api/v1/deduplication/clusters/{id}/ticket',
  relatedClusters: 'GET /api/v1/deduplication/clusters/{id}/related',
  
  // Correlations
  listCorrelations: 'GET /api/v1/deduplication/correlations',
  createCorrelation: 'POST /api/v1/deduplication/correlations',
  dedupStats: 'GET /api/v1/deduplication/stats',
  orgStats: 'GET /api/v1/deduplication/stats/{org_id}',
  crossStage: 'POST /api/v1/deduplication/cross-stage',
  correlationGraph: 'GET /api/v1/deduplication/graph',
  feedback: 'POST /api/v1/deduplication/feedback',
  compareBaseline: 'POST /api/v1/deduplication/compare-baseline',
  mergeClusters: 'POST /api/v1/deduplication/merge',
  splitCluster: 'POST /api/v1/deduplication/split',
  
  // Enrichment
  listExploits: 'GET /api/v1/enrichment/exploits',
  getExploits: 'GET /api/v1/enrichment/exploits/{cve_id}',
  addExploit: 'POST /api/v1/enrichment/exploits',
  enrichFinding: 'POST /api/v1/enrichment/finding',
  exploitConfidence: 'GET /api/v1/enrichment/confidence/{cve_id}'
};
```

### Layout

```
┌────────────────────────────────────────────────────────────────────────┐
│ 🔗 Intelligence Hub - Finding Correlation & Enrichment                │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                    CORRELATION GRAPH                              │ │
│  │                                                                   │ │
│  │           ┌───┐                                                  │ │
│  │           │CVE│──────┐                                           │ │
│  │           └───┘      │    ┌───────┐                             │ │
│  │    ┌───┐             ├────│Cluster│────┐                        │ │
│  │    │PKG│─────────────┤    │  #42  │    │    ┌────────┐          │ │
│  │    └───┘             │    └───────┘    ├────│  JIRA  │          │ │
│  │           ┌───┐      │                 │    │ SEC-123│          │ │
│  │           │SCA│──────┘    ┌───────┐    │    └────────┘          │ │
│  │           └───┘           │ Asset │────┘                        │ │
│  │                           │ app-3 │                              │ │
│  │                           └───────┘                              │ │
│  │                                                                   │ │
│  │  [Zoom] [Pan] [Filter: Critical ▼] [Export Graph]                │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  ┌─────────────────────────────┐  ┌────────────────────────────────┐  │
│  │  DEDUPLICATION STATS        │  │  FINDING CLUSTERS              │  │
│  │                             │  │                                 │  │
│  │  Total Findings: 4,567      │  │  ┌─────────────────────────┐   │  │
│  │  Unique Clusters: 1,234     │  │  │ Cluster #42             │   │  │
│  │  Dedup Rate: 73%            │  │  │ CVE-2024-1234           │   │  │
│  │  Cross-Stage: 456           │  │  │ 7 findings, 3 scanners  │   │  │
│  │  ─────────────────────      │  │  │ Severity: Critical      │   │  │
│  │  False Positive Rate:       │  │  │ [View] [Merge] [Split]  │   │  │
│  │  Before: 60%                │  │  └─────────────────────────┘   │  │
│  │  After:  8%                 │  │  ┌─────────────────────────┐   │  │
│  │  Reduction: 87%             │  │  │ Cluster #43             │   │  │
│  │                             │  │  │ Log4Shell variants      │   │  │
│  │  [📊 Full Stats]            │  │  │ 12 findings, 5 scanners │   │  │
│  └─────────────────────────────┘  │  │ Severity: Critical      │   │  │
│                                   │  └─────────────────────────┘   │  │
│  ┌─────────────────────────────┐  │                                 │  │
│  │  ENRICHMENT SOURCES         │  │  [Load More...]                │  │
│  │                             │  └────────────────────────────────┘  │
│  │  ✓ NVD                      │                                      │
│  │  ✓ EPSS                     │                                      │
│  │  ✓ KEV                      │                                      │
│  │  ✓ Exploit-DB               │                                      │
│  │  ✓ GitHub Advisories        │                                      │
│  └─────────────────────────────┘                                      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 PAGE 4: Decision Engine (Decide - FR-DEC)

### APIs Consumed (32 endpoints)

```javascript
const decisionApis = {
  // Multi-LLM Consensus
  enhancedAnalysis: 'POST /api/v1/enhanced/analysis',
  compareLLMs: 'POST /api/v1/enhanced/compare-llms',
  capabilities: 'GET /api/v1/enhanced/capabilities',
  signals: 'GET /api/v1/enhanced/signals',
  
  // Monte Carlo FAIR
  monteCarloQuantify: 'POST /api/v1/algorithms/monte-carlo/quantify',
  monteCarloCVE: 'POST /api/v1/algorithms/monte-carlo/cve',
  monteCarloPortfolio: 'POST /api/v1/algorithms/monte-carlo/portfolio',
  
  // Causal Inference
  causalAnalyze: 'POST /api/v1/algorithms/causal/analyze',
  causalCounterfactual: 'POST /api/v1/algorithms/causal/counterfactual',
  causalTreatment: 'POST /api/v1/algorithms/causal/treatment-effect',
  
  // GNN Attack Paths
  gnnAttackSurface: 'POST /api/v1/algorithms/gnn/attack-surface',
  gnnCriticalNodes: 'POST /api/v1/algorithms/gnn/critical-nodes',
  gnnRiskPropagation: 'POST /api/v1/algorithms/gnn/risk-propagation',
  
  // Algorithm Status
  algorithmStatus: 'GET /api/v1/algorithms/status',
  algorithmCapabilities: 'GET /api/v1/algorithms/capabilities',
  
  // Predictive Analytics
  attackChain: 'POST /api/v1/predictions/attack-chain',
  riskTrajectory: 'POST /api/v1/predictions/risk-trajectory',
  simulateAttack: 'POST /api/v1/predictions/simulate-attack',
  markovStates: 'GET /api/v1/predictions/markov/states',
  markovTransitions: 'GET /api/v1/predictions/markov/transitions',
  bayesianUpdate: 'POST /api/v1/predictions/bayesian/update',
  bayesianRisk: 'POST /api/v1/predictions/bayesian/risk-assessment',
  combinedAnalysis: 'POST /api/v1/predictions/combined-analysis',
  
  // Policy Engine
  listPolicies: 'GET /api/v1/policies',
  createPolicy: 'POST /api/v1/policies',
  getPolicy: 'GET /api/v1/policies/{id}',
  updatePolicy: 'PUT /api/v1/policies/{id}',
  deletePolicy: 'DELETE /api/v1/policies/{id}',
  validatePolicy: 'POST /api/v1/policies/validate',
  testPolicy: 'POST /api/v1/policies/test',
  violations: 'GET /api/v1/policies/violations',
  
  // LLM Configuration
  llmStatus: 'GET /api/v1/llm/status',
  llmTest: 'POST /api/v1/llm/test',
  llmSettings: 'GET /api/v1/llm/settings',
  llmUpdate: 'PATCH /api/v1/llm/settings',
  llmProviders: 'GET /api/v1/llm/providers',
  llmHealth: 'GET /api/v1/llm/health'
};
```

### Layout

```
┌────────────────────────────────────────────────────────────────────────┐
│ 🧠 Decision Engine - Algorithmic Risk Analysis & Multi-LLM Consensus  │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  MULTI-LLM CONSENSUS ANALYSIS                                     │ │
│  │                                                                   │ │
│  │  Service: payment-gateway  │  Environment: production             │ │
│  │  ────────────────────────────────────────────────────────────    │ │
│  │                                                                   │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  │ │
│  │  │   GPT-5    │  │  Claude-3  │  │ Gemini-2.0 │  │  Sentinel  │  │ │
│  │  │   ALLOW    │  │   ALLOW    │  │   BLOCK    │  │   ALLOW    │  │ │
│  │  │   85%      │  │   82%      │  │   45%      │  │   88%      │  │ │
│  │  │  Weight:30%│  │  Weight:25%│  │  Weight:25%│  │  Weight:20%│  │ │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘  │ │
│  │                                                                   │ │
│  │  ═══════════════════════════════════════════════════════════════ │ │
│  │  FINAL CONSENSUS: ALLOW @ 81.5% confidence                       │ │
│  │  Method: Weighted Majority Voting                                │ │
│  │  Disagreement: Gemini flagged unpatched Log4j (override by 3/4)  │ │
│  │  Expert Review: Not Required                                     │ │
│  │  ═══════════════════════════════════════════════════════════════ │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────┐   │
│  │ MONTE CARLO FAIR │ │ CAUSAL INFERENCE │ │ GNN ATTACK PATHS     │   │
│  │                  │ │                  │ │                       │   │
│  │ Expected Loss:   │ │ Impact Graph:    │ │ Critical Nodes:       │   │
│  │ $2.4M - $8.7M    │ │                  │ │                       │   │
│  │                  │ │   CVE → App → DB │ │  1. API Gateway       │   │
│  │ VaR @ 95%:       │ │        ↓         │ │  2. Auth Service      │   │
│  │ $6.2M            │ │     Revenue      │ │  3. Payment DB        │   │
│  │                  │ │                  │ │                       │   │
│  │ Simulations:     │ │ Treatment Effect:│ │ Propagation Risk:     │   │
│  │ 10,000 runs      │ │ Patch = -$4.2M   │ │ 78% → 23% (if fixed) │   │
│  │                  │ │                  │ │                       │   │
│  │ [Run Analysis]   │ │ [What-If Query]  │ │ [View Attack Graph]   │   │
│  └──────────────────┘ └──────────────────┘ └──────────────────────┘   │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  PREDICTIVE ANALYTICS                                             │ │
│  │                                                                   │ │
│  │  Markov Chain State: "Elevated Risk" (P=0.34)                    │ │
│  │  Next State Probabilities:                                        │ │
│  │    → Critical: 12%  → Elevated: 45%  → Normal: 43%               │ │
│  │                                                                   │ │
│  │  Bayesian Posterior: P(exploit|evidence) = 0.78                  │ │
│  │  Prior: 0.45  |  Likelihood: 0.89  |  Update: +0.33              │ │
│  │                                                                   │ │
│  │  [📈 View Risk Trajectory]  [🎯 Simulate Attack Chain]           │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ⚔️ PAGE 5: Attack Lab (Verify - FR-VER)

### APIs Consumed (40 endpoints)

```javascript
const verifyApis = {
  // Micro-Pentest
  runMicroPentest: 'POST /api/v1/micro-pentest/run',
  pentestStatus: 'GET /api/v1/micro-pentest/{id}/status',
  batchPentest: 'POST /api/v1/micro-pentest/batch',
  enterpriseScan: 'POST /api/v1/micro-pentest/enterprise/scan',
  getEnterpriseScan: 'GET /api/v1/micro-pentest/enterprise/{id}',
  listEnterpriseScans: 'GET /api/v1/micro-pentest/enterprise',
  cancelScan: 'POST /api/v1/micro-pentest/enterprise/{id}/cancel',
  auditLogs: 'GET /api/v1/micro-pentest/audit',
  enterpriseHealth: 'GET /api/v1/micro-pentest/enterprise/health',
  attackVectors: 'GET /api/v1/micro-pentest/vectors',
  threatCategories: 'GET /api/v1/micro-pentest/threats',
  complianceFrameworks: 'GET /api/v1/micro-pentest/compliance',
  scanModes: 'GET /api/v1/micro-pentest/modes',
  
  // PentAGI Enhanced
  listRequests: 'GET /api/v1/pentagi/requests',
  createRequest: 'POST /api/v1/pentagi/requests',
  getRequest: 'GET /api/v1/pentagi/requests/{id}',
  updateRequest: 'PUT /api/v1/pentagi/requests/{id}',
  startPentest: 'POST /api/v1/pentagi/requests/{id}/start',
  cancelPentest: 'POST /api/v1/pentagi/requests/{id}/cancel',
  listResults: 'GET /api/v1/pentagi/results',
  createResult: 'POST /api/v1/pentagi/results',
  getResultByRequest: 'GET /api/v1/pentagi/results/by-request/{request_id}',
  listConfigs: 'GET /api/v1/pentagi/configs',
  createConfig: 'POST /api/v1/pentagi/configs',
  getConfig: 'GET /api/v1/pentagi/configs/{id}',
  updateConfig: 'PUT /api/v1/pentagi/configs/{id}',
  deleteConfig: 'DELETE /api/v1/pentagi/configs/{id}',
  
  // Reachability Analysis
  analyzeReachability: 'POST /api/v1/reachability/analyze',
  bulkReachability: 'POST /api/v1/reachability/bulk',
  reachabilityStatus: 'GET /api/v1/reachability/{job_id}/status',
  cachedResults: 'GET /api/v1/reachability/cached',
  
  // Intelligent Engine
  engineStatus: 'GET /intelligent-engine/status',
  listSessions: 'GET /intelligent-engine/sessions',
  startScan: 'POST /intelligent-engine/scan',
  getScanStatus: 'GET /intelligent-engine/scan/{session_id}',
  stopScan: 'POST /intelligent-engine/scan/{session_id}/stop',
  
  // Attack Simulation (Predictions)
  attackChain: 'POST /api/v1/predictions/attack-chain',
  simulateAttack: 'POST /api/v1/predictions/simulate-attack',
  riskTrajectory: 'POST /api/v1/predictions/risk-trajectory'
};
```

### Layout (PentAGI-Style with Chat)

```
┌────────────────────────────────────────────────────────────────────────┐
│ ⚔️ Attack Lab - Exploit Verification & Penetration Testing            │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────────────────────────────┐ ┌──────────────────────────┐ │
│  │  PENTAGI CHAT INTERFACE             │ │  ACTIVE CAMPAIGNS        │ │
│  │                                     │ │                          │ │
│  │  ┌─────────────────────────────┐    │ │  Campaign: Log4j Hunt    │ │
│  │  │ 🤖 ALdeci: I've identified │    │ │  Status: 🟢 Running      │ │
│  │  │ 3 potentially exploitable  │    │ │  Progress: ████░░ 67%    │ │
│  │  │ CVEs in payment-gateway:   │    │ │  Findings: 12            │ │
│  │  │                            │    │ │  Exploited: 4            │ │
│  │  │ 1. CVE-2024-1234 (SQL Inj) │    │ │  ─────────────────────   │ │
│  │  │ 2. CVE-2024-5678 (XSS)     │    │ │  Campaign: OWASP Top 10  │ │
│  │  │ 3. CVE-2024-9012 (RCE)     │    │ │  Status: ⏸️ Paused       │ │
│  │  │                            │    │ │  Progress: ██░░░░ 34%    │ │
│  │  │ Want me to run micro-      │    │ │                          │ │
│  │  │ pentests on these?         │    │ │  [+ New Campaign]        │ │
│  │  └─────────────────────────────┘    │ └──────────────────────────┘ │
│  │                                     │                              │
│  │  ┌─────────────────────────────┐    │ ┌──────────────────────────┐ │
│  │  │ 👤 User: Yes, prioritize   │    │ │  PENTEST RESULTS         │ │
│  │  │ the RCE first. Use safe    │    │ │                          │ │
│  │  │ mode in staging env.       │    │ │  CVE-2024-1234           │ │
│  │  └─────────────────────────────┘    │ │  ├─ Status: Exploited ✓  │ │
│  │                                     │ │  ├─ Severity: CRITICAL   │ │
│  │  ┌─────────────────────────────┐    │ │  ├─ CVSS: 9.8            │ │
│  │  │ 🤖 Starting micro-pentest  │    │ │  ├─ EPSS: 0.94           │ │
│  │  │ for CVE-2024-9012...       │    │ │  └─ Reachable: Yes       │ │
│  │  │                            │    │ │                          │ │
│  │  │ ████████░░ 80%             │    │ │  CVE-2024-5678           │ │
│  │  │                            │    │ │  ├─ Status: Blocked ⬚    │ │
│  │  │ Exploit chain detected:    │    │ │  ├─ Mitigation: WAF rule │ │
│  │  │ 1. Initial access via API  │    │ │  └─ Risk: Reduced        │ │
│  │  │ 2. Escalation to admin     │    │ │                          │ │
│  │  │ 3. RCE achieved ⚠️         │    │ │  [Export Evidence]       │ │
│  │  └─────────────────────────────┘    │ └──────────────────────────┘ │
│  │                                     │                              │
│  │  [Type message...          ] [Send] │                              │
│  └─────────────────────────────────────┘                              │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  ATTACK FLOW VISUALIZATION                                        │ │
│  │                                                                   │ │
│  │  Internet → [WAF] → [API GW] → [Payment Svc] → [DB]              │ │
│  │              │         │              │          │                │ │
│  │              ✓         ✓              ⚠️          🔴               │ │
│  │            Blocked   Detected     Exploited    Compromised       │ │
│  │                                                                   │ │
│  │  Legend: ✓ Protected  ⚠️ Vulnerable  🔴 Exploited                 │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔧 PAGE 6: Remediation Center (Remediate - FR-REM)

### APIs Consumed (25 endpoints)

```javascript
const remediateApis = {
  // Task Management
  createTask: 'POST /api/v1/remediation/tasks',
  listTasks: 'GET /api/v1/remediation/tasks',
  getTask: 'GET /api/v1/remediation/tasks/{id}',
  updateStatus: 'PUT /api/v1/remediation/tasks/{id}/status',
  assignTask: 'PUT /api/v1/remediation/tasks/{id}/assign',
  submitVerification: 'POST /api/v1/remediation/tasks/{id}/verification',
  linkTicket: 'PUT /api/v1/remediation/tasks/{id}/ticket',
  transitionStatus: 'PUT /api/v1/remediation/tasks/{id}/transition',
  verifyTask: 'POST /api/v1/remediation/tasks/{id}/verify',
  checkSLA: 'POST /api/v1/remediation/sla/check',
  metrics: 'GET /api/v1/remediation/metrics',
  globalMetrics: 'GET /api/v1/remediation/metrics/{org_id}',
  statuses: 'GET /api/v1/remediation/statuses',
  
  // Bulk Operations
  bulkStatus: 'POST /api/v1/bulk/status',
  bulkAssign: 'POST /api/v1/bulk/assign',
  bulkAcceptRisk: 'POST /api/v1/bulk/accept-risk',
  bulkCreateTickets: 'POST /api/v1/bulk/tickets',
  bulkExport: 'POST /api/v1/bulk/export',
  jobStatus: 'GET /api/v1/bulk/jobs/{id}',
  cancelJob: 'POST /api/v1/bulk/jobs/{id}/cancel',
  listJobs: 'GET /api/v1/bulk/jobs',
  
  // Collaboration
  addComment: 'POST /api/v1/collaboration/comments',
  getComments: 'GET /api/v1/collaboration/comments',
  promoteToEvidence: 'PUT /api/v1/collaboration/comments/{id}/evidence',
  addWatcher: 'POST /api/v1/collaboration/watchers',
  removeWatcher: 'DELETE /api/v1/collaboration/watchers',
  getWatchers: 'GET /api/v1/collaboration/watchers',
  recordActivity: 'POST /api/v1/collaboration/activity',
  getActivity: 'GET /api/v1/collaboration/activity'
};
```

### Layout

```
┌────────────────────────────────────────────────────────────────────────┐
│ 🔧 Remediation Center - Vulnerability Lifecycle Management            │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  [All Tasks] [My Tasks] [Overdue] [SLA Breach Risk] [+ Create Task]   │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  TASK BOARD (Kanban View)                                         │ │
│  │                                                                   │ │
│  │  OPEN (45)      IN PROGRESS (23)   REVIEW (12)    CLOSED (234)   │ │
│  │  ┌─────────┐    ┌─────────┐        ┌─────────┐    ┌─────────┐    │ │
│  │  │ SEC-123 │    │ SEC-089 │        │ SEC-045 │    │ SEC-012 │    │ │
│  │  │ Log4j   │    │ SQLi    │        │ XSS     │    │ CSRF    │    │ │
│  │  │ @alice  │    │ @bob    │        │ @carol  │    │ ✓       │    │ │
│  │  │ 🔴 2d SLA│    │ 🟡 5d SLA│        │ 🟢 OK   │    │         │    │ │
│  │  └─────────┘    └─────────┘        └─────────┘    └─────────┘    │ │
│  │  ┌─────────┐    ┌─────────┐                                      │ │
│  │  │ SEC-124 │    │ SEC-090 │                                      │ │
│  │  │ RCE     │    │ AuthZ   │                                      │ │
│  │  │ UNASSIGN│    │ @dave   │                                      │ │
│  │  │ 🔴 1d SLA│    │ 🟢 7d   │                                      │ │
│  │  └─────────┘    └─────────┘                                      │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  ┌─────────────────────────────┐  ┌────────────────────────────────┐  │
│  │  BULK OPERATIONS            │  │  TICKET INTEGRATIONS           │  │
│  │                             │  │                                 │  │
│  │  Selected: 12 findings      │  │  ┌─────┐ ┌─────┐ ┌─────┐      │  │
│  │                             │  │  │JIRA │ │SNOW │ │GitLab│      │  │
│  │  [🔄 Bulk Status Change]    │  │  │ ✓   │ │ ✓   │ │  ✓   │      │  │
│  │  [👤 Bulk Assign]           │  │  └─────┘ └─────┘ └─────┘      │  │
│  │  [✓ Bulk Accept Risk]       │  │  ┌─────┐ ┌─────┐              │  │
│  │  [🎫 Bulk Create Tickets]   │  │  │Azure│ │GitHub│              │  │
│  │  [📤 Bulk Export]           │  │  │DevOps│ │     │              │  │
│  │                             │  │  │  ✓  │ │  ✓  │              │  │
│  │  Running Jobs: 2            │  │  └─────┘ └─────┘              │  │
│  └─────────────────────────────┘  └────────────────────────────────┘  │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  SLA METRICS                                                      │ │
│  │                                                                   │ │
│  │  MTTR (Critical): 2.1 days    │  SLA Compliance: 87%             │ │
│  │  MTTR (High): 5.3 days        │  Breaches This Week: 3           │ │
│  │  MTTR (Medium): 12.7 days     │  At-Risk: 7 tasks                │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 PAGE 7: Evidence Vault (Evidence - FR-EVD)

### APIs Consumed (15 endpoints)

```javascript
const evidenceApis = {
  // Evidence Bundles
  listBundles: 'GET /api/v1/evidence/bundles',
  getManifest: 'GET /api/v1/evidence/manifests/{id}',
  downloadBundle: 'GET /api/v1/evidence/bundles/{id}/download',
  verifySignature: 'POST /api/v1/evidence/verify',
  
  // SLSA Provenance
  listAttestations: 'GET /api/v1/provenance/attestations',
  getAttestation: 'GET /api/v1/provenance/attestations/{id}',
  
  // Audit Trail
  listAuditLogs: 'GET /api/v1/audit/logs',
  getAuditLog: 'GET /api/v1/audit/logs/{id}',
  userActivity: 'GET /api/v1/audit/users/{id}/activity',
  policyChanges: 'GET /api/v1/audit/policies/changes',
  decisionTrail: 'GET /api/v1/audit/decisions/{id}/trail',
  
  // Compliance
  listFrameworks: 'GET /api/v1/compliance/frameworks',
  frameworkStatus: 'GET /api/v1/compliance/frameworks/{id}/status',
  complianceGaps: 'GET /api/v1/compliance/gaps',
  generateReport: 'POST /api/v1/compliance/reports',
  listControls: 'GET /api/v1/compliance/controls'
};
```

### Layout

```
┌────────────────────────────────────────────────────────────────────────┐
│ 📦 Evidence Vault - Cryptographic Proof & Compliance Artifacts        │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  EVIDENCE BUNDLES                                                 │ │
│  │                                                                   │ │
│  │  Bundle ID           Created      Size    Signed   SLSA Level    │ │
│  │  ────────────────────────────────────────────────────────────    │ │
│  │  evd-2024-0115-001   2hr ago     4.2MB    ✓ RSA    L3           │ │
│  │  evd-2024-0114-003   1d ago      2.8MB    ✓ RSA    L3           │ │
│  │  evd-2024-0113-007   2d ago      5.1MB    ✓ RSA    L2           │ │
│  │  evd-2024-0112-002   3d ago      1.9MB    ✓ RSA    L3           │ │
│  │                                                                   │ │
│  │  [📥 Download]  [🔍 Verify]  [📋 View Manifest]                   │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  ┌─────────────────────────────┐  ┌────────────────────────────────┐  │
│  │  COMPLIANCE FRAMEWORKS      │  │  SLSA ATTESTATIONS             │  │
│  │                             │  │                                 │  │
│  │  ┌─────────────────────┐   │  │  Subject: payment-gateway:v2.1 │  │
│  │  │ PCI-DSS 4.0         │   │  │  Builder: github-actions       │  │
│  │  │ ████████░░ 82%      │   │  │  Level: SLSA L3                │  │
│  │  │ 12 gaps remaining   │   │  │  Build Type: Dockerfile        │  │
│  │  └─────────────────────┘   │  │  Signed: RSA-SHA256            │  │
│  │  ┌─────────────────────┐   │  │  ─────────────────────────     │  │
│  │  │ SOC2 Type II        │   │  │  Materials:                    │  │
│  │  │ █████████░ 91%      │   │  │  • Source: github.com/...      │  │
│  │  │ 4 gaps remaining    │   │  │  • SBOM: sha256:abc123...      │  │
│  │  └─────────────────────┘   │  │  • Config: sha256:def456...    │  │
│  │  ┌─────────────────────┐   │  │                                 │  │
│  │  │ ISO 27001:2022      │   │  │  [Verify Chain]  [Export]      │  │
│  │  │ ███████░░░ 75%      │   │  └────────────────────────────────┘  │
│  │  │ 18 gaps remaining   │   │                                      │
│  │  └─────────────────────┘   │                                      │
│  │                             │                                      │
│  │  [📊 Gap Analysis]         │                                      │
│  │  [📄 Generate Report]      │                                      │
│  └─────────────────────────────┘                                      │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  AUDIT TRAIL                                                      │ │
│  │                                                                   │ │
│  │  2024-01-15 14:32  alice@corp  Decision: ALLOW on SEC-123       │ │
│  │  2024-01-15 14:28  system      Policy updated: critical-sla     │ │
│  │  2024-01-15 14:15  bob@corp    Evidence bundle generated        │ │
│  │  2024-01-15 13:45  carol@corp  Bulk accept-risk (12 findings)   │ │
│  │                                                                   │ │
│  │  [View Full Trail]  [Export for Auditors]                        │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🤖 PAGE 8: Automation Studio (Automation - FR-AUT)

### APIs Consumed (26 endpoints)

```javascript
const automationApis = {
  // Workflows
  listWorkflows: 'GET /api/v1/workflows',
  createWorkflow: 'POST /api/v1/workflows',
  getWorkflow: 'GET /api/v1/workflows/{id}',
  updateWorkflow: 'PUT /api/v1/workflows/{id}',
  deleteWorkflow: 'DELETE /api/v1/workflows/{id}',
  executeWorkflow: 'POST /api/v1/workflows/{id}/execute',
  executionHistory: 'GET /api/v1/workflows/{id}/history',
  
  // Marketplace
  fetchPack: 'GET /api/v1/marketplace/remediation-packs/{id}',
  browse: 'GET /api/v1/marketplace/browse',
  recommendations: 'GET /api/v1/marketplace/recommendations',
  getItem: 'GET /api/v1/marketplace/items/{id}',
  contribute: 'POST /api/v1/marketplace/items',
  updateItem: 'PUT /api/v1/marketplace/items/{id}',
  rateItem: 'POST /api/v1/marketplace/items/{id}/rate',
  purchaseItem: 'POST /api/v1/marketplace/items/{id}/purchase',
  marketplaceStats: 'GET /api/v1/marketplace/stats',
  topContributors: 'GET /api/v1/marketplace/contributors',
  
  // Webhooks & Integrations
  listMappings: 'GET /api/v1/webhooks/mappings',
  createMapping: 'POST /api/v1/webhooks/mappings',
  getSyncDrift: 'GET /api/v1/webhooks/drift',
  resolveDrift: 'POST /api/v1/webhooks/drift/resolve',
  outboxItems: 'GET /api/v1/webhooks/outbox',
  processOutbox: 'POST /api/v1/webhooks/outbox/process',
  
  // Webhook Receivers (inbound)
  jiraWebhook: 'POST /api/v1/webhooks/jira',
  serviceNowWebhook: 'POST /api/v1/webhooks/servicenow',
  gitlabWebhook: 'POST /api/v1/webhooks/gitlab',
  azureDevOpsWebhook: 'POST /api/v1/webhooks/azure-devops'
};
```

---

## 💬 PAGE 9: PentAGI Chat (Interactive Assistant)

### Key Features

```javascript
const chatFeatures = {
  // Natural Language Commands
  commands: [
    'analyze CVE-2024-1234 for payment-gateway',
    'run micro-pentest on auth service',
    'show attack path to database',
    'what is the risk if we deploy now?',
    'create JIRA ticket for critical findings',
    'compare LLM opinions on this decision',
    'simulate ransomware attack scenario',
    'generate compliance report for PCI-DSS'
  ],
  
  // Multi-Agent Orchestration
  agents: [
    'Reconnaissance Agent',
    'Exploitation Agent', 
    'Post-Exploitation Agent',
    'Reporting Agent'
  ],
  
  // Connected APIs (All 363 via natural language)
  apiAccess: 'Full API access through conversational interface'
};
```

---

## ⚙️ PAGE 10: Settings & Admin

### APIs Consumed (38 endpoints)

```javascript
const settingsApis = {
  // Users
  login: 'POST /api/v1/users/login',
  listUsers: 'GET /api/v1/users',
  createUser: 'POST /api/v1/users',
  getUser: 'GET /api/v1/users/{id}',
  updateUser: 'PUT /api/v1/users/{id}',
  deleteUser: 'DELETE /api/v1/users/{id}',
  
  // Teams
  listTeams: 'GET /api/v1/teams',
  createTeam: 'POST /api/v1/teams',
  getTeam: 'GET /api/v1/teams/{id}',
  updateTeam: 'PUT /api/v1/teams/{id}',
  deleteTeam: 'DELETE /api/v1/teams/{id}',
  listMembers: 'GET /api/v1/teams/{id}/members',
  addMember: 'POST /api/v1/teams/{id}/members',
  removeMember: 'DELETE /api/v1/teams/{id}/members/{user_id}',
  
  // SSO/Auth
  listSSO: 'GET /api/v1/auth/sso',
  createSSO: 'POST /api/v1/auth/sso',
  getSSO: 'GET /api/v1/auth/sso/{id}',
  updateSSO: 'PUT /api/v1/auth/sso/{id}',
  
  // Integrations
  listIntegrations: 'GET /api/v1/integrations',
  createIntegration: 'POST /api/v1/integrations',
  getIntegration: 'GET /api/v1/integrations/{id}',
  updateIntegration: 'PUT /api/v1/integrations/{id}',
  deleteIntegration: 'DELETE /api/v1/integrations/{id}',
  testIntegration: 'POST /api/v1/integrations/{id}/test',
  
  // LLM Configuration
  llmStatus: 'GET /api/v1/llm/status',
  llmSettings: 'GET /api/v1/llm/settings',
  llmUpdate: 'PATCH /api/v1/llm/settings',
  llmProviders: 'GET /api/v1/llm/providers',
  
  // System Health
  health: 'GET /health',
  status: 'GET /api/v1/status',
  algorithmStatus: 'GET /api/v1/algorithms/status'
};
```

---

## 🔌 Technical Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                    ALdeci Intelligence Hub                       │
├─────────────────────────────────────────────────────────────────┤
│  Frontend: Vanilla JS (PentAGI-style) | Port 4567               │
│  Backend: FastAPI + 363 endpoints | Port 8000                   │
│  PentAGI: Multi-agent pentest | Port 8443                       │
│  MindsDB: ML predictions + MongoDB API | Port 47334/47336       │
│  MongoDB: Primary data store (Production) | Port 27017          │
│  Redis: Caching + Sessions | Port 6380                          │
│  PostgreSQL: PentAGI DB | Port 5433                             │
├─────────────────────────────────────────────────────────────────┤
│  Algorithmic Engines:                                            │
│  • Monte Carlo FAIR (Risk Quantification)                       │
│  • Causal DAG (Impact Analysis)                                 │
│  • GNN (Attack Path Prediction)                                 │
│  • Markov Chain (State Transition)                              │
│  • Bayesian Network (Probability Update)                        │
│  • Multi-LLM Consensus (GPT-5, Claude, Gemini, Sentinel)       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🗄️ Data Architecture: MongoDB + MindsDB Unified Layer

### All APIs Feed MongoDB → MindsDB Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    UNIFIED DATA ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    363 API ENDPOINTS                                 │   │
│  │   (All suites: CODE, CLOUD, ATTACK, PROTECT, AI ENGINE, EVIDENCE)  │   │
│  └───────────────────────────────┬─────────────────────────────────────┘   │
│                                  │                                          │
│                                  ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    MONGODB (Port 27017)                              │   │
│  │                    Primary Data Store                                │   │
│  │                                                                       │   │
│  │  Collections:                                                        │   │
│  │  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐              │   │
│  │  │ findings      │ │ assets        │ │ pentests      │              │   │
│  │  │ (vulns, CVEs) │ │ (inventory)   │ │ (results)     │              │   │
│  │  └───────────────┘ └───────────────┘ └───────────────┘              │   │
│  │  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐              │   │
│  │  │ threat_intel  │ │ dark_web      │ │ zero_days     │              │   │
│  │  │ (feeds)       │ │ (darkweb)     │ │ (discovered)  │              │   │
│  │  └───────────────┘ └───────────────┘ └───────────────┘              │   │
│  │  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐              │   │
│  │  │ remediations  │ │ evidence      │ │ compliance    │              │   │
│  │  │ (fixes)       │ │ (bundles)     │ │ (frameworks)  │              │   │
│  │  └───────────────┘ └───────────────┘ └───────────────┘              │   │
│  └───────────────────────────────┬─────────────────────────────────────┘   │
│                                  │                                          │
│                                  ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    MINDSDB (Port 47334)                              │   │
│  │            Federated AI/ML Layer + MongoDB API (47336)              │   │
│  │                                                                       │   │
│  │  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐        │   │
│  │  │ KNOWLEDGE BASES │ │ ML PREDICTORS   │ │ AI AGENTS       │        │   │
│  │  │                 │ │                 │ │                 │        │   │
│  │  │ • CVE KB        │ │ • Exploit Pred  │ │ • Security      │        │   │
│  │  │ • Dark Web KB   │ │ • Attack Path   │ │   Analyst       │        │   │
│  │  │ • Zero-Day KB   │ │ • MTTR Pred     │ │ • Pentest Agent │        │   │
│  │  │ • Exploit KB    │ │ • Risk Score    │ │ • Compliance    │        │   │
│  │  │ • Remediation KB│ │ • Priority      │ │ • Remediation   │        │   │
│  │  └─────────────────┘ └─────────────────┘ └─────────────────┘        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Data Flow: API → MongoDB (storage) → MindsDB (intelligence) → Copilot    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Current vs Production Database Status

| Layer | Current (Dev) | Production Target | Status |
|-------|--------------|-------------------|--------|
| Primary Store | SQLite (12+ DBs) | **MongoDB** | 🔲 Migration needed |
| ML/AI Layer | MindsDB | MindsDB | ✅ Ready |
| MindsDB MongoDB API | Port 47336 | Port 47336 | ✅ Ready |
| Cache | Redis (6380) | Redis Cluster | ✅ Ready |
| PentAGI DB | PostgreSQL (5433) | PostgreSQL | ✅ Ready |

---

## 🌐 World's Largest Threat Intelligence Feed Network

### 8 Feed Categories (Already Implemented in feeds_router.py)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ALDECI THREAT INTELLIGENCE NETWORK                        │
│                    "Largest AppSec Intel Feed on the Planet"                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 1. GLOBAL AUTHORITATIVE FEEDS                                       │   │
│  │    ├── NVD (National Vulnerability Database)                        │   │
│  │    ├── CISA KEV (Known Exploited Vulnerabilities)                   │   │
│  │    ├── MITRE CVE/CWE/ATT&CK                                         │   │
│  │    ├── CERT/CC Advisories                                           │   │
│  │    └── FIRST EPSS (Exploit Prediction Scoring)                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 2. NATIONAL CERTS (45+ Countries)                                   │   │
│  │    ├── NCSC UK, BSI Germany, ANSSI France                           │   │
│  │    ├── JPCERT Japan, ACSC Australia, CNCERT China                   │   │
│  │    ├── CERT-In India, KrCERT Korea, CERT.br Brazil                  │   │
│  │    └── + 35 more national CERTs                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 3. EXPLOIT INTELLIGENCE                                             │   │
│  │    ├── Exploit-DB (Historical & Active)                             │   │
│  │    ├── Metasploit Modules                                           │   │
│  │    ├── Vulners Database                                             │   │
│  │    ├── Nuclei Templates                                             │   │
│  │    ├── PacketStorm Security                                         │   │
│  │    └── GitHub PoC Repositories                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 4. THREAT ACTOR INTELLIGENCE                                        │   │
│  │    ├── MITRE ATT&CK Framework                                       │   │
│  │    ├── AlienVault OTX                                               │   │
│  │    ├── MISP Threat Sharing                                          │   │
│  │    ├── APT Groups Tracking                                          │   │
│  │    └── Ransomware Gang Monitoring                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 5. SUPPLY-CHAIN & SBOM INTELLIGENCE                                 │   │
│  │    ├── OSV (Open Source Vulnerabilities)                            │   │
│  │    ├── GitHub Security Advisories                                   │   │
│  │    ├── Snyk Vulnerability Database                                  │   │
│  │    ├── deps.dev (Google)                                            │   │
│  │    ├── npm/PyPI/Maven/Cargo Advisories                              │   │
│  │    └── VulnCheck KEV                                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 6. CLOUD & RUNTIME VULNERABILITY FEEDS                              │   │
│  │    ├── AWS Security Bulletins                                       │   │
│  │    ├── Azure Security Advisories                                    │   │
│  │    ├── GCP Security Bulletins                                       │   │
│  │    ├── Kubernetes CVEs                                              │   │
│  │    ├── Docker Security Advisories                                   │   │
│  │    └── Terraform/Helm Security                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 7. ZERO-DAY & EARLY-SIGNAL FEEDS ⚡ (UNIQUE TO ALDECI)              │   │
│  │    ├── Vendor Security Blogs (Pre-CVE)                              │   │
│  │    ├── GitHub Commit Monitoring (Patch Analysis)                    │   │
│  │    ├── Mailing List Intelligence (oss-security, full-disclosure)   │   │
│  │    ├── Twitter/X Security Researchers                               │   │
│  │    ├── HackerNews/Reddit Security                                   │   │
│  │    └── Proprietary Zero-Day Detection Engine                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 8. DARK WEB INTELLIGENCE 🕸️ (UNIQUE TO ALDECI)                      │   │
│  │    ├── Dark Web Market Monitoring                                   │   │
│  │    ├── Exploit Sales Tracking                                       │   │
│  │    ├── Ransomware Leak Sites                                        │   │
│  │    ├── Breach Database Monitoring                                   │   │
│  │    ├── Threat Actor Communications                                  │   │
│  │    └── Zero-Day Auction Tracking                                    │   │
│  │                                                                       │   │
│  │    Ingestion: DarkWebIntelNormalizer (apps/api/ingestion.py:687)    │   │
│  │    Format: POST /inputs/multipart with format_hint=dark_web_intel   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 9. PENTEST-DISCOVERED VULNERABILITIES 🔥 (UNIQUE TO ALDECI)         │   │
│  │    ├── PentAGI Exploitation Results                                 │   │
│  │    ├── Micro-Pentest Findings (Pre-CVE)                             │   │
│  │    ├── Attack Simulation Discoveries                                │   │
│  │    ├── Custom PoC Development                                       │   │
│  │    ├── Zero-Day Contribution (to CVE program)                       │   │
│  │    └── Proprietary Vulnerability Research                           │   │
│  │                                                                       │   │
│  │    🔄 FEEDBACK LOOP:                                                 │   │
│  │    Pentest → Discover New Vuln → Create Internal CVE →              │   │
│  │    Train ML Models → Improve Detection → Contribute to Community   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Proprietary Threat Intelligence Engine

**File:** `risk/reachability/proprietary_threat_intel.py`

```python
# Already Implemented:
class ProprietaryThreatIntelligenceEngine:
    """Proprietary threat intelligence engine - custom algorithms."""
    
    # Zero-day detection indicators
    zero_day_indicators: List[ProprietaryZeroDayIndicator]
    
    # Threat pattern matching
    threat_patterns: Dict[str, List[Dict[str, Any]]]
    
    # Anomaly detection models
    anomaly_models: Dict[str, Any]
    
    def detect_zero_days(self, ...) -> List[ProprietaryZeroDayIndicator]
    def process_threat_feed(self, ...) -> Dict[str, Any]
```

### Pentest Contribution to Vulnerability Database

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PENTEST → VULN DISCOVERY PIPELINE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   PentAGI   │ →  │  Discover   │ →  │  Internal   │ →  │   Enrich    │  │
│  │   Attack    │    │  New Vuln   │    │   CVE-ID    │    │  Threat DB  │  │
│  │             │    │  (Pre-CVE)  │    │  Assignment │    │             │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│        │                  │                   │                   │         │
│        ▼                  ▼                   ▼                   ▼         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  Evidence   │    │   Train     │ →  │  Improve    │ →  │  Community  │  │
│  │  Collection │    │  ML Models  │    │  Detection  │    │ Contribution│  │
│  │             │    │             │    │             │    │   (CVE.org) │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                             │
│  VALIDATION_TRIGGER.VULNERABILITY_DISCOVERED (apps/pentagi_integration.py) │
│                                                                             │
│  New APIs Needed:                                                           │
│  • POST /api/v1/vulns/discovered      - Report pentest-discovered vuln    │
│  • POST /api/v1/vulns/contribute      - Submit to CVE program             │
│  • GET /api/v1/vulns/internal         - List internal (pre-CVE) vulns     │
│  • POST /api/v1/vulns/train           - Retrain ML on new vuln data       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Feed Count Summary

| Feed Category | Sources | Status |
|--------------|---------|--------|
| Global Authoritative | 5 | ✅ Implemented |
| National CERTs | 45+ | ✅ Implemented |
| Exploit Intelligence | 6+ | ✅ Implemented |
| Threat Actor Intel | 5+ | ✅ Implemented |
| Supply-Chain/SBOM | 6+ | ✅ Implemented |
| Cloud & Runtime | 6+ | ✅ Implemented |
| Zero-Day Early-Signal | 6+ | ✅ Implemented |
| Dark Web Intel | 6+ | ✅ Normalizer Ready |
| Pentest-Discovered | N/A | 🔲 APIs Needed |
| **TOTAL SOURCES** | **85+** | |

---

## 📋 Comparison: ALdeci vs Aikido (5 Suite Architecture)

### ✅ VERIFIED: 363 Total API Endpoints (Code-Verified February 2026)

**Verified Total: 363 API Endpoints**

| Suite | Router Files | API Count |
|-------|--------------|----------|
| 🔍 CODE | secrets, iac, validation | **15** |
| ☁️ CLOUD | feeds, deduplication, inventory | **56** |
| ⚔️ ATTACK | pentagi, pentagi_enhanced, micro_pentest, intelligent_engine | **62** |
| 🛡️ PROTECT | remediation, bulk, workflows, webhooks, collaboration, marketplace | **84** |
| 🧠 AI ENGINE | algorithmic, predictions, llm, policies, enhanced | **37** |
| 📦 EVIDENCE | audit, reports, analytics, evidence, provenance, graph, risk | **52** |
| ⚙️ SETTINGS | users, teams, auth, integrations, ide, health | **32** |
| 💬 COPILOT | app.py ingestion endpoints + health.py | **25** |
| **TOTAL** | | **363** |

---

## 💬 PAGE 2: AI COPILOT (MindsDB-Powered Chat)

### Architecture: MindsDB as Central Intelligence Layer

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     ALDECI COPILOT ARCHITECTURE                             │
│                     (MindsDB-Powered Chat Interface)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        USER CHAT INTERFACE                          │   │
│  │  "What CVEs should I prioritize for payment-gateway?"               │   │
│  │  "Run a pentest on auth service for Log4j"                          │   │
│  │  "Show attack paths to our database"                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    MINDSDB FEDERATED AI LAYER                       │   │
│  │                    (Port 47334 - aldeci-mindsdb)                    │   │
│  │                                                                      │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐           │   │
│  │  │ KNOWLEDGE     │  │ ML PREDICTORS │  │ AI AGENTS     │           │   │
│  │  │ BASES (RAG)   │  │               │  │               │           │   │
│  │  │               │  │               │  │               │           │   │
│  │  │ • CVE KB      │  │ • Exploit     │  │ • Security    │           │   │
│  │  │ • Attack      │  │   Success     │  │   Analyst     │           │   │
│  │  │   Patterns KB │  │ • Attack Path │  │ • Pentest     │           │   │
│  │  │ • Remediation │  │ • Risk Score  │  │   Agent       │           │   │
│  │  │   KB          │  │ • MTTR        │  │ • Compliance  │           │   │
│  │  │               │  │               │  │   Agent       │           │   │
│  │  └───────────────┘  └───────────────┘  └───────────────┘           │   │
│  │                                                                      │   │
│  │  SQL Interface: CREATE MODEL, CREATE KNOWLEDGE_BASE, CREATE AGENT   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                    ┌───────────────┼───────────────┐                       │
│                    ▼               ▼               ▼                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                   DATA SOURCES (Federated Query)                    │   │
│  │                                                                      │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │   │
│  │  │ FixOps  │  │ PentAGI │  │ External│  │ LLM     │  │ Feeds   │   │   │
│  │  │   API   │  │  API    │  │   APIs  │  │Providers│  │(EPSS/KEV)│  │   │
│  │  │ :8000   │  │ :8443   │  │         │  │         │  │         │   │   │
│  │  │         │  │         │  │         │  │         │  │         │   │   │
│  │  │363 APIs │  │ Pentest │  │ • NVD   │  │ • GPT-5 │  │ • EPSS  │   │   │
│  │  │         │  │ Tasks   │  │ • MITRE │  │ • Claude│  │ • KEV   │   │   │
│  │  │         │  │ Results │  │ • GitHub│  │ • Gemini│  │ • CISA  │   │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### MindsDB Integration APIs (NEW - 11 endpoints)

```javascript
const mindsdbApis = {
  // Intelligent Engine (MindsDB-powered)
  engineStatus: 'GET /intelligent-engine/status',
  listSessions: 'GET /intelligent-engine/sessions',
  startScan: 'POST /intelligent-engine/scan',
  getScanStatus: 'GET /intelligent-engine/scan/{session_id}',
  stopScan: 'POST /intelligent-engine/scan/{session_id}/stop',
  
  // Threat Intelligence
  gatherIntel: 'POST /intelligent-engine/intelligence/gather',
  
  // Attack Planning (Multi-LLM)
  generatePlan: 'POST /intelligent-engine/plan/generate',
  executePlan: 'POST /intelligent-engine/plan/{plan_id}/execute',
  
  // MindsDB Direct
  mindsdbStatus: 'GET /intelligent-engine/mindsdb/status',
  mindsdbPredict: 'POST /intelligent-engine/mindsdb/predict',
  
  // Multi-LLM Consensus
  consensusAnalyze: 'POST /intelligent-engine/consensus/analyze'
};
```

### Copilot Chat API (NEEDS TO BE CREATED)

```javascript
// NEW APIs needed for Copilot Chat
const copilotApis = {
  // Chat session management
  createChat: 'POST /api/v1/copilot/sessions',
  listChats: 'GET /api/v1/copilot/sessions',
  getChat: 'GET /api/v1/copilot/sessions/{id}',
  deleteChat: 'DELETE /api/v1/copilot/sessions/{id}',
  
  // Message handling (feeds MindsDB)
  sendMessage: 'POST /api/v1/copilot/sessions/{id}/messages',
  getMessages: 'GET /api/v1/copilot/sessions/{id}/messages',
  
  // Agent actions (MindsDB agents execute)
  executeAction: 'POST /api/v1/copilot/sessions/{id}/actions',
  getActionStatus: 'GET /api/v1/copilot/actions/{action_id}',
  
  // Context injection (feed data to MindsDB KB)
  addContext: 'POST /api/v1/copilot/sessions/{id}/context',
  
  // Suggestions (MindsDB predictions)
  getSuggestions: 'GET /api/v1/copilot/suggestions',
  
  // Quick commands
  analyzeVuln: 'POST /api/v1/copilot/quick/analyze',
  runPentest: 'POST /api/v1/copilot/quick/pentest',
  generateReport: 'POST /api/v1/copilot/quick/report'
};
```

### How ALdeci APIs Feed MindsDB

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    API → MINDSDB DATA FLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. INGESTION APIS → MindsDB Knowledge Bases                               │
│     ├── /inputs/sbom → CVE KB (component vulnerabilities)                  │
│     ├── /inputs/sarif → Attack Patterns KB (scan findings)                 │
│     ├── /inputs/cnapp → Cloud KB (misconfigurations)                       │
│     └── /api/v1/feeds/* → Threat Intel KB (EPSS, KEV, exploits)           │
│                                                                             │
│  2. DECISION APIS → MindsDB ML Models                                      │
│     ├── /api/v1/algorithms/monte-carlo/* → Risk Predictor training        │
│     ├── /api/v1/predictions/* → Attack Path Predictor training            │
│     ├── /api/v1/enhanced/* → Multi-LLM consensus data                     │
│     └── /api/v1/policies/* → Policy evaluation training                   │
│                                                                             │
│  3. VERIFICATION APIS → MindsDB Agent Skills                               │
│     ├── /api/v1/pentagi/* → Pentest Agent skill                           │
│     ├── /api/v1/micro-pentest/* → Validation Agent skill                  │
│     └── /api/v1/reachability/* → Attack Path Agent skill                  │
│                                                                             │
│  4. REMEDIATION APIS → MindsDB Recommendations                             │
│     ├── /api/v1/remediation/* → MTTR Predictor training                   │
│     ├── /api/v1/bulk/* → Batch operation patterns                         │
│     └── /api/v1/marketplace/* → Remediation KB                            │
│                                                                             │
│  5. EVIDENCE APIS → MindsDB Compliance KB                                  │
│     ├── /api/v1/audit/* → Audit Trail KB                                  │
│     ├── /api/v1/compliance/* → Framework compliance training              │
│     └── /api/v1/evidence/* → Evidence pattern recognition                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Copilot UI Wireframe

```
┌────────────────────────────────────────────────────────────────────────────┐
│ 💬 ALdeci Copilot                                         [Minimize] [X]   │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 🤖 ALdeci: Welcome! I can help you with:                             │ │
│  │    • Analyzing vulnerabilities and attack paths                      │ │
│  │    • Running pentests and simulations                                │ │
│  │    • Generating compliance reports                                    │ │
│  │    • Explaining risk scores and decisions                            │ │
│  │                                                                       │ │
│  │    What would you like to do today?                                  │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 👤 You: What critical CVEs affect payment-gateway and should I       │ │
│  │    prioritize based on exploit availability?                         │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 🤖 ALdeci: Analyzing payment-gateway with MindsDB...                 │ │
│  │                                                                       │ │
│  │    📊 Querying: /api/v1/inventory/applications/payment-gateway       │ │
│  │    🔍 Fetching: /api/v1/deduplication/clusters?app=payment-gateway   │ │
│  │    📈 Running: MindsDB exploit_success_predictor                     │ │
│  │                                                                       │ │
│  │    Found 3 critical CVEs with high exploit probability:              │ │
│  │                                                                       │ │
│  │    ┌─────────────────────────────────────────────────────────────┐   │ │
│  │    │ CVE-2024-21762  │ CRITICAL │ EPSS: 0.94 │ KEV: ✓ │ Exploit: PoC │ │
│  │    │ CVE-2024-1234   │ CRITICAL │ EPSS: 0.87 │ KEV: ✗ │ Exploit: ✓   │ │
│  │    │ CVE-2024-5678   │ HIGH     │ EPSS: 0.72 │ KEV: ✗ │ Exploit: ✗   │ │
│  │    └─────────────────────────────────────────────────────────────┘   │ │
│  │                                                                       │ │
│  │    🎯 Recommendation: Prioritize CVE-2024-21762 (KEV + high EPSS)   │ │
│  │                                                                       │ │
│  │    [🔬 Run Pentest] [📊 Show Attack Path] [🎫 Create Ticket]         │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 👤 You: Run pentest on CVE-2024-21762                                │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 🤖 ALdeci: Starting micro-pentest via PentAGI...                     │ │
│  │                                                                       │ │
│  │    📡 POST /api/v1/pentagi/requests                                  │ │
│  │    ⚔️ Target: payment-gateway.prod.internal                          │ │
│  │    🎯 CVE: CVE-2024-21762 (FortiOS SSL-VPN RCE)                      │ │
│  │                                                                       │ │
│  │    Status: ████████░░ 80%                                            │ │
│  │                                                                       │ │
│  │    ⚠️ EXPLOIT CONFIRMED                                              │ │
│  │    • Remote code execution achieved                                  │ │
│  │    • No authentication required                                      │ │
│  │    • Evidence collected: /evidence/pentest-2024-001.zip             │ │
│  │                                                                       │ │
│  │    [📥 Download Evidence] [📊 Generate Report] [🚨 Escalate]         │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ Type a message... (try: "analyze", "pentest", "report", "explain")   │ │
│  │                                                                       │ │
│  │ Quick Actions: [📊 Dashboard] [⚔️ Pentest] [📑 Report] [🔍 Search]   │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

### Suite-by-Suite Feature Comparison

| Suite | Aikido Feature | ALdeci Feature | ALdeci Advantage |
|-------|----------------|----------------|------------------|
| **🔍 CODE** | SAST, SCA, Secrets, IaC | Same + License + Multi-format SBOM | CycloneDX/SPDX/Syft auto-detect |
| **☁️ CLOUD** | CSPM, Container Scanning | Same + Finding Deduplication + GNN Attack Paths | 73% noise reduction |
| **⚔️ ATTACK** | AI Pentesting (200 agents), DAST | PentAGI + Micro-Pentest + Reachability + Simulation | Full exploit validation + what-if |
| **🛡️ PROTECT** | Runtime WAF, Monitoring | Same + Workflow Automation + Bulk Ops + SLA Tracking | Enterprise remediation at scale |
| **🧠 AI ENGINE** | Single AI model | Multi-LLM Consensus (4 models) + Monte Carlo + Causal + Bayesian | Algorithmic decision support |
| **📦 EVIDENCE** | Basic reporting | SLSA L3 + Cryptographic bundles + Compliance mapping | Audit-ready evidence lake |

### CTEM Framework Integration

| CTEM Step | Aikido Coverage | ALdeci Coverage | Advantage |
|-----------|-----------------|-----------------|-----------|
| **1. Discover (Ingest)** | Scanner integrations | Scanner-agnostic multipart + 16 formats | Any scanner works |
| **2. Correlate** | Basic grouping | Deduplication engine + Cross-stage correlation | 73% FP reduction |
| **3. Prioritize (Decide)** | AI scoring | Multi-LLM + Monte Carlo FAIR + Policy engine | $$ business impact |
| **4. Validate (Verify)** | AI pentesting | PentAGI + Reachability + Attack simulation | Proof of exploitability |
| **5. Mobilize (Remediate)** | Issue creation | Bulk ops + Workflows + Jira/ServiceNow/GitLab | Enterprise scale |
| **6. Measure (Evidence)** | Dashboards | SLSA attestations + Evidence bundles + Compliance | Cryptographic proof |

### API Coverage Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                    API ENDPOINT COVERAGE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Aikido:    ████████████████████░░░░░░░░░░░░░░░░░░ ~100 APIs    │
│                                                                  │
│  ALdeci:    ████████████████████████████████████████ 363 APIs   │
│                                                                  │
│  CODE:      ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  15 APIs   │
│  CLOUD:     ███████████████░░░░░░░░░░░░░░░░░░░░░░░░░  56 APIs   │
│  ATTACK:    █████████████████░░░░░░░░░░░░░░░░░░░░░░░  62 APIs   │
│  PROTECT:   ███████████████████████░░░░░░░░░░░░░░░░░  84 APIs   │
│  AI ENGINE: ██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  37 APIs   │
│  EVIDENCE:  ██████████████░░░░░░░░░░░░░░░░░░░░░░░░░░  52 APIs   │
│  SETTINGS:  █████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  32 APIs   │
│  COPILOT:   ███████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  25 APIs   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Unique ALdeci Differentiators

| Feature | Description | Business Value |
|---------|-------------|----------------|
| **Multi-LLM Consensus** | 4 AI models vote on decisions | Reduced bias, higher accuracy |
| **Monte Carlo FAIR** | 10,000 simulation risk quantification | $$ impact for executives |
| **Causal Inference** | What-if analysis for remediation | Predict patch effectiveness |
| **GNN Attack Graphs** | Neural network attack path prediction | Find critical nodes |
| **Bayesian Updates** | Continuous probability refinement | Learn from new evidence |
| **SLSA L3 Evidence** | Cryptographic provenance chains | Pass any audit |
| **PentAGI Chat** | Natural language security operations | Accessible for all skill levels |

---

## 🤖 AGENTS & CAPABILITIES

### Current Agent Inventory

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ALDECI AGENT ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  EXISTING AGENTS (in /agents/)                                              │
│  ═══════════════════════════════                                            │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │ CORE FRAMEWORK  │  │ DESIGN TIME     │  │ RUNTIME         │             │
│  │ (/core/)        │  │ (/design_time/) │  │ (/runtime/)     │             │
│  │                 │  │                 │  │                 │             │
│  │ • BaseAgent     │  │ • CodeRepoAgent │  │ • ContainerAgent│             │
│  │ • Orchestrator  │  │                 │  │                 │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────┐           │
│  │                LANGUAGE AGENTS (/language/)                  │           │
│  │                                                              │           │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │           │
│  │  │ Python   │ │ Java     │ │ Go       │ │JavaScript│       │           │
│  │  │ Agent    │ │ Agent    │ │ Agent    │ │ Agent    │       │           │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │           │
│  └─────────────────────────────────────────────────────────────┘           │
│                                                                             │
│  AGENT TYPES (AgentType Enum):                                              │
│  • DESIGN_TIME - Code repos, CI/CD, design tools                           │
│  • RUNTIME - Containers, cloud, APIs                                        │
│  • LANGUAGE - Language-specific analysis                                    │
│  • IAC - Infrastructure as Code                                             │
│  • COMPLIANCE - Compliance monitoring                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Agent Status Lifecycle

```
┌──────────────────────────────────────────────────────────────────┐
│                    AGENT STATUS FLOW                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│    ┌──────┐      ┌────────────┐      ┌────────────┐              │
│    │ IDLE │ ──▶  │ CONNECTING │ ──▶  │ MONITORING │              │
│    └──────┘      └────────────┘      └────────────┘              │
│        ▲                                   │                      │
│        │                                   ▼                      │
│        │              ┌────────────┐  ┌────────────┐             │
│        └───────────── │ PUSHING    │◀─│ COLLECTING │             │
│                       └────────────┘  └────────────┘             │
│                             │                                     │
│                       ┌─────▼─────┐                              │
│                       │  ERROR /   │                              │
│                       │DISCONNECTED│                              │
│                       └───────────┘                               │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### MISSING AGENTS - To Be Built

#### 1. MindsDB AI Agents (Priority: HIGH)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MINDSDB AI AGENTS (PORT 47334)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                 SECURITY ANALYST AGENT                               │   │
│  │  Status: ❌ NOT BUILT                                                │   │
│  │                                                                       │   │
│  │  Purpose: Autonomous vulnerability analysis and triage               │   │
│  │  Skills:                                                             │   │
│  │    • CVE analysis using CVE Knowledge Base                          │   │
│  │    • CVSS scoring with EPSS enrichment                              │   │
│  │    • Attack surface mapping                                         │   │
│  │    • Dependency chain analysis                                      │   │
│  │    • False positive detection                                       │   │
│  │                                                                       │   │
│  │  MindsDB Definition:                                                 │   │
│  │  ```sql                                                             │   │
│  │  CREATE AGENT security_analyst_agent                                │   │
│  │  USING                                                              │   │
│  │    model = 'gpt-4o',                                               │   │
│  │    skills = ['cve_lookup', 'epss_scoring', 'reachability_check'],  │   │
│  │    knowledge_bases = ['cve_kb', 'attack_patterns_kb'];             │   │
│  │  ```                                                                │   │
│  │                                                                       │   │
│  │  API Integration:                                                    │   │
│  │    • POST /copilot/agents/security-analyst/analyze                  │   │
│  │    • GET /copilot/agents/security-analyst/status                    │   │
│  │                                                                       │   │
│  │  Data Sources:                                                       │   │
│  │    • /api/v1/findings/* → Vulnerability data                        │   │
│  │    • /api/v1/feeds/* → Threat intelligence                          │   │
│  │    • /api/v1/inventory/* → Asset context                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    PENTEST AGENT                                     │   │
│  │  Status: ❌ NOT BUILT                                                │   │
│  │                                                                       │   │
│  │  Purpose: Automated penetration testing and exploit validation       │   │
│  │  Skills:                                                             │   │
│  │    • Reconnaissance (port scanning, service detection)              │   │
│  │    • Exploitation (CVE-based, proof-of-concept)                     │   │
│  │    • Post-exploitation (privilege escalation checks)                │   │
│  │    • Evidence collection (screenshots, logs, artifacts)             │   │
│  │                                                                       │   │
│  │  MindsDB Definition:                                                 │   │
│  │  ```sql                                                             │   │
│  │  CREATE AGENT pentest_agent                                         │   │
│  │  USING                                                              │   │
│  │    model = 'gpt-4o',                                               │   │
│  │    skills = ['nmap_scan', 'exploit_check', 'evidence_capture'],    │   │
│  │    knowledge_bases = ['exploit_kb', 'attack_patterns_kb'];         │   │
│  │  ```                                                                │   │
│  │                                                                       │   │
│  │  API Integration:                                                    │   │
│  │    • POST /copilot/agents/pentest/scan                              │   │
│  │    • POST /copilot/agents/pentest/exploit                           │   │
│  │    • GET /copilot/agents/pentest/results/{task_id}                  │   │
│  │                                                                       │   │
│  │  PentAGI Bridge:                                                     │   │
│  │    • Delegates to PentAGI (port 8443) for execution                 │   │
│  │    • MindsDB orchestrates, PentAGI executes                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                  COMPLIANCE AGENT                                    │   │
│  │  Status: ❌ NOT BUILT                                                │   │
│  │                                                                       │   │
│  │  Purpose: Automated compliance checking and gap analysis            │   │
│  │  Skills:                                                             │   │
│  │    • Framework mapping (PCI-DSS, SOC2, HIPAA, ISO27001)            │   │
│  │    • Control validation                                             │   │
│  │    • Evidence collection for audits                                 │   │
│  │    • Gap analysis reporting                                         │   │
│  │                                                                       │   │
│  │  MindsDB Definition:                                                 │   │
│  │  ```sql                                                             │   │
│  │  CREATE AGENT compliance_agent                                      │   │
│  │  USING                                                              │   │
│  │    model = 'gpt-4o',                                               │   │
│  │    skills = ['framework_mapping', 'control_check', 'gap_analysis'],│   │
│  │    knowledge_bases = ['compliance_kb', 'remediation_kb'];          │   │
│  │  ```                                                                │   │
│  │                                                                       │   │
│  │  API Integration:                                                    │   │
│  │    • POST /copilot/agents/compliance/assess                         │   │
│  │    • GET /copilot/agents/compliance/frameworks                      │   │
│  │    • POST /copilot/agents/compliance/report                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                 REMEDIATION AGENT                                    │   │
│  │  Status: ❌ NOT BUILT                                                │   │
│  │                                                                       │   │
│  │  Purpose: Automated fix generation and patch recommendations        │   │
│  │  Skills:                                                             │   │
│  │    • Fix generation (code patches, config changes)                  │   │
│  │    • Dependency upgrade recommendations                             │   │
│  │    • PR/MR creation                                                 │   │
│  │    • Rollback planning                                              │   │
│  │                                                                       │   │
│  │  MindsDB Definition:                                                 │   │
│  │  ```sql                                                             │   │
│  │  CREATE AGENT remediation_agent                                     │   │
│  │  USING                                                              │   │
│  │    model = 'gpt-4o',                                               │   │
│  │    skills = ['fix_gen', 'dep_upgrade', 'pr_create', 'rollback'],   │   │
│  │    knowledge_bases = ['remediation_kb', 'cve_kb'];                 │   │
│  │  ```                                                                │   │
│  │                                                                       │   │
│  │  API Integration:                                                    │   │
│  │    • POST /copilot/agents/remediation/generate-fix                  │   │
│  │    • POST /copilot/agents/remediation/create-pr                     │   │
│  │    • GET /copilot/agents/remediation/recommendations                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 2. PentAGI Multi-Agent System (Priority: HIGH)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PENTAGI MULTI-AGENT SYSTEM (PORT 8443)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Current PentAGI Agents (from architecture doc):                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                       │   │
│  │  ┌─────────────────┐    ┌─────────────────┐                         │   │
│  │  │ Reconnaissance  │ ─▶ │ Exploitation    │                         │   │
│  │  │ Agent           │    │ Agent           │                         │   │
│  │  │                 │    │                 │                         │   │
│  │  │ • Port scanning │    │ • CVE exploit   │                         │   │
│  │  │ • Service enum  │    │ • Custom PoC    │                         │   │
│  │  │ • Vuln scanning │    │ • Payload gen   │                         │   │
│  │  └─────────────────┘    └─────────────────┘                         │   │
│  │          │                       │                                   │   │
│  │          ▼                       ▼                                   │   │
│  │  ┌─────────────────┐    ┌─────────────────┐                         │   │
│  │  │ Post-Exploit    │ ◀─ │ Reporting       │                         │   │
│  │  │ Agent           │    │ Agent           │                         │   │
│  │  │                 │    │                 │                         │   │
│  │  │ • Priv escalate │    │ • Evidence pkg  │                         │   │
│  │  │ • Lateral move  │    │ • Risk scoring  │                         │   │
│  │  │ • Persistence   │    │ • Report gen    │                         │   │
│  │  └─────────────────┘    └─────────────────┘                         │   │
│  │                                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  MISSING PentAGI Capabilities - To Be Built:                                │
│  ═══════════════════════════════════════════                                │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 1. SOCIAL ENGINEERING AGENT                                          │   │
│  │    Status: ❌ NOT BUILT                                              │   │
│  │    • Phishing simulation                                             │   │
│  │    • Credential harvesting tests                                     │   │
│  │    • Pretexting scenarios                                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 2. WIRELESS SECURITY AGENT                                           │   │
│  │    Status: ❌ NOT BUILT                                              │   │
│  │    • WiFi assessment                                                 │   │
│  │    • Bluetooth scanning                                              │   │
│  │    • Rogue AP detection                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 3. CLOUD SECURITY AGENT                                              │   │
│  │    Status: ❌ NOT BUILT                                              │   │
│  │    • AWS/Azure/GCP misconfiguration detection                       │   │
│  │    • IAM privilege escalation paths                                 │   │
│  │    • Cloud-native attack simulation                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 4. API SECURITY AGENT                                                │   │
│  │    Status: ❌ NOT BUILT                                              │   │
│  │    • OWASP API Top 10 testing                                       │   │
│  │    • GraphQL/REST fuzzing                                           │   │
│  │    • Authentication bypass                                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 3. Data Collection Agents (Priority: MEDIUM)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DATA COLLECTION AGENTS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  EXISTING (✅) vs MISSING (❌):                                             │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ DESIGN TIME AGENTS                                                   │   │
│  │                                                                       │   │
│  │ ✅ CodeRepoAgent - Generic code repository monitoring               │   │
│  │ ❌ GitHubAgent - GitHub-specific integrations (Actions, Security)   │   │
│  │ ❌ GitLabAgent - GitLab CI/CD and security scanning                 │   │
│  │ ❌ BitbucketAgent - Bitbucket Pipelines integration                 │   │
│  │ ❌ JiraAgent - Issue tracking and vulnerability linking             │   │
│  │ ❌ ServiceNowAgent - ITSM integration                               │   │
│  │ ❌ SonarQubeAgent - Code quality and SAST results                   │   │
│  │ ❌ CheckmarxAgent - SAST scanner integration                        │   │
│  │ ❌ SnykAgent - SCA and container scanning                           │   │
│  │ ❌ VeracodeAgent - SAST/DAST results                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ RUNTIME AGENTS                                                       │   │
│  │                                                                       │   │
│  │ ✅ ContainerAgent - Container security monitoring                   │   │
│  │ ❌ KubernetesAgent - K8s cluster security                           │   │
│  │ ❌ DockerAgent - Docker daemon and registry scanning                │   │
│  │ ❌ AWSAgent - AWS Security Hub, GuardDuty, Inspector                │   │
│  │ ❌ AzureAgent - Azure Security Center, Defender                     │   │
│  │ ❌ GCPAgent - Google Security Command Center                        │   │
│  │ ❌ TerraformAgent - Terraform state security analysis               │   │
│  │ ❌ AnsibleAgent - Ansible playbook security scanning                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ LANGUAGE AGENTS                                                      │   │
│  │                                                                       │   │
│  │ ✅ PythonAgent - Python dependency and code analysis                │   │
│  │ ✅ JavaAgent - Java/Maven/Gradle analysis                           │   │
│  │ ✅ GoAgent - Go module security                                     │   │
│  │ ✅ JavaScriptAgent - npm/yarn dependency scanning                   │   │
│  │ ❌ RubyAgent - Ruby gem security                                    │   │
│  │ ❌ RustAgent - Cargo dependency analysis                            │   │
│  │ ❌ PHPAgent - Composer security scanning                            │   │
│  │ ❌ DotNetAgent - NuGet package security                             │   │
│  │ ❌ SwiftAgent - iOS/macOS dependency security                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ THREAT INTELLIGENCE AGENTS                                           │   │
│  │                                                                       │   │
│  │ ❌ NVDAgent - National Vulnerability Database feeds                 │   │
│  │ ❌ MITREAgent - MITRE ATT&CK framework updates                      │   │
│  │ ❌ EPSSAgent - Exploit Prediction Scoring System                    │   │
│  │ ❌ KEVAgent - Known Exploited Vulnerabilities catalog               │   │
│  │ ❌ ExploitDBAgent - Exploit-DB monitoring                           │   │
│  │ ❌ VulnCheckAgent - VulnCheck KEV feed                              │   │
│  │ ❌ OpenCTIAgent - Threat intelligence platform                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Agent Capability Matrix

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AGENT CAPABILITY MATRIX                                   │
├───────────────────┬─────────┬─────────┬──────────┬──────────┬──────────────┤
│ Capability        │ Existing│ MindsDB │ PentAGI  │ Collector│ Priority     │
├───────────────────┼─────────┼─────────┼──────────┼──────────┼──────────────┤
│ Code Analysis     │   ✅    │   ❌    │    ❌    │    ✅    │ ⬜ Done      │
│ Container Scan    │   ✅    │   ❌    │    ❌    │    ✅    │ ⬜ Done      │
│ Vuln Triage       │   ❌    │   🔲    │    ❌    │    ❌    │ 🔴 Critical  │
│ Pentest Automation│   ❌    │   🔲    │    ✅    │    ❌    │ 🔴 Critical  │
│ Compliance Check  │   ❌    │   🔲    │    ❌    │    ❌    │ 🟠 High      │
│ Fix Generation    │   ❌    │   🔲    │    ❌    │    ❌    │ 🟠 High      │
│ Threat Intel Feed │   ❌    │   ❌    │    ❌    │    🔲    │ 🟡 Medium    │
│ Cloud Security    │   ❌    │   ❌    │    🔲    │    🔲    │ 🟡 Medium    │
│ API Testing       │   ❌    │   ❌    │    🔲    │    ❌    │ 🟢 Low       │
│ Social Engineering│   ❌    │   ❌    │    🔲    │    ❌    │ 🟢 Low       │
├───────────────────┼─────────┼─────────┼──────────┼──────────┼──────────────┤
│ Legend: ✅ Built  │ ❌ Not  │ 🔲 To   │          │          │              │
│         Built     │         │ Build   │          │          │              │
└───────────────────┴─────────┴─────────┴──────────┴──────────┴──────────────┘
```

### Copilot Agent API Design (NEW - 28 endpoints)

```javascript
// NEW APIs needed for Copilot Agents
const copilotAgentApis = {
  // Agent Discovery
  listAgents: 'GET /api/v1/copilot/agents',
  getAgent: 'GET /api/v1/copilot/agents/{agent_id}',
  getAgentStatus: 'GET /api/v1/copilot/agents/{agent_id}/status',
  
  // Security Analyst Agent
  analyzeVulnerability: 'POST /api/v1/copilot/agents/security-analyst/analyze',
  triageFindings: 'POST /api/v1/copilot/agents/security-analyst/triage',
  assessRisk: 'POST /api/v1/copilot/agents/security-analyst/assess-risk',
  
  // Pentest Agent
  startPentest: 'POST /api/v1/copilot/agents/pentest/start',
  getPentestStatus: 'GET /api/v1/copilot/agents/pentest/{task_id}/status',
  stopPentest: 'POST /api/v1/copilot/agents/pentest/{task_id}/stop',
  getPentestResults: 'GET /api/v1/copilot/agents/pentest/{task_id}/results',
  downloadEvidence: 'GET /api/v1/copilot/agents/pentest/{task_id}/evidence',
  
  // Compliance Agent
  assessCompliance: 'POST /api/v1/copilot/agents/compliance/assess',
  listFrameworks: 'GET /api/v1/copilot/agents/compliance/frameworks',
  mapControls: 'POST /api/v1/copilot/agents/compliance/map-controls',
  generateComplianceReport: 'POST /api/v1/copilot/agents/compliance/report',
  
  // Remediation Agent
  generateFix: 'POST /api/v1/copilot/agents/remediation/generate-fix',
  validateFix: 'POST /api/v1/copilot/agents/remediation/validate-fix',
  createPullRequest: 'POST /api/v1/copilot/agents/remediation/create-pr',
  getRecommendations: 'GET /api/v1/copilot/agents/remediation/recommendations',
  
  // Agent Orchestration
  createTask: 'POST /api/v1/copilot/agents/tasks',
  getTask: 'GET /api/v1/copilot/agents/tasks/{task_id}',
  cancelTask: 'POST /api/v1/copilot/agents/tasks/{task_id}/cancel',
  listTasks: 'GET /api/v1/copilot/agents/tasks',
  
  // Agent Skills (MindsDB)
  listSkills: 'GET /api/v1/copilot/agents/{agent_id}/skills',
  executeSkill: 'POST /api/v1/copilot/agents/{agent_id}/skills/{skill_id}/execute',
  
  // Agent Knowledge Bases
  queryKnowledgeBase: 'POST /api/v1/copilot/agents/{agent_id}/kb/query',
  updateKnowledgeBase: 'POST /api/v1/copilot/agents/{agent_id}/kb/update'
};
```

### MindsDB Agent Skills Definition

```sql
-- Security Analyst Agent Skills
CREATE SKILL cve_lookup_skill
USING
  type = 'text2sql',
  database = 'cve_database',
  tables = ['cve_entries', 'epss_scores', 'kev_list'];

CREATE SKILL attack_surface_skill
USING
  type = 'knowledge_base',
  source = 'attack_patterns_kb';

CREATE SKILL dedup_skill
USING
  type = 'ml_model',
  model = 'finding_deduplicator';

-- Pentest Agent Skills  
CREATE SKILL nmap_scan_skill
USING
  type = 'api_call',
  api = 'pentagi_api',
  endpoint = '/api/v1/pentagi/scan';

CREATE SKILL exploit_check_skill
USING
  type = 'ml_model',
  model = 'exploit_success_predictor';

-- Compliance Agent Skills
CREATE SKILL framework_mapping_skill
USING
  type = 'knowledge_base',
  source = 'compliance_frameworks_kb';

CREATE SKILL control_validation_skill
USING
  type = 'text2sql',
  database = 'compliance_db',
  tables = ['controls', 'requirements', 'evidence'];

-- Remediation Agent Skills
CREATE SKILL fix_generation_skill
USING
  type = 'code_generation',
  model = 'gpt-4o';

CREATE SKILL pr_creation_skill
USING
  type = 'api_call',
  api = 'github_api',
  endpoint = '/repos/{owner}/{repo}/pulls';
```

### Agent Implementation Roadmap

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AGENT IMPLEMENTATION ROADMAP                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 1: MindsDB AI Agents (Weeks 1-4)                                     │
│  ═══════════════════════════════════════                                    │
│  Week 1: Security Analyst Agent                                             │
│    ├── Create MindsDB agent definition                                      │
│    ├── Configure CVE Knowledge Base                                         │
│    ├── Implement cve_lookup_skill                                          │
│    └── Wire to /copilot/agents/security-analyst/* APIs                     │
│                                                                             │
│  Week 2: Pentest Agent (MindsDB → PentAGI bridge)                          │
│    ├── Create MindsDB agent with PentAGI delegation                        │
│    ├── Implement task orchestration                                        │
│    └── Wire to /copilot/agents/pentest/* APIs                              │
│                                                                             │
│  Week 3: Compliance Agent                                                   │
│    ├── Create compliance frameworks KB                                      │
│    ├── Implement framework_mapping_skill                                   │
│    └── Wire to /copilot/agents/compliance/* APIs                           │
│                                                                             │
│  Week 4: Remediation Agent                                                  │
│    ├── Create remediation KB                                               │
│    ├── Implement fix_generation_skill                                      │
│    └── Wire to /copilot/agents/remediation/* APIs                          │
│                                                                             │
│  PHASE 2: Data Collection Agents (Weeks 5-8)                                │
│  ═══════════════════════════════════════════                                │
│  Week 5: CI/CD Integrations                                                 │
│    ├── GitHubAgent                                                         │
│    ├── GitLabAgent                                                         │
│    └── BitbucketAgent                                                      │
│                                                                             │
│  Week 6: Scanner Integrations                                               │
│    ├── SonarQubeAgent                                                      │
│    ├── SnykAgent                                                           │
│    └── CheckmarxAgent                                                      │
│                                                                             │
│  Week 7: Cloud Agents                                                       │
│    ├── AWSAgent                                                            │
│    ├── AzureAgent                                                          │
│    └── GCPAgent                                                            │
│                                                                             │
│  Week 8: Threat Intelligence Agents                                         │
│    ├── NVDAgent                                                            │
│    ├── EPSSAgent                                                           │
│    └── KEVAgent                                                            │
│                                                                             │
│  PHASE 3: PentAGI Extensions (Weeks 9-12)                                   │
│  ════════════════════════════════════════                                   │
│  Week 9: Cloud Security Agent                                               │
│  Week 10: API Security Agent                                                │
│  Week 11: Social Engineering Agent                                          │
│  Week 12: Wireless Security Agent                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Agent Count Summary

| Category | Existing | To Build | Total |
|----------|----------|----------|-------|
| Core Framework | 2 | 0 | 2 |
| MindsDB AI Agents | 0 | 4 | 4 |
| PentAGI Agents | 4 | 4 | 8 |
| Design Time Collectors | 1 | 9 | 10 |
| Runtime Collectors | 1 | 7 | 8 |
| Language Agents | 4 | 5 | 9 |
| Threat Intel Agents | 0 | 7 | 7 |
| **TOTAL** | **12** | **36** | **48** |

### Aikido Comparison: Agent Coverage

| Feature | Aikido (200+ agents) | ALdeci Current | ALdeci Target |
|---------|---------------------|----------------|---------------|
| SAST Analysis | ✅ | ✅ (4 language) | ✅ (9 language) |
| SCA Scanning | ✅ | ✅ (CodeRepoAgent) | ✅ (10 CI/CD) |
| Container Scanning | ✅ | ✅ (ContainerAgent) | ✅ (3 container) |
| Cloud Security | ✅ | ❌ | ✅ (3 cloud) |
| AI Pentesting | ✅ | ✅ (PentAGI 4) | ✅ (PentAGI 8) |
| Compliance | ✅ | ❌ | ✅ (Compliance Agent) |
| Remediation | ✅ | ❌ | ✅ (Remediation Agent) |
| Threat Intel | ✅ | ❌ | ✅ (7 feed agents) |
| **AI Chat/Copilot** | ✅ (AI reasoning) | ❌ | ✅ (MindsDB Copilot) |

---

## 🚀 Next Steps

1. **Create Copilot Chat Router** - `/apps/api/copilot_router.py` with 13 chat + 28 agent endpoints
2. **Configure MindsDB Knowledge Bases** - CVE KB, Attack Patterns KB, Compliance KB, Remediation KB
3. **Create MindsDB AI Agents** - Security Analyst, Pentest, Compliance, Remediation agents
4. **Train MindsDB ML Models** - exploit_success_predictor, attack_path_predictor, mttr_predictor
5. **Build Copilot UI Component** - Chat interface with agent action buttons
6. **Wire 363 API endpoints to MindsDB** - Feed data for RAG and training
7. **Implement Agent Orchestrator** - `/core/copilot_orchestrator.py`
8. **Build Data Collection Agents** - Start with CI/CD integrations (GitHub, GitLab)
9. **Extend PentAGI** - Add Cloud, API, Social Engineering agents
10. **Implement 6-step CTEM progress ring** - Real-time cycle tracking
11. **Deploy on Port 4567** - Extend `aldeci-professional-ui.js`

---

## 📊 Complete API Inventory by Suite

### Updated Suite → API Count (Verified February 2026)

| Suite | APIs | Key Routers |
|-------|------|-------------|
| **🔍 CODE** | 15 | secrets_router, iac_router, validation_router |
| **☁️ CLOUD** | 56 | feeds_router, deduplication_router, inventory_router |
| **⚔️ ATTACK** | 62 | pentagi_router, pentagi_router_enhanced, micro_pentest_router, intelligent_engine_routes |
| **🛡️ PROTECT** | 84 | remediation_router, bulk_router, collaboration_router, workflows_router, webhooks_router, marketplace_router |
| **🧠 AI ENGINE** | 37 | algorithmic_router, predictions_router, llm_router, policies_router, enhanced |
| **📦 EVIDENCE** | 52 | audit_router, reports_router, analytics_router, evidence, provenance, graph, risk |
| **⚙️ SETTINGS** | 32 | users_router, teams_router, auth_router, integrations_router, ide_router, health_router |
| **💬 COPILOT** | 25 | app.py ingestion endpoints, health.py |
| **TOTAL** | **363** | |
