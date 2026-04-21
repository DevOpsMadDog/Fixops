# Wiz.io UI Pattern Analysis — ALDECI Improvement Recommendations

**Date:** 2026-04-17
**Analyst:** Executor (Claude Sonnet 4.6)
**Purpose:** Identify Wiz UI/UX patterns ALDECI should adopt to reach enterprise-grade quality

---

## 1. Wiz Platform Overview

Wiz is a CNAPP (Cloud-Native Application Protection Platform) that consolidates CSPM, KSPM, CWPP, Vulnerability Management, IaC scanning, CIEM, and DSPM into a single interface. In 2024 Google acquired Wiz for $32B — the largest cybersecurity acquisition in history — validating their UI/UX as the gold standard for cloud security platforms. ALDECI competes directly in this space.

---

## 2. Wiz UI Design Principles (Researched)

### 2.1 The Security Graph — Core Differentiator

Wiz's single most distinctive UI element is the **Security Graph**: an interactive node-and-edge graph that maps relationships between cloud resources, identities, vulnerabilities, and data.

**What it does:**
- Nodes represent cloud resources (VMs, containers, S3 buckets, IAM roles, databases)
- Edges represent relationships: network reachability, IAM permission chains, data flows
- Critical attack paths are highlighted as traversal routes through the graph
- "Toxic combinations" — multiple low-risk issues chaining into a high-impact path — are surfaced as a single prioritized finding
- Blast radius: clicking any node immediately shows how far compromise can spread
- Root cause: clicking any finding traces backward through the graph to origin

**Key insight:** Wiz does NOT show a list of 500 individual findings. It shows **1 attack path** that represents the actual breach scenario. This is the fundamental difference between Wiz and legacy tools.

**Severity color coding (inferred from documentation):**
- Critical: Red
- High: Orange
- Medium: Yellow
- Low: Blue/Grey
- Resolved/Clean: Green

### 2.2 Navigation Structure

Wiz uses a **top-level horizontal navigation** with ~6 product areas, NOT a deep nested sidebar. Their product areas map roughly to:

- **Inventory** — all cloud assets, unified view
- **Issues** — prioritized risk queue (NOT an alert list)
- **Graph** — Security Graph explorer
- **Compliance** — heatmap + framework drill-down
- **Reports** — executive and on-demand exports
- **Settings** — integrations, policies, users

**Key insight:** Wiz surfaces ~6 top-level concepts. Users never click more than 2 levels deep to reach any feature. Navigation clarity is a primary UX investment.

### 2.3 Cloud Security Posture (CSPM) Dashboard

Wiz's CSPM view leads with:
1. **Posture score as a large, prominent number** — single score across the entire cloud environment (not per-domain sub-scores buried in cards)
2. **Provider breakdown** — AWS / Azure / GCP / OCI each get a score bar
3. **Single prioritized risk queue** — findings sorted by actual exploitability, not CVSS alone
4. **Graph context per finding** — every finding links directly into the Security Graph
5. **2,800+ configuration rules** running continuously — shown as a rule coverage metric
6. **Remediation guidance inline** — not a separate page, shown in the finding detail panel

**Data density:** Medium-high. Dense information but with clear visual hierarchy. No empty states or placeholder widgets.

### 2.4 Compliance Dashboard — Heatmap Pattern

Wiz's compliance view is built around a **compliance heatmap** — a visual grid where:
- Rows = compliance frameworks (CIS, NIST, PCI-DSS, HIPAA, SOC2, GDPR, ISO 27001, etc.)
- Columns = cloud accounts / business units / environments (prod, staging, dev)
- Cells = color-coded compliance score (green=passing, yellow=partial, red=failing)
- Click any cell → drill into controls for that framework + account combination
- Click any control → see all affected resources across all clouds

**Key insight:** The heatmap gives a bird's-eye view across 100+ frameworks at once. Users instantly see where the worst gaps are without reading any text.

**Drill-down path:**
```
Heatmap cell → Framework categories → Individual controls → Resource list → Remediation
```

### 2.5 Attack Path Visualization

Wiz surfaces attack paths as:
1. A **card-based list** of prioritized attack paths (not a raw graph dump)
2. Each card shows: start node type, end node (crown jewel), path length, CVEs required, blast radius score
3. Clicking a card opens the **Security Graph** with that specific path highlighted end-to-end
4. The graph uses a **force-directed layout** with the crown jewel at center
5. Nodes on the critical path are highlighted; off-path nodes are dimmed
6. A side panel shows: node details, associated CVEs, remediation options, owner attribution

**Toxic combinations** are shown as a special badge — multiple medium-severity issues that together create a critical path. This is Wiz's signature UX innovation.

### 2.6 Color Scheme & Visual Design

Based on Wiz's public materials and product documentation:
- **Background:** White (#FFFFFF) with very light grey section dividers — NOT dark mode
- **Primary accent:** Blue (#0066CC range) for interactive elements, links, CTAs
- **Graph edges:** Light grey for normal relationships, red for attack path edges
- **Severity spectrum:** Red → Orange → Yellow → Blue (critical → high → medium → low)
- **Typography:** Clean sans-serif, high contrast, generous line spacing
- **Cards:** White with subtle drop shadow, rounded corners, no heavy borders
- **Data tables:** Alternating row shading, sticky headers, sortable columns
- **Charts:** Minimal, flat design — no 3D charts, no heavy gradients

**Key insight:** Wiz is deliberately light/white. Enterprise buyers want professional, readable tools — not dark "hacker aesthetic" UIs.

### 2.7 Finding/Issue Display Pattern

Wiz's issue list uses a **risk-prioritized queue** pattern:
- Single unified queue across ALL cloud environments
- Each row: severity badge | issue title | affected resource | cloud provider | discovery time | owner
- Inline remediation: expand any row to see fix steps without navigating away
- Bulk actions: select multiple findings → assign owner, create ticket, accept risk
- Filters: by severity, provider, resource type, compliance framework, age, owner
- No pagination — virtual scrolling through the full queue

**Key insight:** No separate pages for "AWS findings" vs "Azure findings." Everything in one queue with filters.

---

## 3. ALDECI Current State Assessment

### 3.1 Navigation (WorkspaceLayout.tsx)

ALDECI currently has:
- **6 top-level sections** in a collapsible left sidebar: Discover, Protect, Respond, Comply, Govern, AI
- Each section has **3-7 groups** with **4-10 items each**
- Total nav items: **200+** — far too many to navigate
- Deep nesting: up to 3 levels (Section → Group → Item)
- Many duplicate/overlapping items (e.g., "Cloud Posture" appears in 3 different groups: `/discover/cloud`, `/cspm`, `/cloud-security`, `/cloud-compliance`, `/cloud-posture`)

**Gap vs Wiz:** Wiz has ~20 top-level items total. ALDECI has 200+. Users get lost.

### 3.2 Cloud Posture (CloudPostureDashboard.tsx)

ALDECI currently shows:
- 4 KPI cards (Cloud Accounts, Avg Posture Score, Open Findings, Critical Findings)
- A flat table of findings with severity badges
- No graph visualization
- No cross-provider posture comparison
- No attack path context per finding

**Gap vs Wiz:** Missing the Security Graph context. Findings are a flat list, not a prioritized queue with exploitability context. No inline remediation guidance.

### 3.3 Security Posture (SecurityPostureDashboard.tsx)

ALDECI currently shows:
- Large score circle (74/100) with grade B — good pattern
- 4 KPI cards
- 8 component score bars (lowest 3 highlighted red)
- Industry benchmark comparison
- 12-month score history line chart
- Top 5 improvement recommendations

**Gap vs Wiz:** The score circle is a good Wiz-like element. But the component breakdown (Vulnerability Management, Identity Security, etc.) is domain-internal. Wiz shows scores per **cloud provider** and per **business unit**, enabling cross-team accountability.

### 3.4 Attack Path Analysis (AttackPathAnalysis.tsx)

ALDECI currently shows:
- KPI cards (total paths, crown jewels at risk, entry points)
- A list of attack paths with length, start/end node, CVEs required, blast radius
- An SVG node graph (hand-rolled, basic)

**Gap vs Wiz:** The data model is good (matching Wiz's concepts: entry points, crown jewels, blast radius, CVEs required). The visualization is where ALDECI falls behind — a basic SVG vs Wiz's interactive force-directed graph with drill-down panels.

### 3.5 Compliance Dashboard (CloudComplianceDashboard.tsx)

ALDECI currently shows:
- 4 KPI cards (frameworks assessed, controls passed/failed, overall score)
- Assessments table (framework name, pass/fail/score)
- Failed controls table
- Remediation plans list

**Gap vs Wiz:** Missing the signature **compliance heatmap** (frameworks × accounts/environments grid). The flat table approach does not give the bird's-eye view Wiz delivers.

### 3.6 Color Scheme & Theme

ALDECI uses a **dark theme** (dark backgrounds, colored text, glowing badges). Wiz uses a **light/white theme**.

**Assessment:** Dark theme is not wrong — many security tools use it (Splunk, Datadog). The issue is consistency and professionalism. ALDECI's dark theme uses many competing accent colors (red, orange, yellow, green, blue, purple all visible simultaneously), reducing clarity. Wiz's restraint — using color only for severity — makes their UI scannable.

---

## 4. Gap Summary Table

| Feature | Wiz | ALDECI Current | Gap Level |
|---------|-----|----------------|-----------|
| Security Graph (interactive) | Core UI element | Basic SVG, no interactivity | CRITICAL |
| Navigation depth | 2 levels max, ~20 items | 3 levels, 200+ items | HIGH |
| Compliance heatmap | Frameworks × accounts grid | Flat table | HIGH |
| Findings queue (unified) | Single prioritized queue | Separate page per domain | HIGH |
| Inline remediation | Per-finding, no nav | Separate remediation pages | HIGH |
| Toxic combinations | Signature feature | Not implemented | HIGH |
| Attack path graph (interactive) | Force-directed + drill-down | Basic SVG list | HIGH |
| Posture score per provider | AWS/Azure/GCP breakdown | Single composite score | MEDIUM |
| Blast radius visualization | Click any node | Text field on card | MEDIUM |
| Bulk finding actions | Select → assign/ticket/accept | Not present | MEDIUM |
| Light/white theme option | Default | Dark only | LOW |
| Executive PDF exports | One-click, branded | Manual | LOW |
| Owner attribution per finding | Built-in | Not present | MEDIUM |

---

## 5. Specific ALDECI Pages to Improve (Priority Order)

### PRIORITY 1 — Security Graph (New Component Needed)

**File to create:** `suite-ui/aldeci-ui-new/src/components/graph/SecurityGraph.tsx`

The single highest-impact improvement. ALDECI already has all the data (attack paths, crown jewels, blast radius, CVEs, IAM relationships). What's missing is an **interactive graph visualization** using a proper library.

**Recommended library:** `@xyflow/react` (React Flow) — the same type of library Wiz uses internally. Already popular in security tool UIs.

**What to build:**
- Force-directed graph with zoom/pan
- Node types: VM, Container, Database, IAM Role, S3/Storage, Network, Crown Jewel
- Edge types: network reachability (dashed), IAM permission (solid), data access (dotted)
- Attack path overlay: highlight nodes/edges on the critical path in red
- Click any node → right side panel with: resource details, CVEs, owner, remediation
- Toxic combination badge on nodes where multiple risks converge
- Mini-map in corner for large environments

**Pages that should embed this component:**
- `/attack-paths` (AttackPathAnalysis.tsx) — replace basic SVG
- `/discover/graph` (KnowledgeGraph) — replace with SecurityGraph
- `/cloud-posture` (CloudPostureDashboard.tsx) — add as secondary panel
- `/insider-threats` — add lateral movement graph view

### PRIORITY 2 — Compliance Heatmap (CloudComplianceDashboard.tsx)

**File:** `/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages/CloudComplianceDashboard.tsx`

**What to add above the current tables:**
- A grid component: rows = frameworks (CIS-AWS, CIS-Azure, NIST 800-53, SOC2, PCI-DSS, GDPR, HIPAA, ISO27001), columns = environments (prod, staging, dev, all)
- Each cell: colored square (green ≥80%, yellow 60-79%, red <60%) + score number
- Click any cell → scroll to / filter the controls table below
- Add "Export compliance report" button per framework row (PDF/CSV)

**Estimated change:** ~120 lines of new JSX, no backend changes needed (data already exists from `/api/v1/cloud-compliance/assessments`).

### PRIORITY 3 — Unified Findings Queue (New Page)

**File to create:** `suite-ui/aldeci-ui-new/src/pages/FindingsQueue.tsx`
**Route:** `/findings` (already exists in App.tsx as `FindingsExplorer`)

Replace or enhance the existing `FindingsExplorer` to match Wiz's unified queue pattern:
- Single queue pulling from ALL engines (cloud posture, vuln lifecycle, attack surface, container security, etc.)
- Default sort: exploitability score (not CVSS alone — factor in network exposure + IAM path + asset criticality)
- Inline expand row: show remediation steps without navigation
- Bulk actions toolbar: assign owner, create Jira/ticket, accept risk (mark exception)
- Filter bar: severity | provider | resource type | framework | age | owner | status
- Virtual scroll (no pagination)

**Backend dependency:** `/api/v1/security-findings` engine already exists (SecurityFindings engine, Wave 33).

### PRIORITY 4 — Navigation Reduction (WorkspaceLayout.tsx)

**File:** `/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/components/layout/WorkspaceLayout.tsx`

The 200+ item navigation is the biggest UX debt. Recommended restructure:

**Proposed top-level sections (6 max):**
1. **Dashboard** — Command, Executive, CISO, SOC T1, Risk Overview
2. **Discover** — Asset Inventory, Cloud Posture, Attack Surface, Code Scanning, SBOM
3. **Protect** — Vulns, Identity, AppSec, Endpoint, Network
4. **Detect & Respond** — Incident Response, Threat Hunting, SIEM, Insider Threats
5. **Comply** — Frameworks, Evidence, Audit Trail, Reports
6. **Settings** — Integrations, Users, Policies

Collapse the 200 items into ~40 items total by:
- Merging overlapping pages (4x "Cloud Posture" variants → 1 page with tabs)
- Moving niche dashboards (Wave 25-41 engines) behind a "More" expandable section or a "Labs" section
- Creating category landing pages that surface sub-features as tabs rather than separate nav items

**Estimated impact:** This alone would make ALDECI feel 10x more professional to an enterprise buyer doing a demo.

### PRIORITY 5 — Cloud Posture Posture Score by Provider

**File:** `/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages/CloudPostureDashboard.tsx`

Replace the single "Avg Posture Score" KPI card with a **provider breakdown row**:
- AWS: 72% [progress bar] 23 open findings
- Azure: 68% [progress bar] 18 open findings
- GCP: 81% [progress bar] 6 open findings
- Overall: 74% [progress bar] 47 open findings

This maps directly to how Wiz shows multi-cloud posture and gives cloud account owners clear ownership.

### PRIORITY 6 — Attack Path Cards with Toxic Combination Badges

**File:** `/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages/AttackPathAnalysis.tsx`

Add **toxic combination detection** to the attack path cards:
- A path involving 2+ medium-severity issues that together create a critical path → badge "TOXIC COMBO"
- Show the individual components: "Public IP + Excessive IAM + Unpatched CVE-2024-XXXX"
- Color the card red regardless of individual component severity

This is Wiz's most-cited UX innovation in analyst reviews and demos. It directly communicates "why should I care about medium findings" to a CISO.

### PRIORITY 7 — Inline Remediation in Findings

**File:** `/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages/CloudPostureDashboard.tsx` (and all findings tables)

Convert the flat findings table rows to expandable accordion rows:
- Default: compressed row with severity | title | resource | provider | status
- Expanded (click row): remediation steps, affected resource details, owner field, link to Security Graph, "Create Ticket" button, "Accept Risk" button

This eliminates the need to navigate to separate remediation pages for each finding.

---

## 6. Quick Wins (Low Effort, High Visual Impact)

These can be done in under 2 hours each:

1. **Posture score gauge → prominent hero element**: On the Security Posture dashboard, make the score circle larger (at least 160px diameter), add a trend arrow (+3 pts from last month), and move it to the top-left of the page as the primary visual anchor.

2. **Severity color standardization**: Audit all 309 page files and enforce the same severity palette everywhere:
   - `critical` → `text-red-400 bg-red-500/10 border-red-500/30`
   - `high` → `text-orange-400 bg-orange-500/10 border-orange-500/30`
   - `medium` → `text-yellow-400 bg-yellow-500/10 border-yellow-500/30`
   - `low` → `text-blue-400 bg-blue-500/10 border-blue-500/30`
   - `info` → `text-zinc-400 bg-zinc-500/10 border-zinc-500/30`

3. **Add provider badges to cloud findings**: Every row in every cloud-related table should show a colored provider badge: `AWS` (orange), `Azure` (blue), `GCP` (red), `OCI` (maroon). Currently most tables show plain text.

4. **"Last scanned" timestamps on all dashboards**: Wiz shows when data was last refreshed on every panel. ALDECI shows no data freshness indicators. Add `Last updated: 3 min ago` to every KpiCard and table header.

5. **Empty state improvements**: Several dashboards show a blank white area when no data loads. Replace all empty states with an explanatory message + "Connect your cloud account" CTA (modeled on Wiz's onboarding pattern).

---

## 7. What ALDECI Does Better Than Wiz

Not everything should change. ALDECI has genuine advantages to preserve:

1. **Breadth**: 344+ engines vs Wiz's focused CNAPP scope. ALDECI covers SOC workflow, insider threat, OT/IoT security, physical security — Wiz does not.

2. **Self-hosted**: ALDECI runs entirely on-prem. Wiz is SaaS-only. This is a hard differentiator for regulated industries.

3. **Compliance depth**: ALDECI has 100+ compliance frameworks with engine-level data. The compliance infrastructure (engines, evidence collection, audit trails) is already superior to Wiz's compliance layer.

4. **AI Copilot**: ALDECI has a built-in AI copilot with GraphRAG. Wiz has a chatbot but ALDECI's TrustGraph knowledge cores provide deeper context.

5. **Price**: ALDECI costs $35-60/month self-hosted vs Wiz's $300K-500K/year enterprise contracts.

**Recommendation:** ALDECI's marketing and UI should lead with self-hosted + breadth + price. The UI improvements above close the visual/UX gap so buyers can see the value without getting distracted by interface polish differences.

---

## 8. Implementation Roadmap

| Phase | Work | Effort | Impact |
|-------|------|--------|--------|
| Phase 1 (1 day) | Severity color standardization, provider badges, last-updated timestamps, empty states | Small | Medium |
| Phase 2 (2 days) | Compliance heatmap grid, provider posture score breakdown, attack path toxic combo badges | Medium | High |
| Phase 3 (3 days) | SecurityGraph component (React Flow), wire into AttackPathAnalysis + KnowledgeGraph | Large | Critical |
| Phase 4 (2 days) | Unified FindingsQueue page with inline expand + bulk actions | Medium | High |
| Phase 5 (1 day) | Navigation reduction: merge duplicates, 40-item max | Small | Very High (demo impact) |

**Total estimated effort:** ~9 engineering days for a full Wiz-quality UI overhaul.

---

## 9. Sources

- [Wiz CSPM Solution Page](https://www.wiz.io/solutions/cspm)
- [Wiz Compliance Solution Page](https://www.wiz.io/solutions/compliance)
- [Wiz Security Graph LP](https://www.wiz.io/lp/wiz-security-graph)
- [Wiz Attack Path Analysis Academy](https://www.wiz.io/academy/detection-and-response/attack-path-analysis)
- [Wiz Platform Overview](https://www.wiz.io/platform)
- [Wiz Cloud Platform](https://www.wiz.io/platform/wiz-cloud)
- [Wiz Cloud Compliance Posture Blog](https://www.wiz.io/blog/wiz-cloud-compliance-posture)
- [Wiz Security Graph + Cloud IR Blog](https://www.wiz.io/blog/wiz-security-graph-enhances-cloud-incident-response)
- [Wiz AI-SPM Announcement](https://www.wiz.io/blog/ai-security-posture-management)
- [Recreating Wiz Security Graph with PuppyGraph](https://www.puppygraph.com/blog/wiz-security-graph)
- [Wiz + Google Cloud Architecture Guide](https://docs.cloud.google.com/architecture/partners/id-prioritize-security-risks-with-wiz)
- [Wiz Defend / Runtime Security Analysis](https://softwareanalyst.substack.com/p/runtime-security-in-2025-how-wiz)
- [Wiz in 2026: Definitive Guide](https://solideinfo.com/wiz-cloud-security/)
