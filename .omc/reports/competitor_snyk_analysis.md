# Snyk Platform UI Patterns — ALDECI ASPM Comparison

**Date:** 2026-04-17
**Author:** Executor agent (competitive research)
**Scope:** Snyk dashboard UI patterns for dependencies, vulnerability prioritization, and fix suggestions vs. ALDECI supply chain and vuln pages

---

## 1. Snyk Platform Overview

Snyk is a developer-first ASPM/SCA platform focused on open-source dependency scanning, container security, IaC, and code scanning. Its key differentiator is embedding security directly into developer workflows (IDE plugins, PR checks, auto-fix PRs).

### Core UI Philosophy
- **Developer-first**: security findings surface in IDE, PR, and CI — not just a separate security console
- **Dependency-grouped views**: vulnerabilities are organized by the *dependency that introduces them*, not by CVE ID alone
- **Cost/benefit remediation**: each upgrade shows all issues resolved, not just the minimum fix
- **Reachability-gated prioritization**: findings are suppressed unless the vulnerable code path is actually called

---

## 2. Snyk Dashboard UI Patterns

### 2.1 Navigation and Layout

Snyk recently launched a "Unified Navigation" consolidating previously fragmented product areas (Code, Open Source, Container, IaC) into a single sidebar. Key claims:
- 60% reduction in triage time via better prioritization and consolidated navigation
- 85% faster time-to-fix through global search across all projects and issues
- Simple tasks previously required 8+ clicks; now reduced significantly

**Layout structure:**
```
Top nav: Org selector | Global search | Notifications
Left sidebar: Projects | Issues | Reports | Settings
Main area: Filterable project list or issue list (context-dependent)
```

### 2.2 Project List View

Projects grouped and filterable by:
- "With issues" / "Without issues" buckets
- Integrated source (GitHub, GitLab, Bitbucket, CLI)
- Asset class (application, container, IaC)
- Owner / team attribution
- Severity distribution per project (color-coded severity bar)

Each project card shows:
- Project name + ecosystem icon (npm, Maven, pip, etc.)
- Last scan timestamp
- Issue count broken down by severity (Critical / High / Medium / Low)
- Fix availability indicator

### 2.3 Project Detail — Three-Tab Architecture

Snyk uses a three-tab layout per project:

| Tab | Content |
|-----|---------|
| **Issues** | Full vulnerability list with priority score, severity, CVE, description, fix info |
| **Fixes** | Grouped by dependency — shows which version upgrades resolve which set of issues |
| **Dependencies** | Full dependency tree (direct + transitive) with version and vulnerability mapping |

**Issues tab filters:**
- Issue type (vuln / license)
- Severity (Critical / High / Medium / Low)
- Fixability (fixable / partially fixable / no fix available)
- Exploit maturity (mature / proof-of-concept / no known exploit)
- Reachability (reachable / potentially reachable / no path found)
- Status (open / ignored / resolved)

### 2.4 Dependency View (Dependencies Tab)

- Full tree from direct dependency down to transitive vulnerable package
- Each node shows: package name, version, ecosystem, CVE count
- Expandable tree — can drill from your `package.json` entry through 4-5 levels to the actual vulnerable function
- PURL (Package URL) displayed for each component

### 2.5 Vulnerability Card (Issue Detail)

Each issue card contains:
```
[Priority Score: 850/1000]  [Severity: Critical]  [Exploit: Mature]
CVE-2024-XXXX — Remote Code Execution in lodash
Introduced via: express > body-parser > qs > lodash@4.17.20
Fix: Upgrade lodash to 4.17.21

[Reachability: REACHABLE — call path found]
  your-app/routes/api.js:42 → qs.parse() → lodash.merge() [vulnerable]

[Fix this vulnerability] [Ignore with reason] [Open Fix PR]
```

Key data points per vulnerability:
- Snyk Priority Score (1–1000, composite)
- CVSS base score
- EPSS score
- CVE identifier + NVD link
- Exploit maturity label
- Reachability status + call path detail
- Transitive dependency chain showing introduction path
- Fix version recommendation
- Number of other issues resolved by this same fix

### 2.6 Fixes Tab — Dependency-Grouped Remediation View

This is Snyk's most distinctive UI element. Instead of listing CVEs, it lists **dependencies with their aggregate fix cost/benefit**:

```
┌─ lodash  4.17.20  →  upgrade to 4.17.21 ──────────────────────────┐
│  Fixes 3 vulnerabilities:                                           │
│    • Prototype Pollution [High] CVE-2021-23337                      │
│    • Command Injection [High] CVE-2020-8203                         │
│    • Regular Expression DoS [Medium] CVE-2020-28500                 │
│  [Open Fix PR]                                                       │
└─────────────────────────────────────────────────────────────────────┘

┌─ minimist  1.2.5  →  upgrade to 1.2.6 ────────────────────────────┐
│  Fixes 1 vulnerability:                                             │
│    • Prototype Pollution [Critical] CVE-2021-44906                  │
│  [Open Fix PR]                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

The "Open Fix PR" button generates a pull request with:
- The dependency bump in the manifest file
- PR description listing all CVEs resolved
- Link to each CVE for stakeholder review

### 2.7 Prioritization System — Risk Score

Snyk uses two complementary scores:

**Priority Score (1–1000):**
- CVSS base score (severity)
- Exploit maturity (mature > PoC > theoretical)
- Reachability (reachable > potentially reachable > not reachable)
- Social trend (recent discussion / active exploitation)
- EPSS probability
- Time since publication (newer = higher urgency)
- Fix availability

**Risk Score (newer, broader):**
- All Priority Score factors PLUS:
- Asset business criticality
- Deployment environment (prod vs. dev)
- Data sensitivity context
- CVSS exploitability sub-score
- Transitive depth (closer to root = higher risk)

Presentation: numeric badge (color-coded red/orange/yellow/green) displayed prominently on every issue card. Default sort is by Risk Score descending.

### 2.8 SBOM Integration

Snyk supports SBOM in two modes:

1. **Generate SBOM**: Export CycloneDX 1.4 or SPDX 2.3 from any scanned project via API (`GET /api/v2/projects/{id}/sbom?format=cyclonedx`)
2. **Import SBOM**: Upload external SBOM to test against Snyk vulnerability database

SBOM dashboard (via ServiceNow integration):
- Total components count
- Vulnerable component count + severity breakdown
- License issue count
- Last scan timestamp
- Exportable to CSV/JSON

---

## 3. ALDECI Current State — Supply Chain and Vuln Pages

### 3.1 Pages Audited

| Page | Route | File |
|------|-------|------|
| VulnPrioritizationDashboard | /vuln-prioritization | VulnPrioritizationDashboard.tsx |
| SCADashboard | /sca | SCADashboard.tsx |
| SupplyChainDashboard | /supply-chain | SupplyChainDashboard.tsx |
| SBOMExportDashboard | /sbom-export | SBOMExportDashboard.tsx |
| SecurityDependencyRiskDashboard | /dependency-risk | SecurityDependencyRiskDashboard.tsx |
| SupplyChainAttackDashboard | /supply-chain-attacks | SupplyChainAttackDashboard.tsx |

### 3.2 ALDECI VulnPrioritizationDashboard

**What it has:**
- KPI row: Total Vulns, Critical Priority, Exploited in Wild, Avg Priority Score
- Remediation queue table with: CVE ID, Asset, Priority Score (0–100), Priority Level badge, CVSS, EPSS, Status
- Color-coded priority scores (red ≥80, orange ≥60, yellow ≥40, green <40)
- Composite scoring using CVSS + EPSS + KEV data
- Status lifecycle: open → in_progress → resolved

**What it lacks vs. Snyk:**
- No reachability analysis — no call path from code to vulnerable function
- No exploit maturity label (mature / PoC / no known exploit)
- No "introduced via" dependency chain visualization
- No fix version recommendation per CVE
- No "Fix PR" generation button
- No grouping by dependency (Snyk's key differentiator)
- No transitive depth indicator
- No social trend / trending indicator
- Priority score is 0–100; Snyk uses 0–1000 (more granular)

### 3.3 ALDECI SCADashboard

**What it has:**
- KPI row: Projects, Total Scans, Vulnerable Dependencies, License Violations
- Projects table: name, language (with color badges), last scan date, vuln count (color-coded), risk level badge
- Language-specific color coding (Go=cyan, Python=blue, TypeScript=indigo, etc.)

**What it lacks vs. Snyk:**
- No per-project dependency tree view
- No drill-down from project → dependency → CVE chain
- No three-tab layout (Issues / Fixes / Dependencies)
- No fix recommendation per project
- No fixability filter (fixable vs. no-fix-available)
- No "Open Fix PR" workflow
- No ecosystem-specific grouping (Maven vs. npm vs. pip)
- License violations shown as a KPI count only — no detail on which packages violate which licenses

### 3.4 ALDECI SupplyChainDashboard

**What it has (strongest of the three):**
- Supplier registry table: name, category (cloud/software/hardware), country, risk tier, compliance score bar, last assessed, risk count, View action
- Component risk registry: component name, version, supplier, license, CVE count badge, EOL badge, PURL
- Risk breakdown cards: 6 categories (Single Source, EOL/Deprecated, Geo-Political, Breach History, No Recent Audit, License Issues)
- SBOM summary panel: total components, EOL%, CVE-affected%, license issue%, progress bars
- SBOM import button
- Live API wiring to `/api/v1/supply-chain/vendors`, `/api/v1/supply-chain/components`

**What it lacks vs. Snyk:**
- No per-component CVE detail drill-down
- No transitive dependency graph visualization
- No auto-fix PR generation
- No reachability context (is the vulnerable component actually called?)
- No upgrade path recommendation (e.g., "upgrade openssl 1.0.2k → 3.0.x to fix 14 CVEs")
- Component table shows CVE count but not which CVEs (no expandable detail)
- No license conflict detail (which license conflicts with which)

---

## 4. Feature Gap Matrix

| Feature | Snyk | ALDECI |
|---------|------|--------|
| Dependency-grouped vulnerability view | YES — core UI | NO — CVE-first view |
| Reachability analysis + call path | YES — with source line | NO |
| Exploit maturity labels | YES | NO |
| Fix PR auto-generation | YES — one click | NO |
| Transitive dependency tree | YES — full expandable tree | Partial (PURL shown, no tree) |
| Priority Score (composite) | YES — 0–1000, 7 factors | YES — 0–100, 3 factors (CVSS+EPSS+KEV) |
| Risk Score (business context) | YES — asset criticality + env | NO |
| Per-project three-tab layout | YES | NO — single flat view |
| License detail per package | YES | Count only |
| SBOM import + scan | YES | Import button exists, scan not wired |
| SBOM export (CycloneDX/SPDX) | YES | YES — `/api/v1/sbom-export` |
| Supplier/vendor registry | NO (not Snyk's focus) | YES — strong |
| Geo-political risk | NO | YES |
| EOL component tracking | Partial | YES |
| Supply chain attack detection | NO | YES |
| Breach history tracking | NO | YES |
| SBOM summary panel | YES (ServiceNow) | YES — built-in |

---

## 5. Competitive Positioning

### Where Snyk Wins Over ALDECI Today

1. **Fix workflow**: Snyk's "Open Fix PR" is a conversion feature — it removes all friction between finding and fixing. ALDECI shows you what's wrong but doesn't help you fix it in-repo.

2. **Reachability**: Snyk's reachability analysis reduces false-positive noise by filtering unreachable vulns. ALDECI shows all CVEs regardless of whether the vulnerable function is exercised.

3. **Dependency-grouped remediation**: Grouping vulns by the upgrading action (not by CVE) is cognitively superior. A developer sees "upgrade lodash and fix 3 issues" rather than "here are 3 separate CVEs."

4. **Developer integration**: IDE plugins, PR checks, CLI — Snyk meets developers where they work. ALDECI is purely a security console.

5. **Exploit maturity context**: "Mature exploit available" is higher signal than CVSS 7.5 alone. ALDECI lacks this label.

### Where ALDECI Wins Over Snyk

1. **Breadth**: ALDECI covers CSPM, CTEM, SIEM, IAM, OT/IoT, ZeroTrust, physical security — Snyk is narrowly SCA/SAST/container. ALDECI is a unified platform; Snyk is a point tool.

2. **Supply chain intelligence**: ALDECI tracks vendor compliance, breach history, geo-political risk, EOL components, and supply chain attack detection. Snyk has none of this.

3. **Vendor/supplier registry**: Full compliance score, country-of-origin, tier classification — this is TPRM that Snyk doesn't do.

4. **Self-hosted**: ALDECI is deployable on-prem at $35–60/mo. Snyk SaaS enterprise is $50K+/yr.

5. **SBOM export breadth**: ALDECI has a dedicated SBOM export engine supporting CycloneDX + SPDX with component dedup and vuln tracking. Snyk's SBOM is API-only.

6. **Unified security platform**: ALDECI replaces Snyk + Wiz + Lacework + Rapid7 in a single console vs. Snyk as a stand-alone SCA tool.

---

## 6. Recommended ALDECI UI Improvements (Snyk-Inspired)

### Priority 1 — High Impact, Moderate Effort

**A. Dependency-grouped fix view for SCADashboard**
Add a "Fixes" tab per project showing dependencies grouped with their associated CVEs and recommended upgrade version. Pattern: `{package} {current_version} → {fix_version} — fixes N issues`.

**B. Exploit maturity badges on VulnPrioritizationDashboard**
Add a fifth data point to each vuln row: `Exploit Maturity` (Mature / PoC / No Known Exploit). Source from EPSS + KEV data already wired.

**C. Expandable CVE list in SupplyChainDashboard component table**
The component table shows "14 CVEs" for openssl but no drill-down. Add a row-expandable detail showing the top CVEs by CVSS for that component.

### Priority 2 — High Impact, Higher Effort

**D. Reachability indicator on SCADashboard**
Add a "Reachable?" column to the vuln table. Even a binary yes/no (sourced from static analysis) would differentiate ALDECI from other ASPM tools. Full call path display would match Snyk.

**E. Fix PR generation**
Add a "Create Fix PR" button that generates a GitHub/GitLab PR bumping the vulnerable dependency version. Wire to `/api/v1/sca/fix-pr` endpoint (to be created). This is Snyk's #1 conversion feature.

**F. Upgrade path recommendation in VulnPrioritizationDashboard**
For each CVE row, add a "Fix" column showing the minimum version that resolves the issue (where known from NVD/GHSA data).

### Priority 3 — Lower Effort, Polish

**G. License detail modal in SCADashboard**
License Violations KPI links to a modal/panel listing each violating package with its license type and the conflict reason (e.g., GPL-3 in commercial product).

**H. Three-tab layout for SCADashboard project drill-down**
When clicking a project row, open a side panel or detail page with Issues / Fixes / Dependencies tabs matching the Snyk mental model that developers already know.

---

## 7. Summary

Snyk's UI excels at the **developer remediation workflow**: it makes fixing easy by grouping by dependency, generating fix PRs automatically, and filtering noise via reachability. Its priority score system (7 factors, 0–1000) is more granular than ALDECI's current 0–100 composite.

ALDECI's competitive advantage is **breadth and self-hosted cost**: it covers the entire enterprise security surface (not just SCA) and costs 1000x less than equivalent enterprise tooling. The supply chain pages (SupplyChainDashboard) are already more capable than Snyk in vendor risk, geo-political tracking, and EOL management.

The three highest-ROI improvements to close the Snyk UX gap are:
1. Dependency-grouped fix view (closes Snyk's core differentiator)
2. Exploit maturity badges (low effort, high signal value)
3. Expandable CVE detail in component tables (removes the biggest information gap)

---

## Sources

- [Snyk — Prioritize with Snyk's Open Source Vulnerability Experience](https://snyk.io/blog/prioritize-with-snyks-open-source-vulnerability-experience/)
- [Snyk User Docs — Prioritize issues for fixing](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing)
- [Snyk User Docs — Fix your vulnerabilities](https://docs.snyk.io/scan-with-snyk/snyk-open-source/manage-vulnerabilities/fix-your-vulnerabilities)
- [Snyk — Risk-Based Prioritization solutions page](https://snyk.io/solutions/risk-based-prioritization/)
- [Snyk — Reachability analysis docs](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability-analysis)
- [Snyk — Announcing developer-first prioritization capabilities](https://snyk.io/blog/snyks-developer-first-prioritization-capabilities/)
- [Snyk — SBOM API reference](https://docs.snyk.io/snyk-api/reference/sbom)
- [Snyk Vulnerability Intelligence for SBOM — ServiceNow integration](https://snyk.io/blog/snyk-vulnerability-intelligence-sbom-servicenow/)
- [Snyk Open Source Review 2026](https://appsecsanta.com/snyk-open-source)
- [SCA Tools Comparison 2026 — Rafter](https://rafter.so/blog/sca-tools-comparison)
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages/VulnPrioritizationDashboard.tsx`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages/SCADashboard.tsx`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages/SupplyChainDashboard.tsx`
