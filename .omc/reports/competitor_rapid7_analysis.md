# Competitor Analysis: Rapid7 InsightVM vs ALDECI

**Date:** 2026-04-17
**Analyst:** Executor agent (Beast Mode v6)
**Sources:** Rapid7 official docs, Gartner Peer Insights, PeerSpot, Coralogix guide, SC Media review

---

## 1. Rapid7 InsightVM Platform Overview

InsightVM is Rapid7's flagship vulnerability management product, used by 11,000+ global organizations. It sits within Rapid7's broader "Command Platform" ecosystem alongside InsightCloudSec (CSPM), Surface Command (ASM), and InsightConnect (SOAR).

**Market positioning:** Enterprise-grade VM with a focus on action-oriented remediation — bridging security and IT teams via native ticketing integrations. Priced at $1.93/asset/month (~$23/asset/year) for 512+ assets; enterprise contracts $30K–$150K+/year.

---

## 2. Risk Scoring

### InsightVM — Active Risk (0–1000 scale)

Rapid7 deprecated all legacy risk strategies (RealRisk, Temporal, TemporalPlus, Weighted, PCI ASV 2.0) as of January 21, 2026. The sole model is now **Active Risk**.

**Algorithm inputs:**
- CVSSv3.1 base score (fallback to v3 or v2 if unavailable)
- Exploit availability (Metasploit, ExploitDB — functional exploit confirmed)
- Real-world exploitation evidence (Rapid7 research + CISA KEV catalog)
- AttackerKB assessments (attacker value, ease of exploitation)
- Dark web / Project Lorelei threat feed signals
- Asset business sensitivity / criticality weight
- Organizational impact potential

**Output:** Score 0–1000. Granularity intentional — thousands of CVEs share CVSS 10.0, Active Risk differentiates them. The scale allows security teams to meaningfully rank 50,000+ findings.

**Strengths:** Real-world exploitation correlation, proprietary threat research (Rapid7 Labs), CISA KEV integration, business context weighting.

**Weaknesses (per user reviews):** Score opacity — engineers struggle to explain score deltas to executives. No per-team or per-org score customization exposed in UI. False positive rate affects reliability of scoring signals.

---

## 3. Dashboard and UI

### Architecture
- Widget-based drag-and-drop interface
- Pre-built Rapid7 templates + custom from scratch
- Plain-language dashboard card queries (no SQL required for basic use)
- PDF snapshot export for distribution

### Widget categories cover:
- Asset risk trend graphs
- Vulnerability counts by severity
- Remediation project progress
- Scan coverage / scan completion rates
- SLA compliance status
- Compliance posture per framework (PCI DSS, HIPAA, CIS)

### UI consistency issue (2025–2026)
Rapid7 is mid-migration of InsightVM console UI to align with the Command Platform visual language. Users report inconsistency between the legacy Security Console (Java-based, browser-rendered) and the newer Cloud Platform interface — two separate login surfaces with different visual languages still coexist as of Q1 2026.

### Reported UI friction (Gartner, PeerSpot reviews):
- "Buggy security console" affecting daily workflow reliability
- Reports difficult for non-technical stakeholders without significant customization
- Initial setup requires significant technical expertise
- Limited filtering capabilities on asset/vulnerability grids
- Jira integration frequently unreliable

---

## 4. Remediation Workflow

### Remediation Projects
A **Remediation Project** groups vulnerability solutions scoped to a set of assets within a time window.

**Creation logic:** Console algorithm identifies optimal solution set — minimum fixes yielding maximum risk reduction. Combined solutions reduce redundancy.

**Workflow states per solution:**
| State | Meaning |
|---|---|
| Open | Asset vulnerable; work pending |
| Awaiting Verification | Fix applied, pending rescan confirmation |
| Will Not Fix | Accepted risk; excluded from project risk total |
| Closed | Complete |
| Reopen | Re-escalated (ticketing mode only) |
| Unknown Solution | Insufficient data to classify |

**Project states:** Open → Expired (auto, post-due-date) or Closed (manual).

**Assignment model:**
- Project Owner: security team — defines scope, assigns
- Project Assignee: IT/ops team — executes fixes, updates status
- Role-based visibility: Global Admin, Security Manager, Site Owner, Asset Owner, User

**Progress tracking:** Solutions applied / total assets. 100% = all solutions deployed.

**SLA enforcement:** Due dates set per project. Expired = automatic freeze, no further updates. No built-in SLA tier system (P1/P2/P3/P4).

**Export:** CSV in 5 formats (project listing, solutions, assets, vulnerabilities, remediator combined).

### Remediation Hub (Command Platform layer)
Aggregates risk from InsightVM + InsightCloudSec + Surface Command + third-party connectors (Amazon Inspector, Qualys VMDR, Tenable, Wiz, SentinelOne).

- Top 25 prioritized remediation actions shown
- Total Risk: normalized 0–1000 aggregate
- AI-generated summaries (criticality + exploitability + operational complexity analysis)
- InsightConnect workflow triggers for automated response (max 10,000 assets/workflow)

**500+ native integrations** including automated patching tools (SCCM, Intune, Jamf, etc.) and ticketing (ServiceNow, Jira, etc.).

---

## 5. Executive Reporting

- Auto-generated monthly executive summary (Goals + SLAs + Remediation project status)
- Compliance reports: PCI DSS, GDPR, HIPAA
- Dashboard PDF export
- Customizable widgets for management-facing views
- Separate report templates for technical vs. executive audiences

**Weakness:** Non-intuitive default reports require heavy customization for board-level use. No built-in board deck generator. Executives must be trained to interpret the console or rely on pre-exported PDFs.

---

## 6. Additional Platform Capabilities

| Feature | Detail |
|---|---|
| Agent scanning | Lightweight Insight Agent for continuous endpoint data collection (remote, offline, cloud) |
| Agentless scanning | Network-based authenticated/unauthenticated scan |
| External ASM | Project Sonar — continuous internet scan of exposed assets |
| Policy compliance | CIS benchmarks, PCI DSS, HIPAA, DISA STIG |
| Cloud coverage | AWS, Azure, GCP via InsightCloudSec add-on (separate product/license) |
| Container scanning | Separate add-on; not native to InsightVM base |
| API | RESTful API + SQL-based advanced search (Nexpose Query Language) |
| Threat intel feeds | AttackerKB, Metasploit, ExploitDB, CISA KEV, Project Lorelei (dark web) |
| SOAR | InsightConnect (separate product, 500+ workflow integrations) |

---

## 7. ALDECI vs Rapid7 InsightVM — Competitive Comparison

### Where ALDECI leads

| Dimension | ALDECI | Rapid7 InsightVM |
|---|---|---|
| **Platform scope** | ASPM + CTEM + CSPM unified in one platform (344+ engines) | VM-first; cloud/CSPM via separate InsightCloudSec license |
| **Cost** | $35–60/month self-hosted | $1.93/asset/month; $30K–150K+/year enterprise |
| **Risk scoring** | Composite score: CVSS + EPSS + KEV + exposure (VulnerabilityScoring engine); configurable weights per org | Fixed Active Risk algorithm; no per-org weight customization |
| **SLA enforcement** | Built-in P1/P2/P3/P4 SLA tiers with overdue detection, escalation engine | Single due-date per project; auto-expire; no tier escalation |
| **Remediation states** | 8-state vulnerability lifecycle FSM | 6-state (Open/AwaitingVerification/WillNotFix/Closed/Reopen/Unknown) |
| **Board reporting** | Executive Reporting engine with board decks, KPI tracking | Monthly auto-summary + PDF export; no native board deck generation |
| **MITRE ATT&CK** | Full ATT&CK coverage dashboard (14 tactics), gap analysis | No native ATT&CK mapping in InsightVM base |
| **Threat modeling** | STRIDE engine, 16-cell risk matrix, threat modeling pipeline | Not present |
| **AI architecture** | 4-model Karpathy LLM Consensus + AI-powered SOC engine | AI summaries in Remediation Hub only (no reasoning transparency) |
| **Frontend pages** | 296+ purpose-built dashboards | Single unified console with widget dashboards |
| **Self-hosted** | Full self-hosted on $35–60/month infra | SaaS/on-prem hybrid; on-prem requires Security Console (Java) |
| **Open source stack** | FastAPI + SQLite + DuckDB + React 19 — fully auditable | Proprietary closed-source platform |
| **TrustGraph** | Knowledge graph with GraphRAG, versioned security intelligence | No knowledge graph; flat relational data model |

### Where Rapid7 leads

| Dimension | Rapid7 InsightVM | ALDECI Gap |
|---|---|---|
| **Scanner breadth** | Authenticated + unauthenticated network scanning, agent, agentless, cloud | ALDECI has 32 scanner normalizers (parsers) but relies on external scanner output; no native network scanner |
| **Integration ecosystem** | 500+ native integrations (SCCM, Intune, ServiceNow, Jira, Qualys, Tenable, Wiz...) | ALDECI has 13 PULL + 7 bidirectional connectors; 500-integration gap is significant for enterprise buyers |
| **Project Sonar (ASM)** | Continuous external internet scan of exposed attack surface | ALDECI has AttackSurfaceEngine but no continuous external scanning infrastructure |
| **Market credibility** | 11,000+ customers, Gartner Magic Quadrant presence, 20+ years in market | ALDECI is pre-GA; no customer base yet |
| **Audit trail / compliance** | SOC 2 Type II, FedRAMP (in progress), GDPR compliant as vendor | ALDECI compliance posture as a vendor not yet established |
| **Agent maturity** | Battle-tested Insight Agent across millions of endpoints | No native agent; depends on connector data ingestion |
| **Vulnerability DB** | Proprietary vuln DB + Rapid7 Labs research team | Relies on NVD, EPSS, KEV, external feeds — no proprietary research |
| **Support / SLA** | 24/7 enterprise support, dedicated CSM for enterprise | No support org yet |

---

## 8. Strategic Implications for ALDECI

### Priority gaps to close before enterprise sales:

1. **Native scanner or deep scanner integration** — The absence of a network scanner is the single biggest technical gap vs. InsightVM. ALDECI must either build authenticated scan capability or create a first-class Nessus/Qualys/Tenable import workflow with instant normalization.

2. **Integration count** — 500 vs. ~20 is a deal-breaker at Fortune 500. Priority integrations to add: ServiceNow (ticketing), Jira (already attempted, InsightVM's is "unreliable" — ALDECI can differentiate here), Splunk/Sentinel (SIEM), SCCM/Intune (patching).

3. **External ASM** — Project Sonar equivalent. Continuous internet-facing exposure monitoring. Could be powered by Shodan/Censys API + scheduled scanning.

4. **Vendor compliance posture** — SOC 2 Type II readiness work must begin. Enterprise procurement requires it.

5. **Customer credibility** — Rapid7's 11,000-customer moat. ALDECI needs 3–5 design partners / reference customers before broader go-to-market.

### Differentiators to amplify in sales messaging:

1. **"All-in-one at 1/100th the cost"** — InsightVM + InsightCloudSec + Surface Command + InsightConnect combined = $60K–200K+/year. ALDECI delivers equivalent scope for $60/month.

2. **STRIDE threat modeling + MITRE ATT&CK coverage** — InsightVM has neither natively. Security architects consider these table stakes in modern programs.

3. **Board deck generation** — InsightVM's executive reporting requires heavy customization. ALDECI's Executive Reporting engine generates board-ready decks automatically. Lead with this in CISO demos.

4. **SLA tiering** — P1/P2/P3/P4 with automatic escalation engine. InsightVM's single-due-date model frustrates mature SOC teams. Market as "SLA-native VM."

5. **Transparent AI** — Rapid7's AI summaries are black-box. ALDECI's 4-model Karpathy consensus with confidence scoring is auditable — important for regulated industries.

6. **Self-hosted data sovereignty** — No data leaves customer infrastructure. InsightVM SaaS sends vulnerability data to Rapid7 cloud. GDPR/HIPAA-sensitive orgs (EU healthcare, financial services) will pay for this guarantee.

---

## 9. Summary Scorecard

| Category | Rapid7 InsightVM | ALDECI |
|---|---|---|
| VM depth | ★★★★★ | ★★★★☆ |
| Risk scoring sophistication | ★★★★☆ | ★★★★☆ |
| Remediation workflow | ★★★★☆ | ★★★★★ |
| Executive reporting | ★★★☆☆ | ★★★★★ |
| Platform breadth | ★★★☆☆ | ★★★★★ |
| Integration ecosystem | ★★★★★ | ★★☆☆☆ |
| UI/UX consistency | ★★★☆☆ | ★★★★☆ |
| AI capabilities | ★★★☆☆ | ★★★★☆ |
| Cost efficiency | ★★☆☆☆ | ★★★★★ |
| Market maturity | ★★★★★ | ★☆☆☆☆ |

---

*Sources: Rapid7 official documentation (docs.rapid7.com/insightvm), rapid7.com/products/insightvm, Gartner Peer Insights, PeerSpot, Coralogix guides, SC Media review, UnderDefense pricing guide.*
