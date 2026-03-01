# ALdeci — VISION TO ACCOMPLISH

> **Purpose**: This is THE complete handover document for autonomous Claude agents building ALdeci. It contains every architectural decision, every persona, every screen specification, every build task, and every technical detail needed to execute without asking questions.
>
> **Sources synthesized**: `ALDECI_UNIFIED_VISION.md` (1,321 lines), `USER_STORY_APP_FLOW.md` (1,855 lines), `research_next_features_to_build.md` (2,707 lines) — 5,883 lines distilled into one actionable blueprint.
>
> **Last updated**: 2026-02-27

---

## Table of Contents

- **Part I — Identity & Vision** (What ALdeci IS)
  - 1.1 The 30-Second Pitch
  - 1.2 The 10 Vision Pillars
  - 1.3 What ALdeci Is NOT
  - 1.4 The "Switzerland of AppSec" Positioning
- **Part II — Architecture** (How it works)
  - 2.1 APP_ID-Centric Hierarchy
  - 2.2 The 10-Phase Security Lifecycle
  - 2.3 The 12-Step Brain Pipeline
  - 2.4 FalkorDB Knowledge Graph Schema
  - 2.5 618-Endpoint API Surface
  - 2.6 Self-Hosted AI (Single Agent)
  - 2.7 Quantum-Secure Evidence
  - 2.8 MCP Protocol Gateway
- **Part III — Who We Serve** (25 personas, their pain, their workflows)
  - 3.1 The 5 Persona Groups
  - 3.2 Complete Persona × Feature Map (72 features × 25 personas)
  - 3.3 The HealthPay Transformation Story (before/after metrics)
- **Part IV — The Steve Jobs UI Redesign** (The new navigation paradigm)
  - 4.1 The Problem: 8 Technical Suites vs. What People Need
  - 4.2 The Solution: 5 Workflow Spaces
  - 4.3 Space 1 — MISSION CONTROL
  - 4.4 Space 2 — DISCOVER
  - 4.5 Space 3 — VALIDATE
  - 4.6 Space 4 — REMEDIATE
  - 4.7 Space 5 — COMPLY
  - 4.8 The Persistent AI Copilot (available everywhere)
  - 4.9 Settings & Administration
  - 4.10 Navigation Architecture & Route Map
  - 4.11 Persona-to-Space Mapping
  - 4.12 Onboarding Wizard (First-Run Experience)
- **Part V — 7 Unique Differentiators** (Technical specifications)
  - 5.1 FAIL Engine (Fault & Attack Injection Layer)
  - 5.2 MCP Architecture Expansion
  - 5.3 Single AI Agent (Zero-Token Self-Hosted)
  - 5.4 Quantum-Secure Cryptography
  - 5.5 Zero-Gravity Data (Intelligent Data Lifecycle)
  - 5.6 MPTE (Micro-Pentest Engine)
  - 5.7 "Switzerland" Tool Orchestration
- **Part VI — Build Plan** (Sprint-by-sprint execution)
  - 6.1 Current Codebase Status
  - 6.2 Master Build Order (5 Sprints, 20 Weeks)
  - 6.3 Screen-by-Screen Build Tasks
  - 6.4 Backend Build Tasks
  - 6.5 Critical Stub Pages to Rebuild
- **Part VII — Business Case**
  - 7.1 Pricing Model
  - 7.2 Competitive Comparison Matrix
  - 7.3 The 7-Point Moat
- **Part VIII — Agent Context** (Codebase conventions for Claude agents)
  - 8.1 Repository Structure
  - 8.2 Import Resolution (sitecustomize.py)
  - 8.3 Connector Pattern
  - 8.4 Router Pattern
  - 8.5 Frontend Conventions
  - 8.6 Testing Conventions
  - 8.7 Critical Files Reference

---

# Part I — Identity & Vision

## 1.1 The 30-Second Pitch

> **ALdeci is not a scanner. It is a Decision Intelligence platform for application security.**
>
> Every enterprise runs 5-15 security scanners that flood teams with 11,300+ uncontextualized findings. ALdeci ingests results from ALL of them, deduplicates, correlates via a knowledge graph, verifies exploitability with micro-pentests, makes AI-powered decisions using multi-LLM consensus, auto-fixes code, generates quantum-secure compliance evidence — and learns from every outcome.
>
> We don't replace your scanners. We make them intelligent.

**The transformation**: 11,300 raw findings → 340 actionable exposure cases (97% noise reduction) with verified exploitability, auto-generated fixes, and signed compliance evidence.

## 1.2 The 10 Vision Pillars

Every feature, every screen, every line of code must serve at least one of these pillars. If it doesn't, it doesn't belong.

| # | Pillar | Phase | Promise |
|---|--------|-------|---------|
| V1 | **APP_ID-Centric Architecture** | ① | Every finding, decision, evidence traces to App → Component → Feature |
| V2 | **10-Phase Security Lifecycle** | ①–⑩ | Design → IDE → ALM → Pre-merge → Build → IaC → KG → AI → Remediation → Self-Learning |
| V3 | **Decision Intelligence** | ⑧ | "What to DO about a risk, not just what the risk IS" |
| V4 | **Multi-LLM Consensus / Self-Hosted AI** | ⑧ | 3+ LLMs with 85% threshold OR zero-token self-hosted model (4 expert roles + moderator) |
| V5 | **MPTE Verification** | ⑧ | Prove exploitability, don't just detect vulnerability |
| V6 | **Quantum-Secure Evidence** | ⑨ | FIPS 204 ML-DSA + RSA hybrid, 7-year WORM retention |
| V7 | **MCP-Native AI Platform** | ②⑧ | First AppSec platform AI agents can programmatically use (650 auto-discovered tools) |
| V8 | **Self-Learning (5 Feedback Loops)** | ⑩ | Decision outcomes, MPTE results, FP rates, remediation success, policy violations |
| V9 | **Air-Gapped / On-Prem Deployment** | All | Full offline capability on commodity hardware (<1 GB/year storage) |
| V10 | **CTEM Full Loop with Cryptographic Proof** | All | Discover → Prioritize → Validate → Remediate → Measure (with signed evidence at each step) |

## 1.3 What ALdeci Is NOT

- **Not a scanner** — We orchestrate scanners, we don't compete with them (Snyk, Semgrep, Trivy, etc.)
- **Not a SIEM** — We focus on AppSec decisions, not log aggregation
- **Not a ticketing system** — We integrate with Jira/ServiceNow, we don't replace them
- **Not cloud-only** — Full air-gapped deployment is a first-class citizen
- **Not a vendor lock-in** — "Switzerland of AppSec" — works with every tool, replaces none

## 1.4 The "Switzerland of AppSec" Positioning

ALdeci is the **neutral decision layer** that sits above all security tools:

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR EXISTING TOOLS                       │
│  Snyk · Semgrep · Trivy · Wiz · Prisma · ZAP · Checkmarx  │
│  Burp Suite · SonarQube · Grype · Gitleaks · Checkov       │
└──────────────────────────┬──────────────────────────────────┘
                           │ Raw findings (SARIF, SBOM, CVE, VEX)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      ALdeci = THE BRAIN                      │
│  Normalize → Dedup → Graph → Enrich → Score → Decide →     │
│  Verify (MPTE) → Fix → Evidence → Learn                    │
└──────────────────────────┬──────────────────────────────────┘
                           │ Actionable decisions + signed evidence
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               YOUR EXISTING WORKFLOWS                        │
│  Jira · Slack · GitHub PRs · CI/CD Gates · Board Reports    │
└─────────────────────────────────────────────────────────────┘
```

**Why this matters**: Every competitor (Snyk, Wiz, ArmorCode) tries to REPLACE tools. ALdeci makes the tools enterprises ALREADY own smarter. No rip-and-replace. Day 1 value.

---

# Part II — Architecture

## 2.1 APP_ID-Centric Hierarchy

Everything in ALdeci is organized under a 3-level hierarchy:

```
APP_ID (e.g., "website-12345")
  ├── Component (e.g., "payment-service")
  │     ├── Feature (e.g., "checkout-flow")
  │     │     ├── Finding (CVE-2024-XXXX)
  │     │     ├── Decision (AUTO_FIX / ACCEPT_RISK / BLOCK)
  │     │     ├── Evidence Bundle (signed, timestamped)
  │     │     └── MPTE Result (VULNERABLE_VERIFIED / NOT_VULNERABLE)
  │     ├── Feature ("user-auth")
  │     └── ...
  ├── Component ("api-gateway")
  └── ...
```

**Configuration**: Each APP_ID has an `aldeci.yaml` at its repository root:

```yaml
# aldeci.yaml — per-application security configuration
app_id: website-12345
name: "HealthPay Patient Portal"
criticality: critical
data_classification: phi  # Protected Health Information
compliance:
  - soc2-type2
  - hipaa
  - pci-dss-v4
components:
  - name: payment-service
    language: python
    owner: team-backend
    sla:
      critical: 24h
      high: 72h
      medium: 14d
  - name: patient-portal
    language: typescript
    owner: team-frontend
scanners:
  sast: [semgrep, bandit]
  sca: [snyk, trivy]
  iac: [checkov]
  dast: [zap]
policies:
  block_on_critical: true
  require_mpte_for: [critical, high]
  auto_fix: true
  evidence_retention: 7y
```

**API endpoints for APP_ID management**:
- `POST /api/v1/apps` — Register new APP_ID
- `GET /api/v1/apps` — List all APP_IDs
- `GET /api/v1/apps/{id}` — Get APP_ID details with component tree
- `POST /inputs/design` — Ingest architecture.md for design-stage analysis

## 2.2 The 10-Phase Security Lifecycle

Every security event flows through these phases. Each phase has dedicated API endpoints, UI screens, and data flows.

```
Phase ① ───► Phase ② ───► Phase ③ ───► Phase ④ ───► Phase ⑤
DESIGN       IDE          ALM          PRE-MERGE     BUILD
(aldeci.yaml) (VS Code/MCP) (Jira/Conf)  (PR gate)    (SBOM/SLSA)
   3 EP         15 EP       31 EP        94 EP         4 EP

    ▼
Phase ⑥ ───► Phase ⑦ ───► Phase ⑧ ───► Phase ⑨ ───► Phase ⑩
IaC/RUNTIME  KNOWLEDGE    AI DECISION  REMEDIATION   SELF-LEARNING
(Cloud/K8s)  GRAPH        ENGINE       + EVIDENCE     (5 ML loops)
  18 EP       31 EP        140 EP       128 EP         46 EP
```

**EP = API Endpoints. Total: 618 across 61 router sources in 6 backend suites.**

### Phase Details

| Phase | When | What Happens | Key Artifacts |
|-------|------|-------------|---------------|
| ① Design | App registered | `aldeci.yaml` parsed, architecture.md ingested, APP_ID created in graph | App node in FalkorDB |
| ② IDE | Developer codes | VS Code extension detects tools, MCP server exposes 650 tools to AI agents, pre-commit hooks | Real-time scan results |
| ③ ALM | Sprint planning | Jira bi-sync, Confluence security pages, ticket auto-creation with SLA | Linked Jira tickets |
| ④ Pre-Merge | PR opened | 8+ scanners orchestrated, SARIF/SBOM/CVE normalized, dedup, identity resolution | Normalized findings |
| ⑤ Build | CI runs | SBOM generation (CycloneDX/SPDX), SLSA v1 attestation, artifact tracking | Signed SBOM + SLSA |
| ⑥ IaC/Runtime | Deploy | Terraform/K8s parsed → graph, cloud posture checks, reachability analysis | Attack surface map |
| ⑦ Knowledge Graph | Continuous | FalkorDB graph built from all phases, 15+ node types, natural language queries via MindsDB | Connected risk graph |
| ⑧ AI Decision | On findings | 12-step brain pipeline, multi-LLM consensus, MPTE verification, MITRE mapping | Decisions + verdicts |
| ⑨ Remediation | On decisions | AutoFix PRs, Jira tickets, playbook execution, evidence bundles, compliance mapping | Signed evidence |
| ⑩ Self-Learning | Always | 5 feedback loops train models, improve dedup, tune scoring, adjust policies | Better predictions |

## 2.3 The 12-Step Brain Pipeline

The heart of ALdeci. Every finding flows through these 12 steps:

```
┌─────────────────────────────────────────────────┐
│           12-STEP BRAIN PIPELINE                │
│                                                 │
│  Step 1: CONNECT sources                        │
│  • Ingest SARIF, SBOM, CVE, VEX, CNAPP formats │
│  • 20+ scanner adapters auto-detected           │
│  • Chunked upload for large payloads            │
│                                                 │
│  Step 2: NORMALIZE findings                     │
│  • Map to unified finding schema                │
│  • Severity: CVSS 3.1 base + temporal + env     │
│  • Category: CWE taxonomy alignment             │
│                                                 │
│  Step 3: RESOLVE identities                     │
│  • Cross-scanner asset fingerprinting           │
│  • Same CVE from Snyk + Trivy = 1 finding       │
│  • Fuzzy matching for package name variations    │
│                                                 │
│  Step 4: DEDUPLICATE                            │
│  • Clustering by similarity (>90% = duplicate)  │
│  • Near-duplicate detection (MinHash + LSH)     │
│  • Noise reduction: 11,300 → ~2,000 unique      │
│                                                 │
│  Step 5: BUILD KNOWLEDGE GRAPH                  │
│  • Insert nodes: Finding, Component, CVE, CWE   │
│  • Create edges: AFFECTS, DEPENDS_ON, EXPLOITS  │
│  • Compute graph metrics: centrality, blast radius│
│                                                 │
│  Step 6: ENRICH with threat intel               │
│  • NVD: CVSS scores, references                 │
│  • EPSS: exploitation probability (0.0-1.0)     │
│  • KEV: CISA Known Exploited Vulnerabilities    │
│  • ExploitDB: public exploit availability       │
│  • GitHub Advisories, OSV, vendor feeds         │
│                                                 │
│  Step 7: SCORE risk (composite)                 │
│  • CVSS × EPSS × reachability × blast_radius    │
│  • Business context: data classification, SLA   │
│  • Temporal factors: trending, exploit maturity  │
│                                                 │
│  Step 8: EVALUATE POLICY                        │
│  • Check aldeci.yaml rules                      │
│  • block_on_critical? require_mpte? auto_fix?   │
│  • SLA thresholds per severity                  │
│                                                 │
│  Step 9: MULTI-LLM CONSENSUS                   │
│  • GPT-4 (0.25) + Claude (0.40) + Gemini (0.35)│
│  • OR: Self-hosted Single Agent (4 roles + mod) │
│  • ≥85% agreement = auto-decide                 │
│  • Reasoning chains with MITRE ATT&CK mapping   │
│                                                 │
│  Step 10: MICRO-PENTEST (MPTE)                  │
│  • 19-phase deterministic scanner               │
│  • AI orchestrator for advanced scenarios        │
│  • 4-state verdict: VULNERABLE_VERIFIED /        │
│    NOT_VULNERABLE_VERIFIED / NOT_APPLICABLE /    │
│    UNVERIFIED                                    │
│  • 3 confidence metrics per result               │
│  • Reachability-aware targeting                  │
│                                                 │
│  Step 11: RUN PLAYBOOKS & AUTOFIX               │
│  • YAML playbook execution engine               │
│  • AST-based AutoFix (tree-sitter transforms)   │
│  • Jira ticket creation (APP_ID-scoped)          │
│  • Slack/Teams/PagerDuty notifications           │
│  • GitHub/GitLab auto-fix PR generation          │
│                                                 │
│  Step 12: GENERATE EVIDENCE                     │
│  • Hybrid RSA-SHA256 + ML-DSA (quantum-secure)  │
│  • Per-APP_ID evidence bundles                   │
│  • SLSA v1 attestation                           │
│  • SOC2/PCI/ISO/NIST compliance control mapping  │
│  • 7-year WORM retention                         │
└─────────────────────────────────────────────────┘
```

**Backend implementation**: `suite-core/core/brain_pipeline.py` (12-step function chain)
**API**: `POST /pipeline/run`, `GET /api/v1/brain/pipeline/*` (6 endpoints)
**UI**: Brain Pipeline Dashboard page (`BrainPipelineDashboard.tsx`, 448 LOC, feature-complete)

## 2.4 FalkorDB Knowledge Graph Schema

FalkorDB replaces NetworkX for production graph operations. The schema models the complete security domain:

### Node Types (15+)

| Node | Key Properties | Created By |
|------|---------------|-----------|
| `App` | app_id, name, criticality, data_classification | Phase ① |
| `Component` | name, language, owner, repo_url | Phase ① |
| `Feature` | name, description, entry_points | Phase ① |
| `Finding` | id, severity, cve_id, cwe_id, scanner, status | Phase ④ |
| `CVE` | cve_id, cvss_score, epss_score, kev_status | Phase ⑥ |
| `CWE` | cwe_id, name, category | Phase ④ |
| `ExposureCase` | id, findings_count, composite_score | Phase ④ |
| `Decision` | action, reasoning, confidence, llm_votes | Phase ⑧ |
| `MicroPentest` | verdict, confidence, phases_completed | Phase ⑧ |
| `Evidence` | bundle_id, framework, control, signature | Phase ⑨ |
| `Playbook` | name, steps, trigger_conditions | Phase ⑨ |
| `Package` | name, version, ecosystem, license | Phase ⑤ |
| `CloudResource` | arn/id, type, region, tags | Phase ⑥ |
| `AttackPath` | id, source, target, hops, blast_radius | Phase ⑦ |
| `User` | id, email, role, team | Platform |
| `Team` | id, name, members, owned_components | Platform |

### Relationship Types (15+)

| Relationship | From → To | Meaning |
|-------------|-----------|---------|
| `HAS_COMPONENT` | App → Component | App contains component |
| `HAS_FEATURE` | Component → Feature | Component exposes feature |
| `AFFECTS` | Finding → Component | Vulnerability found in component |
| `MAPS_TO` | Finding → CVE | Finding corresponds to CVE |
| `CLASSIFIED_AS` | Finding → CWE | Finding's weakness category |
| `DEPENDS_ON` | Package → Package | Transitive dependency chain |
| `USES` | Component → Package | Component depends on package |
| `GROUPED_INTO` | Finding → ExposureCase | Deduplicated finding group |
| `DECIDED_BY` | ExposureCase → Decision | AI/human decision on case |
| `VERIFIED_BY` | Finding → MicroPentest | MPTE verification result |
| `EVIDENCED_BY` | Decision → Evidence | Signed proof of action |
| `DEPLOYED_ON` | Component → CloudResource | Runtime infrastructure |
| `CAN_REACH` | CloudResource → CloudResource | Network reachability |
| `ATTACK_PATH` | Finding → CloudResource | Exploitable chain |
| `OWNED_BY` | Component → Team | Ownership for routing |

### Natural Language Queries (MindsDB → FalkorDB)

```sql
-- "Show me all critical findings in the payment service that are exploitable"
MATCH (a:App)-[:HAS_COMPONENT]->(c:Component {name: 'payment-service'})
      -[:AFFECTS]-(f:Finding {severity: 'critical'})
      -[:VERIFIED_BY]->(m:MicroPentest {verdict: 'VULNERABLE_VERIFIED'})
RETURN f.cve_id, f.description, m.confidence

-- "What's the blast radius if this CVE is exploited?"
MATCH path = (f:Finding {cve_id: 'CVE-2024-XXXX'})-[:AFFECTS]->(c:Component)
      -[:DEPLOYED_ON]->(cr:CloudResource)-[:CAN_REACH*1..5]->(target)
RETURN nodes(path), relationships(path)
```

**Migration from NetworkX**: Replace `suite-core/core/knowledge_graph.py` (in-memory NetworkX) with FalkorDB client. FalkorDB runs as a Docker sidecar (`docker-compose.yml` already has placeholder).

## 2.5 618-Endpoint API Surface

All 618 endpoints mapped to lifecycle phases. Zero waste.

| Phase | Endpoints | % | Key Routers |
|-------|-----------|---|------------|
| ① Design | 3 | 0.5% | APP_ID CRUD (new) |
| ② IDE | 15 | 2.4% | ide_router, mcp_router |
| ③ ALM | 31 | 5.0% | integrations_router, webhooks_router |
| ④ Pre-Merge | 94 | 15.2% | sast, dast, secrets, container, cspm, api_fuzzer, oss_tools, iac, inventory, identity, dedup, exposure_case |
| ⑤ Build | 4 | 0.6% | code_to_cloud, provenance |
| ⑥ IaC/Runtime | 18 | 2.9% | iac, graph, reachability |
| ⑦ Knowledge Graph | 31 | 5.0% | brain_router (22), nerve_center (9) |
| ⑧ AI Decision Engine | 140 | 22.7% | pipeline, feeds (30), risk, LLM (6+4), decisions, micro_pentest (18), mpte (19+8), attack_sim (13), malware (4) |
| ⑨ Remediation + Evidence | 128 | 20.7% | remediation (15), autofix (12), workflows (13), bulk (13), policies (11), collaboration (21), evidence (6), reports (14), audit (14), analytics (22) |
| ⑩ Self-Learning | 46 | 7.4% | predictions (8), algorithmic (11), mindsdb (14), vuln_discovery (11) |
| Platform | 62 | 10.0% | copilot (14), agents (32), auth (4), users (6), teams (8), marketplace (12), health (4), logs (5) |
| **TOTAL** | **618** | **100%** | **61 router sources across 6 suites** |

### API Distribution Visualization

```
Phase ⑧ AI Engine    ████████████████████████  140 (22.7%)
Phase ⑨ Remediation  ████████████████████      128 (20.7%)
Phase ④ Pre-Merge    █████████████████          94 (15.2%)
Platform             ██████████                 62 (10.0%)
Phase ⑩ Self-Learn   ████████                   46 (7.4%)
Phase ③ ALM          ██████                     31 (5.0%)
Phase ⑦ Graph        ██████                     31 (5.0%)
Phase ⑥ IaC/Runtime  ████                       18 (2.9%)
Phase ② IDE          ███                        15 (2.4%)
Phase ⑤ Build        ██                          4 (0.6%)
Phase ① Design       █                           3 (0.5%)
```

## 2.6 Self-Hosted AI (Single Agent Architecture)

For air-gapped deployments, ALdeci replaces multi-vendor LLM calls with a single self-hosted model assuming 4 expert roles:

```
┌──────────────────────────────────────────┐
│  FIXOPS_LLM_MODE=single-agent           │
│                                          │
│  One model (Llama 3.1 70B via vLLM)     │
│  assumes 4 expert roles sequentially:    │
│                                          │
│  🔍 Security Analyst — threat assessment │
│  ⚔️  Pentest Expert — exploitation paths  │
│  📋 Compliance Auditor — control mapping │
│  📊 Risk Quantifier — business impact    │
│  🎯 Moderator — synthesizes all 4 views  │
│                                          │
│  Cost: $0 API tokens / ~$500/mo GPU      │
│  vs. $6,000/mo multi-vendor API          │
│  Privacy: Data never leaves infra        │
└──────────────────────────────────────────┘
```

**Implementation**: ~2,000 LOC in `suite-core/core/single_agent.py`
**Config**: `FIXOPS_LLM_MODE=single-agent` env var
**Backward compatible**: Falls back to multi-LLM consensus when `FIXOPS_LLM_MODE=multi`

## 2.7 Quantum-Secure Evidence

Evidence bundles use hybrid cryptographic signatures that are secure against both classical and quantum computers:

```json
{
  "version": 2,
  "app_id": "website-12345",
  "component": "payment-service",
  "framework": "pci-dss-v4",
  "control": "6.2.4",
  "evidence_type": "sast_scan",
  "payload": { "...scan results..." },
  "signature": {
    "format_version": 2,
    "algorithm": "hybrid-rsa-ml-dsa",
    "classical_sig": "base64(RSA-SHA256 with 4096-bit key)",
    "pq_sig": "base64(ML-DSA-65 / Dilithium3 — FIPS 204)",
    "key_fingerprint": "sha256:abc123..."
  },
  "slsa_attestation": { "...SLSA v1..." },
  "timestamp": "2026-01-15T08:30:00Z",
  "retention_until": "2033-01-15T08:30:00Z"
}
```

**Standards**: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
**Implementation**: ~1,800 LOC in `suite-core/core/crypto.py` (extend existing RSA signing)
**Backward compatible**: Verify either signature alone; both must be present for v2 bundles

## 2.8 MCP Protocol Gateway

ALdeci is the first AppSec platform that AI agents (Copilot, Cursor, Claude Code) can programmatically use via the Model Context Protocol:

```
┌──────────────────────────────────────────────┐
│            MCP PROTOCOL GATEWAY              │
│                                              │
│  Auto-discovers 650 tools from FastAPI routes│
│  Transports: stdio, SSE, WebSocket          │
│                                              │
│  Tool categories:                            │
│  • scan/* — trigger scans                    │
│  • findings/* — query findings               │
│  • graph/* — query knowledge graph           │
│  • decide/* — get AI decisions               │
│  • fix/* — generate/apply fixes              │
│  • evidence/* — generate compliance proof    │
│                                              │
│  Resource streams (live data):               │
│  • findings://app/{id}/critical              │
│  • graph://components/{name}/dependencies    │
│  • metrics://sla/breaches                    │
│                                              │
│  Prompt registry:                            │
│  • "Triage this CVE for {app_id}"           │
│  • "Generate SOC2 evidence for {control}"   │
│  • "Is {cve_id} exploitable via MPTE?"      │
└──────────────────────────────────────────────┘
```

**Implementation**: ~3,500 LOC, extends existing `mcp_router.py`
**Auto-discovery**: Walks FastAPI `app.routes` at startup → generates MCP tool manifest

---

# Part III — Who We Serve

## 3.1 The 5 Persona Groups (25 Characters)

Each persona has specific pain points ALdeci solves. These personas drive every UI design decision.

### Group 1: Leadership (4 personas)

| Persona | Role | Core Pain | ALdeci Solution |
|---------|------|-----------|----------------|
| **Sarah Chen** | CISO | "Board asks 'are we secure?' — I can't answer with confidence" | Risk register, executive dashboard, compliance posture, trend analytics |
| **David Kim** | VP Engineering | "Security slows my velocity. Every sprint loses 2 days to 'security review'" | AutoFix PRs, pre-merge gates with zero dev friction, SLA tracking |
| **Priya Patel** | CTO/CIO | "I need architecture-level risk decisions, not CVE lists" | Knowledge graph, attack path visualization, blast radius analysis |
| **Tom Bradley** | CFO | "How much does fixing vulnerabilities actually cost us?" | ROI dashboard ($110K saved), cost-per-fix analytics, tool consolidation metrics |

### Group 2: Security Operations (9 personas)

| Persona | Role | Core Pain | ALdeci Solution |
|---------|------|-----------|----------------|
| **Alex Rivera** | Security Engineer | "I spend 80% of my time on data janitoring — dedup, triage, context-gathering" | Automated dedup (97% noise reduction), AI triage, exposure case grouping |
| **Marcus Thompson** | AppSec Engineer | "I review 8 PRs/week because context-switching between tools kills productivity" | Unified PR gate, all scanners in one view, one-click approve/block |
| **Raj Mehta** | DevSecOps Lead | "Overnight CVEs wake me up. By morning, I'm already behind" | AI Copilot overnight analysis, prioritized morning briefing, auto-triage |
| **Janet Liu** | SOC Analyst | "MTTD is 4 hours, MTTR is 12 hours — too slow" | Real-time nerve center, automated response playbooks, shift handoff |
| **Maria Santos** | Compliance Lead | "Audit prep takes 3 weeks. We're always scrambling" | Auto-generated evidence bundles, compliance dashboard, always audit-ready |
| **Derek Washington** | VM Manager | "90% of 'critical' findings are noise — but I still have to prove I checked each one" | AI-verified exploitability, automated FP marking, SLA dashboard |
| **Jason Wu** | Red Team Lead | "We do 1 pentest per year. We need 365" | MPTE continuous micro-pentesting, FAIL Engine for resilience testing |
| **Emily Foster** | Threat Analyst | "Correlating threat intel across 50+ feeds manually is impossible" | Unified threat feed with AI correlation, TTP mapping, trend detection |
| **Brian Mitchell** | Cloud Security | "IaC drift detection → finding → fix cycle is 2 weeks" | Real-time cloud posture, IaC scanning, auto-remediation playbooks |

### Group 3: Engineering (6 personas)

| Persona | Role | Core Pain | ALdeci Solution |
|---------|------|-----------|----------------|
| **Mike Chen** | Senior Developer | "Security PR reviews block me for days. Just tell me what to fix" | AutoFix PRs with test verification, post-deploy validation, IDE integration |
| **Lisa Park** | Cloud Architect | "I can't see the security impact of my infrastructure decisions" | Knowledge graph with cloud topology, attack path analysis, blast radius |
| **Rachel Kim** | Junior Dev | "I'm terrified of introducing vulnerabilities. Security tools scream at me" | Guided explanations, educational fix suggestions, progressive severity display |
| **Kevin O'Brien** | Dev Lead | "Sprint planning never accounts for security debt" | Security backlog integration, effort estimations, sprint-aware prioritization |
| **Amy Rodriguez** | QA / Release Eng | "I need to know if this build is safe to deploy — yes or no" | Binary deploy gate, SLSA attestation, security sign-off dashboard |
| **Chris Taylor** | Platform Engineer | "Managing 15 security tool configurations across 200 repos" | Centralized `aldeci.yaml`, tool orchestration, marketplace for connectors |

### Group 4: Data & AI Team (4 personas)

| Persona | Role | Core Pain | ALdeci Solution |
|---------|------|-----------|----------------|
| **Dr. Wei** | ML Engineer | "Training security models requires labeled data we don't have" | FAIL Engine generates labeled training data, 5 feedback loops, priority buffer |
| **Aisha Johnson** | Data Scientist | "Model drift in threat detection — my models go stale in 2 weeks" | Online learning (River ML), concept drift detection (ADWIN/DDM), continuous retraining |
| **Nina Kowalski** | Security Architect | "I need a holistic view of security posture, not per-tool dashboards" | Knowledge Graph Explorer, unified posture score, architecture risk view |
| **Sam Parker** | AI Agent Developer | "I want my AI agent to query security state programmatically" | MCP protocol gateway, 650 auto-discovered tools, resource streams |

### Group 5: External (2 personas)

| Persona | Role | Core Pain | ALdeci Solution |
|---------|------|-----------|----------------|
| **Laura Chen** | External Auditor | "Collecting evidence takes 3 days per engagement" | Pre-generated evidence bundles, quantum-signed, WORM-retained, instant export |
| **Carlos Mendez** | Security Consultant | "Every client has different tools — I need a unified view" | Switzerland positioning — connect any scanner, unified dashboard |

## 3.2 Complete Persona × Feature Map

72 features mapped to 25 personas. This is the definitive reference for which screens each persona needs.

### Key Feature-to-Persona Mappings (Condensed)

| Feature | Primary Personas | Benefit |
|---------|-----------------|---------|
| **Unified Dashboard** | Sarah, Raj, Janet, Derek | Single pane for security posture |
| **AI Triage / Copilot** | Raj, Alex, Marcus | "Good morning, here's what happened overnight" |
| **AutoFix PRs** | Mike, Marcus, Rachel | Fix code without leaving IDE |
| **Knowledge Graph** | Priya, Lisa, Nina | Visualize connections between risks |
| **Attack Path Visualization** | Jason, Brian, Lisa | See how attacker gets from internet to PHI |
| **MPTE Micro-Pentest** | Jason, Marcus, Alex | Prove it's exploitable, not just flagged |
| **Evidence Bundles** | Maria, Laura, Sarah | Quantum-signed compliance proof |
| **Compliance Dashboard** | Maria, Laura, Sarah | SOC2/PCI/ISO status at a glance |
| **Executive Report** | Sarah, Priya, Tom | Board-ready security metrics |
| **FAIL Engine** | Jason, Dr. Wei, Janet | Inject faults, grade team response |
| **SLA Dashboard** | Derek, David, Kevin | Track fix timelines, identify bottlenecks |
| **ROI Dashboard** | Tom, David, Sarah | $110K saved, 97% noise reduction |
| **Playbooks** | Janet, Alex, Raj | Automate response in 90 seconds |
| **Remediation Center** | Alex, Marcus, Mike | One place for all fixes |
| **Bulk Operations** | Alex, Derek, Janet | Mass triage 1,000 findings in minutes |
| **Threat Feeds** | Emily, Raj, Janet | 50+ feeds, AI-correlated |
| **Onboarding Wizard** | Chris, Carlos, Rachel | Connect tools in <5 minutes |
| **MCP Gateway** | Sam, AI agents | Programmatic security queries |
| **Nerve Center** | Janet, Raj, Alex | Real-time security pulse |

## 3.3 The HealthPay Transformation Story

HealthPay is the running example throughout all user stories. A healthcare fintech with 200 developers, PCI + HIPAA compliance requirements, and 47 microservices.

### Before ALdeci → After ALdeci (22 metrics)

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Raw findings per week | 11,300 | 340 actionable cases | 97% reduction |
| Mean Time to Detect (MTTD) | 4 hours | 12 minutes | 95% faster |
| Mean Time to Remediate (MTTR) | 14 days | 2.3 days | 84% faster |
| Developer PRs reviewed/week | 8 | 20 | 2.5× increase |
| Security review cycle | 3 days | 4 hours | 94% faster |
| Pentests per year | 1 | 365 (continuous) | 365× more |
| Audit prep time | 3 weeks | 2 hours | 99% reduction |
| False positive rate | 68% | 3% | 22× better |
| Compliance evidence generation | Manual, 2 days | Auto, 5 minutes | 99.6% faster |
| External audit duration | 3 days | 4 hours | 94% faster |
| Tool-switching per analyst/day | 12 tools | 1 platform | 92% reduction |
| Data janitoring time | 80% of analyst day | <5% | 94% reduction |
| Sprint velocity lost to security | 2 days/sprint | 0.5 days/sprint | 75% faster |
| Security tool annual cost | $180K (15 tools) | $96K (existing + ALdeci) | 47% savings |
| Cost per vulnerability fixed | $4,200 | $890 | 79% reduction |
| Annual cost savings | — | $110K | — |
| Playbook execution time | 25 minutes manual | 90 seconds auto | 94% faster |
| SLA compliance rate | 45% | 94% | 109% improvement |
| Night/weekend coverage | 0% | 100% (AI Copilot) | ∞ |
| Junior dev productivity | 2 PRs/day | 5 PRs/day | 2.5× increase |
| Board report generation | 2 days manual | 5 minutes auto | 99.6% faster |
| Storage per year (on-prem) | ~20 GB | ~1 GB | 95% reduction |

---

# Part IV — The Steve Jobs UI Redesign

> **⚠️ CRITICAL BUILD DIRECTIVE — aldeci-ui-new**
>
> All 5 Workflow Space screens MUST be built as a **brand-new frontend project** at `suite-ui/aldeci-ui-new/`.
> **DO NOT modify `suite-ui/aldeci/`** — it remains frozen as legacy reference.
>
> **Tech stack for aldeci-ui-new:**
> - React 19 + Vite 6 + TypeScript 5.x strict mode
> - **Apple HIG-inspired design** — clean typography, generous whitespace, depth via subtle shadows not borders
> - shadcn/ui (Radix primitives) as the component foundation — same philosophy as Apple's SwiftUI: composable, accessible, beautiful by default
> - Tailwind CSS 4 with custom design tokens mirroring Apple aesthetics (SF Pro font stack, 8pt grid, consistent radius/spacing)
> - Framer Motion for fluid, physics-based transitions (Apple-quality animation curves)
> - Recharts for data visualization with Apple-style minimal chrome
> - Dark mode first (Apple Dark Aqua palette), with light mode support
> - Persistent AI Copilot sidebar (macOS Spotlight-inspired)
> - Onboarding wizard (Apple Setup Assistant-inspired)
> - Persona-based home routing ("What's your role?" → auto-navigate to home space)
>
> **Design principles (Steve Jobs / Jony Ive):**
> 1. Organize by WHAT PEOPLE DO, not what the product can do
> 2. Every pixel earns its place — remove until it breaks
> 3. Animation is information, not decoration
> 4. Typography is the UI — let Geist/Inter do the heavy lifting
> 5. One primary action per screen, everything else recedes

## 4.1 The Problem: 8 Technical Suites

The current UI is organized by **technical capability** — what the product CAN do:

```
Current sidebar (8 groups, ~40 nav items):
├── Dashboard + Core (6 items)
├── Code Security (4 items)
├── Cloud & Data (5 items)
├── Attack & Validation (5 items)
├── Remediation (6 items)
├── AI & Intelligence (5 items)
├── Evidence & Compliance (6 items)
└── Settings & Admin (2 items)
```

**The problem**: This is like organizing an iPhone as "Radio Module, Camera Module, Computing Module, Display Module." Engineers love it. Users hate it. When Maria the Compliance Lead needs to prepare for an audit, she has to visit 4 different sidebar groups (Evidence, Compliance, Reports, Analytics). When Raj the DevSecOps Lead arrives in the morning, he bounces between Dashboard, Nerve Center, AI Copilot, and Remediation — 4 different nav groups.

**Steve Jobs' insight**: *"You've got to start with the customer experience and work back toward the technology — not the other way around."*

## 4.2 The Solution: 5 Workflow Spaces

Reorganize everything around **WHAT PEOPLE NEED TO DO**, not what the product can do:

```
New Navigation (5 Workflow Spaces):
┌─────────────────────────────────────────────┐
│  🎯 MISSION CONTROL   — What needs attention now?     │
│  🔍 DISCOVER           — Find every risk               │
│  ⚡ VALIDATE            — Prove what's exploitable      │
│  🔧 REMEDIATE           — Fix it, track it, close it   │
│  🛡️ COMPLY              — Prove we're secure           │
│  ─────────────────────────────────────────── │
│  🤖 AI Copilot          — Persistent sidebar (any space)│
│  ⚙️ Settings             — Gear icon (bottom)           │
└─────────────────────────────────────────────┘
```

### The iPhone Analogy

| iPhone (User Task) | NOT This (Tech Module) | ALdeci (User Task) | NOT This (Tech Suite) |
|-------|-------------|---------|-------------|
| Phone | Radio Module | Mission Control | Dashboard + Core |
| Messages | SMS Transceiver | Discover | Code Security + Cloud & Data |
| Camera | Camera Module | Validate | Attack & Validation |
| Safari | Network Stack | Remediate | Remediation |
| Wallet | NFC Chip | Comply | Evidence & Compliance |

## 4.3 Space 1 — MISSION CONTROL

> **User question**: "What needs my attention right now?"
> **Primary personas**: Sarah (CISO), Raj (DevSecOps), Janet (SOC), Derek (VM Manager), Tom (CFO)

### Pages in this space

| Page | Source | Status | LOC | Description |
|------|--------|--------|-----|-------------|
| **Command Dashboard** | Dashboard.tsx (merge with NerveCenter) | Rebuild | 472+306 | Unified real-time security posture: active threats, SLA breaches, priority queue, team performance |
| **Executive View** | NEW | Build | — | Board-ready metrics: risk trend, compliance status, ROI, cost savings, posture score over time |
| **SLA Dashboard** | NEW | Build | — | SLA compliance by team/severity/app, breaches, aging analysis, escalation queue |
| **Live Feed** | LiveFeedDashboard.tsx | Enhance | 206 | Real-time event stream: new findings, decisions, MPTE results, deployments, policy changes |
| **Risk Overview** | NEW | Build | — | Organization-wide risk heat map, top 10 riskiest apps, risk trend by APP_ID, business impact |

### Command Dashboard Design Specification

The Command Dashboard merges the current `Dashboard.tsx` and `NerveCenter.tsx` into one screen that answers "What happened while I was away?":

**Layout** (3-column responsive grid):
```
┌─────────────────────────────────────────────────────────────┐
│ COMMAND DASHBOARD                     [Last 24h ▼] [⟳ Live]│
├───────────────┬───────────────────────┬─────────────────────┤
│ POSTURE SCORE │ PRIORITY QUEUE        │ KEY METRICS         │
│               │                       │                     │
│   ███  78/100 │ 5 Critical (3 new)   │ MTTR: 2.3 days     │
│   ▲ +3 today  │ 12 High (2 MPTE-     │ SLA: 94% on-time   │
│               │      verified)        │ Noise: 97% reduced │
│ [View Graph]  │ 23 Medium            │ FP Rate: 3%        │
│               │ [Triage Queue →]     │ Fixes Today: 12    │
├───────────────┼───────────────────────┤                     │
│ TOP THREATS   │ AI OVERNIGHT SUMMARY  │ COMPLIANCE          │
│               │                       │                     │
│ 1. CVE-2024-  │ "3 new CVEs affect   │ SOC2: ✅ 47/47     │
│    XXXX (9.8) │  payment-service.     │ PCI: ⚠️ 44/46      │
│ 2. Log4Shell  │  MPTE verified 2     │ HIPAA: ✅ 23/23    │
│    variant    │  exploitable. AutoFix │ ISO27001: 🔄 90%   │
│ 3. Leaked     │  PRs ready for       │                     │
│    API key    │  review."            │ [Full Report →]    │
├───────────────┴───────────────────────┴─────────────────────┤
│ ACTIVITY TIMELINE                          [Filter ▼]       │
│ ──●── 08:00 MPTE verified CVE-2024-1234 in payment-svc    │
│ ──●── 07:45 AutoFix PR #423 merged (checkout-flow)         │
│ ──●── 03:00 AI triage: 45 new findings → 3 exposure cases  │
│ ──●── 02:15 FAIL Engine: Team scored 8.2/10 on drill       │
└─────────────────────────────────────────────────────────────┘
```

**Data sources**: `/api/v1/nerve-center/*`, `/api/v1/analytics/dashboard`, `/api/v1/triage`, `/api/v1/predictions/*`

### Executive View Design Specification

**For**: Sarah (CISO board presentations), Tom (CFO ROI tracking), Priya (CTO architecture risk)

```
┌─────────────────────────────────────────────────────────────┐
│ EXECUTIVE VIEW                    [This Quarter ▼] [Export] │
├─────────────────────────────────────────────────────────────┤
│ SECURITY POSTURE TREND (12-month line chart)                │
│ ▁▂▃▃▄▅▅▆▆▇▇█                                               │
│ Score: 62 → 78 (+26%)    Industry avg: 71                   │
├──────────────────────┬──────────────────────────────────────┤
│ ROI SUMMARY          │ RISK BY BUSINESS UNIT                │
│                      │                                      │
│ Annual savings:      │ ┌─── Payments (Critical)  ██░ 2     │
│  $110,140           │ ├─── Portal (High)        █░░ 1     │
│                      │ ├─── API Gateway (Med)    ░░░ 0     │
│ Cost per fix:        │ └─── Mobile App (Low)     ░░░ 0     │
│  $890 (was $4,200)  │                                      │
│                      │                                      │
│ Tools consolidated:  │ COMPLIANCE STATUS                    │
│  15 → 1 platform    │ SOC2: ✅ | PCI: ⚠️ | HIPAA: ✅      │
├──────────────────────┴──────────────────────────────────────┤
│ KEY DECISIONS THIS QUARTER                                   │
│ • 340 findings resolved (97% auto-triaged)                  │
│ • 12 AutoFix PRs merged (0 reverted)                        │
│ • 3 risk acceptances (all signed, approved by CISO)         │
│ • MPTE ran 1,200 micro-pentests (365 verified exploitable)  │
└─────────────────────────────────────────────────────────────┘
```

### SLA Dashboard Design Specification

**For**: Derek (VM Manager), David (VP Engineering), Kevin (Dev Lead)

```
┌─────────────────────────────────────────────────────────────┐
│ SLA DASHBOARD                       [All Teams ▼] [30 Days]│
├──────────────────────┬──────────────────────────────────────┤
│ SLA COMPLIANCE       │ AGING ANALYSIS                       │
│                      │                                      │
│ Overall: 94%        │ Overdue Critical: 2 (was 15)         │
│ Critical: 100%      │ Overdue High: 5 (was 42)             │
│ High: 92%           │ At Risk (>80% SLA): 8                │
│ Medium: 89%         │                                      │
├──────────────────────┤ [Heatmap: Team × Severity × Age]    │
│ BY TEAM              │                                      │
│ Backend: 97% ✅     │ backend   ░░░ ░░░ ░░                │
│ Frontend: 88% ⚠️    │ frontend  ░░░ ██░ ░░                │
│ Platform: 95% ✅    │ platform  ░░░ ░░░ ░░                │
│ Mobile: 91% ✅      │ mobile    ░░░ ░█░ ░░                │
├──────────────────────┴──────────────────────────────────────┤
│ ESCALATION QUEUE (items approaching SLA breach)             │
│ ⚠️ CVE-2024-5678 — payment-service — 6h remaining         │
│ ⚠️ CVE-2024-9012 — api-gateway — 18h remaining            │
└─────────────────────────────────────────────────────────────┘
```

## 4.4 Space 2 — DISCOVER

> **User question**: "What risks exist across my applications?"
> **Primary personas**: Alex (Security Eng), Marcus (AppSec), Brian (Cloud Sec), Lisa (Cloud Architect), Emily (Threat Analyst)

### Pages in this space

| Page | Source | Status | LOC | Description |
|------|--------|--------|-----|-------------|
| **Finding Explorer** | ExposureCaseCenter.tsx | Enhance | 565 | Unified finding browser: filter by app/severity/scanner/status, grouped into exposure cases |
| **Code Scanning** | CodeScanning.tsx | Enhance | 260 | SAST results, code snippets, fix suggestions, scanner comparison |
| **Secrets Detection** | SecretsDetection.tsx | Done | 400 | Leaked secrets, rotation status, affected repos |
| **IaC Scanning** | IaCScanning.tsx | Rebuild | 67 | Terraform/CloudFormation/K8s misconfigurations, drift detection |
| **Cloud Posture** | CloudPosture.tsx | Done | 416 | CSPM results, multi-cloud view (AWS/Azure/GCP), compliance status |
| **Container Security** | ContainerSecurity.tsx | Rebuild | 134 | Image scanning, runtime protection, registry monitoring |
| **SBOM & Inventory** | SBOMGeneration.tsx + Inventory.tsx | Rebuild both | 136+53 | Complete software bill of materials, license compliance, dependency tree, asset inventory |
| **Knowledge Graph** | KnowledgeGraphExplorer.tsx | Done | 589 | Interactive graph visualization, natural language queries, attack path exploration |
| **Attack Paths** | AttackPaths.tsx | Enhance | 395 | Internet → data path visualization, blast radius, reachability analysis |
| **Threat Feeds** | ThreatFeeds.tsx | Rebuild | 80 | 50+ threat intel feeds, AI correlation, trending CVEs, MITRE ATT&CK mapping |
| **Data Fabric** | DataFabric.tsx | Done | 453 | Cross-source finding correlation, unified data model |
| **Finding Correlation** | CorrelationEngine.tsx | Rebuild | 78 | Cross-scanner correlation, same-vulnerability grouping, noise analysis |

## 4.5 Space 3 — VALIDATE

> **User question**: "Is this vulnerability actually exploitable? How resilient is my team?"
> **Primary personas**: Jason (Red Team), Marcus (AppSec), Dr. Wei (ML Eng), Janet (SOC Analyst)

### Pages in this space

| Page | Source | Status | LOC | Description |
|------|--------|--------|-----|-------------|
| **MPTE Console** | MicroPentest.tsx + AttackLab.tsx | Merge & Enhance | 395+458 | Micro-pentest engine: launch scans, 19-phase progress, 4-state verdicts, confidence metrics |
| **Attack Simulation** | AttackSimulation.tsx | Rebuild | 123 | MITRE ATT&CK scenario builder, kill chain analysis, tabletop exercises |
| **FAIL Engine** | NEW | Build | — | Fault injection console: inject synthetic CVEs, grade team response, neglect zone detection |
| **Playbooks** | Playbooks.tsx | Done | 523 | YAML playbook library, execution history, one-click run |
| **Playbook Editor** | PlaybookEditor.tsx | Done | 387 | Visual YAML editor, step-by-step builder, test playbook |
| **Reachability** | Reachability.tsx | Enhance | 103 | Internet-reachable attack surface, network path analysis |

### FAIL Engine Design Specification

**For**: Jason (Red Team), Dr. Wei (ML training data), Janet (incident response practice)

The FAIL Engine (Fault & Attack Injection Layer) is a chaos engineering system for security teams. It injects synthetic vulnerabilities and measures organizational response time.

```
┌─────────────────────────────────────────────────────────────┐
│ FAIL ENGINE                           [New Drill ▼] [History]│
├─────────────────────┬───────────────────────────────────────┤
│ ACTIVE DRILLS       │ TEAM SCORE CARD                       │
│                     │                                       │
│ 🔴 Log4Shell Inject │ Overall Readiness: 8.2/10            │
│   Target: payment-  │                                       │
│   service           │ Detection Speed: 9.1/10               │
│   Injected: 2h ago  │ Triage Accuracy: 7.8/10              │
│   Detected: YES ✅  │ Remediation Speed: 8.0/10            │
│   Triaged: YES ✅   │ Communication: 7.9/10                │
│   Fixed: PENDING ⏳ │                                       │
│                     │ NEGLECT ZONES (no drill in 90+ days)  │
│ 🟢 Last drill score │ ⚠️ mobile-app                        │
│   8.2/10           │ ⚠️ data-pipeline                      │
│                     │ ⚠️ internal-tools                     │
├─────────────────────┴───────────────────────────────────────┤
│ DRILL HISTORY (last 30 days)                                │
│ ┌─────────┬──────────┬───────────┬──────────┬─────────┐    │
│ │ Date    │ Scenario │ Target    │ Score    │ MTTR    │    │
│ ├─────────┼──────────┼───────────┼──────────┼─────────┤    │
│ │ Feb 24  │ Log4Shell│ payment   │ 8.2/10  │ 2.1h   │    │
│ │ Feb 17  │ SSRF     │ api-gw    │ 7.5/10  │ 3.4h   │    │
│ │ Feb 10  │ SQLi     │ user-svc  │ 9.0/10  │ 0.8h   │    │
│ └─────────┴──────────┴───────────┴──────────┴─────────┘    │
│                                                             │
│ COMPARISON: Your org vs industry average                    │
│ Detection: 12min (avg: 4h) | Fix: 2.1h (avg: 14d)         │
└─────────────────────────────────────────────────────────────┘
```

**API endpoints** (7 new):
- `POST /api/v1/fail/inject` — Inject synthetic vulnerability
- `GET /api/v1/fail/drills` — List active/past drills
- `GET /api/v1/fail/drills/{id}` — Drill detail + score
- `POST /api/v1/fail/drills/{id}/grade` — Grade team response
- `GET /api/v1/fail/neglect-zones` — Components with no recent drills
- `GET /api/v1/fail/readiness-score` — Organization readiness score
- `GET /api/v1/fail/comparison` — Industry benchmark comparison

**Backend**: ~1,830 LOC in `suite-attack/attack/fail_engine.py`
**Vision pillars**: V3 (Decision Intelligence), V5 (MPTE Verification), V8 (Self-Learning), V10 (CTEM)

## 4.6 Space 4 — REMEDIATE

> **User question**: "How do I fix these vulnerabilities efficiently?"
> **Primary personas**: Alex (Security Eng), Mike (Developer), Marcus (AppSec), Kevin (Dev Lead), Rachel (Junior Dev)

### Pages in this space

| Page | Source | Status | LOC | Description |
|------|--------|--------|-----|-------------|
| **Remediation Center** | RemediationCenter.tsx | Done | 435 | All remediation tasks, SLA tracking, assignment, status workflow |
| **AutoFix** | AutoFixDashboard.tsx | Enhance | 248 | AST-based fix generation, PR preview, apply/approve workflow |
| **Bulk Operations** | BulkOperations.tsx | Done | 412 | Mass triage, mass assign, mass status change, mass export |
| **Collaboration** | Collaboration.tsx | Rebuild | 72 | War rooms, shared investigation views, team chat, findings discussion |
| **Workflows** | Workflows.tsx | Rebuild | 71 | Automation rules: "If critical + MPTE verified → auto-create Jira + notify Slack" |
| **Exposure Cases** | ExposureCaseCenter.tsx (also in Discover) | Done | 565 | Deduplicated finding groups, linked decisions, lifecycle tracking |
| **Ticket Integration** | IntegrationsSettings.tsx | Enhance | 337 | Jira/ServiceNow/GitHub bi-directional sync configuration |

### Collaboration Design Specification

**For**: Alex (Security Eng), Mike (Developer), Marcus (AppSec)

The current `Collaboration.tsx` is only 72 LOC — a stub. Rebuild as a full team collaboration space:

```
┌─────────────────────────────────────────────────────────────┐
│ COLLABORATION                    [War Rooms ▼] [+ New Room] │
├────────────────────┬────────────────────────────────────────┤
│ ACTIVE WAR ROOMS   │ LOG4SHELL RESPONSE WAR ROOM           │
│                    │                                        │
│ 🔴 Log4Shell       │ PARTICIPANTS: Alex, Mike, Marcus, Raj  │
│    Response        │                                        │
│    4 participants  │ 📋 LINKED FINDINGS                    │
│                    │ CVE-2024-1234 (payment-service)        │
│ 🟡 Q1 Audit        │ CVE-2024-1235 (api-gateway)            │
│    Prep            │                                        │
│    2 participants  │ 💬 DISCUSSION                          │
│                    │ Alex: MPTE confirms exploitable. PR    │
│ 🟢 Sprint 23       │  #423 has the fix.                     │
│    Security Debt   │ Mike: Reviewing now. Tests pass.       │
│    3 participants  │ Marcus: Approved. Deploying to staging.│
│                    │                                        │
│ [+ Create Room]    │ 📎 ATTACHMENTS                        │
│                    │ MPTE Report · Evidence Bundle · PR Link│
│                    │                                        │
│                    │ ✅ ACTIONS                             │
│                    │ [x] MPTE scan completed                │
│                    │ [x] Fix PR created                     │
│                    │ [ ] Deploy to production               │
│                    │ [ ] Generate evidence bundle            │
└────────────────────┴────────────────────────────────────────┘
```

### Workflows Design Specification

**For**: Raj (DevSecOps), Janet (SOC), Alex (Security Eng)

The current `Workflows.tsx` is only 71 LOC — a stub. Rebuild as a visual automation rule builder:

```
┌─────────────────────────────────────────────────────────────┐
│ WORKFLOWS & AUTOMATION              [+ New Rule] [Templates]│
├─────────────────────────────────────────────────────────────┤
│ ACTIVE RULES (12)                                           │
│                                                             │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Rule: Critical MPTE Auto-Response                  ✅ ON│ │
│ │ WHEN: Finding.severity = critical                      │ │
│ │  AND: MPTE.verdict = VULNERABLE_VERIFIED               │ │
│ │ THEN: 1. Create Jira ticket (P0)                       │ │
│ │       2. Notify #security-critical (Slack)             │ │
│ │       3. Generate AutoFix PR                           │ │
│ │       4. Page on-call (PagerDuty)                      │ │
│ │ Triggered: 23 times | Last: 2h ago                     │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Rule: Weekly Compliance Evidence                   ✅ ON│ │
│ │ WHEN: schedule = every Monday 06:00                    │ │
│ │ THEN: 1. Generate SOC2 evidence for all APP_IDs        │ │
│ │       2. Sign with quantum-secure keys                 │ │
│ │       3. Store in WORM archive                         │ │
│ │ Triggered: 8 times | Last: 3 days ago                  │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
│ RULE BUILDER (drag-and-drop)                                │
│ ┌──────────┐    ┌──────────┐    ┌──────────┐               │
│ │ TRIGGER  │ →  │ CONDITION│ →  │ ACTION   │               │
│ │ ▼ Select │    │ ▼ Select │    │ ▼ Select │               │
│ └──────────┘    └──────────┘    └──────────┘               │
└─────────────────────────────────────────────────────────────┘
```

## 4.7 Space 5 — COMPLY

> **User question**: "Can I prove we're secure to auditors and the board?"
> **Primary personas**: Maria (Compliance), Laura (Auditor), Sarah (CISO), Tom (CFO)

### Pages in this space

| Page | Source | Status | LOC | Description |
|------|--------|--------|-----|-------------|
| **Compliance Dashboard** | ComplianceReports.tsx | Enhance | 400 | SOC2/PCI/ISO/HIPAA/NIST status, control coverage, gap analysis |
| **Evidence Vault** | EvidenceVault.tsx | Done | 444 | All evidence bundles, quantum-signed, searchable by framework/control/app |
| **Evidence Bundles** | EvidenceBundles.tsx | Rebuild | 74 | Per-APP_ID evidence generation, bulk export, retention management |
| **SOC2 Evidence** | SOC2EvidenceUI.tsx | Enhance | 337 | SOC2-specific control mapping, evidence completeness, auditor portal |
| **SLSA Provenance** | SLSAProvenance.tsx | Rebuild | 142 | Build provenance tracking, SLSA v1 attestation verification |
| **Audit Trail** | AuditLogs.tsx | Rebuild | 52 | Complete audit log, hash-chain verification, tamper detection, export |
| **Reports** | Reports.tsx | Rebuild | 76 | Executive, technical, compliance, trend reports in PDF/CSV/JSON |
| **Analytics** | EvidenceAnalytics.tsx | Enhance | 151 | MTTR trends, noise reduction over time, SLA compliance trends, scanner ROI |

### Evidence Export Center Design Specification

**For**: Laura (External Auditor), Maria (Compliance Lead)

Currently there's no dedicated evidence export page. Build one inside the Comply space:

```
┌─────────────────────────────────────────────────────────────┐
│ EVIDENCE EXPORT CENTER                         [+ New Export]│
├──────────────────────┬──────────────────────────────────────┤
│ EXPORT BUILDER       │ PREVIEW                              │
│                      │                                      │
│ Framework:           │ SOC2 Type II Evidence Package         │
│ [SOC2 Type II ▼]     │ for HealthPay (Q1 2026)              │
│                      │                                      │
│ APP_IDs:             │ Controls covered: 47/47 (100%)       │
│ [✓] website-12345    │ Evidence bundles: 156                 │
│ [✓] api-gateway      │ Signatures: All quantum-secure ✅    │
│ [ ] mobile-app       │                                      │
│                      │ ┌───────────────────────────────┐   │
│ Period:              │ │ CC6.1 Access Controls         │   │
│ [Q1 2026 ▼]          │ │  ├── RBAC config evidence     │   │
│                      │ │  ├── Access review log        │   │
│ Format:              │ │  └── SSO configuration        │   │
│ [PDF + JSON ▼]       │ │ CC7.1 System Operations       │   │
│                      │ │  ├── Scan results (156 scans) │   │
│ Include:             │ │  ├── MPTE verdicts (45)       │   │
│ [✓] MPTE results     │ │  └── Incident response log    │   │
│ [✓] Scan history     │ │ CC8.1 Change Management       │   │
│ [✓] Decision log     │ │  ├── PR review evidence       │   │
│ [ ] Raw findings     │ │  └── Deploy gate results      │   │
│                      │ └───────────────────────────────┘   │
│ [Generate Export]    │                                      │
│ ~2 min estimated     │ [Download] [Send to Auditor]        │
└──────────────────────┴──────────────────────────────────────┘
```

## 4.8 The Persistent AI Copilot

The AI Copilot is available from EVERY space as a persistent right-hand sidebar (like Spotlight on Mac). It follows the user across spaces and maintains conversation context.

```
┌──────────────────────────────── ANY SPACE ──┬─── AI COPILOT ─────┐
│                                             │                     │
│  [Current space content]                    │ 🤖 ALdeci Copilot   │
│                                             │                     │
│                                             │ "Good morning Raj.  │
│                                             │  While you slept:   │
│                                             │  - 3 new CVEs in    │
│                                             │    payment-service  │
│                                             │  - MPTE verified 2  │
│                                             │  - AutoFix PR ready │
│                                             │    for review"      │
│                                             │                     │
│                                             │ Ask me anything:    │
│                                             │ [________________]  │
│                                             │                     │
│                                             │ Quick actions:      │
│                                             │ [Triage findings]   │
│                                             │ [Run MPTE scan]     │
│                                             │ [Generate evidence] │
│                                             │ [Explain this CVE]  │
└─────────────────────────────────────────────┴─────────────────────┘
```

**Current state**: `Copilot.tsx` is 153 LOC — partial implementation
**Backend**: `/api/v1/copilot/*` (14 endpoints) + `/api/v1/copilot/agents/*` (32 endpoints)
**Enhancement needed**: Persistent sidebar mode, conversation memory, context-aware suggestions based on current page

## 4.9 Settings & Administration

Accessible via gear icon at bottom of sidebar. Not a workflow space — it's infrastructure.

| Page | Source | Status | LOC | Description |
|------|--------|--------|-----|-------------|
| **Settings Hub** | Settings.tsx | Done | 537 | General configuration, API keys, notifications |
| **Integrations** | Integrations.tsx | Done | 466 | Connect scanners, ALM tools, cloud providers |
| **Users & RBAC** | Users.tsx | Rebuild | 55 | User management, role assignment, SSO/SAML |
| **Teams** | Teams.tsx | Rebuild | 55 | Team management, component ownership mapping |
| **Marketplace** | Marketplace.tsx | Rebuild | 66 | Browse/install connectors, micro-apps, community playbooks |
| **Policies** | Policies.tsx | Rebuild | 75 | Security policy editor, SLA rules, auto-triage rules |
| **System Health** | SystemHealth.tsx | Enhance | 89 | Backend health, DB status, queue depth, API latency |
| **Log Viewer** | LogViewer.tsx | Done | 480 | Application logs, structured search, export |
| **API Reference** | NEW (or link) | — | — | Interactive API docs (Swagger/FastAPI auto-generated) |

## 4.10 Navigation Architecture & Route Map

### New Route Structure

Replace the current 8-group routing with 5 workflow spaces:

```tsx
// New App.tsx route structure
<Routes>
  {/* Space 1: Mission Control */}
  <Route path="/" element={<CommandDashboard />} />
  <Route path="/mission-control" element={<CommandDashboard />} />
  <Route path="/mission-control/executive" element={<ExecutiveView />} />
  <Route path="/mission-control/sla" element={<SLADashboard />} />
  <Route path="/mission-control/live-feed" element={<LiveFeed />} />
  <Route path="/mission-control/risk" element={<RiskOverview />} />

  {/* Space 2: Discover */}
  <Route path="/discover" element={<FindingExplorer />} />
  <Route path="/discover/code" element={<CodeScanning />} />
  <Route path="/discover/secrets" element={<SecretsDetection />} />
  <Route path="/discover/iac" element={<IaCScanning />} />
  <Route path="/discover/cloud" element={<CloudPosture />} />
  <Route path="/discover/containers" element={<ContainerSecurity />} />
  <Route path="/discover/sbom" element={<SBOMInventory />} />
  <Route path="/discover/graph" element={<KnowledgeGraph />} />
  <Route path="/discover/attack-paths" element={<AttackPaths />} />
  <Route path="/discover/threats" element={<ThreatFeeds />} />
  <Route path="/discover/data-fabric" element={<DataFabric />} />
  <Route path="/discover/correlation" element={<CorrelationEngine />} />

  {/* Space 3: Validate */}
  <Route path="/validate" element={<MPTEConsole />} />
  <Route path="/validate/mpte" element={<MPTEConsole />} />
  <Route path="/validate/simulation" element={<AttackSimulation />} />
  <Route path="/validate/fail" element={<FAILEngine />} />
  <Route path="/validate/playbooks" element={<Playbooks />} />
  <Route path="/validate/playbooks/editor" element={<PlaybookEditor />} />
  <Route path="/validate/reachability" element={<Reachability />} />

  {/* Space 4: Remediate */}
  <Route path="/remediate" element={<RemediationCenter />} />
  <Route path="/remediate/autofix" element={<AutoFix />} />
  <Route path="/remediate/bulk" element={<BulkOperations />} />
  <Route path="/remediate/collaborate" element={<Collaboration />} />
  <Route path="/remediate/workflows" element={<Workflows />} />
  <Route path="/remediate/cases" element={<ExposureCases />} />
  <Route path="/remediate/tickets" element={<TicketIntegration />} />

  {/* Space 5: Comply */}
  <Route path="/comply" element={<ComplianceDashboard />} />
  <Route path="/comply/evidence" element={<EvidenceVault />} />
  <Route path="/comply/bundles" element={<EvidenceBundles />} />
  <Route path="/comply/soc2" element={<SOC2Evidence />} />
  <Route path="/comply/slsa" element={<SLSAProvenance />} />
  <Route path="/comply/audit" element={<AuditTrail />} />
  <Route path="/comply/reports" element={<Reports />} />
  <Route path="/comply/analytics" element={<Analytics />} />
  <Route path="/comply/export" element={<EvidenceExportCenter />} />

  {/* Settings (gear icon) */}
  <Route path="/settings" element={<Settings />} />
  <Route path="/settings/integrations" element={<Integrations />} />
  <Route path="/settings/users" element={<Users />} />
  <Route path="/settings/teams" element={<Teams />} />
  <Route path="/settings/marketplace" element={<Marketplace />} />
  <Route path="/settings/policies" element={<Policies />} />
  <Route path="/settings/health" element={<SystemHealth />} />
  <Route path="/settings/logs" element={<LogViewer />} />

  {/* AI Engine (accessible from Copilot sidebar, not primary nav) */}
  <Route path="/ai/copilot" element={<Copilot />} />
  <Route path="/ai/algorithms" element={<AlgorithmicLab />} />
  <Route path="/ai/consensus" element={<MultiLLM />} />
  <Route path="/ai/ml" element={<MLDashboard />} />
  <Route path="/ai/predictions" element={<Predictions />} />
  <Route path="/ai/brain" element={<BrainPipeline />} />

  {/* Legacy redirects (keep old routes working) */}
  <Route path="/core/dashboard" element={<Navigate to="/" />} />
  <Route path="/code/*" element={<Navigate to="/discover" />} />
  <Route path="/cloud/*" element={<Navigate to="/discover/cloud" />} />
  <Route path="/attack/*" element={<Navigate to="/validate" />} />
  <Route path="/protect/*" element={<Navigate to="/remediate" />} />
  <Route path="/evidence/*" element={<Navigate to="/comply" />} />
</Routes>
```

### New Sidebar Navigation

```tsx
// New MainLayout.tsx sidebar structure
const navGroups = [
  {
    label: "Mission Control",
    icon: Target,
    items: [
      { label: "Command Dashboard", to: "/mission-control", icon: LayoutDashboard },
      { label: "Executive View", to: "/mission-control/executive", icon: Crown },
      { label: "SLA Dashboard", to: "/mission-control/sla", icon: Clock },
      { label: "Live Feed", to: "/mission-control/live-feed", icon: Activity },
      { label: "Risk Overview", to: "/mission-control/risk", icon: AlertTriangle },
    ],
  },
  {
    label: "Discover",
    icon: Search,
    items: [
      { label: "Finding Explorer", to: "/discover", icon: Bug },
      { label: "Code Scanning", to: "/discover/code", icon: Code },
      { label: "Secrets", to: "/discover/secrets", icon: KeyRound },
      { label: "IaC Scanning", to: "/discover/iac", icon: Server },
      { label: "Cloud Posture", to: "/discover/cloud", icon: Cloud },
      { label: "Containers", to: "/discover/containers", icon: Container },
      { label: "SBOM & Inventory", to: "/discover/sbom", icon: Package },
      { label: "Knowledge Graph", to: "/discover/graph", icon: Share2 },
      { label: "Attack Paths", to: "/discover/attack-paths", icon: Route },
      { label: "Threat Feeds", to: "/discover/threats", icon: Rss },
    ],
  },
  {
    label: "Validate",
    icon: ShieldCheck,
    items: [
      { label: "MPTE Console", to: "/validate/mpte", icon: Crosshair },
      { label: "Attack Simulation", to: "/validate/simulation", icon: Swords },
      { label: "FAIL Engine", to: "/validate/fail", icon: Flame, badge: "NEW" },
      { label: "Playbooks", to: "/validate/playbooks", icon: BookOpen },
      { label: "Reachability", to: "/validate/reachability", icon: Network },
    ],
  },
  {
    label: "Remediate",
    icon: Wrench,
    items: [
      { label: "Remediation Center", to: "/remediate", icon: CheckCircle },
      { label: "AutoFix", to: "/remediate/autofix", icon: Wand2 },
      { label: "Bulk Operations", to: "/remediate/bulk", icon: Layers },
      { label: "Collaboration", to: "/remediate/collaborate", icon: Users },
      { label: "Workflows", to: "/remediate/workflows", icon: Workflow },
      { label: "Ticket Integration", to: "/remediate/tickets", icon: Ticket },
    ],
  },
  {
    label: "Comply",
    icon: Shield,
    items: [
      { label: "Compliance Dashboard", to: "/comply", icon: ClipboardCheck },
      { label: "Evidence Vault", to: "/comply/evidence", icon: Lock },
      { label: "Evidence Export", to: "/comply/export", icon: Download },
      { label: "SOC2 Evidence", to: "/comply/soc2", icon: FileCheck },
      { label: "SLSA Provenance", to: "/comply/slsa", icon: FileSignature },
      { label: "Audit Trail", to: "/comply/audit", icon: ScrollText },
      { label: "Reports", to: "/comply/reports", icon: FileText },
      { label: "Analytics", to: "/comply/analytics", icon: BarChart3 },
    ],
  },
];
```

## 4.11 Persona-to-Space Mapping

Every persona has a **home space** (where they start their day) and **secondary spaces** they visit:

| Persona | Role | Home Space | Secondary Spaces |
|---------|------|-----------|-----------------|
| Sarah Chen | CISO | Mission Control (Executive View) | Comply |
| David Kim | VP Engineering | Mission Control (SLA Dashboard) | Remediate |
| Priya Patel | CTO | Mission Control (Risk Overview) | Discover (Graph) |
| Tom Bradley | CFO | Mission Control (Executive View) | Comply (Reports) |
| Alex Rivera | Security Engineer | Remediate | Discover, Validate |
| Marcus Thompson | AppSec Engineer | Discover | Validate, Remediate |
| Raj Mehta | DevSecOps Lead | Mission Control (Dashboard) | Remediate, Discover |
| Janet Liu | SOC Analyst | Mission Control (Live Feed) | Validate, Remediate |
| Maria Santos | Compliance Lead | Comply | Mission Control |
| Derek Washington | VM Manager | Mission Control (SLA Dashboard) | Remediate |
| Jason Wu | Red Team Lead | Validate (MPTE) | Validate (FAIL) |
| Emily Foster | Threat Analyst | Discover (Threat Feeds) | Discover (Graph) |
| Brian Mitchell | Cloud Security | Discover (Cloud Posture) | Validate |
| Mike Chen | Senior Developer | Remediate (AutoFix) | Discover (Code) |
| Lisa Park | Cloud Architect | Discover (Graph) | Discover (Attack Paths) |
| Rachel Kim | Junior Dev | Remediate (AutoFix) | Discover (Code) |
| Kevin O'Brien | Dev Lead | Mission Control (SLA) | Remediate |
| Amy Rodriguez | QA/Release | Mission Control | Comply (SLSA) |
| Chris Taylor | Platform Eng | Settings (Integrations) | Discover |
| Dr. Wei | ML Engineer | Validate (FAIL Engine) | AI Engine (hidden) |
| Aisha Johnson | Data Scientist | AI Engine (hidden) | Mission Control |
| Nina Kowalski | Security Architect | Discover (Graph) | Mission Control |
| Sam Parker | AI Agent Dev | Settings (API/MCP) | — |
| Laura Chen | External Auditor | Comply (Evidence Export) | Comply (Audit Trail) |
| Carlos Mendez | Security Consultant | Mission Control | All spaces |

## 4.12 Onboarding Wizard (First-Run Experience)

Currently missing. This is the FIRST screen new users should see:

```
┌─────────────────────────────────────────────────────────────┐
│               Welcome to ALdeci 🎯                          │
│        Let's get you set up in under 5 minutes              │
│                                                             │
│  Step 1 of 5: Connect Your Tools              ●○○○○        │
│  ─────────────────────────────────────────────              │
│                                                             │
│  Which scanners do you use? (select all that apply)         │
│                                                             │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐             │
│  │  ✅ Snyk   │ │  ✅ Trivy  │ │  ☐ Wiz     │             │
│  └────────────┘ └────────────┘ └────────────┘             │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐             │
│  │  ✅ Semgrep│ │  ☐ Prisma  │ │  ☐ Checkov │             │
│  └────────────┘ └────────────┘ └────────────┘             │
│                                                             │
│  Where does your code live?                                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐             │
│  │  ✅ GitHub │ │  ☐ GitLab  │ │  ☐ Azure   │             │
│  └────────────┘ └────────────┘ └────────────┘             │
│                                                             │
│  What's your role?                                          │
│  [DevSecOps Lead ▼]  ← This personalizes your home space   │
│                                                             │
│                              [Next: Register Your First App]│
└─────────────────────────────────────────────────────────────┘
```

**5 wizard steps**:
1. Connect Your Tools (scanner selection)
2. Register Your First App (APP_ID creation + aldeci.yaml generation)
3. Run First Scan (trigger pipeline on a real repo)
4. Review Results (guided tour of Mission Control)
5. Personalize (role-based home space, notification preferences)

---

# Part V — 7 Unique Differentiators

These are features no competitor has. Each one is a defensible moat.

## 5.1 FAIL Engine (Fault & Attack Injection Layer)

**What**: Chaos engineering for security teams. Inject synthetic vulnerabilities into your environment and measure how quickly your team detects, triages, and remediates them.

**Why unique**: Zero competitors offer this. Google has internal "Fire Drills" for SRE — ALdeci brings the same concept to AppSec.

**Research basis**: Mondragon et al. 2025 — fault injection for security operations

**Specs**:
- 7 new API endpoints (see Section 4.5)
- ~1,830 LOC in `suite-attack/attack/fail_engine.py`
- 10-day build
- Generates labeled training data for ML models (Loop 1 & Loop 2 of self-learning)
- 4 scoring dimensions: Detection Speed, Triage Accuracy, Remediation Speed, Communication
- Neglect Zone detection: identifies components with no recent security activity
- ROI: 233:1 (based on prevented breach cost vs. drill cost)

**Vision pillars**: V3, V5, V8, V10

## 5.2 MCP Architecture Expansion

**What**: Full Model Context Protocol gateway that exposes ALdeci's 650 tools to any AI agent (GitHub Copilot, Cursor, Claude Code, custom agents).

**Why unique**: First AppSec platform that AI agents can programmatically use. Other platforms are human-only interfaces.

**Specs**:
- Auto-discovers tools by walking FastAPI `app.routes` at startup
- 3 transport layers: stdio, SSE (Server-Sent Events), WebSocket
- Resource streams for live data (findings, metrics, SLA)
- Prompt registry for common security queries
- ~3,500 LOC extending existing `mcp_router.py`
- 15-day build
- Frontend MCP bridge: agents can interact with UI screens programmatically

**Vision pillars**: V7, V2

## 5.3 Single AI Agent (Zero-Token Self-Hosted)

**What**: Replace $6,000/month in multi-vendor API calls with a single self-hosted model (Llama 3.1 70B via vLLM) that assumes 4 expert roles.

**Why unique**: Every competitor uses cloud-hosted AI. ALdeci works fully air-gapped with $0 API cost.

**Specs**:
- 4 expert roles: Security Analyst, Pentest Expert, Compliance Auditor, Risk Quantifier
- 1 moderator role synthesizes all 4 perspectives
- Fine-tuning pipeline on security domain data
- ~2,000 LOC in `suite-core/core/single_agent.py`
- 15-day build
- Config: `FIXOPS_LLM_MODE=single-agent`
- Backward compatible with multi-LLM consensus mode
- Cost comparison: $0/mo API + ~$500/mo GPU vs. $6,000/mo vendor APIs

**Vision pillars**: V4, V9

## 5.4 Quantum-Secure Cryptography

**What**: Hybrid RSA-4096 + ML-DSA-65 (Dilithium3) signatures for all evidence bundles, future-proof against quantum computers.

**Why unique**: Zero competitors have post-quantum cryptography. ALdeci evidence is valid for 30+ years.

**Specs**:
- FIPS 203 (ML-KEM for encryption), FIPS 204 (ML-DSA for signatures), FIPS 205 (SLH-DSA backup)
- Hybrid signing: classical RSA + post-quantum ML-DSA (verify either alone)
- Encryption upgrade: AES-256-GCM + ML-KEM key exchange
- ~1,800 LOC extending `suite-core/core/crypto.py`
- 14-day build
- Backward compatible: v1 bundles (RSA-only) still verify
- Size impact: signature grows from ~512 bytes to ~3.3 KB (negligible)

**Vision pillars**: V6, V10

## 5.5 Zero-Gravity Data (Intelligent Data Lifecycle)

**What**: 4-tier data aging system that reduces on-prem storage from ~20 GB/year to ~1 GB/year per customer while maintaining ML model accuracy.

**Why unique**: Competitors are cloud-hosted — they don't need to solve storage. ALdeci's air-gapped deployment makes this essential.

**Specs**:
- **Tier 1 (Hot)**: SQLite WAL, uncompressed, last 7 days, ~500 MB/APP_ID
- **Tier 2 (Warm)**: SQLite + ZSTD row-level compression, 7-90 days, 80% reduction
- **Tier 3 (Cold)**: Coreset selection (NeurIPS 2022 data pruning), 90+ days, keep top 5-10% most informative samples
- **Tier 4 (Distilled)**: Online learning (River ML) — raw data deleted, knowledge lives in model weights only
- **Exception**: Human feedback NEVER aged out (triage decisions, FP flags = most valuable data)
- Prioritized Experience Buffer: 10,000 samples per model, priority scoring (surprise + human_signal + recency + diversity)
- MinHash + LSH near-duplicate detection for findings (70-85% dedup ratio)
- ~1,500 LOC, 15-day build
- Dependencies: `river` (BSD-3), `datasketch` (MIT), `sqlite-zstd` (LGPL-3.0)

**Storage budget per customer/year**:

| Component | Before | After | Reduction |
|-----------|--------|-------|-----------|
| API traffic | 15 GB | 150 MB | 99% |
| Findings | 2 GB | 60 MB | 97% |
| Human feedback | 150 MB | 150 MB | 0% (never reduced) |
| MPTE results | 500 MB | 100 MB | 80% |
| Evidence bundles | 1 GB | 200 MB | 80% |
| Knowledge Graph | 500 MB | 300 MB | 40% |
| **Total** | **~20 GB** | **~1 GB** | **94.6%** |

**Vision pillars**: V8, V9

## 5.6 MPTE (Micro-Pentest Engine)

**What**: 19-phase deterministic scanner + AI orchestrator that proves vulnerability exploitability, not just detects it.

**Why unique**: Every other platform stops at "vulnerability detected." ALdeci proves it's actually exploitable (or not).

**Current state**: Already built. `micro_pentest_router.py` (18 endpoints), `mpte_router.py` (19 endpoints), `mpte_orchestrator_router.py` (8 endpoints). Core engine in `suite-attack/attack/micro_pentest.py` and `attack/mpte_advanced.py`.

**4-state verdict system**:
- `VULNERABLE_VERIFIED` — Exploitation confirmed
- `NOT_VULNERABLE_VERIFIED` — Exploitation attempted but failed
- `NOT_APPLICABLE` — Vulnerability doesn't apply to this context
- `UNVERIFIED` — Could not determine (insufficient access, timeout, etc.)

**Vision pillars**: V5, V3, V10

## 5.7 "Switzerland" Tool Orchestration

**What**: ALdeci works with every security tool, replaces none. "Switzerland of AppSec."

**Why unique**: Snyk wants you to use Snyk. Wiz wants you to use Wiz. ALdeci makes what you ALREADY have work together.

**Current state**: Built. 20+ scanner adapters, OSS fallbacks for every category:

| Category | Commercial Tools Supported | OSS Fallback |
|----------|--------------------------|-------------|
| SCA | Snyk, Checkmarx | Trivy, Grype |
| SAST | Semgrep, SonarQube, Veracode | Semgrep, Bandit |
| Secret Detection | — | Gitleaks, ALdeci scanner |
| IaC | — | Checkov, ALdeci IaC |
| DAST | — | OWASP ZAP |
| Container | — | Trivy |
| Cloud | AWS Security Hub, Azure, Wiz, Prisma | Prowler |

**Vision pillars**: V2, V4 (indirectly)

---

# Part VI — Build Plan

## 6.1 Current Codebase Status

### Backend (6 suites)

| Suite | Purpose | Key LOC | Status |
|-------|---------|---------|--------|
| suite-api | FastAPI gateway, 61 routers, auth | ~15K | ✅ Solid |
| suite-core | Brain pipeline, connectors, LLM, graph | ~20K | ✅ Solid (NetworkX→FalkorDB pending) |
| suite-attack | MPTE, attack sim, SAST, DAST, FAIL | ~12K | ✅ Core done, FAIL pending |
| suite-feeds | NVD, KEV, EPSS, GitHub, OSV feeds | ~8K | ✅ Solid |
| suite-evidence-risk | Evidence, compliance, risk, reachability | ~10K | ✅ Solid |
| suite-integrations | Jira, Slack, GitHub, IDE, MCP | ~8K | ✅ Solid, MCP expansion pending |

### Frontend (57 pages)

| Category | Count | LOC Range | Status |
|----------|-------|-----------|--------|
| Feature-complete (>400 LOC) | 19 pages | 400-589 | ✅ Done |
| Partial (100-400 LOC) | 23 pages | 103-395 | ⚠️ Need enhancement |
| Critical stubs (<100 LOC) | 15 pages | 52-89 | ❌ Need complete rebuild |

### 15 Critical Stub Pages (Under 100 LOC — Need Complete Rebuild)

| Page | Current LOC | New Space | Priority |
|------|-------------|-----------|----------|
| AuditLogs.tsx | 52 | Comply | P0 — Required for compliance demos |
| Inventory.tsx | 53 | Discover (merge into SBOM) | P1 |
| Users.tsx | 55 | Settings | P1 — Required for RBAC |
| Teams.tsx | 55 | Settings | P1 — Required for ownership |
| Marketplace.tsx | 66 | Settings | P2 |
| IaCScanning.tsx | 67 | Discover | P1 |
| Workflows.tsx | 71 | Remediate | P0 — Core automation |
| Collaboration.tsx | 72 | Remediate | P0 — Team collaboration |
| EvidenceBundles.tsx | 74 | Comply | P0 — Evidence generation |
| Policies.tsx | 75 | Settings | P1 — Policy engine |
| Reports.tsx | 76 | Comply | P0 — Executive reports |
| Predictions.tsx | 76 | AI Engine | P2 |
| CorrelationEngine.tsx | 78 | Discover | P1 |
| ThreatFeeds.tsx | 80 | Discover | P1 |
| SystemHealth.tsx | 89 | Settings | P2 |

## 6.2 Master Build Order (5 Sprints, 20 Weeks)

### Sprint 1 — Demo-Ready Foundation (Weeks 1-4)

**Goal**: Build the demo that closes enterprise deals.

| # | Work Item | Days | Vision Pillars | Deliverable |
|---|----------|------|---------------|-------------|
| 1 | **FAIL Engine** — fault injection, response grading, neglect zones | 10 | V3 V5 V8 V10 | 7 new API endpoints, 1 new UI page |
| 2 | **Attack Path Visualization** — graph-based internet→data paths | 10 | V3 V5 V10 | Enhanced AttackPaths.tsx page |
| **Total** | | **20 days** | | |

**Demo flow after Sprint 1**: Inject synthetic CVE → Watch team response → Grade MTTR → Show attack path → One-click fix

### Sprint 2 — AI Moats (Weeks 5-8)

**Goal**: Make ALdeci the security brain for all AI agents.

| # | Work Item | Days | Vision Pillars | Deliverable |
|---|----------|------|---------------|-------------|
| 3 | **MCP Full Protocol Gateway** — auto-discover 650 tools, SSE transport | 15 | V7 V2 | Extended mcp_router.py |
| 4 | **Single Agent Engine** — 4 roles + moderator, vLLM | 15 | V4 V9 | New single_agent.py |
| **Total** | | **30 days** | | |

**After Sprint 2**: Any AI agent (Copilot, Cursor, Claude) can use ALdeci as its security oracle. Self-hosted decisions cost $0.

### Sprint 3 — Compliance & Crypto (Weeks 9-12)

**Goal**: "First AppSec platform with quantum-secure evidence signing."

| # | Work Item | Days | Vision Pillars | Deliverable |
|---|----------|------|---------------|-------------|
| 5 | **Quantum-Secure Hybrid Signing** — RSA + ML-DSA | 14 | V6 V10 | Extended crypto.py |
| 6 | **Compliance Auto-Mapping** — SOC2/PCI/ISO/NIST evidence generation | 10 | V6 V10 | New compliance engine |
| **Total** | | **24 days** | | |

### Sprint 4 — UI Polish (Weeks 13-16)

**Goal**: Zero stub pages. Every persona served. Every pitch deck promise has matching UI.

> **⚠️ BUILD IN `aldeci-ui-new` — DO NOT TOUCH `suite-ui/aldeci/`**
> All Sprint 4 UI work targets the new `suite-ui/aldeci-ui-new/` project.
> Use shadcn/ui + Apple HIG design language. See Part IV header for full stack spec.

| # | Work Item | Days | Vision Pillars | Deliverable |
|---|----------|------|---------------|-------------|
| 7 | **New UI Navigation** — 5 workflow spaces, sidebar redesign, route migration | 5 | V2 V10 | `aldeci-ui-new` MainLayout.tsx + App.tsx |
| 8 | **New screens** — Executive View, SLA Dashboard, Risk Overview, FAIL Engine UI, Evidence Export, Onboarding | 10 | V2 V10 | 6 new pages in `aldeci-ui-new` |
| 9 | **Stub rebuilds** — 15 pages under 100 LOC | 10 | V2 V10 | 15 rebuilt pages in `aldeci-ui-new` |
| **Total** | | **25 days** | | |

### Sprint 5 — Infrastructure Optimization (Weeks 17-20)

**Goal**: On-prem costs cut by 94.6%. Developer adoption pathway built.

| # | Work Item | Days | Vision Pillars | Deliverable |
|---|----------|------|---------------|-------------|
| 10 | **Zero-Gravity Data** — sqlite-zstd, River ML migration, priority buffer, MinHash dedup | 15 | V8 V9 | Data lifecycle engine |
| 11 | **Developer Experience** — VS Code extension polish, GitHub App, CLI improvements | 10 | V2 V7 | Developer tools |
| **Total** | | **25 days** | | |

### Grand Total: 124 days / ~20 weeks

```
Sprint 1 (NOW):  FAIL Engine + Attack Path        → Demo that closes deals
Sprint 2:        MCP Gateway + Single AI Agent     → AI agents use ALdeci as brain
Sprint 3:        Quantum Crypto + Compliance Auto  → Evidence valid for 30+ years
Sprint 4:        UI Redesign + Stub Rebuilds       → Every pitch has matching UI
Sprint 5:        Zero-Gravity + DX                 → On-prem costs cut 95%
```

## 6.3 Screen-by-Screen Build Tasks

### NEW Screens to Build (6 pages)

#### 1. Executive View (`/mission-control/executive`)
- **File**: `suite-ui/aldeci-ui-new/src/spaces/mission-control/ExecutiveView.tsx`
- **Target LOC**: 500+
- **Data sources**: `/api/v1/analytics/*`, `/api/v1/risk/*`, `/api/v1/evidence/*`
- **Components**: Posture trend chart (12mo), ROI summary card, risk-by-business-unit heatmap, compliance status badges, key decisions table
- **Libraries**: recharts for charts, framer-motion for transitions
- **Persona**: Sarah (CISO), Tom (CFO), Priya (CTO)

#### 2. SLA Dashboard (`/mission-control/sla`)
- **File**: `suite-ui/aldeci-ui-new/src/spaces/mission-control/SLADashboard.tsx`
- **Target LOC**: 450+
- **Data sources**: `/api/v1/remediation/*`, `/api/v1/analytics/*`
- **Components**: SLA compliance gauge, team breakdown table, aging analysis heatmap, escalation queue, trend charts
- **Persona**: Derek (VM Manager), David (VP Eng), Kevin (Dev Lead)

#### 3. Risk Overview (`/mission-control/risk`)
- **File**: `suite-ui/aldeci-ui-new/src/spaces/mission-control/RiskOverview.tsx`
- **Target LOC**: 400+
- **Data sources**: `/api/v1/risk/*`, `/api/v1/brain/*`, `/api/v1/analytics/*`
- **Components**: Organization risk heatmap, top-10 riskiest apps, risk trend by APP_ID, business impact assessment
- **Persona**: Priya (CTO), Sarah (CISO), Nina (Security Architect)

#### 4. FAIL Engine (`/validate/fail`)
- **File**: `suite-ui/aldeci-ui-new/src/spaces/validate/FAILEngine.tsx`
- **Target LOC**: 500+
- **Data sources**: `/api/v1/fail/*` (7 new endpoints)
- **Components**: Active drills panel, team scorecard, neglect zone warnings, drill history table, industry comparison, new drill wizard
- **Persona**: Jason (Red Team), Dr. Wei (ML Eng), Janet (SOC)

#### 5. Evidence Export Center (`/comply/export`)
- **File**: `suite-ui/aldeci-ui-new/src/spaces/comply/EvidenceExportCenter.tsx`
- **Target LOC**: 400+
- **Data sources**: `/api/v1/evidence/*`, `/api/v1/reports/*`
- **Components**: Framework selector, APP_ID multi-select, period picker, format options, evidence preview tree, download/send actions
- **Persona**: Laura (Auditor), Maria (Compliance)

#### 6. Onboarding Wizard (`/onboarding`)
- **File**: `suite-ui/aldeci-ui-new/src/spaces/onboarding/OnboardingWizard.tsx`
- **Target LOC**: 600+
- **Data sources**: `/api/v1/integrations/*`, `/api/v1/apps`, `/pipeline/run`
- **Components**: 5-step stepper, scanner grid selector, APP_ID registration form, aldeci.yaml generator, first-scan trigger, guided tour overlay, role selector for personalized home space
- **Persona**: Chris (Platform Eng), Carlos (Consultant), Rachel (Junior Dev)

### Stub Pages to Rebuild (15 pages — full specifications)

#### AuditLogs.tsx → Audit Trail (52 → 400+ LOC)
- **New path**: `/comply/audit`
- **Components**: Searchable log table (timestamp, actor, action, resource, IP), hash-chain verification badge, tamper detection alerts, filter by date/actor/action, export to CSV/JSON, compliance control linkage
- **Data**: `/api/v1/audit/*` (14 endpoints)

#### Users.tsx → User Management (55 → 350+ LOC)
- **New path**: `/settings/users`
- **Components**: User table (name, email, role, last login, status), invite dialog, role assignment (Admin/Manager/Analyst/Developer/Viewer), SSO/SAML config panel, API key management, activity log per user
- **Data**: `/api/v1/users/*` (6 endpoints), `/api/v1/auth/*` (4 endpoints)

#### Teams.tsx → Team Management (55 → 350+ LOC)
- **New path**: `/settings/teams`
- **Components**: Team list with member count, create/edit team dialog, member management (add/remove), component ownership mapping (which team owns which APP_ID components), team performance metrics (MTTR, SLA compliance)
- **Data**: `/api/v1/teams/*` (8 endpoints)

#### Marketplace.tsx → Connector Marketplace (66 → 400+ LOC)
- **New path**: `/settings/marketplace`
- **Components**: Category-filtered grid (Scanners, ALM, Cloud, Notification), install/uninstall buttons, connector health badges, community playbook library, rating system, configuration wizard per connector
- **Data**: `/api/v1/marketplace/*` (12 endpoints)

#### IaCScanning.tsx → IaC Security (67 → 350+ LOC)
- **New path**: `/discover/iac`
- **Components**: Terraform/CloudFormation/K8s file browser, misconfiguration list with fix suggestions, drift detection alerts, compliance mapping (CIS benchmarks), scan history
- **Data**: `/api/v1/iac/*` (7 endpoints)

#### Workflows.tsx → Workflow Automation (71 → 500+ LOC)
- **New path**: `/remediate/workflows`
- **Components**: Rule list with on/off toggle, visual rule builder (trigger → condition → action), template library, execution history, trigger statistics
- **Data**: `/api/v1/workflows/*` (13 endpoints)
- **See detailed spec in Section 4.6**

#### Collaboration.tsx → Team Collaboration (72 → 450+ LOC)
- **New path**: `/remediate/collaborate`
- **Components**: War room list, room creation wizard, participant management, finding linkage, threaded discussion, action items with checkboxes, file attachments, real-time updates (SSE)
- **Data**: `/api/v1/collaboration/*` (21 endpoints)
- **See detailed spec in Section 4.6**

#### EvidenceBundles.tsx → Evidence Generation (74 → 400+ LOC)
- **New path**: `/comply/bundles`
- **Components**: Bundle list by APP_ID, generate new bundle dialog (framework, period, controls), signature verification badge (quantum-secure indicator), retention countdown, bulk generation, bundle comparison (diff between periods)
- **Data**: `/api/v1/evidence/*` (6 endpoints)

#### Policies.tsx → Policy Engine (75 → 400+ LOC)
- **New path**: `/settings/policies`
- **Components**: Policy list with activate/deactivate, YAML-based policy editor, SLA rule configuration (severity → time limit), auto-triage rules (if scanner=X and severity<medium → auto-accept), severity override rules, policy violation log
- **Data**: `/api/v1/policies/*` (11 endpoints)

#### Reports.tsx → Report Center (76 → 400+ LOC)
- **New path**: `/comply/reports`
- **Components**: Report template gallery (Executive, Technical, Compliance, Trend, Board), parameter configuration (date range, APP_IDs, frameworks), format selector (PDF/CSV/JSON/HTML), scheduled report configuration, report history with download links
- **Data**: `/api/v1/reports/*` (14 endpoints)

#### Predictions.tsx → ML Predictions (76 → 300+ LOC)
- **New path**: `/ai/predictions`
- **Components**: Risk forecast chart (next 30/60/90 days), anomaly alerts, trend predictions, model accuracy metrics, feature importance visualization
- **Data**: `/api/v1/predictions/*` (8 endpoints)

#### CorrelationEngine.tsx → Finding Correlation (78 → 350+ LOC)
- **New path**: `/discover/correlation`
- **Components**: Cross-scanner correlation matrix (Snyk vs Trivy vs Semgrep), same-vulnerability grouping, noise analysis dashboard, dedup effectiveness metrics, manual merge/split controls
- **Data**: `/api/v1/deduplication/*` (18 endpoints), `/api/v1/identity/*` (7 endpoints)

#### ThreatFeeds.tsx → Threat Intelligence (80 → 400+ LOC)
- **New path**: `/discover/threats`
- **Components**: Feed status dashboard (50+ feeds with health), trending CVEs this week, MITRE ATT&CK heatmap, EPSS score distribution, KEV status tracker, feed configuration (enable/disable/schedule), AI-correlated threat briefing
- **Data**: `/api/v1/feeds/*` (30 endpoints)

#### SystemHealth.tsx → System Health (89 → 300+ LOC)
- **New path**: `/settings/health`
- **Components**: Backend service status grid, database stats (size, WAL, connections), API latency chart, queue depth, integration health, LLM token usage, error rate trends
- **Data**: `/api/v1/health/*` (4 endpoints), `/api/v1/status`

#### Inventory.tsx → Merge into SBOM & Inventory (53 → merged)
- **New path**: `/discover/sbom` (merge with SBOMGeneration.tsx)
- **Components**: Asset inventory table (repos, services, containers, cloud resources), SBOM viewer (CycloneDX/SPDX tree), license compliance checker, dependency graph, outdated package alerts
- **Data**: `/api/v1/inventory/*` (19 endpoints)

### Pages to Enhance (key partial pages, 100-400 LOC)

| Page | Current LOC | Target LOC | Key Enhancements Needed |
|------|-------------|------------|------------------------|
| CodeScanning.tsx | 260 | 400+ | Add scanner comparison view, fix suggestion cards, inline code diff |
| AttackPaths.tsx | 395 | 500+ | Add Wiz-style graph visualization, blast radius calculator, remediation impact preview |
| ContainerSecurity.tsx | 134 | 350+ | Add image scan results table, runtime protection config, registry monitoring |
| SBOMGeneration.tsx | 136 | 400+ | Merge with Inventory, add dependency tree, license compliance, outdated alerts |
| AutoFixDashboard.tsx | 248 | 400+ | Add PR preview with diff, test results, one-click approve, batch operations |
| Copilot.tsx | 153 | 400+ | Persistent sidebar mode, conversation memory, context-aware suggestions, quick actions |
| SLSAProvenance.tsx | 142 | 300+ | Add attestation verification, build provenance chain, compliance linkage |
| AttackSimulation.tsx | 123 | 400+ | MITRE ATT&CK scenario builder, kill chain visualization, tabletop exercises |
| Reachability.tsx | 103 | 300+ | Network path visualization, internet-reachable surface map, filter by criticality |
| AlgorithmicLab.tsx | 118 | 350+ | Model training UI, A/B test config, feature importance charts, evaluation metrics |
| LiveFeedDashboard.tsx | 206 | 350+ | Real-time event stream with filters, event type badges, alarm configuration |
| SOC2EvidenceUI.tsx | 337 | 450+ | Control-by-control evidence completeness, auditor portal view, gap analysis |
| MultiLLMPage.tsx | 316 | 400+ | Provider health dashboard, consensus visualization, cost tracking, model comparison |
| NerveCenter.tsx | 306 | Merge | Merge into Command Dashboard (see Section 4.3) |

## 6.4 Backend Build Tasks

### New Backend Components to Build

| Component | Suite | File | LOC | Sprint | Description |
|-----------|-------|------|-----|--------|-------------|
| FAIL Engine | suite-attack | `attack/fail_engine.py` | ~1,830 | 1 | Fault injection, response grading, neglect zones |
| FAIL Router | suite-attack | `api/fail_router.py` | ~200 | 1 | 7 API endpoints for FAIL Engine |
| Attack Path Engine | suite-core | `core/attack_path_engine.py` | ~800 | 1 | FalkorDB graph traversal for attack paths |
| MCP Gateway | suite-integrations | `api/mcp_router.py` (extend) | ~3,500 | 2 | Full MCP protocol, auto-discovery, SSE transport |
| Single Agent | suite-core | `core/single_agent.py` | ~2,000 | 2 | vLLM integration, 4 roles + moderator, fine-tuning |
| Quantum Crypto | suite-core | `core/crypto.py` (extend) | ~1,800 | 3 | Hybrid RSA + ML-DSA signing |
| Compliance Engine | suite-evidence-risk | `evidence/compliance_engine.py` | ~1,500 | 3 | Auto-mapping findings to SOC2/PCI/ISO/NIST controls |
| Zero-Gravity | suite-core | `core/zero_gravity.py` | ~1,500 | 5 | 4-tier aging, sqlite-zstd, River ML, MinHash dedup |
| FalkorDB Client | suite-core | `core/falkordb_client.py` | ~500 | 1-2 | Replace NetworkX with FalkorDB |
| aldeci.yaml Parser | suite-core | `core/app_config.py` | ~300 | 1 | APP_ID + component + policy parsing |

### Existing Backend Improvements

| Component | File | Change | Sprint |
|-----------|------|--------|--------|
| Brain Pipeline | `core/brain_pipeline.py` | Wire in FalkorDB for Step 5, real EPSS for Step 6 | 1 |
| Policy Engine | `core/policy_engine.py` | YAML-driven policies from aldeci.yaml | 1 |
| Evidence Router | `api/evidence_router.py` | Add quantum signature verification endpoint | 3 |
| Dedup Engine | `core/dedup_engine.py` | Add MinHash/LSH for near-duplicate detection | 5 |
| Learning Store | `core/api_learning_store.py` | Migrate from scikit-learn batch to River online learning | 5 |

## 6.5 Critical Stub Pages to Rebuild — Priority Order

Based on demo impact and persona coverage:

**P0 — Demo blockers** (rebuild immediately):
1. Workflows.tsx (71 LOC) — Core automation, needed for every demo
2. Collaboration.tsx (72 LOC) — Team collaboration, needed for team demos
3. Reports.tsx (76 LOC) — Executive reports, needed for CISO demos
4. EvidenceBundles.tsx (74 LOC) — Evidence generation, needed for compliance demos
5. AuditLogs.tsx (52 LOC) — Audit trail, needed for compliance demos

**P1 — Feature completeness**:
6. IaCScanning.tsx (67 LOC) — Required for cloud security story
7. ThreatFeeds.tsx (80 LOC) — Required for threat intel story
8. CorrelationEngine.tsx (78 LOC) — Required for dedup story
9. Users.tsx (55 LOC) — Required for RBAC/enterprise
10. Teams.tsx (55 LOC) — Required for ownership model
11. Policies.tsx (75 LOC) — Required for policy engine

**P2 — Nice to have**:
12. Marketplace.tsx (66 LOC) — Connector marketplace
13. SystemHealth.tsx (89 LOC) — Admin monitoring
14. Predictions.tsx (76 LOC) — ML predictions
15. Inventory.tsx (53 LOC) — Merge into SBOM page

---

# Part VII — Business Case

## 7.1 Pricing Model (APP_ID-Based)

| Tier | Annual Price | Includes |
|------|-------------|---------|
| **Community** | Free | 3 APP_IDs, OSS scanners only, no LLM, SQLite |
| **Professional** | $36-60K/yr | 25 APP_IDs, Multi-LLM, FalkorDB, MPTE, basic compliance |
| **Enterprise** | $96-180K/yr | Unlimited APP_IDs, self-hosted LLM, quantum-secure, RBAC, SSO, audit trail |
| **Air-Gapped** | $180-300K/yr | Full offline, dedicated support, custom compliance frameworks, SLA guarantees |

**Revenue path to $10M ARR**:

| Quarter | Customers | Avg MRR | ARR |
|---------|-----------|---------|-----|
| Q1 2026 | 5 design partners | $0 | $0 |
| Q2 2026 | 10 paid (Pro) | $4K | $480K |
| Q3 2026 | 20 paid (Pro+Ent) | $6K | $1.4M |
| Q4 2026 | 35 paid | $7K | $2.9M |
| 2027 | 80 paid | $10K | $9.6M |

## 7.2 Competitive Comparison Matrix

| Capability | Snyk | Wiz | ArmorCode | Apiiro | ALdeci |
|-----------|------|-----|-----------|--------|--------|
| APP_ID hierarchy | ❌ | ❌ | ❌ | ❌ (repo-level) | ✅ App→Component→Feature |
| Design stage integration | ❌ | ❌ | ❌ | ❌ | ✅ architecture.md→graph |
| IDE real-time agent | ✅ scanner | ❌ | ❌ | ❌ | ✅ Agent+MCP+scanner |
| ALM bi-directional sync | ❌ push only | ❌ | ✅ basic | ❌ | ✅ Full Jira/Confluence |
| Tool orchestration | ❌ replaces | ❌ replaces | ✅ ingests | ✅ ingests | ✅ Orchestrate+OSS fallback |
| Knowledge graph | ❌ flat list | ❌ | ❌ | ✅ basic | ✅ FalkorDB full graph |
| Multi-LLM consensus | ❌ | ❌ | ❌ | ❌ | ✅ 3 LLMs OR self-hosted |
| Micro-pentest engine | ❌ | ❌ | ❌ | ❌ | ✅ 19-phase MPTE |
| Attack paths | ❌ | ✅ cloud only | ❌ | ✅ code→cloud | ✅ Code→Cloud+MPTE verify |
| Quantum-secure evidence | ❌ | ❌ | ❌ | ❌ | ✅ FIPS 204 ML-DSA |
| Self-learning ML | ❌ | ❌ | ❌ | ❌ | ✅ 5 feedback loops |
| NL queries | ❌ | ❌ | ❌ | ❌ | ✅ MindsDB+FalkorDB |
| Air-gapped/on-prem | ❌ | ❌ | ❌ | ❌ | ✅ Full offline |
| MCP server (AI-native) | ❌ | ❌ | ❌ | ❌ | ✅ 650 tools auto-discovered |
| CTEM full loop | ❌ scan only | ❌ detect only | ❌ partial | ❌ partial | ✅ 5-phase+signed proof |
| FAIL Engine | ❌ | ❌ | ❌ | ❌ | ✅ Chaos for AppSec |
| Zero-Gravity Data | N/A (cloud) | N/A (cloud) | N/A (cloud) | N/A (cloud) | ✅ <1 GB/yr on-prem |

## 7.3 The 7-Point Moat

1. **APP_ID-centric graph** — Requires rearchitecting from scratch (12-18 months for competitors)
2. **Switzerland positioning** — Works with every tool, replaces none (Snyk CAN'T do this — they ARE a tool)
3. **Multi-LLM consensus** — No competitor has weighted voting across 3+ LLMs
4. **MPTE verification** — Only platform that PROVES exploitability
5. **Quantum-secure evidence** — Zero competitors have FIPS 204/205 post-quantum crypto
6. **MCP-native** — First AppSec platform AI agents can programmatically use
7. **Self-learning** — 5 feedback loops continuously improve all models

---

# Part VIII — Agent Context

> **For Claude agents executing build tasks**: This section contains everything you need to write code correctly in this codebase.

## 8.1 Repository Structure

```
Fixops/                         (monorepo root)
├── sitecustomize.py            # Auto-prepends all suite paths to sys.path
├── requirements.txt            # Python dependencies
├── pyproject.toml              # pytest config, markers, coverage
├── Makefile                    # test, fmt, demo commands
│
├── suite-api/                  # FastAPI gateway
│   └── apps/api/
│       ├── app.py              # Main FastAPI app, include_router() calls
│       ├── dependencies.py     # X-API-Key auth
│       ├── *_router.py         # Route handlers
│       └── routes/             # Additional route modules
│
├── suite-core/                 # Brain, pipeline, connectors
│   ├── core/
│   │   ├── brain_pipeline.py   # 12-step pipeline
│   │   ├── connectors.py       # _BaseConnector, JiraConnector, etc.
│   │   ├── crypto.py           # RSA signing (extend for quantum)
│   │   ├── event_bus.py        # Event-driven messaging (no external MQ)
│   │   ├── llm_providers.py    # GPT-4, Claude, Gemini providers
│   │   └── *_models.py         # Dataclasses, Pydantic models, enums
│   └── api/
│       └── *_router.py         # Brain, copilot, decisions, LLM routes
│
├── suite-attack/               # MPTE, attack simulation
│   ├── attack/
│   │   ├── micro_pentest.py    # 19-phase MPTE engine
│   │   └── mpte_advanced.py    # AI-powered MPTE orchestrator
│   └── api/
│       └── *_router.py         # MPTE, attack sim, SAST, DAST routes
│
├── suite-feeds/                # Threat intelligence
│   ├── feeds/
│   │   └── *.py                # NVD, KEV, EPSS, GitHub, OSV adapters
│   └── api/
│       └── feeds_router.py     # 30 feed endpoints
│
├── suite-evidence-risk/        # Compliance, evidence, risk
│   ├── evidence/               # Evidence bundle generation
│   ├── risk/                   # Risk scoring, reachability
│   └── api/
│       └── *_router.py         # Evidence, risk, compliance routes
│
├── suite-integrations/         # External tool connectors
│   └── api/
│       └── *_router.py         # IDE, MCP, integrations, webhooks
│
├── suite-ui/aldeci/            # ❄️ FROZEN — Legacy UI (do not modify)
│   ├── src/                    # Reference only, not active development
│   │   ├── App.tsx
│   │   ├── layouts/
│   │   ├── pages/
│   │   ├── components/
│   │   └── lib/
│
├── suite-ui/aldeci-ui-new/     # ✅ NEW — 5 Workflow Spaces (Apple HIG + shadcn/ui)
│   ├── src/
│   │   ├── App.tsx             # React Router — 5 spaces + onboarding
│   │   ├── layouts/
│   │   │   └── WorkspaceLayout.tsx  # 5-space sidebar + persistent AI Copilot
│   │   ├── spaces/             # Pages grouped by Workflow Space
│   │   │   ├── mission-control/ # Dashboard, Executive, SLA, LiveFeed, Risk
│   │   │   ├── discover/        # Findings, Code, Secrets, IaC, Cloud, SBOM, Graph
│   │   │   ├── validate/        # MPTE, AttackSim, FAIL, Playbooks, Reachability
│   │   │   ├── remediate/       # RemCenter, AutoFix, Bulk, Collab, Workflows
│   │   │   └── comply/          # Compliance, Evidence, Bundles, SOC2, Audit, Reports
│   │   ├── components/
│   │   │   ├── ui/             # shadcn/ui primitives (Radix-based)
│   │   │   └── aldeci/         # Custom Apple-inspired components
│   │   └── lib/
│   │       └── api.ts          # Axios client, API namespaces
│   ├── package.json
│   └── vite.config.ts
│
├── tests/                      # pytest test files
│   ├── conftest.py             # Shared fixtures
│   └── test_*.py               # Test modules
│
├── data/                       # Runtime data (SQLite DBs, artifacts)
├── docker/                     # Docker configurations
├── docs/                       # Documentation (this file lives here)
└── scripts/                    # Utility scripts
```

## 8.2 Import Resolution (sitecustomize.py)

`sitecustomize.py` at project root is auto-loaded by Python and prepends all suite paths to `sys.path`. This means:

```python
# These imports work from anywhere in the codebase:
from core.connectors import JiraConnector
from core.brain_pipeline import run_pipeline
from core.crypto import sign_evidence
from attack.micro_pentest import MicroPentestEngine
from feeds.nvd_feed import NVDFeed
```

**NEVER manually manipulate `sys.path`** — `sitecustomize.py` handles everything.

## 8.3 Connector Pattern

All external connectors inherit from `_BaseConnector` in `suite-core/core/connectors.py`:

```python
class MyNewConnector(_BaseConnector):
    """Example: Adding a new external integration."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)  # Gets circuit breaker, retry, rate limiting
        self.base_url = config.get("url", "")
        if self.base_url and config.get("api_key"):
            self.configured = True
    
    def health_check(self) -> Dict[str, Any]:
        """Must implement — used by /api/v1/integrations/{id}/test"""
        return self._request("GET", f"{self.base_url}/health")
    
    def fetch_data(self) -> List[Dict]:
        """Custom method for this connector."""
        return self._request("GET", f"{self.base_url}/api/v1/data")
```

**Key features from `_BaseConnector`**:
- Circuit breaker (`CircuitBreaker` dataclass) — auto-opens after N failures
- Retry with exponential backoff (urllib3 `Retry`)
- Rate limiting
- `self.configured` flag — set to `True` when all required config fields are present

## 8.4 Router Pattern

All routers follow this pattern:

```python
# suite-api/apps/api/my_router.py
from fastapi import APIRouter, Depends
from apps.api.dependencies import verify_api_key

router = APIRouter(
    prefix="/api/v1/my-feature",
    tags=["My Feature"],
    dependencies=[Depends(verify_api_key)]
)

@router.get("/")
async def list_items():
    """List all items."""
    return {"items": [...]}

@router.post("/")
async def create_item(data: dict):
    """Create a new item."""
    return {"id": "...", "status": "created"}
```

**After creating a router, register it in `apps/api/app.py`**:

```python
from apps.api.my_router import router as my_router
app.include_router(my_router)
```

**CRITICAL**: Always add new routers to `app.py` `include_router()` calls.

## 8.5 Frontend Conventions

### Stack
- **React 18** + TypeScript
- **Vite** build tool
- **React Router v6** with lazy loading (`React.lazy`)
- **TanStack Query** for data fetching
- **shadcn/ui** for base components (`src/components/ui/`)
- **Framer Motion** for animations
- **Sonner** for toast notifications
- **recharts** for charts
- **Lucide React** for icons

### API Client (`src/lib/api.ts`)

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || 'dev-key' }
});

// Namespace pattern for API calls:
export const findingsApi = {
  list: (params?: any) => api.get('/api/v1/cases', { params }),
  get: (id: string) => api.get(`/api/v1/cases/${id}`),
  triage: (id: string, action: string) => api.post(`/api/v1/cases/${id}/triage`, { action }),
};

export const failApi = {
  inject: (data: any) => api.post('/api/v1/fail/inject', data),
  getDrills: () => api.get('/api/v1/fail/drills'),
  getDrill: (id: string) => api.get(`/api/v1/fail/drills/${id}`),
  grade: (id: string) => api.post(`/api/v1/fail/drills/${id}/grade`),
  getNeglectZones: () => api.get('/api/v1/fail/neglect-zones'),
  getReadinessScore: () => api.get('/api/v1/fail/readiness-score'),
};
```

### Page File Template

```tsx
// src/pages/validate/FAILEngine.tsx
import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { failApi } from '@/lib/api';
import { motion } from 'framer-motion';
import { Flame, Target, TrendingUp } from 'lucide-react';
import { toast } from 'sonner';

export default function FAILEngine() {
  const { data: drills, isLoading } = useQuery({
    queryKey: ['fail-drills'],
    queryFn: () => failApi.getDrills(),
  });
  
  const { data: readiness } = useQuery({
    queryKey: ['fail-readiness'],
    queryFn: () => failApi.getReadinessScore(),
  });

  const injectMutation = useMutation({
    mutationFn: (scenario: any) => failApi.inject(scenario),
    onSuccess: () => {
      toast.success('Drill injected');
      // queryClient.invalidateQueries(['fail-drills']);
    },
  });

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="container mx-auto p-6 space-y-6"
    >
      <h1 className="text-3xl font-bold">FAIL Engine</h1>
      {/* Components here — see Section 4.5 for layout spec */}
    </motion.div>
  );
}
```

### Environment Variables (`.env`)

```env
VITE_API_URL=http://localhost:8000
VITE_API_KEY=dev-key-for-local
```

## 8.6 Testing Conventions

```bash
# Run all tests
make test                           # pytest with 60% coverage gate

# Run specific test file
pytest tests/test_fail_engine.py -v

# Run by marker
pytest -m unit -v
pytest -m integration -v
pytest -m e2e -v

# Run by pattern
pytest -k "test_fail" -v
```

**Test markers** (defined in `pyproject.toml`):
- `@pytest.mark.unit` — Fast, no external deps
- `@pytest.mark.integration` — May use DB or network
- `@pytest.mark.e2e` — Full end-to-end

**Coverage gate**: 60% minimum (`--cov-fail-under=60`)

**Test file naming**: `tests/test_<feature>.py`

## 8.7 Critical Files Reference

| File | Purpose | When to Modify |
|------|---------|---------------|
| `suite-api/apps/api/app.py` | Main FastAPI app | When adding a new router |
| `suite-api/apps/api/dependencies.py` | Auth middleware | When changing auth behavior |
| `suite-core/core/connectors.py` | Base connector class | When adding new integrations |
| `suite-core/core/brain_pipeline.py` | 12-step pipeline | When modifying finding processing |
| `suite-core/core/crypto.py` | Evidence signing | When implementing quantum crypto |
| `suite-core/core/event_bus.py` | Internal messaging | When adding new events |
| `suite-core/core/llm_providers.py` | LLM integrations | When adding Single Agent mode |
| `suite-core/core/integration_models.py` | `IntegrationType` enum | When adding new integration types |
| `suite-ui/aldeci/src/App.tsx` | **FROZEN** Legacy routing | **DO NOT MODIFY** |
| `suite-ui/aldeci/src/layouts/MainLayout.tsx` | **FROZEN** Legacy sidebar | **DO NOT MODIFY** |
| `suite-ui/aldeci/src/lib/api.ts` | **FROZEN** Legacy API client | **DO NOT MODIFY** |
| `suite-ui/aldeci-ui-new/src/App.tsx` | NEW frontend routing | When adding new pages |
| `suite-ui/aldeci-ui-new/src/layouts/WorkspaceLayout.tsx` | 5-space sidebar + Copilot | When reorganizing spaces |
| `suite-ui/aldeci-ui-new/src/lib/api.ts` | NEW API client | When adding new API namespaces |
| `sitecustomize.py` | Import path setup | Almost never |
| `pyproject.toml` | pytest config | When adding test markers |

### Key Design Rules for Agents

1. **All DBs use SQLite with WAL mode** — No Postgres, no MySQL
2. **No external message queues** — Use `core/event_bus.py` for event-driven messaging
3. **Signed evidence** — All evidence bundles must be cryptographically signed
4. **NEVER create files in `WIP/`** — Excluded from formatting/linting
5. **Add new routers to `app.py`** — Or they won't be mounted
6. Add API namespace in `suite-ui/aldeci-ui-new/src/lib/api.ts` — Follow existing pattern
7. **All new UI in `aldeci-ui-new/`** — NEVER modify `suite-ui/aldeci/` (frozen legacy)
8. **Use shadcn/ui components** — Apple HIG-inspired, don't install competing UI libs
8. **Use Lucide icons** — Don't install other icon libraries
9. **Use TanStack Query for data fetching** — Not raw useEffect + fetch
10. **Use Sonner for toasts** — Not custom toast implementations

---

# Appendix A — CTEM Loop Mapping

The Continuous Threat Exposure Management (CTEM) framework maps directly to ALdeci's phases:

| CTEM Phase | ALdeci Phase | Key Screens | Key Endpoints |
|-----------|-------------|-------------|---------------|
| **Scoping** | ① Design | Onboarding Wizard, Settings/Integrations | `/api/v1/apps`, aldeci.yaml |
| **Discovery** | ②③④⑤⑥ | Discover space (all pages) | Scanning, inventory, feed endpoints |
| **Prioritization** | ⑦⑧ | Knowledge Graph, Brain Pipeline, AI Copilot | `/api/v1/brain/*`, `/api/v1/risk/*` |
| **Validation** | ⑧ (MPTE) | Validate space (MPTE, FAIL, Simulation) | `/api/v1/mpte/*`, `/api/v1/fail/*` |
| **Mobilization** | ⑨⑩ | Remediate + Comply spaces | `/api/v1/remediation/*`, `/api/v1/evidence/*` |

---

# Appendix B — 5 Self-Learning Feedback Loops

| Loop | Input Signal | What Improves | Storage |
|------|-------------|--------------|---------|
| 1. Decision Outcomes | Human marks decision correct/incorrect | LLM consensus weights, role prompts | Prioritized experience buffer |
| 2. MPTE Results | Pentest confirms/denies vulnerability | Scan targeting (skip NOT_APPLICABLE) | MPTE results DB |
| 3. False Positive Rates | Developer marks finding as FP | Dedup clustering thresholds per APP_ID | Learning store |
| 4. Remediation Success | AutoFix PRs that pass/fail CI | Fix strategy ranking, pattern preference | Remediation outcomes DB |
| 5. Policy Violations | SLA breaches, policy overrides | Auto-adjust rules, suggest policy updates | Audit trail |

---

# Appendix C — Integration Type Wiring Checklist

When adding a new integration:

1. Add to `IntegrationType` enum in `suite-core/core/integration_models.py`
2. Create connector class extending `_BaseConnector` in `suite-core/core/connectors.py`
3. Add `elif` case in `test_integration()` endpoint in `suite-integrations/api/integrations_router.py`
4. Add `elif` case in `trigger_sync()` endpoint in same file
5. Add to marketplace catalog in `suite-api/apps/api/marketplace_router.py`
6. Add API namespace in `suite-ui/aldeci-ui-new/src/lib/api.ts`
7. Add health check badge in Integrations settings page

---

# Appendix D — Quantified Impact Summary

| Metric | Today (Manual) | With ALdeci | Improvement |
|--------|---------------|-------------|-------------|
| Findings → actionable cases | 11,300 | 340 | 97% noise reduction |
| MTTD | 4 hours | 12 minutes | 20× faster |
| MTTR | 14 days | 2.3 days | 6× faster |
| False positive rate | 68% | 3% | 22× better |
| Pentests per year | 1 | 365 | 365× more |
| Audit prep | 3 weeks | 2 hours | 252× faster |
| Compliance evidence | Manual, 2 days | Auto, 5 min | 576× faster |
| Cost per vuln fixed | $4,200 | $890 | 79% cheaper |
| Annual tool cost savings | — | $110K/yr | — |
| On-prem storage | ~20 GB/yr | ~1 GB/yr | 95% reduction |
| API token cost (self-hosted) | $6,000/mo | $0/mo | 100% savings |
| Night/weekend coverage | 0% | 100% | ∞ |

---

*End of VISION_TO_ACCOMPLISH.MD*
*Total: 8 Parts + 4 Appendices*
*Sources: ALDECI_UNIFIED_VISION.md, USER_STORY_APP_FLOW.md, research_next_features_to_build.md*
*Created: 2026-02-27*
