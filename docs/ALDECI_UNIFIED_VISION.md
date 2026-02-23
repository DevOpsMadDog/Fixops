# ALdeci — Unified Platform Vision: APP_ID-Centric Security Intelligence

> **The Complete Lifecycle**: From application design to quantum-secure compliance evidence — organized around a single identity: **APP_ID**.

> *"Not a scanner — a Security Brain that knows your application from architecture to production."*

---

## Executive Summary

ALdeci is the **Decision Intelligence layer for AI-native security**. Unlike scanners (Snyk, Checkmarx, Veracode) that scan code after it's written, ALdeci builds a **living knowledge graph** of every application from the moment it's designed, through development, build, deployment, and runtime — all organized around a hierarchical APP_ID.

**The APP_ID is the atom of ALdeci.** Every finding, every decision, every evidence bundle, every compliance control traces back to a specific application → component → feature. This is the missing link in every competitor's architecture.

---

## Part 1: The APP_ID Hierarchy

```
APP_ID (e.g., "website-12345")
├── component_id: payment-service (ABCD)
│   ├── feature: checkout-flow (PR #421)
│   ├── feature: refund-engine (PR #388)
│   └── dependencies: stripe-sdk@3.2, redis@7.0
├── component_id: auth-service (EFGH)
│   ├── feature: oauth2-flow (PR #415)
│   └── dependencies: passport@0.6, bcrypt@5.1
├── component_id: frontend-app (IJKL)
│   └── feature: dashboard-v2 (PR #430)
├── infrastructure:
│   ├── iac: terraform/aws/ (VPC, ECS, RDS)
│   ├── runtime: ECS Fargate, us-east-1
│   └── secrets: AWS Secrets Manager
└── compliance:
    ├── frameworks: SOC2, PCI-DSS
    ├── data-classification: PII, PCI
    └── retention: 7 years
```

**Why APP_ID matters**: Competitors treat findings as flat lists. ALdeci ties every vulnerability, every decision, every evidence bundle to a specific application component. This enables:
- **Contextual risk scoring**: A SQL injection in `payment-service` (PCI scope) is 10x more critical than in an internal dashboard
- **Component-aware scanning**: Run different tool chains per component (SAST for auth, DAST for APIs, container scanning for microservices)
- **Blast radius calculation**: If `payment-service` is compromised, what data/users/revenue is affected?
- **Compliance mapping**: Auto-generate per-APP_ID compliance evidence for auditors

---

## Part 2: The 10-Phase Lifecycle

ALdeci covers the **full application security lifecycle** — from design through self-learning — in 10 phases:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ALdeci 10-Phase Lifecycle                     │
│                                                                 │
│  ①Design → ②IDE → ③ALM → ④Pre-merge → ⑤Build → ⑥IaC/Runtime  │
│                              ↓                                  │
│  ⑦ Knowledge Graph (FalkorDB) ← all phases feed into graph     │
│                              ↓                                  │
│  ⑧ AI Decision Engine (12-step pipeline)                       │
│                              ↓                                  │
│  ⑨ Remediation + Evidence + Compliance                         │
│                              ↓                                  │
│  ⑩ Self-Learning (ML + feedback loops)                         │
│                              ↓                                  │
│              loops back to all phases                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase ① — Design Stage: APP_ID Birth

**When**: Before a single line of code is written.
**What**: Architect creates an APP_ID and defines its architecture.

### Flow

```
Architect creates new project
        │
        ▼
┌─────────────────────────────┐
│  ALdeci APP_ID Registration │
│  • APP_ID auto-generated    │
│  • Name, owner, team        │
│  • Data classification      │
│  • Compliance frameworks    │
│  • Business criticality     │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  architecture.md created    │
│  (in repo root or Confluence│
│  • System diagram (Mermaid) │
│  • Component breakdown      │
│  • Data flows               │
│  • Technology stack          │
│  • Security requirements    │
│  • Threat model (STRIDE)    │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  FalkorDB: First Nodes      │
│  (:App {id: APP_ID})        │
│  (:Component {id: comp_id}) │
│  (:DataFlow {from, to})     │
│  (:ThreatModel {stride})    │
│  (:ComplianceReq {soc2..})  │
└─────────────────────────────┘
```

### What Gets Created

| Artifact | Storage | Purpose |
|----------|---------|---------|
| APP_ID record | FalkorDB + SQLite | Central identity for everything |
| `architecture.md` | Git repo root | Human-readable system design |
| Component graph | FalkorDB | Architecture as queryable graph |
| Threat model | FalkorDB | STRIDE threats linked to components |
| Compliance tags | FalkorDB | Which frameworks apply to this app |
| Scanning config | `aldeci.yaml` in repo | Tools/policies per component |

### `aldeci.yaml` — Per-APP_ID Configuration

```yaml
# aldeci.yaml — lives in each repo root
app_id: "website-12345"
owner: "platform-team"
data_classification: "pci"
compliance_frameworks: ["soc2", "pci-dss"]
business_criticality: "high"  # high/medium/low

components:
  payment-service:
    id: "comp-ABCD"
    type: "microservice"
    language: "python"
    scan_tools:
      sast: ["semgrep", "bandit"]
      sca: ["snyk", "trivy"]
      dast: ["zap"]
      secrets: ["gitleaks"]
      iac: ["checkov"]
    policies:
      sla_critical: "24h"
      sla_high: "7d"
      auto_fix: true
      block_on: ["critical", "high-exploitable"]
    
  auth-service:
    id: "comp-EFGH"
    type: "microservice"
    language: "golang"
    scan_tools:
      sast: ["semgrep", "gosec"]
      sca: ["snyk"]
    policies:
      sla_critical: "4h"  # auth is highest priority
      block_on: ["critical"]

  frontend-app:
    id: "comp-IJKL"
    type: "spa"
    language: "typescript"
    scan_tools:
      sast: ["eslint-security", "semgrep"]
      sca: ["npm-audit"]
    policies:
      sla_critical: "48h"
      auto_fix: true

# OSS fallback: if customer doesn't have Snyk/Veracode,
# ALdeci runs its own Trivy/Grype/Semgrep/Gitleaks
oss_fallback: true

# Pre-merge gate
pre_merge:
  required_checks: ["sast", "sca", "secrets"]
  block_severity: "critical"
  require_review_for: ["high"]
```

### Existing Capabilities Enhanced

| Existing Feature | Enhancement |
|-----------------|-------------|
| Brain Pipeline Step 1 (connect) | Now has APP_ID context — knows WHICH app it's connecting |
| Knowledge Graph (NetworkX) | Migrates to FalkorDB with APP_ID as root node |
| Policy Engine (Step 8) | Reads `aldeci.yaml` per-component policies |
| Compliance Mapping | Auto-tags from Design Stage frameworks |
| Evidence Bundles | Scoped per APP_ID for audit isolation |

### New Capabilities

| Feature | From Research Doc | Status |
|---------|------------------|--------|
| Architecture-as-graph | Gap 3: Cloud Attack Path | NEW |
| Threat modeling integration | Gap 4: Compliance | NEW |
| Per-component tool config | Not in any feature | NEW |
| `aldeci.yaml` GitOps config | Part 25: MCP/Config | NEW |

---

## Phase ② — Developer IDE: Real-Time Security Intelligence

**When**: While developers write code.
**What**: ALdeci agent runs in the IDE, providing security context and pre-commit validation.

### Flow

```
Developer opens project in VS Code / JetBrains / Cursor
        │
        ▼
┌─────────────────────────────────────────┐
│  ALdeci IDE Extension / MCP Server      │
│  • Reads aldeci.yaml → knows APP_ID    │
│  • Reads architecture.md → knows design│
│  • Background scanning (lightweight)    │
│  • Inline security hints               │
│  • Pre-commit hook integration          │
└────────────┬────────────────────────────┘
             │
    ┌────────┼────────────┐
    ▼        ▼            ▼
┌────────┐ ┌──────────┐ ┌──────────────┐
│ Detect │ │ Metadata │ │ Pre-commit   │
│ tools  │ │ collect  │ │ gate         │
│ in use │ │          │ │              │
│ (Snyk, │ │ • deps   │ │ • secrets    │
│ ESLint,│ │ • APIs   │ │ • critical   │
│ etc.)  │ │ • envs   │ │   vulns      │
└────┬───┘ └────┬─────┘ └──────┬───────┘
     │          │               │
     └──────────┴───────────────┘
                │
                ▼
  FalkorDB Knowledge Graph (APP_ID node updated)
```

### IDE Agent Capabilities

| Capability | Description | Existing/New |
|-----------|-------------|--------------|
| **Tool Detection** | Scans `package.json`, `.snyk`, `sonar-project.properties` to know which tools the team uses | NEW (from user vision) |
| **Background Scanning** | Runs lightweight Semgrep/Trivy on save (not blocking) | NEW (Research Gap 1: VS Code Ext) |
| **Architecture MD Watch** | Detects changes to `architecture.md`, updates graph | NEW (from user vision) |
| **Pre-commit Gate** | Blocks commits with secrets or critical vulns from `aldeci.yaml` | NEW (Research Gap 1) |
| **Inline Annotations** | Shows EPSS/KEV/risk context on CVE comments in code | NEW (Research Gap 5: AI Copilot) |
| **MCP Server** | AI coding agents (Copilot, Cursor, Claude) query ALdeci for security context | Existing (Research Part 25) |
| **Metadata Collection** | Tracks dependencies, APIs called, environment variables → feeds graph | NEW (from user vision) |

### MCP Integration (from Research Part 25)

```
AI Coding Agent (Copilot/Cursor/Claude)
        │
        │ MCP Protocol (tools/call)
        ▼
┌─────────────────────────────────┐
│  ALdeci MCP Server              │
│  650 auto-discovered tools      │
│  8 live resource streams        │
│  Context-aware prompts          │
├─────────────────────────────────┤
│  Agent asks:                    │
│  "Is stripe-sdk@3.2 safe?"     │
│  "Does this pattern violate     │
│   our PCI policy?"             │
│  "What's the risk score for     │
│   this auth implementation?"    │
├─────────────────────────────────┤
│  ALdeci responds with:          │
│  • APP_ID-scoped context        │
│  • Known CVEs for dependency    │
│  • Policy compliance check      │
│  • Recommended secure pattern   │
└─────────────────────────────────┘
```

---

## Phase ③ — ALM Integration: Jira/Confluence → Knowledge Graph

**When**: During sprint planning, story creation, documentation.
**What**: ALdeci watches Jira/Confluence to enrich the knowledge graph with business context.

### Flow

```
Jira / Confluence / Azure Boards
        │
        │ Webhooks + Bi-directional Sync
        ▼
┌─────────────────────────────────────────┐
│  ALdeci ALM Connector                   │
│  • Maps Jira projects → APP_IDs        │
│  • Maps epics → components              │
│  • Maps stories → features              │
│  • Syncs architecture.md to Confluence  │
│  • Links security tickets to findings   │
└────────────┬────────────────────────────┘
             │
             ▼
  FalkorDB Knowledge Graph
  (:JiraProject)-[:MAPS_TO]->(:App)
  (:Epic)-[:MAPS_TO]->(:Component)
  (:Story)-[:IMPLEMENTS]->(:Feature)
  (:SecurityTicket)-[:REMEDIATES]->(:Finding)
```

### What Gets Enriched

| ALM Artifact | Graph Enrichment | Impact |
|-------------|-----------------|--------|
| Jira Project metadata | Team ownership, sprint velocity | Owner auto-assignment for findings |
| Epic/Story structure | Component → Feature mapping | Feature-level risk scoring |
| Confluence design docs | Architecture updates | Design drift detection |
| Sprint timelines | Remediation SLA context | Smart SLA based on sprint capacity |
| Security ticket status | Real-time fix tracking | MTTR calculation per APP_ID |

### Existing Connector Enhancement

| Current | Enhanced |
|---------|----------|
| `JiraConnector` in `connectors.py` — creates tickets | + reads project structure → APP_ID mapping |
| `SlackConnector` — sends notifications | + reads channel context → team mapping |
| One-way: ALdeci → Jira | Bi-directional: Jira ↔ ALdeci ↔ FalkorDB |

---

## Phase ④ — Pre-Merge Orchestration: Component-Aware Security Gates

**When**: Developer creates a PR/MR.
**What**: ALdeci orchestrates the right security tools for the right component, based on `aldeci.yaml`.

### Flow

```
Developer creates PR in GitHub/GitLab/Azure DevOps
        │
        ▼
┌─────────────────────────────────────────────────────┐
│  ALdeci Pre-Merge Orchestrator                      │
│                                                     │
│  1. Read aldeci.yaml → determine component          │
│  2. Look up component scan_tools config             │
│  3. Orchestrate configured tools (parallel)         │
│  4. Collect results → normalize → deduplicate       │
│  5. Score risk with APP_ID context                  │
│  6. Apply component policies (block/warn/pass)      │
│  7. Post results as PR comment / check status       │
│  8. Update FalkorDB graph (feature → findings)      │
└────────────┬────────────────────────────────────────┘
             │
    ┌────────┴────────────────────────────┐
    │            TOOL ORCHESTRATION       │
    │                                     │
    │  ┌─────────┐ ┌─────────┐ ┌───────┐ │
    │  │Customer │ │Customer │ │ALdeci │ │
    │  │Tool:    │ │Tool:    │ │OSS    │ │
    │  │Snyk     │ │Veracode │ │Fallbk │ │
    │  │(if avl) │ │(if avl) │ │(Trivy,│ │
    │  │         │ │         │ │Grype, │ │
    │  │         │ │         │ │Semgrep│ │
    │  └────┬────┘ └────┬────┘ └───┬───┘ │
    │       └───────────┴──────────┘     │
    │                │                    │
    │     Normalize to Unified Schema     │
    │     (SARIF → SarifFinding)          │
    └────────────┬────────────────────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ PR Status:      │
        │ ✅ PASS         │
        │ ⚠️ WARN (2 med) │
        │ ❌ BLOCK (1 crt)│
        └─────────────────┘
```

### Key Innovation: Tool Orchestration, Not Tool Replacement

ALdeci does NOT replace Snyk/Veracode/Checkmarx. It **orchestrates** them:

| If Customer Has | ALdeci Does | If Customer Doesn't Have | ALdeci Does |
|----------------|-------------|-------------------------|-------------|
| Snyk | Ingest Snyk results via API/webhook | No SCA tool | Run Trivy + Grype (OSS fallback) |
| Veracode | Ingest Veracode SARIF | No SAST tool | Run Semgrep (OSS fallback) |
| Wiz | Ingest Wiz findings | No CSPM tool | Run Prowler + Checkov (OSS fallback) |
| OWASP ZAP | Ingest ZAP results | No DAST tool | Run ZAP scan (OSS fallback) |
| Gitleaks | Ingest secret findings | No secrets tool | Run ALdeci Secrets Scanner |

**This is the "Switzerland of AppSec"** — we work with every tool, replace none, add intelligence to all.

### Existing Pipeline Integration

This phase maps to **Steps 1-4** of the existing 12-step Brain Pipeline:
- Step 1 (connect): Now triggered by PR webhook, reads `aldeci.yaml`
- Step 2 (normalize): Same SARIF/SBOM normalization, now scoped to component
- Step 3 (resolve_identity): Uses APP_ID + component_id from `aldeci.yaml`
- Step 4 (deduplicate): Cross-tool dedup within the same component scope

---

## Phase ⑤ — Build Server: SBOM + Dependency Graph

**When**: CI/CD pipeline builds the application.
**What**: Lightweight ALdeci build agent generates SBOM and dependency graph.

### Flow

```
CI/CD Pipeline (GitHub Actions / GitLab CI / Jenkins)
        │
        ▼
┌─────────────────────────────────────────┐
│  ALdeci Build Agent (lightweight)       │
│                                         │
│  1. Identify APP_ID from aldeci.yaml    │
│  2. Generate SBOM (CycloneDX/SPDX)     │
│  3. Build dependency graph              │
│  4. Compute component hashes            │
│  5. Generate SLSA provenance attestation│
│  6. Push to FalkorDB knowledge graph    │
└────────────┬────────────────────────────┘
             │
             ▼
  FalkorDB Knowledge Graph
  (:Build {hash, timestamp})
  (:SBOM {format, components[]})
  (:Dependency)-[:DEPENDS_ON]->(:Dependency)
  (:Build)-[:PRODUCES]->(:Artifact)
  (:Artifact)-[:ATTESTED_BY]->(:SLSAProvenance)
```

### SBOM as First-Class Graph Citizen

```
# FalkorDB query: "Show all dependencies of payment-service
#                   that have known exploits"

MATCH (app:App {id: 'website-12345'})
  -[:HAS_COMPONENT]->(comp:Component {name: 'payment-service'})
  -[:BUILT_WITH]->(build:Build)
  -[:CONTAINS]->(dep:Dependency)
  -[:HAS_CVE]->(cve:CVE)
WHERE cve.epss > 0.5 OR cve.kev = true
RETURN dep.name, dep.version, cve.id, cve.epss, cve.kev
ORDER BY cve.epss DESC
```

### Existing Enhancement

| Current | Enhanced |
|---------|----------|
| SBOM ingestion via `/inputs/sbom` | Auto-generated at build time, linked to APP_ID |
| Flat dependency list | Graph-based dependency tree with transitive deps |
| Basic SLSA provenance | Full SLSA v1 attestation with hybrid RSA + ML-DSA signing (Phase ⑧ quantum-secure) |

---

## Phase ⑥ — IaC / Runtime: Infrastructure → Knowledge Graph

**When**: Platform/DevOps teams manage infrastructure.
**What**: ALdeci collects IaC definitions and runtime metadata, linking them to APP_IDs.

### Flow

```
Platform Team
├── Terraform/CloudFormation/Pulumi definitions
├── Kubernetes manifests
├── Cloud provider tags (AWS tags, Azure labels)
└── Runtime observability (Datadog, Prometheus tags)
        │
        ▼
┌─────────────────────────────────────────────────┐
│  ALdeci Infrastructure Connector                │
│                                                 │
│  1. Parse IaC → extract resources per APP_ID    │
│  2. Map cloud tags → APP_ID (e.g., tag:app_id) │
│  3. Discover runtime topology (K8s namespaces)  │
│  4. Collect network policies, security groups   │
│  5. Identify internet-facing surfaces           │
│  6. Map data flows (VPC peering, API calls)     │
│  7. Push to FalkorDB knowledge graph            │
└────────────┬────────────────────────────────────┘
             │
             ▼
  FalkorDB Knowledge Graph
  (:CloudResource {type: 'rds', region: 'us-east-1'})
  (:SecurityGroup)-[:ALLOWS]->{port, cidr}
  (:Component)-[:DEPLOYED_ON]->(:CloudResource)
  (:CloudResource)-[:INTERNET_FACING]->{true/false}
  (:CloudResource)-[:STORES]->(:DataClassification {pci: true})
```

### Attack Path Foundation

This phase creates the data needed for **attack path analysis** (Research Gap 3):

```
Internet
  → Load Balancer (internet-facing)
    → ECS Service (auth-service)
      → RDS Instance (user-db, PCI data)
        → Contains: CVE-2024-1234 (SQLi, EPSS 0.97, KEV: YES)

BLAST RADIUS: 2.3M user records, PCI cardholder data
ATTACK PATH SCORE: 9.8 (internet → crown jewel in 3 hops)
```

### Existing Enhancement

| Current | Enhanced |
|---------|----------|
| Prowler adapter (cloud audit) | + IaC parsing + runtime topology |
| Checkov adapter (IaC scanning) | + resource → APP_ID mapping |
| AWS Security Hub connector | + tag-based APP_ID resolution |
| No runtime awareness | Runtime metadata (K8s, cloud tags) → graph |

---

## Phase ⑦ — Knowledge Graph: FalkorDB — The Security Brain

**This is the heart of ALdeci.** All 6 preceding phases feed data into a single, queryable knowledge graph.

### Why FalkorDB (Not NetworkX, Not Neo4j)

| Criteria | NetworkX (Current) | Neo4j | FalkorDB |
|----------|-------------------|-------|----------|
| Production-ready | ❌ In-memory only | ✅ | ✅ |
| Cost | Free | $65K+/year | **Free edition** |
| LLM-optimized | ❌ | ❌ | ✅ GraphRAG built-in |
| Redis-compatible | ❌ | ❌ | ✅ (runs on Redis) |
| Cypher queries | ❌ | ✅ | ✅ (subset) |
| Visual explorer | ❌ | ✅ (Bloom) | ✅ (code-graph.falkordb.com) |
| Self-hosted | N/A | ✅ | ✅ |
| Air-gapped | ✅ | ✅ | ✅ |

### Graph Schema

```
# Core Entities (Nodes)
(:App {id, name, owner, team, criticality, data_class})
(:Component {id, name, type, language, app_id})
(:Feature {id, name, pr_number, component_id})
(:Finding {id, cve, severity, source_tool, status})
(:CVE {id, cvss, epss, kev, cwe, description})
(:Dependency {name, version, license, ecosystem})
(:CloudResource {id, type, region, internet_facing})
(:Build {id, hash, timestamp, slsa_attested})
(:SBOM {id, format, component_count})
(:ThreatModel {stride_type, threat, mitigation})
(:ComplianceControl {framework, control_id, description})
(:Evidence {id, type, signed, signature_version})
(:Decision {id, action, confidence, llm_votes})
(:Playbook {id, name, trigger, actions})
(:JiraTicket {key, status, assignee, sprint})

# Relationships (Edges)
(:App)-[:HAS_COMPONENT]->(:Component)
(:Component)-[:HAS_FEATURE]->(:Feature)
(:Feature)-[:INTRODUCED]->(:Finding)
(:Finding)-[:REFERENCES]->(:CVE)
(:Finding)-[:AFFECTS]->(:Component)
(:Component)-[:DEPENDS_ON]->(:Dependency)
(:Dependency)-[:HAS_CVE]->(:CVE)
(:Component)-[:DEPLOYED_ON]->(:CloudResource)
(:CloudResource)-[:CONNECTS_TO]->(:CloudResource)
(:CloudResource)-[:EXPOSES]->(:Finding)  # attack path edge
(:Finding)-[:DECIDED_BY]->(:Decision)
(:Decision)-[:PRODUCES]->(:Evidence)
(:Finding)-[:REMEDIATES_VIA]->(:JiraTicket)
(:Finding)-[:COMPLIES_WITH]->(:ComplianceControl)
(:Build)-[:PRODUCES]->(:SBOM)
(:SBOM)-[:CONTAINS]->(:Dependency)
(:App)-[:GOVERNED_BY]->(:ComplianceControl)
(:Evidence)-[:SATISFIES]->(:ComplianceControl)
```

### Natural Language Queries via MindsDB

```
# MindsDB sits on top of FalkorDB, enabling:

User: "Show me all critical vulnerabilities in payment-service 
       that are internet-reachable and exploitable"

MindsDB → Cypher:
MATCH (app:App {id: 'website-12345'})
  -[:HAS_COMPONENT]->(c:Component {name: 'payment-service'})
  -[:HAS_FEATURE]->(f:Feature)
  -[:INTRODUCED]->(finding:Finding)
  -[:REFERENCES]->(cve:CVE)
WHERE cve.epss > 0.7 AND cve.kev = true
AND EXISTS {
  MATCH (finding)-[:AFFECTS]->(c)-[:DEPLOYED_ON]->(cloud:CloudResource)
  WHERE cloud.internet_facing = true
}
RETURN finding, cve, cloud
```

### Visual Graph Explorer

FalkorDB's `code-graph.falkordb.com` provides interactive graph visualization:

```
┌─────────────────────────────────────────────────────┐
│  ALdeci Knowledge Graph Explorer                    │
│  (powered by FalkorDB code-graph)                   │
│                                                     │
│     [website-12345]                                 │
│      /      |       \                               │
│  [payment] [auth]  [frontend]                       │
│     |        |        |                             │
│  [CVE-1234] [CVE-5678] [npm-audit-42]              │
│     |                                               │
│  [ECS-task] → [RDS-db] → [S3-bucket]              │
│  (internet)   (PCI)      (backups)                  │
│                                                     │
│  🔴 Attack Path: Internet → ECS → RDS (3 hops)     │
│  💰 Blast Radius: 2.3M records, $4.2M exposure     │
│                                                     │
│  [Run Micro-Pentest] [Create Jira] [Generate Fix]  │
└─────────────────────────────────────────────────────┘
```

### Migration from NetworkX

| Current (NetworkX) | Target (FalkorDB) |
|-------------------|-------------------|
| `brain_pipeline.py` Step 5: `build_graph()` — NetworkX in-memory | FalkorDB persistent graph with Cypher queries |
| 13 in-memory stores across codebase | All persist to FalkorDB or SQLite WAL |
| React Force Graph (D3.js) visualization | FalkorDB code-graph explorer (embeddable) + React Force Graph |
| No persistence across restarts | Full persistence with Redis-backed storage |
| No query language | Cypher queries via MindsDB natural language |

---

## Phase ⑧ — AI Decision Engine: The 12-Step Brain Pipeline (Enhanced)

**This is the existing core of ALdeci**, now enhanced with APP_ID context and FalkorDB.

### Enhanced Pipeline Flow

```
       ALL phases feed into FalkorDB graph
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  BRAIN PIPELINE (brain_pipeline.py, 864 LOC)    │
│  Now with APP_ID context at every step          │
├─────────────────────────────────────────────────┤
│                                                 │
│  Step 1: CONNECT                                │
│  • Read aldeci.yaml for tool config             │
│  • Connect configured customer tools            │
│  • Activate OSS fallback for missing tools      │
│                                                 │
│  Step 2: NORMALIZE                              │
│  • SARIF/SBOM/VEX → unified schema             │
│  • Tag with APP_ID + component_id               │
│                                                 │
│  Step 3: RESOLVE IDENTITY                       │
│  • Cross-scanner asset fingerprinting           │
│  • APP_ID-aware identity resolution             │
│                                                 │
│  Step 4: DEDUPLICATE                            │
│  • Fuzzy ML clustering (within component scope) │
│  • Cross-tool dedup by component                │
│                                                 │
│  Step 5: BUILD GRAPH                            │
│  • FalkorDB upsert (not NetworkX rebuild)       │
│  • Link findings to APP_ID → component → feature│
│  • Build attack path edges                      │
│                                                 │
│  Step 6: ENRICH THREATS                         │
│  • Real EPSS scores (NVD API) ← fix synthetic   │
│  • CISA KEV lookup                              │
│  • ExploitDB / GitHub Advisories / OSV          │
│  • MITRE ATT&CK technique mapping               │
│                                                 │
│  Step 7: SCORE RISK                             │
│  • Attack path analysis (FalkorDB graph queries)│
│  • Business context from APP_ID (criticality,   │
│    data classification, compliance scope)        │
│  • Reachability analysis (internet → resource)  │
│  • Blast radius calculation                     │
│                                                 │
│  Step 8: APPLY POLICY                           │
│  • Read aldeci.yaml per-component policies      │
│  • SLA enforcement based on component criticality│
│  • Auto-triage by APP_ID risk profile           │
│  • Compliance mapping (SOC2/PCI/ISO controls)   │
│                                                 │
│  Step 9: MULTI-LLM CONSENSUS                   │
│  • GPT-4 (0.25) + Claude (0.40) + Gemini (0.35)│
│  • OR: Self-hosted Single Agent (4 expert roles │
│    + moderator) via vLLM — zero API cost        │
│  • ≥85% agreement = auto-decide                 │
│  • Reasoning chains with MITRE mapping          │
│                                                 │
│  Step 10: MICRO-PENTEST (MPTE)                  │
│  • 19-phase deterministic scanner               │
│  • AI orchestrator (PentAGI-powered)            │
│  • 4-state verdict:                             │
│    VULNERABLE_VERIFIED / NOT_VULNERABLE_VERIFIED│
│    NOT_APPLICABLE / UNVERIFIED                  │
│  • 3 confidence metrics                         │
│  • Reachability-aware targeting (only test      │
│    internet-reachable attack paths)             │
│                                                 │
│  Step 11: RUN PLAYBOOKS & AUTOFIX               │
│  • YAML playbook execution                      │
│  • AST-based AutoFix (tree-sitter transforms)  │
│  • Jira ticket creation (linked to APP_ID)      │
│  • Slack/Teams/PagerDuty notifications          │
│  • GitHub/GitLab auto-fix PR generation         │
│                                                 │
│  Step 12: GENERATE EVIDENCE                     │
│  • RSA-SHA256 + ML-DSA (quantum-secure hybrid)  │
│  • Per-APP_ID evidence bundles                  │
│  • SLSA v1 attestation                          │
│  • Compliance control mapping                   │
│  • 7-year WORM retention                        │
└─────────────────────────────────────────────────┘
```

### Self-Hosted AI Option (from Research Part 26)

```
┌──────────────────────────────────────────┐
│  FIXOPS_LLM_MODE=single-agent           │
│                                          │
│  One self-hosted model (Llama 3.1 70B)  │
│  assumes 4 expert roles:                │
│                                          │
│  🔍 Security Analyst                     │
│  ⚔️  Pentest Expert                      │
│  📋 Compliance Auditor                   │
│  📊 Risk Quantifier                      │
│  🎯 Moderator (synthesizes all 4)       │
│                                          │
│  Cost: $0 API / ~$500/mo GPU            │
│  vs. $6,000/mo multi-vendor API         │
│  Privacy: Data never leaves infra       │
└──────────────────────────────────────────┘
```

---

## Phase ⑨ — Remediation + Evidence + Compliance

**When**: After the AI Decision Engine processes findings.
**What**: Automated remediation, compliance evidence generation, and audit-ready reporting.

### Remediation Flow

```
Decision Engine Output
        │
        ▼
┌───────────────────────────────────────────────┐
│  Remediation Orchestrator                     │
│                                               │
│  IF decision = AUTO_FIX:                     │
│    → AST-based code fix (tree-sitter)        │
│    → Generate PR with fix + test             │
│    → Link PR to Jira ticket                  │
│    → Update FalkorDB: Finding.status = FIXING│
│                                               │
│  IF decision = CREATE_TICKET:                │
│    → Create Jira ticket (APP_ID-scoped)      │
│    → Assign to component owner               │
│    → Set SLA from aldeci.yaml policy         │
│    → Notify via Slack/Teams                  │
│                                               │
│  IF decision = ACCEPT_RISK:                  │
│    → Generate risk acceptance evidence       │
│    → Require approval (RBAC-based)           │
│    → Sign evidence bundle (quantum-secure)   │
│    → Store in FalkorDB: Decision.accepted    │
│                                               │
│  IF decision = BLOCK_DEPLOY:                 │
│    → Fail CI/CD gate                         │
│    → Notify team leads                       │
│    → Escalate to CISO if critical path       │
└───────────────────────────────────────────────┘
```

### Compliance Auto-Generation (from Research Part 11)

```
┌───────────────────────────────────────────────┐
│  Compliance Evidence Engine                   │
│                                               │
│  For each APP_ID:                            │
│  ├── SOC 2 Type II                           │
│  │   ├── CC6.1: Access Controls → evidence   │
│  │   ├── CC7.1: System Operations → evidence │
│  │   └── CC8.1: Change Management → evidence │
│  ├── PCI-DSS v4.0                            │
│  │   ├── 6.2.4: Secure Dev → scan evidence   │
│  │   ├── 11.3: Pentest → MPTE evidence       │
│  │   └── 12.3: Risk Assessment → decision log│
│  ├── ISO 27001:2022                          │
│  │   ├── A.8.25: Secure Dev → SAST evidence  │
│  │   └── A.8.9: Config Mgmt → IaC evidence   │
│  └── NIST SSDF                               │
│      ├── PS.1.1: Secure SW → SBOM + scans    │
│      └── PW.5.1: Testing → MPTE reports      │
│                                               │
│  Output: Signed evidence bundles              │
│  Signing: Hybrid RSA-4096 + ML-DSA-65        │
│  (NIST FIPS 204, quantum-secure)              │
│  Retention: 7 years, WORM-compliant          │
└───────────────────────────────────────────────┘
```

### Quantum-Secure Evidence (from Research Part 27)

```
Evidence Bundle v2:
{
  "version": 2,
  "app_id": "website-12345",
  "component": "payment-service",
  "framework": "pci-dss-v4",
  "control": "6.2.4",
  "evidence_type": "sast_scan",
  "payload": { ... scan results ... },
  "signature": {
    "format_version": 2,
    "algorithm": "hybrid-rsa-ml-dsa",
    "classical_sig": "base64(RSA-SHA256)",
    "pq_sig": "base64(ML-DSA-65/Dilithium3)",
    "key_fingerprint": "sha256:abc123..."
  },
  "slsa_attestation": { ... SLSA v1 ... },
  "timestamp": "2026-01-15T08:30:00Z",
  "retention_until": "2033-01-15T08:30:00Z"
}
```

---

## Phase ⑩ — Self-Learning: 5 Feedback Loops

**When**: Continuously, after every decision/remediation/scan.
**What**: ML models learn from outcomes to improve all preceding phases.

### Feedback Architecture

```
┌─────────────────────────────────────────────────────┐
│                 SELF-LEARNING LAYER                  │
│                                                     │
│  Loop 1: DECISION OUTCOMES                          │
│  Decision marked correct/incorrect by human →       │
│  Retrain LLM consensus weights / fine-tune model    │
│                                                     │
│  Loop 2: MPTE RESULTS                               │
│  Pentest confirms/denies vulnerability →             │
│  Improve scan targeting (skip NOT_APPLICABLE types) │
│                                                     │
│  Loop 3: FALSE POSITIVE RATES                       │
│  Findings marked FP by developers →                 │
│  Tune dedup clustering thresholds per APP_ID        │
│                                                     │
│  Loop 4: REMEDIATION SUCCESS                        │
│  AutoFix PRs that pass CI vs. fail →                │
│  Rank fix strategies, prefer successful patterns    │
│                                                     │
│  Loop 5: POLICY VIOLATIONS                          │
│  SLA breaches, policy overrides →                   │
│  Auto-adjust rules, suggest policy updates          │
│                                                     │
│  Storage: APILearningStore (SQLite + scikit-learn)  │
│  Models: IsolationForest (anomaly detection)        │
│          RandomForest (risk prediction)              │
│          GradientBoosting (fix success prediction)  │
│                                                     │
│  Natural Language: MindsDB → FalkorDB               │
│  "Why did this component have 3x more vulnerabilities│
│   this sprint?" → graph + ML analysis               │
└─────────────────────────────────────────────────────┘
```

---

## Part 3: Complete Integration Inventory

### Customer Tool Adapters (Existing + New)

| Category | Tool | Adapter Status | Phase Used |
|----------|------|---------------|------------|
| **SCA** | Snyk | ✅ Existing | ④ Pre-merge |
| **SAST** | Semgrep | ✅ Existing | ②④ IDE + Pre-merge |
| **SAST** | SonarQube | ✅ Existing | ④ Pre-merge |
| **SAST** | Checkmarx | 🟡 Connector ready | ④ Pre-merge |
| **SAST** | Veracode | 🟡 Connector ready | ④ Pre-merge |
| **IaC** | Checkov | ✅ Existing | ④⑥ Pre-merge + IaC |
| **Cloud** | AWS Security Hub | ✅ Existing | ⑥ IaC/Runtime |
| **Cloud** | Azure Security Center | ✅ Existing | ⑥ IaC/Runtime |
| **Cloud** | Wiz | ✅ Existing | ⑥ IaC/Runtime |
| **Cloud** | Prisma Cloud | ✅ Existing | ⑥ IaC/Runtime |
| **DAST** | OWASP ZAP | ✅ Existing | ④ Pre-merge |
| **DevOps** | GitHub | ✅ Existing | ②④⑤ IDE + Pre-merge + Build |
| **DevOps** | GitLab | ✅ Existing | ②④⑤ IDE + Pre-merge + Build |
| **DevOps** | Azure DevOps | ✅ Existing | ②④⑤ IDE + Pre-merge + Build |
| **Runtime** | Trivy | ✅ Existing | ④⑤⑥ Pre-merge + Build + Runtime |
| **Runtime** | Prowler | ✅ Existing | ⑥ IaC/Runtime |
| **ALM** | Jira | ✅ Enhanced | ③⑨ ALM + Remediation |
| **ALM** | Confluence | 🆕 New | ③ ALM |
| **ALM** | Slack | ✅ Existing | ⑨ Remediation |
| **IDE** | VS Code | 🆕 New | ② IDE |
| **IDE** | JetBrains | 🆕 New | ② IDE |
| **Graph** | FalkorDB | 🆕 New | ⑦ Knowledge Graph |
| **NL** | MindsDB | 🟡 Partial | ⑦⑩ Graph + Self-Learning |

### OSS Scanner Fallbacks (Existing)

| Scanner | Replaces | Status |
|---------|----------|--------|
| Trivy | Container/OS SCA | ✅ |
| Grype | SBOM-based SCA | ✅ |
| Semgrep | SAST | ✅ |
| Gitleaks/ALdeci Secrets | Secret detection | ✅ |
| Checkov/ALdeci IaC | IaC scanning | ✅ |

---

## Part 4: Competitor Comparison — Where We Win

| Capability | Snyk | Wiz | ArmorCode | Apiiro | ALdeci |
|-----------|------|-----|-----------|--------|--------|
| APP_ID hierarchy | ❌ | ❌ | ❌ | ❌ (repo-level only) | ✅ App → Component → Feature |
| Design Stage integration | ❌ | ❌ | ❌ | ❌ | ✅ architecture.md → graph |
| IDE real-time agent | ✅ (scanner only) | ❌ | ❌ | ❌ | ✅ Agent + MCP + scanner |
| ALM bi-directional sync | ❌ (push only) | ❌ | ✅ (basic) | ❌ | ✅ Full Jira/Confluence |
| Tool orchestration | ❌ (replaces tools) | ❌ | ✅ (ingests) | ✅ (ingests) | ✅ Orchestrate + OSS fallback |
| Knowledge graph | ❌ (flat list) | ❌ | ❌ | ✅ (basic) | ✅ FalkorDB full graph |
| Multi-LLM consensus | ❌ | ❌ | ❌ | ❌ | ✅ 3 LLMs OR self-hosted |
| Micro-pentest engine | ❌ | ❌ | ❌ | ❌ | ✅ 19-phase MPTE |
| Attack path + blast radius | ❌ | ✅ (cloud only) | ❌ | ✅ (code→cloud) | ✅ Code → Cloud + MPTE verify |
| Quantum-secure evidence | ❌ | ❌ | ❌ | ❌ | ✅ FIPS 204 ML-DSA |
| Self-learning ML | ❌ | ❌ | ❌ | ❌ | ✅ 5 feedback loops |
| Natural language queries | ❌ | ❌ | ❌ | ❌ | ✅ MindsDB + FalkorDB |
| Air-gapped / on-prem | ❌ | ❌ | ❌ | ❌ | ✅ Full offline |
| MCP server (AI-native) | ❌ | ❌ | ❌ | ❌ | ✅ 650 tools auto-discovered |
| CTEM full loop | ❌ Stop at scan | ❌ Stop at detect | ❌ Partial | ❌ Partial | ✅ Full 5-phase + proof |

---

## Part 5: Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)

| # | Task | Effort | Dependencies |
|---|------|--------|-------------|
| 1 | FalkorDB integration — replace NetworkX in Step 5 | 5 days | FalkorDB Docker |
| 2 | `aldeci.yaml` schema + parser | 3 days | None |
| 3 | APP_ID registration API + DB | 3 days | FalkorDB |
| 4 | VS Code extension (basic — tool detection + pre-commit) | 5 days | MCP server |
| 5 | Fix EPSS/KEV in Step 6 (replace synthetic) | 2 days | NVD API key |
| 6 | Fix policy engine Step 8 (YAML-driven, not string matching) | 2 days | aldeci.yaml |

### Phase 2: Intelligence (Weeks 5-8)

| # | Task | Effort | Dependencies |
|---|------|--------|-------------|
| 7 | Pre-merge orchestrator (GitHub/GitLab webhooks) | 5 days | aldeci.yaml, Steps 1-4 |
| 8 | Build agent (SBOM generation + graph update) | 3 days | FalkorDB |
| 9 | IaC/Runtime connector (Terraform parser + cloud tags) | 5 days | FalkorDB |
| 10 | Attack path engine (FalkorDB graph traversal) | 5 days | Phase ⑥ data |
| 11 | MindsDB integration (NL → Cypher → FalkorDB) | 3 days | FalkorDB |
| 12 | Jira bi-directional sync enhancement | 3 days | JiraConnector |

### Phase 3: AI + Security (Weeks 9-12)

| # | Task | Effort | Dependencies |
|---|------|--------|-------------|
| 13 | Single Agent engine (vLLM + 4 roles + moderator) | 5 days | vLLM Docker |
| 14 | MCP auto-discovery (650 tools from FastAPI routes) | 3 days | MCP SDK |
| 15 | Quantum-secure signing (hybrid RSA + ML-DSA) | 5 days | liboqs |
| 16 | Compliance auto-generation (SOC2/PCI/ISO mapping) | 5 days | FalkorDB |
| 17 | AST AutoFix engine (tree-sitter) | 5 days | Semgrep |
| 18 | UI: Attack Path Visualization | 5 days | Attack path engine |

### Phase 4: Polish (Weeks 13-16)

| # | Task | Effort | Dependencies |
|---|------|--------|-------------|
| 19 | UI: Executive Dashboard | 5 days | Graph queries |
| 20 | UI: SLA Dashboard | 3 days | Remediation data |
| 21 | UI: Evidence Export Center | 3 days | Quantum signing |
| 22 | UI: Compliance Dashboard | 5 days | Compliance engine |
| 23 | UI: Onboarding Wizard | 3 days | APP_ID registration |
| 24 | Full E2E testing + CI/CD | 5 days | All phases |

---

## Part 6: The Business Case

### Pricing Model (APP_ID-Based)

| Tier | Price | Includes |
|------|-------|---------|
| **Community** | Free | 3 APP_IDs, OSS scanners only, no LLM, SQLite |
| **Professional** | $3-5K/mo | 25 APP_IDs, Multi-LLM, FalkorDB, MPTE, basic compliance |
| **Enterprise** | $8-15K/mo | Unlimited APP_IDs, self-hosted LLM, quantum-secure, RBAC, audit |
| **Air-Gapped** | $15-25K/mo | Full offline, dedicated support, custom compliance frameworks |

### Revenue Path to $10M ARR

| Quarter | Customers | Avg MRR | Total ARR |
|---------|-----------|---------|-----------|
| Q1 2026 | 5 design partners | $0 (free) | $0 |
| Q2 2026 | 10 paid (Pro) | $4K | $480K |
| Q3 2026 | 20 paid (Pro+Ent) | $6K | $1.4M |
| Q4 2026 | 35 paid | $7K | $2.9M |
| Q1-Q4 2027 | 80 paid | $10K | $9.6M |

### The Moat (Why Competitors Can't Copy This)

1. **APP_ID-centric graph**: Requires rearchitecting from scratch — 12-18 months for any competitor
2. **Tool orchestration**: "Switzerland of AppSec" — works with every tool, replaces none. Snyk can't do this (they ARE a tool)
3. **Multi-LLM consensus**: No competitor has weighted voting across 3+ LLMs
4. **MPTE verification**: Only platform that proves exploitability, not just reports it
5. **Quantum-secure evidence**: Zero competitors have FIPS 204/205 post-quantum crypto
6. **MCP-native**: First AppSec platform that AI agents can programmatically use
7. **Self-learning**: 5 feedback loops continuously improve all models

---

## Summary: The ALdeci Difference

```
Traditional AppSec:  Scan → Report → Ticket → Wait → Maybe Fix → Repeat
                     (flat, disconnected, scanner-dependent)

ALdeci:              Design → Develop → Merge → Build → Deploy → Monitor
                         ↓       ↓        ↓       ↓       ↓        ↓
                     ┌─────────────────────────────────────────────────┐
                     │        FalkorDB Knowledge Graph (APP_ID)       │
                     │  All phases feed → graph builds understanding  │
                     └──────────────────────┬──────────────────────────┘
                                            ↓
                     ┌──────────────────────────────────────────────────┐
                     │  12-Step AI Brain Pipeline                      │
                     │  Connect → Normalize → Resolve → Dedup →        │
                     │  Graph → Enrich → Score → Policy →              │
                     │  LLM Consensus → MPTE Verify →                  │
                     │  Playbooks → Evidence                           │
                     └──────────────────────┬──────────────────────────┘
                                            ↓
                     ┌──────────────────────────────────────────────────┐
                     │  Quantum-Secure Compliance Evidence              │
                     │  Per APP_ID, per framework, signed, auditable   │
                     └──────────────────────────────────────────────────┘
```

**ALdeci doesn't just find vulnerabilities. It understands your applications from design to production, makes intelligent decisions with AI consensus, proves exploitability with micro-pentests, and generates quantum-secure compliance evidence — all organized around the applications that matter to your business.**

---

## Part 7: 618-Endpoint API Surface — Complete Phase Mapping

> **Total**: 618 endpoints across 61 router sources in 6 suites. Every endpoint is mapped to a lifecycle phase below. **Zero waste.**

### Phase ① Design Stage — 3 endpoints (NEW, to be built)

| Router | Endpoints | What It Powers |
|--------|-----------|---------------|
| *APP_ID registration (new)* | `POST /api/v1/apps`, `GET /api/v1/apps`, `GET /api/v1/apps/{id}` | APP_ID creation, architecture.md ingestion, aldeci.yaml registration |

> These map to the existing inline `POST /inputs/design` endpoint in app.py + new APP_ID CRUD.

---

### Phase ② Developer IDE — 15 endpoints

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [ide_router.py](suite-integrations/api/ide_router.py) | `/api/v1/ide/*` | 5 | VS Code/JetBrains extension: tool detection, background scan results, pre-commit config |
| [mcp_router.py](suite-integrations/api/mcp_router.py) | `/api/v1/mcp/*` | 10 | MCP server: tool discovery, resource streams, prompt registry — AI agents query ALdeci |

---

### Phase ③ ALM Integration — 31 endpoints

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [integrations_router.py](suite-integrations/api/integrations_router.py) | `/api/v1/integrations/*` | 8 | Jira/Slack/GitHub connector CRUD, health checks, sync triggers |
| [webhooks_router.py](suite-integrations/api/webhooks_router.py) | `/api/v1/webhooks/*` | 23 | Inbound webhooks from Jira, ServiceNow, GitLab, Azure DevOps + webhook config management |

---

### Phase ④ Pre-Merge Orchestration — 94 endpoints

**Scanning tools orchestration (what runs in the PR gate):**

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [sast_router.py](suite-attack/api/sast_router.py) | `/api/v1/sast/*` | 4 | SAST scanning (Semgrep, Bandit, custom rules) |
| [dast_router.py](suite-attack/api/dast_router.py) | `/api/v1/dast/*` | 2 | DAST scanning (OWASP ZAP orchestration) |
| [secrets_router.py](suite-attack/api/secrets_router.py) | `/api/v1/secrets/*` | 7 | Secret detection (Gitleaks + ALdeci scanner) |
| [container_router.py](suite-attack/api/container_router.py) | `/api/v1/container/*` | 3 | Container image scanning |
| [cspm_router.py](suite-attack/api/cspm_router.py) | `/api/v1/cspm/*` | 4 | Cloud security posture checks |
| [api_fuzzer_router.py](suite-attack/api/api_fuzzer_router.py) | `/api/v1/api-fuzzer/*` | 3 | API fuzzing in pre-merge |
| [oss_tools.py](suite-integrations/api/oss_tools.py) | `/api/v1/oss/*` | 8 | OSS fallback scanners (Trivy, Grype, Semgrep, Gitleaks, Checkov) |
| [iac_router.py](suite-integrations/api/iac_router.py) | `/api/v1/iac/*` | 7 | IaC scanning (Terraform, CloudFormation, Kubernetes) |
| [validation_router.py](suite-api/apps/api/validation_router.py) | `/api/v1/validate/*` | 3 | Input validation, schema checks |

**Normalization & ingestion (results flow into pipeline):**

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| Inline app.py | `/inputs/sbom`, `/inputs/sarif`, `/inputs/cve`, `/inputs/vex`, `/inputs/cnapp`, `/inputs/context` | 6 | Universal format ingestion (SARIF, SBOM, CVE, VEX, CNAPP) |
| Inline app.py | `/inputs/{stage}/chunks/*` | 4 | Chunked upload for large scan results |
| Inline app.py | `/api/v1/ingest/multipart`, `/api/v1/ingest/assets`, `/api/v1/ingest/formats` | 3 | Multipart ingestion, asset listing, format discovery |
| [inventory_router.py](suite-api/apps/api/inventory_router.py) | `/api/v1/inventory/*` | 19 | Asset inventory: CRUD, search, tagging, grouping, dependency tracking |

**Identity resolution & deduplication:**

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [fuzzy_identity_router.py](suite-core/api/fuzzy_identity_router.py) | `/api/v1/identity/*` | 7 | Cross-scanner asset fingerprinting, identity resolution |
| [deduplication_router.py](suite-core/api/deduplication_router.py) | `/api/v1/deduplication/*` | 18 | Smart dedup: clustering, merge/split, strategy selection, noise stats |
| [exposure_case_router.py](suite-core/api/exposure_case_router.py) | `/api/v1/cases/*` | 8 | Exposure case management (deduplicated finding groups) |

---

### Phase ⑤ Build Server — 2 endpoints (existing) + SBOM via ingestion

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [code_to_cloud_router.py](suite-core/api/code_to_cloud_router.py) | `/api/v1/code-to-cloud/*` | 2 | Code-to-cloud mapping, build artifact tracking |
| Inline app.py | `/inputs/sbom` | (counted above) | SBOM ingestion (CycloneDX/SPDX) from build pipeline |
| [provenance_router.py](suite-evidence-risk/api/provenance_router.py) | `/api/v1/provenance/*` | 2 | SLSA provenance attestation tracking |

---

### Phase ⑥ IaC / Runtime — 18 endpoints

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [iac_router.py](suite-integrations/api/iac_router.py) | `/api/v1/iac/*` | 7 | Terraform/CloudFormation/K8s parsing → APP_ID graph (counted in ④ too, dual-use) |
| [graph_router.py](suite-evidence-risk/api/graph_router.py) | `/api/v1/graph/*` | 4 | Asset graph queries, topology visualization |
| [reachability API](suite-evidence-risk/risk/reachability/api.py) | `/api/v1/reachability/*` | 7 | Reachability analysis: internet→code attack path mapping |

---

### Phase ⑦ Knowledge Graph — 31 endpoints

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [brain_router.py](suite-core/api/brain_router.py) | `/api/v1/brain/*` | 22 | Knowledge graph CRUD, entity queries, relationship queries, graph stats |
| [nerve_center.py](suite-core/api/nerve_center.py) | `/api/v1/nerve-center/*` | 9 | Real-time security pulse: active threats, system health, alert dashboard |
| Inline app.py | `/api/v1/graph` | (counted in ⑥) | Graph visualization data |

---

### Phase ⑧ AI Decision Engine — 140 endpoints

**Core pipeline:**

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [pipeline_router.py](suite-core/api/pipeline_router.py) | `/api/v1/brain/pipeline/*` | 6 | Pipeline triggers, run history, step status |
| Inline app.py | `/pipeline/run` | 2 | Pipeline execution trigger (GET + POST) |

**Threat enrichment & risk scoring:**

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [feeds_router.py](suite-feeds/api/feeds_router.py) | `/api/v1/feeds/*` | 30 | NVD, KEV, EPSS, GitHub Advisories, OSV, ExploitDB — threat intel feeds |
| [risk_router.py](suite-evidence-risk/api/risk_router.py) | `/api/v1/risk/*` | 3 | Risk scoring engine, risk model configuration |
| [business_context.py](suite-evidence-risk/api/business_context.py) | `/api/v1/business-context/*` | 3 | Business context for risk weighting (criticality, revenue impact) |
| [business_context_enhanced.py](suite-evidence-risk/api/business_context_enhanced.py) | `/api/v1/business-context/*` | 6 | Enhanced business context (data classification, compliance scope) |
| [intelligent_engine_routes.py](suite-core/api/intelligent_engine_routes.py) | `/api/v1/intelligent-engine/*` | 11 | Intelligent security engine: EPSS enrichment, KEV lookup, MITRE mapping |

**AI consensus & LLM layer:**

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [decisions.py](suite-core/api/decisions.py) | `/api/v1/decisions/*` | 6 | Decision CRUD, verdict history, reasoning chains |
| [llm_router.py](suite-core/api/llm_router.py) | `/api/v1/llm/*` | 6 | LLM provider management, consensus execution, model switching |
| [llm_monitor_router.py](suite-core/api/llm_monitor_router.py) | `/api/v1/llm-monitor/*` | 4 | LLM performance monitoring, token usage, latency tracking |

**Micro-pentest & attack verification:**

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [micro_pentest_router.py](suite-attack/api/micro_pentest_router.py) | `/api/v1/micro-pentest/*` | 18 | 19-phase MPTE: scan launch, phase status, verdicts, evidence artifacts |
| [mpte_router.py](suite-attack/api/mpte_router.py) | `/api/v1/mpte/*` | 19 | MPTE management: profiles, scan history, confidence metrics, campaign management |
| [pentagi_router.py](suite-attack/api/pentagi_router.py) | `/api/v1/pentagi/*` | 8 | PentAGI AI orchestrator: agent tasks, autonomous pentest sessions |
| [attack_sim_router.py](suite-attack/api/attack_sim_router.py) | `/api/v1/attack-sim/*` | 13 | Attack simulation: scenario builder, MITRE ATT&CK mapping, kill chain analysis |
| [malware_router.py](suite-attack/api/malware_router.py) | `/api/v1/malware/*` | 4 | Malware analysis engine: sample submission, behavioral analysis |

---

### Phase ⑨ Remediation + Evidence + Compliance — 128 endpoints

**Remediation & automation:**

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [remediation_router.py](suite-api/apps/api/remediation_router.py) | `/api/v1/remediation/*` | 15 | Remediation tasks: CRUD, SLA tracking, bulk assignment, status workflow |
| [autofix_router.py](suite-core/api/autofix_router.py) | `/api/v1/autofix/*` | 12 | AST-based AutoFix: generate fix, preview diff, apply fix, create PR |
| [workflows_router.py](suite-api/apps/api/workflows_router.py) | `/api/v1/workflows/*` | 13 | Workflow automation: YAML playbook execution, workflow templates, triggers |
| [bulk_router.py](suite-api/apps/api/bulk_router.py) | `/api/v1/bulk/*` | 13 | Bulk operations: mass triage, mass assign, mass status change, mass export |
| [policies_router.py](suite-api/apps/api/policies_router.py) | `/api/v1/policies/*` | 11 | Policy management: CRUD, SLA rules, auto-triage rules, severity overrides |
| [collaboration_router.py](suite-api/apps/api/collaboration_router.py) | `/api/v1/collaboration/*` | 21 | Team collaboration: comments, threads, mentions, shared views, war rooms |

**Evidence & reporting:**

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [evidence_router.py](suite-evidence-risk/api/evidence_router.py) | `/api/v1/evidence/*` | 6 | Evidence bundles: generate, verify signature, list, export, retention policies |
| [reports_router.py](suite-api/apps/api/reports_router.py) | `/api/v1/reports/*` | 14 | Report generation: executive, technical, compliance, trend, PDF/JSON/CSV export |
| [audit_router.py](suite-api/apps/api/audit_router.py) | `/api/v1/audit/*` | 14 | Audit trail: logs, hash-chain verification, compliance controls, gap analysis |

**Analytics & metrics:**

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [analytics_router.py](suite-api/apps/api/analytics_router.py) | `/api/v1/analytics/*` | 22 | MTTR, SLA compliance, noise reduction, ROI, scanner comparison, priority distribution |
| Inline app.py | `/analytics/dashboard`, `/analytics/runs/{run_id}` | 2 | Dashboard overview, pipeline run analytics |
| [streaming_router.py](suite-core/api/streaming_router.py) | `/api/v1/stream/*` | 2 | Server-sent events: real-time finding updates, pipeline progress |
| Inline app.py | `/api/v1/triage`, `/api/v1/triage/export` | 2 | Triage queue, triage export |
| Inline app.py | `/feedback` | 1 | Decision feedback loop input |

---

### Phase ⑩ Self-Learning — 46 endpoints

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [predictions_router.py](suite-core/api/predictions_router.py) | `/api/v1/predictions/*` | 8 | ML predictions: risk forecasting, trend prediction, anomaly alerts |
| [algorithmic_router.py](suite-core/api/algorithmic_router.py) | `/api/v1/algorithms/*` | 11 | Algorithm lab: model training, evaluation, A/B testing, feature importance |
| [mindsdb_router.py](suite-core/api/mindsdb_router.py) | `/api/v1/ml/*` | 14 | MindsDB integration: NL queries, agent management, model training, predictions |
| [vuln_discovery_router.py](suite-attack/api/vuln_discovery_router.py) | `/api/v1/vulns/*` | 11 | Vulnerability discovery ML: training data, model performance, discovery runs |
| [enhanced.py](suite-api/apps/api/routes/enhanced.py) | `/api/v1/enhanced/*` | 2 | Enhanced enrichment with ML-powered context |

---

### Platform / Cross-Cutting — 62 endpoints

| Router | Endpoints | Count | What It Powers |
|--------|-----------|-------|---------------|
| [copilot_router.py](suite-core/api/copilot_router.py) | `/api/v1/copilot/*` | 14 | AI Copilot: natural language security queries, chat sessions, context-aware answers |
| [agents_router.py](suite-core/api/agents_router.py) | `/api/v1/copilot/agents/*` | 32 | 5 AI Agents: Security Analyst, Pentest, Compliance, Remediation, Orchestrator |
| [auth_router.py](suite-api/apps/api/auth_router.py) | `/api/v1/auth/*` | 4 | SSO/SAML configuration |
| [users_router.py](suite-api/apps/api/users_router.py) | `/api/v1/users/*` | 6 | User management: CRUD, role assignment |
| [teams_router.py](suite-api/apps/api/teams_router.py) | `/api/v1/teams/*` | 8 | Team management: CRUD, membership, ownership mapping |
| [marketplace_router.py](suite-api/apps/api/marketplace_router.py) | `/api/v1/marketplace/*` | 12 | Marketplace: browse, install, rate micro-apps and connectors |
| [health.py](suite-api/apps/api/health.py) | `/api/v1/health/*`, `/api/v1/status` | 4 | System health, readiness, liveness probes |
| [detailed_logging.py](suite-api/apps/api/detailed_logging.py) | `/api/v1/logs/*` | 5 | Log management: view, search, filter, delete |
| Inline app.py | `/health`, `/api/v1/status`, `/api/v1/search` | 3 | Legacy health, global search |

---

### Coverage Summary

| Phase | Endpoints | % of Total | Status |
|-------|-----------|-----------|--------|
| ① Design Stage | ~3 | 0.5% | 🆕 New (APP_ID CRUD — uses existing `/inputs/design`) |
| ② Developer IDE | 15 | 2.4% | ✅ Built (ide_router + mcp_router) |
| ③ ALM Integration | 31 | 5.0% | ✅ Built (integrations + webhooks) |
| ④ Pre-Merge Orchestration | 94 | 15.2% | ✅ Built (scanners + ingestion + dedup + identity) |
| ⑤ Build Server | 4 | 0.6% | ✅ Built (code-to-cloud + provenance + SBOM ingestion) |
| ⑥ IaC / Runtime | 18 | 2.9% | ✅ Built (iac + graph + reachability) |
| ⑦ Knowledge Graph | 31 | 5.0% | ✅ Built (brain + nerve-center) |
| ⑧ AI Decision Engine | 140 | 22.7% | ✅ Built (pipeline + feeds + risk + LLM + MPTE + attack) |
| ⑨ Remediation + Evidence | 128 | 20.7% | ✅ Built (remediation + autofix + workflows + evidence + reports + analytics) |
| ⑩ Self-Learning | 46 | 7.4% | ✅ Built (predictions + algorithms + MindsDB + vuln discovery) |
| Platform / Cross-Cutting | 62 | 10.0% | ✅ Built (copilot + agents + auth + users + teams + marketplace + health) |
| **Unmapped** | **0** | **0%** | **Every endpoint has a home** |
| **TOTAL** | **618** | **100%** | **Zero waste** |

### API Surface Distribution

```
Phase ⑧ AI Engine    ████████████████████████  140 (22.7%)
Phase ⑨ Remediation  ████████████████████      128 (20.7%)
Phase ④ Pre-Merge    █████████████████         94 (15.2%)
Platform             ██████████                62 (10.0%)
Phase ⑩ Self-Learn   ████████                  46 (7.4%)
Phase ③ ALM          ██████                    31 (5.0%)
Phase ⑦ Graph        ██████                    31 (5.0%)
Phase ⑥ IaC/Runtime  ████                      18 (2.9%)
Phase ② IDE          ███                       15 (2.4%)
Phase ⑤ Build        ██                        4 (0.6%)
Phase ① Design       █                         3 (0.5%)
                     ─────────────────────────────
                     TOTAL: 618 endpoints, 0 wasted
```

### Architecture Issues Found (Minor)

| Issue | Impact | Fix Effort |
|-------|--------|-----------|
| **Duplicate `/api/v1/brain` prefix** — brain_router (22) + pipeline_router (6) share prefix | Low — no path collisions, but confusing | 1 hour — rename pipeline_router prefix |
| **Duplicate `/api/v1/business-context`** — business_context.py (3) + business_context_enhanced.py (6) share prefix | Low — no collisions | 1 hour — merge into one file |
| **23 inline endpoints in app.py** — not in proper router files | Medium — harder to maintain | 4 hours — extract to ingest_router.py |
| **MCP router not in suite-integrations standalone app** | Low — only matters for isolated deployment | 30 min — add import |
| **webhooks_router exports 2 routers** (authenticated + receiver) | Low — intentional design for webhook security | None needed |

---

*Document created: 2026-02-21, updated 2026-02-22*
*Integrates: ARCHITECTURE_E2E.md (existing 12-step pipeline), research_next_features_to_build.md (gaps 1-5, parts 25-29), user APP_ID design vision*
*API audit: 618 endpoints across 61 router sources, 6 suites — 100% mapped to lifecycle phases*
*Next: Implementation begins with Phase 1 (FalkorDB + aldeci.yaml + APP_ID registration)*
