<!-- ═══════════════════════════════════════════════════════════════════════════
     VISION_TO_ACCOMPLISH.MD — Complete Agent Handover Document
     
     PURPOSE: This is the SINGLE SOURCE OF TRUTH for any AI agent building
     features for ALdeci. It contains ALL vision, architecture, personas,
     UI design, and build tasks needed to work autonomously.
     
     SOURCES: Synthesized from:
       - docs/ALDECI_UNIFIED_VISION.md (1,321 lines)
       - docs/USER_STORY_APP_FLOW.md (1,855 lines)
       - docs/research_next_features_to_build.md (2,707 lines)
       - Complete UI audit (57 pages, 15,328 LOC)
       - Steve Jobs-level UI redesign (new)
     
     LAST UPDATED: 2026-02-27
     ═══════════════════════════════════════════════════════════════════════════ -->

<div align="center">

# ALdeci — Vision to Accomplish

### The Complete Claude Agent Handover: Architecture, Personas, UI, and Build Tasks

**790,000+ LOC · 618 API Endpoints · 114 CLI Commands · 72 Features · 25 Personas**

</div>

---

## Table of Contents

**PART I — VISION & ARCHITECTURE**
1. [One-Sentence Vision](#1-one-sentence-vision)
2. [The 10 Non-Negotiable Vision Pillars](#2-the-10-non-negotiable-vision-pillars)
3. [APP_ID Architecture — The Atom of Everything](#3-app_id-architecture--the-atom-of-everything)
4. [10-Phase Security Lifecycle](#4-10-phase-security-lifecycle)
5. [12-Step AI Brain Pipeline](#5-12-step-ai-brain-pipeline)
6. [The FalkorDB Knowledge Graph](#6-the-falkordb-knowledge-graph)

**PART II — WHO WE SERVE**
7. [25 Personas — Who They Are and What They Need](#7-25-personas--who-they-are-and-what-they-need)
8. [The HealthPay Story — 28 Chapters Condensed](#8-the-healthpay-story--28-chapters-condensed)
9. [Complete Feature × Persona Map (72 Features)](#9-complete-feature--persona-map-72-features)

**PART III — THE NEW UI VISION (Steve Jobs Redesign)**
10. [UI Philosophy — From 8 Technical Suites to 5 Workflow Spaces](#10-ui-philosophy--from-8-technical-suites-to-5-workflow-spaces)
11. [The 5 Spaces — Detailed Screen Specifications](#11-the-5-spaces--detailed-screen-specifications)
12. [Navigation Architecture & Persona Landing](#12-navigation-architecture--persona-landing)
13. [UI Build Tasks — Every Screen to Create or Refactor](#13-ui-build-tasks--every-screen-to-create-or-refactor)
14. [Current UI Inventory — What Exists Today](#14-current-ui-inventory--what-exists-today)

**PART IV — WHAT TO BUILD**
15. [What's Built vs What's Left](#15-whats-built-vs-whats-left)
16. [The 5 Critical Gaps to Close](#16-the-5-critical-gaps-to-close)
17. [7 Unique Differentiators to Build](#17-7-unique-differentiators-to-build)
18. [5-Sprint Build Plan — 20 Weeks to v1.0](#18-5-sprint-build-plan--20-weeks-to-v10)

**PART V — CONTEXT FOR AGENTS**
19. [Codebase Structure & File Paths](#19-codebase-structure--file-paths)
20. [Technical Patterns & Conventions](#20-technical-patterns--conventions)
21. [Competitor Comparison](#21-competitor-comparison)
22. [The Business Case](#22-the-business-case)
23. [The 618-Endpoint API Surface](#23-the-618-endpoint-api-surface)
24. [Quantified Impact — Before/After](#24-quantified-impact--beforeafter)

---

# PART I — VISION & ARCHITECTURE

---

## 1. One-Sentence Vision

> **ALdeci is the brain that sits between all your security tools and your engineering team — it figures out what actually matters, tells developers exactly how to fix it, proves to auditors that you did it, and gets smarter every week.**

We are NOT a scanner. We are **Decision Intelligence for Application Security** — the layer that connects every scanner, every team, every compliance framework into a single knowledge graph and makes intelligent, verifiable, auditable decisions about what to do next.

**Traditional AppSec**: Scan → Report → Ticket → Wait → Maybe Fix → Repeat *(flat, disconnected, scanner-dependent)*

**ALdeci**: Design → Develop → Merge → Build → Deploy → Monitor → **all phases feed into a Knowledge Graph → 12-step AI Brain Pipeline → quantum-secure evidence** *(connected, intelligent, tool-agnostic)*

---

## 2. The 10 Non-Negotiable Vision Pillars

Every feature, every sprint, every line of code must serve at least one of these:

| # | Vision Pillar | Phase | Core Promise |
|---|--------------|-------|-------------|
| **V1** | APP_ID-Centric Architecture | ① | Every finding, decision, evidence traces to App → Component → Feature |
| **V2** | 10-Phase Security Lifecycle | ①-⑩ | Design → IDE → ALM → Pre-merge → Build → IaC → KG → AI → Remediation → Self-Learning |
| **V3** | Decision Intelligence (not scanning) | ⑧ | "What to DO about a risk, not just what the risk IS" |
| **V4** | Multi-LLM Consensus / Self-Hosted AI | ⑧ | 3+ LLMs with 85% threshold OR zero-token self-hosted model |
| **V5** | MPTE (Micro-Pentest Verification) | ⑧ | Prove exploitability, not just detect vulnerability |
| **V6** | Quantum-Secure Evidence | ⑨ | FIPS 204 ML-DSA + RSA hybrid, 7-year WORM retention |
| **V7** | MCP-Native AI Platform | ②⑧ | First AppSec platform AI agents can programmatically use |
| **V8** | Self-Learning (5 Feedback Loops) | ⑩ | Decision outcomes, MPTE results, FP rates, remediation success, policy violations |
| **V9** | Air-Gapped / On-Prem Deployment | All | Full offline capability on commodity hardware |
| **V10** | CTEM Full Loop with Cryptographic Proof | All | Discover → Prioritize → Validate → Remediate → Measure (with signed evidence) |

---

## 3. APP_ID Architecture — The Atom of Everything

APP_ID is ALdeci's fundamental unit. Every finding, every decision, every compliance artifact traces back to an APP_ID. This is what makes us fundamentally different from flat-list scanners.

```
APP_ID (e.g., "website-12345")
├── Component: payment-service
│   ├── Feature: checkout-flow
│   │   ├── Dependencies: stripe-sdk@2.1.0, express@4.18.2
│   │   ├── Infrastructure: us-east-1, ECS, RDS
│   │   └── Compliance: PCI-DSS scope, SOC 2 CC6.1
│   └── Feature: refund-engine
│       ├── Dependencies: ...
│       └── Infrastructure: ...
├── Component: auth-service
│   └── ...
└── Component: admin-portal
    └── ...
```

**Per-APP_ID configuration** via `aldeci.yaml`:
```yaml
app_id: "website-12345"
components:
  payment-service:
    scan_tools: [semgrep, trivy, checkov]
    sla:
      critical: 24h
      high: 7d
    policies:
      block_on: [critical, high_with_exploit]
    oss_fallback: true  # use OSS scanners if commercial unavailable
```

**No competitor has this.** Snyk sees repos. Wiz sees cloud resources. Apiiro sees code. Only ALdeci sees the full hierarchy from design intent down to production infrastructure, organized around the applications that matter to your business.

---

## 4. 10-Phase Security Lifecycle

ALdeci covers the ENTIRE software lifecycle — from architecture decision to production monitoring:

```
Phase ①          Phase ②        Phase ③        Phase ④          Phase ⑤
DESIGN STAGE      IDE            ALM            PRE-MERGE        BUILD SERVER
architecture.md → VS Code/JB  → Jira/Confl   → Security Gate → SBOM + Deps
threat model      extension      bi-dir sync    multi-scanner    CycloneDX/SPDX
APP_ID birth      MCP server     knowledge      orchestration    SLSA provenance
                  pre-commit     ingestion      "Switzerland"

    ↓                ↓              ↓               ↓               ↓

Phase ⑩          Phase ⑨        Phase ⑧        Phase ⑦          Phase ⑥
SELF-LEARNING     REMEDIATION    AI ENGINE      KNOWLEDGE        IaC/RUNTIME
5 feedback loops  AutoFix PRs    12-step brain   GRAPH           Cloud resources
ML retraining     evidence       pipeline        FalkorDB        Terraform parse
concept drift     compliance     multi-LLM       MindsDB NL      attack path
                  quantum-sign   MPTE verify     Cypher queries   foundation
```

### Phase Details

| Phase | When | What Happens | Endpoints |
|-------|------|-------------|-----------|
| **① Design** | Architecture decision | APP_ID born, threat model auto-generated from architecture.md, first graph nodes | 3 |
| **② IDE** | Developer writes code | VS Code/JetBrains extension with MCP server (650 tools), background scanning, pre-commit gates | 15 |
| **③ ALM** | Ticket/doc creation | Jira/Confluence bi-directional sync, knowledge graph fed from ALM artifacts | 31 |
| **④ Pre-Merge** | PR opened | Multi-scanner orchestration (SAST/DAST/SCA/IaC/Secrets), dedup, identity resolution. We orchestrate tools, we don't replace them. | 94 |
| **⑤ Build** | CI/CD runs | SBOM generation, dependency graph, SLSA provenance attestation | 4 |
| **⑥ IaC/Runtime** | Deploy/monitor | Cloud resource ingestion, Terraform parsing, attack path foundation | 18 |
| **⑦ Knowledge Graph** | Always | FalkorDB stores all entities & relationships, MindsDB enables natural language queries | 31 |
| **⑧ AI Decision Engine** | Per finding/event | 12-step brain pipeline, multi-LLM consensus, MPTE verification, risk scoring | 140 |
| **⑨ Remediation** | Action needed | AutoFix PRs, playbook execution, compliance evidence bundles, quantum-secure signing | 128 |
| **⑩ Self-Learning** | Continuously | 5 ML feedback loops improve all preceding phases | 46 |

**Total: 618 endpoints, zero waste. Every endpoint maps to a phase.**

---

## 5. 12-Step AI Brain Pipeline

The core intelligence engine that processes every finding:

```
Step 1:  CONNECT       → Ingest from any scanner (12+ adapters)
Step 2:  NORMALIZE     → Unified schema (SARIF, CycloneDX, SPDX, CSV, JSON, XML)
Step 3:  RESOLVE       → Fuzzy identity resolution (same asset, different scanners)
Step 4:  DEDUPLICATE   → Cross-tool dedup (14,000 findings → 340 that matter)
Step 5:  GRAPH         → FalkorDB knowledge graph update (entities + relationships)
Step 6:  ENRICH        → EPSS (exploit likelihood) + CISA KEV + MITRE ATT&CK + business context
Step 7:  SCORE         → Unified risk score (CVSS × EPSS × reachability × business impact)
Step 8:  POLICY        → SLA enforcement, auto-triage rules, severity overrides
Step 9:  LLM CONSENSUS → Multi-LLM voting (GPT-4 + Claude + Gemini, 85% threshold)
Step 10: MPTE VERIFY   → Micro-pentest proves exploitability (VULNERABLE/NOT_VULNERABLE/NOT_APPLICABLE)
Step 11: PLAYBOOKS     → Automated response workflows (25 hours → 90 seconds)
Step 12: EVIDENCE      → Quantum-secure signed compliance bundles (RSA-4096 + ML-DSA-65)
```

---

## 6. The FalkorDB Knowledge Graph

ALdeci builds a persistent, queryable knowledge graph of your entire security posture:

**15+ Node Types**: Application, Component, Feature, Vulnerability, Finding, Asset, Dependency, CloudResource, AttackPath, ComplianceControl, Evidence, Developer, Team, Policy, ThreatActor

**15+ Relationship Types**: HAS_COMPONENT, DEPENDS_ON, AFFECTED_BY, RUNS_ON, MAPS_TO_CONTROL, MITIGATED_BY, OWNED_BY, TARGETS, EXPLOITS, etc.

**Natural Language Queries** (via MindsDB):
- *"Why did this component have 3x more vulnerabilities this sprint?"*
- *"Show attack paths from internet to patient-records database"*
- *"Which services are affected by the APT41 campaign?"*

---

## 7. Who We Serve — 25 Personas, 72 Features

### The 25 Characters

| Group | Personas | Count |
|-------|----------|-------|
| **Leadership** | Sarah (VP Eng), David (CISO), Priya (CFO), Karen (Compliance Mgr) | 4 |
| **Security Team** | Raj (AppSec Lead), Nina (AppSec Eng), Anika (VM Analyst), Tom (SOC Analyst), Victor (SOC Mgr), Jake (Red Team), Sana (Threat Analyst), Ethan (Security Eng), Lena (Security Architect) | 9 |
| **Engineering & Product** | Mike (Sr Dev), Alex (Jr Dev), Lisa (DevOps), Derek (Scrum Master), Olivia (Product Owner), Hasan (Platform Admin) | 6 |
| **Data & AI** | Farid (LLM Analyst), Maya (Context Eng), Ravi (Data Eng), Chen (Data Scientist) | 4 |
| **External** | Diana (External Auditor) | 1 |

### Persona Impact Summary

| Persona | Key Metric | Before | After |
|---------|-----------|--------|-------|
| **Raj** (AppSec Lead) | Weekly triage hours | 30 hr | 6 hr |
| **Nina** (AppSec Eng) | PR coverage | 8/20 PRs | 20/20 PRs |
| **Anika** (VM Analyst) | Spreadsheet hours/week | 35 hr | 4 hr |
| **Jake** (Red Team) | Pen-tests/year | 1 ($45K) | 365 + annual |
| **Karen** (Compliance) | Audit prep time | 3 weeks | 2 hours |
| **Alex** (Junior Dev) | Time per security fix | 2+ hours (confused) | 20 min (guided) |
| **Diana** (Auditor) | Audit duration | 3 days | 4 hours |
| **Derek** (Scrum Master) | Sprint disruption | 30% velocity loss | 0% (planned) |
| **Priya** (CFO) | Annual savings | $0 visibility | $110K direct + $3.4M risk |
| **Victor** (SOC Mgr) | SOC metrics | Unmeasurable | MTTD: 14 min, MTTR: 4.2 days |
| **Ethan** (Security Eng) | Integration maintenance | 60% of time | 10% |

### Complete Feature × Persona Coverage

| Category | Persona Count | Features Used |
|----------|--------------|---------------|
| Leadership | 4 | 42 features |
| Security Team | 9 | 65 features |
| Engineering & Product | 6 | 38 features |
| Data & AI | 4 | 24 features |
| External | 1 | 8 features |
| **Total** | **25** | **72 unique features** |

---

## 8. The HealthPay Story — Why This Matters

> *HealthPay is a fictional healthcare fintech company with 40 engineers and a 7-person security team. They represent every mid-market company drowning in security alerts.*

### The Problem

- **14,000 findings** across Snyk + Trivy + Qualys — nobody knows which ones matter
- **38-day average fix time** — critical CVEs sit in Jira for weeks
- **80% of the VM team's week** is data janitoring (CSV exports, manual dedup, copy-paste Jira tickets)
- **3 weeks of audit prep** before every HIPAA/PCI audit — screenshots in PowerPoint, scans in CSVs
- The CISO can't answer: *"Are we safe?"*
- The CFO can't answer: *"What's our ROI on $180K/year in security tools?"*

### The Transformation

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Findings to triage | 14,000 | **340** | 97% noise eliminated |
| Time to fix | 38 days | **4.2 days** | 9x faster |
| Audit prep | 3 weeks | **2 hours** | 99.4% reduction |
| Board report prep | 2 days | **5 minutes** | 99.6% reduction |
| Annual pen-tests | 1 ($45K) | **365 + annual** | Always-on signal |
| Tool spend | $180K (blind) | $164K (10x ROI) | $16K saved |
| False positive rate | Unknown | **6%** | Measurable |
| MTTD | Unknown | **14 minutes** | Visible |
| MTTR | Unknown | **4.2 days** | Visible |

**Same team. Same tools. Different brain.**

---

## 9. What's Built vs What's Left

### Backend: ~70% Production-Ready

| Suite | Purpose | Status |
|-------|---------|--------|
| **suite-api** | FastAPI gateway, 61 routers, auth | ✅ Built |
| **suite-core** | Brain pipeline, connectors, knowledge graph, LLM providers | ✅ Built |
| **suite-attack** | MPTE (19-phase), SAST/DAST/secrets scanning | ✅ Built |
| **suite-feeds** | NVD, KEV, EPSS, 50+ threat intel sources | ✅ Built |
| **suite-evidence-risk** | Compliance, evidence bundles, risk scoring | ✅ Built |
| **suite-integrations** | Jira, Slack, GitHub, MCP, webhooks | ✅ Built |
| **suite-ui** | React + Vite + shadcn/ui | 🟡 49% stubs |

### Key Backend Components

| Component | File | LOC | Status |
|-----------|------|-----|--------|
| Brain Pipeline | `core/brain_pipeline.py` | 448 | ✅ Complete |
| LLM Providers | `core/llm_providers.py` | 664 | ✅ 5 providers |
| Connectors | `core/connectors.py` | ~600 | ✅ Circuit breaker + retry |
| Crypto (RSA) | `core/crypto.py` | 571 | ✅ RSA-4096 (needs PQ upgrade) |
| Evidence Hub | `core/evidence.py` | 437 | ✅ Signed bundles |
| MPTE Engine | `attack/micro_pentest.py` | ~800 | ✅ 19-phase |
| API Learning Store | `api_learning_store.py` | ~400 | ✅ 4 ML models |
| Event Bus | `core/event_bus.py` | ~300 | ✅ In-process events |
| Deduplication | `core/deduplication.py` | ~500 | ✅ Fuzzy matching |

### Frontend: Biggest Gap

- **57 pages total** across the UI
- **49% are stubs** (under 200 LOC)
- **Feature-complete pages** (>400 LOC): KnowledgeGraphExplorer (589), Webhooks (573), ExposureCaseCenter (565), Playbooks (523), DecisionEngine (496), DataFabric (453), BrainPipeline (448), EvidenceVault (444), RemediationCenter (435), IntelligenceHub (431)
- **Critical missing screens**: Executive Dashboard, SLA Dashboard, Onboarding Wizard, Evidence Export Center

### Tool Integration Status

| Category | Tool | Status |
|----------|------|--------|
| SCA | Snyk | ✅ |
| SAST | Semgrep, SonarQube | ✅ |
| IaC | Checkov | ✅ |
| Cloud | AWS Security Hub, Azure, Wiz, Prisma | ✅ |
| DAST | OWASP ZAP | ✅ |
| DevOps | GitHub, GitLab, Azure DevOps | ✅ |
| Runtime | Trivy, Prowler | ✅ |
| ALM | Jira (enhanced), Slack | ✅ |
| SAST | Checkmarx, Veracode | 🟡 Connector ready |
| Graph | FalkorDB | 🆕 To build |
| NL | MindsDB | 🟡 Partial |
| IDE | VS Code, JetBrains | 🆕 To build |

---

## 10. The 5 Critical Gaps to Close

### Gap 1: Developer Experience (DX)
- **Problem**: No VS Code extension, no GitHub App, CLI needs polish
- **Impact**: Without DX, no organic adoption. Developers are the growth engine.
- **Build**: VS Code extension + MCP server (650 tools auto-discovered) + pre-commit hooks

### Gap 2: One-Click AutoFix
- **Problem**: ALdeci identifies what to fix but doesn't auto-generate PRs at scale
- **Impact**: Competitors (Snyk, Apiiro) have "Fix this vulnerability" buttons. We need parity.
- **Build**: AST-based AutoFix engine (tree-sitter), diff preview, create PR, post-deploy verify

### Gap 3: Attack Path Visualization (The "Wiz Killer")
- **Problem**: Attack paths exist in data but no compelling visualization
- **Impact**: This is THE screenshot that sells. Wiz's attack path graph is their #1 demo moment.
- **Build**: FalkorDB-powered graph visualization, blast radius calculation, GNN predictions

### Gap 4: Compliance Automation
- **Problem**: Evidence exists but control mapping is incomplete, no auto-generation
- **Impact**: Compliance buyers are 40-60% of enterprise spend
- **Build**: SOC 2/PCI-DSS/ISO 27001/NIST SSDF auto-mapping, evidence bundle export, auditor portal

### Gap 5: AI Copilot (Full Chat Experience)
- **Problem**: Copilot.tsx is 153 LOC stub
- **Impact**: Natural language security queries are the "wow" moment in every demo
- **Build**: Full chat with RAG pipeline, context window engineering, conversation history

---

## 11. 7 Unique Differentiators No Competitor Can Match

### 1. FAIL Engine — Chaos Engineering for AppSec
> *Fault-Aware Injection Layer for Pipeline Neglect Detection*

LLM-driven fault injection that deliberately introduces synthetic vulnerabilities to measure organizational response quality. Think Chaos Monkey, but for security operations.

- Injects realistic CVEs into the pipeline → measures team triage time
- Tests CI/CD gate bypass → proves security gates work (or don't)
- Generates labeled ML training data → self-improving loop
- **Zero competitors** have this. ROI: 233:1 (one prevented breach = $4.2M saved)
- **Build**: 10 days, ~1,830 LOC, 7 new API endpoints
- **Vision Pillars**: V3, V5, V8, V10

### 2. MCP-Native AI Platform — 650 Tools Auto-Discovered
> *First AppSec platform that AI agents can programmatically use*

Full MCP 2024-11-05 server with auto-generated tools from all 650 FastAPI endpoints. Any AI agent (Copilot, Cursor, Claude Desktop) can navigate ALdeci's UI, query findings, trigger scans, and stream live security data.

- Auto-discovers tools from FastAPI routes (zero manual maintenance)
- SSE + WebSocket + Streamable HTTP transports
- Frontend MCP bridge (React ↔ MCP) for agent screen interaction
- **Build**: 15 days, ~3,500 LOC
- **Vision Pillars**: V7, V2

### 3. Single AI Agent — Zero Token Cost
> *One model, 4 expert roles + moderator, self-hosted*

Replace expensive multi-vendor LLM calls ($900-6K/month) with a self-hosted fine-tuned model (Llama 3.1 70B via vLLM) that assumes 4 expert personas (Security Analyst, Pentest Expert, Compliance Auditor, Risk Quantifier) plus a Moderator — all on one model.

- 4 experts + moderator deliberation → consensus recommendation
- Zero API tokens → $0/month (vs $6K/month for multi-vendor)
- Data never leaves customer infrastructure
- QLoRA fine-tuning on 10K+ historical decisions
- **Build**: 15 days, ~2,000 LOC
- **Vision Pillars**: V4, V9

### 4. Quantum-Secure Evidence Signing
> *First AppSec platform with NIST FIPS 203/204/205 post-quantum cryptography*

Hybrid RSA-4096 + ML-DSA-65 (CRYSTALS-Dilithium) dual signatures on every evidence bundle. Future-proofs compliance evidence for 30+ years. Backward-compatible with existing RSA-only bundles.

- Dual signature (classical AND post-quantum) — if either breaks, the other protects
- Upgrade path: RSA-only → Hybrid → PQ-only
- AES-256-GCM + ML-KEM for encryption (replaces Fernet AES-128-CBC)
- **Zero competitors** have PQC. Patent-worthy differentiator.
- **Build**: 14 days, ~1,800 LOC
- **Vision Pillars**: V6, V10

### 5. MPTE — 19-Phase Micro Pen-Test Engine
> *Prove exploitability, not just detect vulnerability*

Every other tool says *"you have a vulnerability."* ALdeci says *"we tried to exploit it, and here's what happened."* 4-state verdicts: VULNERABLE_VERIFIED, NOT_VULNERABLE, NOT_APPLICABLE, UNVERIFIED.

- Safe, targeted exploit simulations (not brute force)
- Full evidence artifacts for each test (request/response, timing, confidence)
- Nightly automated runs against staging environments
- **Already built** — 19-phase engine with 37 API endpoints

### 6. Zero-Gravity Data — On-Prem AI That Forgets Intelligently
> *20 GB/year → 1 GB/year storage through intelligent data lifecycle*

4-tier data gravity system: HOT (7 days, raw) → WARM (7-90 days, compressed) → COLD (90+ days, coreset only) → DISTILLED (365+ days, knowledge in model weights only). Human feedback is Tier 0 — never deleted.

- SQLite ZSTD row-level compression (80% reduction)
- NeurIPS 2022-grade data pruning (keep top 5-10% by information value)
- River ML online learning (model updates per-sample, raw data can be discarded)
- Prioritized Experience Buffer (fixed 10K samples, most "surprising" kept)
- **Build**: 15 days, ~1,500 LOC
- **Vision Pillars**: V8, V9

### 7. "Switzerland of AppSec" Positioning
> *We don't replace any tool. We make them all work together.*

Every other vendor wants customers to rip out existing tools. ALdeci says: **keep everything.** This creates:
- **Zero migration risk** — no tool abandonment
- **Faster time-to-value** — Day 1: connect, ingest, see results
- **Lower switching cost** — if they cancel ALdeci, their tools still work
- **Vendor-neutral trust** — Snyk can partner with us, not compete

---

## 12. Competitor Comparison — Where We Win

| Capability | Snyk | Wiz | ArmorCode | Apiiro | ALdeci |
|-----------|------|-----|-----------|--------|--------|
| APP_ID hierarchy | ❌ | ❌ | ❌ | ❌ (repo-level) | ✅ App → Component → Feature |
| Design Stage integration | ❌ | ❌ | ❌ | ❌ | ✅ architecture.md → graph |
| IDE real-time agent | ✅ scanner only | ❌ | ❌ | ❌ | ✅ Agent + MCP + scanner |
| Tool orchestration | ❌ replaces tools | ❌ replaces tools | ✅ ingests | ✅ ingests | ✅ Orchestrate + OSS fallback |
| Knowledge graph | ❌ flat list | ❌ | ❌ | ✅ basic | ✅ FalkorDB full graph |
| Multi-LLM consensus | ❌ | ❌ | ❌ | ❌ | ✅ 3 LLMs OR self-hosted |
| Micro-pentest engine | ❌ | ❌ | ❌ | ❌ | ✅ 19-phase MPTE |
| Attack path + blast radius | ❌ | ✅ cloud only | ❌ | ✅ code→cloud | ✅ Code → Cloud + MPTE verify |
| Quantum-secure evidence | ❌ | ❌ | ❌ | ❌ | ✅ FIPS 204 ML-DSA |
| Self-learning ML | ❌ | ❌ | ❌ | ❌ | ✅ 5 feedback loops |
| Natural language queries | ❌ | ❌ | ❌ | ❌ | ✅ MindsDB + FalkorDB |
| Air-gapped / on-prem | ❌ | ❌ | ❌ | ❌ | ✅ Full offline |
| MCP server (AI-native) | ❌ | ❌ | ❌ | ❌ | ✅ 650 tools |
| CTEM full loop | ❌ stop at scan | ❌ stop at detect | ❌ partial | ❌ partial | ✅ Full 5-phase + proof |
| FAIL Engine (chaos) | ❌ | ❌ | ❌ | ❌ | ✅ Pipeline neglect detection |
| Pricing | $50-150K/yr | $100-300K/yr | $80-200K/yr | $150-400K/yr | **$36-60K/yr** |

### Key Insight from Research

NopSec ($6M ARR, bootstrapped) was acquired by Vulcan for **$150M**. ALdeci has MORE features but WORSE UI polish. **Fix the UI → exceed NopSec → be worth more than $150M.**

Every funded/acquired competitor has polished UI. The backend is important for differentiation, but the **frontend closes deals**. ALdeci has the strongest backend (790K LOC, 616 APIs, Multi-LLM, MPTE, KG) and the weakest frontend (22K LOC, 49% stubs). This is the single biggest risk to fundraising.

---

## 13. 5-Sprint Build Plan — 20 Weeks to v1.0

### Sprint 1 — Demo-Ready Foundation (Weeks 1-4)

> *"Demo that closes deals"*

| Order | Feature | Days | Vision Pillars |
|-------|---------|------|---------------|
| 1 | **FAIL Engine** — fault injection, response grading, neglect zones | 10 | V3 V5 V8 V10 |
| 2 | **Attack Path Visualization** — FalkorDB graph, blast radius, GNN predictions | 10 | V3 V5 V10 |
| | **Sprint Total** | **20 days** | |

**Demo flow after Sprint 1**: Inject synthetic CVE → watch team response → grade MTTR → show attack path → one-click fix.

### Sprint 2 — AI Moats (Weeks 5-8)

> *"AI agents use ALdeci as their security brain"*

| Order | Feature | Days | Vision Pillars |
|-------|---------|------|---------------|
| 3 | **MCP Full Protocol Gateway** — auto-discover 650 tools, SSE/WebSocket transport | 15 | V7 V2 |
| 4 | **Single Agent Engine** — 4 expert roles + moderator, vLLM self-hosted | 15 | V4 V9 |
| | **Sprint Total** | **30 days** | |

**After Sprint 2**: Any AI agent can use ALdeci. Self-hosted decisions cost $0 in API tokens. Annual savings: $10K-66K/year.

### Sprint 3 — Compliance & Crypto (Weeks 9-12)

> *"Evidence valid for 30+ years"*

| Order | Feature | Days | Vision Pillars |
|-------|---------|------|---------------|
| 5 | **Quantum-Secure Hybrid Signing** — RSA + ML-DSA, backward compatible | 14 | V6 V10 |
| 6 | **Compliance Auto-Mapping** — SOC 2/PCI-DSS/ISO 27001/NIST SSDF | 10 | V6 V10 |
| | **Sprint Total** | **24 days** | |

**After Sprint 3**: "First AppSec platform with quantum-secure evidence signing" — patent-worthy, zero competitors.

### Sprint 4 — UI Polish (Weeks 13-16)

> *"Every pitch deck promise has matching UI"*

| Order | Feature | Days | Vision Pillars |
|-------|---------|------|---------------|
| 7 | **UI Stub Replacement Sprint** — Executive Dashboard, SLA, Evidence Export, Onboarding Wizard, 12 persona screens | 20 | V2 V10 |
| | **Sprint Total** | **20 days** | |

**After Sprint 4**: 0 stub pages under 200 LOC. All 12 personas served. Demo-ready for investors.

### Sprint 5 — Infrastructure Optimization (Weeks 17-20)

> *"On-prem costs cut 94%, developer adoption pathway"*

| Order | Feature | Days | Vision Pillars |
|-------|---------|------|---------------|
| 8 | **Zero-Gravity Data** — sqlite-zstd, River ML, priority buffer, MinHash dedup | 15 | V8 V9 |
| 9 | **Developer Experience** — VS Code Extension, GitHub App, CLI polish | 10 | V2 V7 |
| | **Sprint Total** | **25 days** | |

**After Sprint 5**: On-prem storage reduced from 20 GB/year to 1 GB/year. Developer adoption pathway built.

### Total Engineering Effort

| Sprint | Days | Key Deliverable |
|--------|------|----------------|
| Sprint 1 | 20 | FAIL Engine + Attack Path |
| Sprint 2 | 30 | MCP Gateway + Zero-Token AI |
| Sprint 3 | 24 | Quantum Crypto + Compliance |
| Sprint 4 | 20 | UI: 0 stubs, all personas served |
| Sprint 5 | 25 | Zero-Gravity Data + DX |
| **Total** | **119 days (~20 weeks)** | **Customer-facing first, infrastructure last** |

---

## 14. UI/UX: 57 Pages, 49% Stubs — The Fix Plan

### CTEM Phase Coverage

```
PHASE 1: DISCOVER/INGEST  → 🔴 WEAKEST (no onboarding, stubs everywhere)
PHASE 2: PRIORITIZE       → ✅ STRONGEST (IntelligenceHub, DataFabric, DecisionEngine)
PHASE 3: VALIDATE          → 🟡 PARTIAL (attack path needs blast radius)
PHASE 4: REMEDIATE         → 🟡 PARTIAL (missing SLA tracking)
PHASE 5: MEASURE           → 🔴 WEAK (3 stubs, evidence export broken)
```

### Critical Missing Screens (Must Build)

| Screen | Current | Target | Persona Served |
|--------|---------|--------|---------------|
| **Onboarding Wizard** | MISSING | 300+ LOC | Everyone (first impression) |
| **Executive Dashboard** | MISSING | 500+ LOC | CISO, CTO, VP Eng |
| **SLA Dashboard** | MISSING | 400+ LOC | VM Manager, SOC Manager |
| **Evidence Export Center** | 74 LOC stub | 400+ LOC | Compliance, Auditor |

### Feature-Complete Pages (Strengths to Maintain)

| Page | LOC | Position |
|------|-----|----------|
| KnowledgeGraphExplorer | 589 | **Ahead** — no competitor has interactive KG |
| ExposureCaseCenter | 565 | **Unique** — case management |
| Playbooks | 523 | **Ahead** — ArmorCode has similar |
| DecisionEngine | 496 | **Unique** — no competitor has LLM voting UI |
| AttackLab | 458 | **Unique** — MPTE console |
| DataFabric | 453 | **Ahead** — dedup visualization |
| BrainPipelineDashboard | 448 | **Unique** — 12-stage pipeline vis |
| EvidenceVault | 444 | **Unique** — signed evidence |

### Competitor UX Patterns to Adopt

1. **Onboarding Wizard** (Snyk pattern — every competitor has this)
2. **Findings Table with Inline Actions** (universal pattern — EPSS/KEV badges, status chips)
3. **Executive Dashboard** (every $10M+ competitor)
4. **SLA Tracking Board** (Vulcan/NopSec pattern)
5. **Evidence Export Center** (required for compliance buyers)

### Persona-to-Screen Gaps

| Persona | Primary Screen | Status |
|---------|---------------|--------|
| VM Manager | SLA Dashboard | 🔴 MISSING |
| CISO | Executive Dashboard | 🔴 MISSING |
| CTO/CIO | Risk-vs-delivery | 🔴 MISSING |
| Security Engineer | CI/CD gates + policy-as-code | 🔴 Stub (75 LOC) |
| App Engineering Lead | Prioritized fix list | 🔴 MISSING |

**Critical Finding**: 5 of 12 personas have no dedicated screen. The highest-value personas (VM Manager, CISO, CTO) are unserved.

---

## 15. The Business Case

### Pricing Model (APP_ID-Based)

| Tier | Price | Includes |
|------|-------|---------|
| **Community** | Free | 3 APP_IDs, OSS scanners only, no LLM, SQLite |
| **Professional** | $3-5K/mo | 25 APP_IDs, Multi-LLM, FalkorDB, MPTE, basic compliance |
| **Enterprise** | $8-15K/mo | Unlimited APP_IDs, self-hosted LLM, quantum-secure, RBAC, audit |
| **Air-Gapped** | $15-25K/mo | Full offline, dedicated support, custom compliance frameworks |

### Revenue Path

| Quarter | Customers | Avg MRR | Total ARR |
|---------|-----------|---------|-----------|
| Q1 2026 | 5 design partners | $0 | $0 |
| Q2 2026 | 10 paid (Pro) | $4K | $480K |
| Q3 2026 | 20 paid (Pro+Ent) | $6K | $1.4M |
| Q4 2026 | 35 paid | $7K | $2.9M |
| Q1-Q4 2027 | 80 paid | $10K | $9.6M |

### The 7-Point Moat

1. **APP_ID-centric graph** — rearchitecting from scratch takes any competitor 12-18 months
2. **Tool orchestration** — "Switzerland of AppSec" — we work with every tool, we replace none
3. **Multi-LLM consensus** — no competitor has weighted voting across 3+ LLMs
4. **MPTE verification** — only platform that proves exploitability
5. **Quantum-secure evidence** — zero competitors have FIPS 204/205 PQC
6. **MCP-native** — first AppSec platform AI agents can programmatically use
7. **Self-learning** — 5 feedback loops continuously improve all models

### HealthPay ROI Story (for Customer Pitch)

| Source | Annual Savings |
|--------|---------------|
| Analyst time saved (Raj, Anika, Tom) | $77K |
| Tool consolidation (Qualys right-sizing) | $16K |
| Pen-test optimization (MPTE continuous) | $17K |
| Audit prep time saved (Karen + Diana) | $9K per audit |
| Compliance efficiency | $35K |
| Sprint velocity protection | Unquantified (but real) |
| Risk reduction (Monte Carlo) | $3.4M exposure reduction |
| **Direct savings** | **$110K+/year** |

---

## 16. The 618-Endpoint API Surface

Every endpoint maps to a lifecycle phase. Zero waste.

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
                     ─────────────────────────────
                     TOTAL: 618 endpoints, 0 wasted
```

### Key Router Highlights

| Phase | Key Routers | Endpoints |
|-------|------------|-----------|
| ④ Pre-Merge | sast, dast, secrets, container, cspm, api_fuzzer, oss_tools, iac, deduplication, identity | 94 |
| ⑧ AI Engine | feeds (30), micro_pentest (18), mpte (19), attack_sim (13), llm (6), decisions (6), pipeline (6) | 140 |
| ⑨ Remediation | remediation (15), autofix (12), workflows (13), bulk (13), policies (11), collaboration (21), evidence (6), reports (14), audit (14), analytics (22) | 128 |
| ⑩ Self-Learning | predictions (8), algorithmic (11), mindsdb (14), vuln_discovery (11) | 46 |
| Platform | copilot (14), agents (32), auth (4), users (6), teams (8), marketplace (12) | 62 |

---

## 17. Quantified Impact — Before/After ALdeci

| Metric | Before | After | Change |
|--------|--------|-------|:------:|
| Findings to triage | 14,000 | **340** | **97% noise eliminated** |
| Time to understand one finding | 45 min | **3 min** | **93%** |
| Time to fix | 38 days avg | **4.2 days** | **9x faster** |
| Audit prep | 3 weeks | **2 hours** | **99.4%** |
| Raj's weekly triage hours | 30 | **6** | **80%** |
| Nina's PR coverage | 8 of 20 PRs/week | **All 20** | **2.5x** |
| Anika & Tom's spreadsheet hours | 35 | **4** | **89%** |
| Jake's pen-tests | 1/year ($45K) | **365/year + annual** | **Always-on** |
| Sana's threat briefing | Generic | **Stack-specific, TTP-mapped** | Actionable |
| Ethan's integration time | 60% | **10%** | **83%** |
| Derek's sprint disruption | 30% velocity loss | **0%** | **100%** |
| Karen's audit prep | 3 weeks | **2 hours** | **99.4%** |
| Alex's time per fix | 2+ hours (confused) | **20 min** (guided) | **85%** |
| Diana's audit | 3 days | **4 hours** ($9K saved) | **83%** |
| Lena's architecture decisions | Gut feel | **Data-driven** | Quantified |
| Victor's SOC metrics | Unmeasurable | **MTTD: 14min** | Visible |
| Board report prep | 2 days | **5 minutes** | **99.6%** |
| Annual tool spend | $180K (no correlation) | **$164K** (10x effective) | **$16K saved** |

---

<div align="center">

## The Path Forward

```
┌─────────────────────────────────────────────────────────────┐
│         ALdeci — 5 Sprints to Market-Ready                  │
│                                                             │
│  Sprint 1 (NOW):  FAIL Engine + Attack Path                │
│                   → "Demo that closes deals"                │
│                                                             │
│  Sprint 2:        MCP Gateway + Single AI Agent            │
│                   → "AI agents use ALdeci as security brain"│
│                                                             │
│  Sprint 3:        Quantum Crypto + Compliance Auto          │
│                   → "Evidence valid for 30+ years"          │
│                                                             │
│  Sprint 4:        UI Polish (12 persona screens)            │
│                   → "Every pitch deck promise has UI"       │
│                                                             │
│  Sprint 5:        Zero-Gravity + DX                        │
│                   → "On-prem costs cut 94%, dev adoption"   │
│                                                             │
│  Total: 20 weeks │ Customer-facing first,                   │
│                  │ infrastructure last                      │
└─────────────────────────────────────────────────────────────┘
```

### The 30-Second Pitch

> Companies spend **$180K+/year on 4-5 security tools** that don't talk to each other. They get **14,000 alerts** and have no idea which ones matter. Their CISO can't answer "are we safe?" Their CFO can't prove ROI.
>
> **ALdeci is the intelligence layer** that sits on top of all these tools, deduplicates findings, verifies exploitability with automated pen-testing, prioritizes by business impact, auto-generates developer-ready fixes, produces quantum-secure compliance evidence, and gets smarter every week.
>
> We don't replace any tool. We make them all 10x more useful. **$4K/month. 60-second setup. Value on Day 1.**

---

**70% built. 20 weeks to v1.0. 25 personas. 72 features. One platform.**

*Built by one person. Designed for every security team.*

</div>

---

*Synthesized: 2026-02-27*
*Sources: ALDECI_UNIFIED_VISION.md (1,321 lines), USER_STORY_APP_FLOW.md (1,855 lines), research_next_features_to_build.md (2,707 lines)*
*Total source material: 5,883 lines → this unified document*
