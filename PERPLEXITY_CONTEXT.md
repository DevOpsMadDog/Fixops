# ALdeci / FixOps — Complete Project Context

> **For**: Perplexity Computer (or any external AI worker)
> **Created**: 2026-03-07
> **Repo**: FixOps monorepo (~244K backend LOC + ~45K frontend LOC + ~192K test LOC)
> **Status**: Sprint 2 — Enterprise Demo (Post-Demo Day 1)

---

## 1. Identity & Mission

**ALdeci is a CTEM+ (Continuous Threat Exposure Management Plus) Decision Intelligence platform for application security.**

Every enterprise runs 5–15 security scanners (Snyk, Semgrep, Trivy, Wiz, Prisma, ZAP, Checkmarx…). Each screams "CRITICAL!" independently, flooding teams with **11,300+ uncontextualized findings per week**. 68% are false positives. 80% of analyst time goes to "data janitoring."

ALdeci is the **neutral Brain** that sits above ALL scanners:

```
┌──────────────────────────────────────────────────────┐
│              YOUR EXISTING SCANNERS                   │
│  Snyk · Semgrep · Trivy · Wiz · Prisma · ZAP · …    │
└──────────────────────┬───────────────────────────────┘
                       │  Raw findings (SARIF, SBOM, CVE, VEX)
                       ▼
┌──────────────────────────────────────────────────────┐
│                 ALdeci = THE BRAIN                     │
│  Normalize → Dedup → Graph → Enrich → Score →         │
│  Decide → Verify (MPTE) → Fix → Evidence → Learn      │
└──────────────────────┬───────────────────────────────┘
                       │  Actionable decisions + signed evidence
                       ▼
┌──────────────────────────────────────────────────────┐
│             YOUR EXISTING WORKFLOWS                    │
│  Jira · Slack · GitHub PRs · CI/CD · Board Reports    │
└──────────────────────────────────────────────────────┘
```

**Result**: 11,300 findings → **340 actionable cases** (97% noise reduction). $110K annual savings per enterprise.

**"Switzerland of AppSec"**: ALdeci never replaces your scanners. It makes them intelligent. Day 1 value, no rip-and-replace. **AND** it has 8 built-in native scanners for air-gapped environments where no external tools are available.

---

## 2. The 10 Vision Pillars

Every feature must serve at least one pillar. **Honest status included.**

| # | Pillar | Promise | Status |
|---|--------|---------|--------|
| V1 | APP_ID-Centric Architecture | Every finding traces to App → Component → Feature | ✅ REAL |
| V2 | 10-Phase Security Lifecycle | Design → IDE → ALM → Pre-merge → Build → IaC → Graph → AI → Remediate → Learn | ✅ REAL (framework) |
| V3 | Decision Intelligence | "What to DO about a risk, not just what the risk IS" | ✅ REAL — brain_pipeline.py 1,878 LOC |
| V4 | Multi-LLM Consensus / Self-Hosted AI | 3+ LLMs with 85% threshold OR zero-token self-hosted | ⚠️ PARTIAL — degrades to deterministic thresholds when no API keys |
| V5 | MPTE Verification | Prove exploitability, don't just detect | ✅ REAL — micro_pentest.py 2,054 LOC + mpte_advanced.py 1,089 LOC |
| V6 | Quantum-Secure Evidence | FIPS 204 ML-DSA + RSA hybrid, 7-year WORM | ❌ NOT YET — uses `secrets.token_bytes()` instead of real lattice crypto |
| V7 | MCP-Native AI Platform | First AppSec platform AI agents can use (650 tools) | ⚠️ PARTIAL — tool registration works, execution scaffold |
| V8 | Self-Learning (5 Feedback Loops) | Decision outcomes, MPTE results, FP rates, remediation success | ❌ NOT YET — zero code |
| V9 | Air-Gapped Deployment | Full offline on commodity hardware (<1 GB/year) | ✅ REAL — all native scanners work offline |
| V10 | CTEM Full Loop with Crypto Proof | Discover → Prioritize → Validate → Remediate → Measure | ✅ REAL (loop exists, crypto proof is RSA only, not quantum) |

---

## 3. Architecture

**Modular monolith**: 6 Python backend suites + 1 React frontend, all on a single FastAPI app (port 8000).

### Suite Breakdown

| Suite | Purpose | LOC | Key Files |
|-------|---------|-----|-----------|
| `suite-api/` | FastAPI gateway, 34 router mounts, auth, middleware | 22.6K | `apps/api/app.py` (2,893 LOC — entry point) |
| `suite-core/` | Brain pipeline, all engines, scanners, connectors, CLI | 138.0K | `core/brain_pipeline.py`, `core/autofix_engine.py`, `core/micro_pentest.py`, `core/connectors.py`, `core/cli.py` |
| `suite-attack/` | MPTE, attack simulation, scanner routers | 6.7K | `api/mpte_router.py`, `api/micro_pentest_router.py` |
| `suite-feeds/` | Threat intel feeds (NVD, KEV, EPSS, OSV, ExploitDB) | 4.4K | `feeds/*.py` |
| `suite-evidence-risk/` | Compliance, evidence bundles, risk scoring | 20.3K | `risk/*.py`, `evidence/*.py` |
| `suite-integrations/` | Jira, Slack, GitHub, MCP, webhooks, IaC, OSS tools | 6.8K | `api/mcp_router.py`, `api/oss_tools.py` |
| `suite-ui/aldeci/` | **LEGACY** React UI (wired to real APIs, functional, but OLD navigation) | 45.3K | `src/App.tsx`, `src/pages/**/*.tsx` |
| `aldeci-ui-new/` | **VISION UI** — 5 Workflow Spaces (Steve Jobs redesign). **DOES NOT EXIST YET** | 0 | Needs to be built from scratch |

> **⚠️ IMPORTANT — TWO UIs:**
> - `suite-ui/aldeci/` → **LEGACY UI** (exists, functional, 101 TSX files, 45.3K LOC). Technical-suite navigation. Do NOT modify this for vision work.
> - `aldeci-ui-new/` → **VISION UI** (top-level directory, outside `suite-ui/`. Does NOT exist on disk yet — **THIS IS WHAT NEEDS TO BE BUILT**). 5 Workflow Spaces (Steve Jobs redesign). See Section 11.

### Import Mechanism

`sitecustomize.py` at repo root auto-prepends all 6 suite directories to `sys.path` at Python startup. Cross-suite imports "just work":

```python
# From any file in any suite:
from core.brain_pipeline import BrainPipeline
from core.connectors import AutomationConnectors
from api.mpte_router import router
```

No `pip install -e` or manual `sys.path` manipulation needed.

### Database

SQLite with WAL mode — 56 domain-specific `.db` files across `data/`, `.fixops_data/`, `suite-api/data/`. No shared schema, no migration system. Uses `PersistentDict` pattern.

### Events

In-process `EventBus` (`core/event_bus.py`). No external message queue (RabbitMQ/Kafka). Single-process only.

---

## 4. The 12-Step Brain Pipeline

The heart of ALdeci. Every finding flows through 12 steps. Engine: `suite-core/core/brain_pipeline.py` (1,878 LOC).

| Step | Name | What It Does | Honest Status |
|------|------|-------------|---------------|
| 1 | CONNECT | Ingest from external scanners (SARIF/SBOM/CVE) or native scanners | ✅ Real — 20+ format adapters |
| 2 | NORMALIZE | Map all formats to ALdeci Universal Finding Format | ✅ Real |
| 3 | RESOLVE IDENTITY | Cross-scanner asset fingerprinting (same CVE from Snyk + Trivy = 1 finding) | ✅ Real — fuzzy matching |
| 4 | DEDUPLICATE | Cluster by similarity >90%, MinHash + LSH | ✅ Real — 11,300 → ~2,000 |
| 5 | BUILD GRAPH | Insert nodes/edges into knowledge graph (Finding, Component, CVE, CWE) | ✅ Real — in-memory NetworkX (not FalkorDB yet) |
| 6 | ENRICH | Add NVD/EPSS/KEV threat intelligence | ⚠️ Degrades to deterministic enrichment without API keys |
| 7 | SCORE RISK | CVSS × EPSS × reachability × blast_radius × business context | ✅ Real |
| 8 | EVALUATE POLICY | Check aldeci.yaml rules (block_on_critical, require_mpte, etc.) | ✅ Real |
| 9 | LLM CONSENSUS | GPT-4 + Claude + Gemini vote, 85% agreement threshold | ⚠️ Degrades to deterministic threshold when no LLM API keys |
| 10 | MICRO-PENTEST | MPTE 19-phase exploit verification | ✅ Real — 2,054 LOC |
| 11 | RUN PLAYBOOKS | AutoFix PR generation, Jira tickets, Slack notifications | ✅ Real — 1,534 LOC autofix engine |
| 12 | GENERATE EVIDENCE | Produce compliance evidence bundles | ⚠️ Produces unsigned JSON, not quantum-signed bundle. Evidence packager exists (335 LOC) but disconnected from pipeline |

---

## 5. 8 Native Scanners

All work air-gapped with ZERO external dependencies.

| # | Scanner | Engine File | LOC | Endpoints | Status |
|---|---------|-------------|-----|-----------|--------|
| 1 | **SAST** | `suite-core/core/sast_engine.py` | 1,623 | 4 | ✅ REAL — 101+ regex rules, multi-language (Python/JS/Java/Go) |
| 2 | **DAST** | `suite-core/core/dast_engine.py` | 634 | 2 | ✅ REAL — actual HTTP payloads, XSS/SQLi/SSRF detection |
| 3 | **Secrets** | `suite-core/core/secrets_scanner.py` | 849 | 7 | ✅ REAL — 200+ patterns, entropy analysis, wraps gitleaks/trufflehog |
| 4 | **Container** | `suite-core/core/container_scanner.py` | 446 | 3 | ✅ REAL — Dockerfile parsing, layer scanning, CVE matching |
| 5 | **CSPM/IaC** | `suite-core/core/cspm_engine.py` | 610 | 9 | ✅ REAL but basic — ~6 rules for Terraform/CloudFormation |
| 6 | **API Fuzzer** | `suite-attack/api/api_fuzzer_router.py` | ~200 | 3 | ⚠️ PARTIAL — router-inline, not standalone engine |
| 7 | **Malware** | `suite-attack/api/malware_router.py` | ~200 | 4 | ⚠️ PARTIAL — router-inline, not standalone engine |
| 8 | **LLM Monitor** | `suite-core/api/llm_monitor_router.py` | ~200 | 4 | ⚠️ PARTIAL — router-inline, not standalone engine |

**Total**: ~4,762 LOC across scanner engines, ~36 API endpoints

---

## 6. AutoFix Engine

Engine: `suite-core/core/autofix_engine.py` (1,534 LOC). LLM-powered auto-remediation.

**10 Fix Types**: CODE_PATCH, DEPENDENCY_UPDATE, CONFIG_HARDENING, IAC_FIX, SECRET_ROTATION, PERMISSION_FIX, INPUT_VALIDATION, OUTPUT_ENCODING, WAF_RULE, CONTAINER_FIX

**Confidence**: HIGH (>85% → auto-apply & create PR) | MEDIUM (60-85% → PR for review) | LOW (<60% → suggest only)

**14 API endpoints**: `/autofix/generate`, `/autofix/apply/{id}`, `/autofix/validate/{id}`, `/autofix/rollback/{id}`, `/autofix/bulk`, `/autofix/history`, `/autofix/stats`, etc.

---

## 7. MPTE (Micro-Pentest Engine)

Proves exploitability — doesn't just detect vulnerabilities.

- **Core**: `suite-core/core/micro_pentest.py` (2,054 LOC)
- **Advanced**: `suite-core/core/mpte_advanced.py` (1,089 LOC)
- **69 API endpoints** across 5 router files
- **19-phase deterministic scanner**: recon → enumeration → vuln ID → exploitation → post-exploitation → cleanup → evidence report
- **Verdicts**: VULNERABLE_VERIFIED | NOT_VULNERABLE_VERIFIED | NOT_APPLICABLE | UNVERIFIED

---

## 8. Enterprise Connectors

### Integration Connectors — `suite-core/core/connectors.py` (3,030 LOC)

| Connector | API | Capabilities |
|-----------|-----|-------------|
| Jira | REST v3 | Bi-directional sync, SLA tracking, ticket creation |
| Confluence | REST v2 | Security page generation |
| Slack | Web API | Alerts, workflow notifications |
| ServiceNow | Table API | ITSM integration |
| GitLab | REST v4 | MR creation, pipeline triggers |
| Azure DevOps | REST v7.2 | Work items, pipeline integration |
| GitHub | REST v3 | PR creation, issue tracking, webhooks |

All connectors use: circuit breaker, retry with exponential backoff, rate limiting, health check endpoints. Inherit from `_BaseConnector`.

### Security Tool Connectors — `suite-core/core/security_connectors.py` (1,336 LOC)

Snyk, SonarQube, Dependabot, AWS SecurityHub, Azure Defender, Wiz, Prisma Cloud, Orca, Lacework, ThreatMapper — all with normalized finding ingestion.

---

## 9. API Surface — 771 Endpoints

| Prefix | Router | Endpoints | Purpose |
|--------|--------|-----------|---------|
| `/api/v1/brain` | brain_router.py | 24 | Brain pipeline operations |
| `/api/v1/mpte` | mpte_router.py | 23 | MPTE orchestration |
| `/api/v1/micro-pentest` | micro_pentest_router.py | 19 | Micro-pentest execution |
| `/api/v1/feeds` | feeds_router.py | 31 | Threat intelligence feeds |
| `/api/v1/agents` | agents_router.py | 32 | AI agent management |
| `/api/v1/autofix` | autofix_router.py | 13 | Auto-remediation |
| `/api/v1/mcp-server` | mcp_router.py | 10 | MCP tool gateway |
| `/api/v1/mcp` | mcp_router.py | 8 | MCP auto-discovery |
| `/api/v1/scanner-ingest` | scanner_ingest_router.py | 7 | Universal scanner ingest |
| + 55 more routers | ... | ~600+ | Full platform surface |

**Auth**: `X-API-Key` header (`FIXOPS_API_TOKEN`) + JWT tokens (`FIXOPS_JWT_SECRET`)

---

## 10. Legacy UI — `suite-ui/aldeci/` (101 TSX files, 45.3K LOC)

> **This is the LEGACY UI. It exists and is functional but uses OLD technical-suite navigation.**
> **Do NOT build the vision UI here. The vision UI goes in `suite-ui/aldeci-ui-new/` (Section 11).**

Stack: React 18 + Vite 5 + TypeScript 5 + Tailwind 3 + shadcn/ui + Framer Motion

### Existing Route Map (from `suite-ui/aldeci/src/App.tsx`)

| Route | Page | Category |
|-------|------|----------|
| `/` `/dashboard` | Dashboard | Core |
| `/executive` `/ceo` | CEODashboard | Core |
| `/nerve-center` | NerveCenter | Core |
| `/core/brain-pipeline` | BrainPipelineDashboard | Core |
| `/core/knowledge-graph` | KnowledgeGraphExplorer | Core |
| `/core/exposure-cases` | ExposureCaseCenter | Core |
| `/code/code-scanning` | CodeScanning | Code Suite |
| `/code/secrets-detection` | SecretsDetection | Code Suite |
| `/code/iac-scanning` | IaCScanning | Code Suite |
| `/code/sbom-generation` | SBOMGeneration | Code Suite |
| `/code/inventory` | Inventory | Code Suite |
| `/cloud/cloud-posture` | CloudPosture | Cloud Suite |
| `/cloud/container-security` | ContainerSecurity | Cloud Suite |
| `/cloud/runtime-protection` | RuntimeProtection | Cloud Suite |
| `/cloud/threat-feeds` | ThreatFeeds | Cloud Suite |
| `/discover/scanners` | ScannerDashboard | Discover |
| `/discover/scanner-ingest` | ScannerIngestUpload | Discover |
| `/attack/mpte` | MPTEConsole | Attack Suite |
| `/attack/micro-pentest` | MicroPentest | Attack Suite |
| `/attack/attack-simulation` | AttackSimulation | Attack Suite |
| `/attack/attack-paths` | AttackPaths | Attack Suite |
| `/attack/reachability` | Reachability | Attack Suite |
| `/attack/sandbox` | SandboxVerification | Attack Suite |
| `/validate/fail-engine` | FAILEngineDashboard | Validate |
| `/protect/remediation` | Remediation | Protect Suite |
| `/protect/autofix` | AutoFixDashboard | Protect Suite |
| `/protect/playbooks` | Playbooks | Protect Suite |
| `/protect/bulk-operations` | BulkOperations | Protect Suite |
| `/protect/workflows` | Workflows | Protect Suite |
| `/protect/collaboration` | Collaboration | Protect Suite |
| `/protect/integrations` | Integrations | Protect Suite |
| `/evidence/bundles` | EvidenceBundles | Evidence |
| `/evidence/compliance` | ComplianceReports | Evidence |
| `/evidence/soc2` | SOC2EvidenceUI | Evidence |
| `/evidence/slsa-provenance` | SLSAProvenance | Evidence |
| `/evidence/audit-trail` | AuditLogs | Evidence |
| `/evidence/reports` | Reports | Evidence |
| `/evidence/analytics` | EvidenceAnalytics | Evidence |
| `/ai-engine/multi-llm` | MultiLLMPage | AI |
| `/ai-engine/ml-dashboard` | MLDashboard | AI |
| `/ai-engine/algorithmic-lab` | AlgorithmicLab | AI |
| `/ai-engine/predictions` | Predictions | AI |
| `/ai-engine/policies` | Policies | AI |
| `/feeds/live` | LiveFeedDashboard | Intel |
| `/mission-control/sla` | SLADashboard | Mission Control |
| `/settings/*` | 8 settings pages | Admin |
| `/copilot` | Copilot | AI Assistant |

These pages are **wired to real backend APIs** on port 8000. They work. But the navigation is organized by technical suites (Code, Cloud, Attack, Protect, Evidence, AI Engine) — NOT by the vision's 5 Workflow Spaces.

---

## 11. ⭐ VISION UI — `aldeci-ui-new/` (NEEDS TO BE BUILT)

> **This is a TOP-LEVEL directory (NOT inside `suite-ui/`). It does NOT exist on disk yet. This is the #1 build priority.**
> **The vision UI replaces the legacy UI's technical-suite navigation with 5 Workflow Spaces organized by WHAT PEOPLE NEED TO DO.**

### Design Philosophy (Steve Jobs Redesign)

- **Apple HIG-inspired**: Clean typography, generous whitespace, physics-based animations
- **Organized by workflows, not features**: People don't think "I need Code Suite" — they think "What needs my attention?"
- **25 personas served**: CISO, VP Engineering, CTO, CFO, DevSecOps (9 roles), Engineering (6 roles), Data/AI (4 roles), External (Auditor, Consultant)

### The 5 Workflow Spaces

| Space | Icon | Question It Answers | Key Pages to Build |
|-------|------|--------------------|--------------------|
| 🎯 **MISSION CONTROL** | Target | "What needs attention now?" | Command Dashboard, Executive View, SLA Dashboard, Live Feed, Risk Overview |
| 🔍 **DISCOVER** | Search | "What risks exist?" | Finding Explorer, Code Scanning, Secrets, IaC, Cloud Posture, Containers, SBOM, Knowledge Graph, Attack Paths, Threat Feeds, Scanner Dashboard |
| ⚡ **VALIDATE** | Lightning | "Is it actually exploitable?" | MPTE Console, Attack Simulation, FAIL Engine, Playbooks, Reachability, Sandbox Verification |
| 🔧 **REMEDIATE** | Wrench | "How do I fix it?" | Remediation Center, AutoFix Dashboard, Bulk Operations, Collaboration, Workflows, Tickets, Integrations |
| 🛡️ **COMPLY** | Shield | "Can I prove we're secure?" | Compliance Dashboard, Evidence Vault, Evidence Bundles, SOC2, SLSA, Audit Trail, Reports, Analytics |

Plus: **AI Copilot** (persistent sidebar, available in every space) and **Settings** (gear icon, bottom).

### Recommended Tech Stack (same as legacy for consistency)

- React 18 + Vite 5 + TypeScript 5
- Tailwind CSS 3 + shadcn/ui components
- Framer Motion for physics-based animations
- @tanstack/react-query for data fetching
- React Router v6 for routing
- Zustand for state management
- axios for API calls (backend on port 8000)

### Sidebar Navigation Structure

```
┌──────────────────────────────┐
│  🔮 ALdeci                   │
│                              │
│  🎯 Mission Control          │
│     ├─ Command Dashboard     │
│     ├─ Executive View        │
│     ├─ SLA Dashboard         │
│     └─ Live Feed             │
│                              │
│  🔍 Discover                 │
│     ├─ Finding Explorer      │
│     ├─ Code Scanning         │
│     ├─ Secrets Detection     │
│     ├─ IaC Scanning          │
│     ├─ Cloud Posture         │
│     ├─ Container Security    │
│     ├─ SBOM & Inventory      │
│     ├─ Knowledge Graph       │
│     ├─ Attack Paths          │
│     ├─ Threat Feeds          │
│     └─ Scanner Dashboard     │
│                              │
│  ⚡ Validate                 │
│     ├─ MPTE Console          │
│     ├─ Attack Simulation     │
│     ├─ FAIL Engine           │
│     ├─ Reachability          │
│     └─ Sandbox Verification  │
│                              │
│  🔧 Remediate                │
│     ├─ Remediation Center    │
│     ├─ AutoFix Dashboard     │
│     ├─ Bulk Operations       │
│     ├─ Playbooks             │
│     ├─ Workflows             │
│     ├─ Collaboration         │
│     └─ Integrations          │
│                              │
│  🛡️ Comply                   │
│     ├─ Compliance Dashboard  │
│     ├─ Evidence Vault        │
│     ├─ Evidence Bundles      │
│     ├─ SOC2 Evidence         │
│     ├─ SLSA Provenance       │
│     ├─ Audit Trail           │
│     ├─ Reports               │
│     └─ Analytics             │
│                              │
│  ─────────────────────────── │
│  🤖 AI Copilot               │
│  ⚙️ Settings                 │
└──────────────────────────────┘
```

### All 25 Personas → Space Mapping

The 5 Workflow Spaces cover **all 25 personas**. Each persona has a Home Space (where they start their day) and Secondary Spaces they visit:

**Group 1: Leadership (4)**

| # | Persona | Role | Home Space | Secondary |
|---|---------|------|-----------|-----------|
| 1 | Sarah Chen | CISO | Mission Control (Executive View) | Comply |
| 2 | David Kim | VP Engineering | Mission Control (SLA Dashboard) | Remediate |
| 3 | Priya Patel | CTO/CIO | Mission Control (Risk Overview) | Discover (Graph) |
| 4 | Tom Bradley | CFO | Mission Control (Executive View) | Comply (Reports) |

**Group 2: Security Operations (9)**

| # | Persona | Role | Home Space | Secondary |
|---|---------|------|-----------|-----------|
| 5 | Alex Rivera | Security Engineer | Remediate | Discover, Validate |
| 6 | Marcus Thompson | AppSec Engineer | Discover | Validate, Remediate |
| 7 | Raj Mehta | DevSecOps Lead | Mission Control (Dashboard) | Remediate, Discover |
| 8 | Janet Liu | SOC Analyst | Mission Control (Live Feed) | Validate, Remediate |
| 9 | Maria Santos | Compliance Lead | Comply | Mission Control |
| 10 | Derek Washington | VM Manager | Mission Control (SLA Dashboard) | Remediate |
| 11 | Jason Wu | Red Team Lead | Validate (MPTE) | Validate (FAIL) |
| 12 | Emily Foster | Threat Analyst | Discover (Threat Feeds) | Discover (Graph) |
| 13 | Brian Mitchell | Cloud Security Eng | Discover (Cloud Posture) | Validate |

**Group 3: Engineering (6)**

| # | Persona | Role | Home Space | Secondary |
|---|---------|------|-----------|-----------|
| 14 | Mike Chen | Senior Developer | Remediate (AutoFix) | Discover (Code) |
| 15 | Lisa Park | Cloud Architect | Discover (Graph) | Discover (Attack Paths) |
| 16 | Rachel Kim | Junior Developer | Remediate (AutoFix) | Discover (Code) |
| 17 | Kevin O'Brien | Dev Lead | Mission Control (SLA) | Remediate |
| 18 | Amy Rodriguez | QA / Release Eng | Mission Control | Comply (SLSA) |
| 19 | Chris Taylor | Platform Engineer | Settings (Integrations) | Discover |

**Group 4: Data & AI (4)**

| # | Persona | Role | Home Space | Secondary |
|---|---------|------|-----------|-----------|
| 20 | Dr. Wei | ML Engineer | Validate (FAIL Engine) | AI Copilot |
| 21 | Aisha Johnson | Data Scientist | AI Copilot | Mission Control |
| 22 | Nina Kowalski | Security Architect | Discover (Graph) | Mission Control |
| 23 | Sam Parker | AI Agent Developer | Settings (API/MCP) | — |

**Group 5: External (2)**

| # | Persona | Role | Home Space | Secondary |
|---|---------|------|-----------|-----------|
| 24 | Laura Chen | External Auditor | Comply (Evidence Export) | Comply (Audit Trail) |
| 25 | Carlos Mendez | Security Consultant | Mission Control | All spaces |

**Space coverage summary**: Mission Control serves 10 personas as home, Discover serves 5, Remediate serves 3, Validate serves 2, Comply serves 2, Settings serves 2, AI Copilot serves 1. Every persona has at least one Workflow Space as their home.

### API Integration

All pages connect to the **same backend** on port 8000. The API surface (771 endpoints) already exists. The vision UI just reorganizes HOW users navigate to these endpoints.

Key API namespaces the new UI should use:
- `GET /api/v1/brain/pipeline/*` — Brain pipeline status, steps
- `GET /api/v1/findings/*` — Finding explorer
- `POST /api/v1/scanner-ingest/*` — Scanner result upload
- `GET /api/v1/mpte/*` — MPTE console
- `GET /api/v1/micro-pentest/*` — Micro-pentest results
- `GET /api/v1/autofix/*` — AutoFix dashboard
- `POST /api/v1/autofix/generate` — Generate fixes
- `GET /api/v1/evidence/*` — Evidence bundles
- `GET /api/v1/compliance/*` — Compliance reports
- `GET /api/v1/feeds/*` — Live threat feeds
- `GET /api/v1/agents/*` — AI copilot operations
- `GET /api/v1/integrations/*` — Enterprise integrations
- `GET /api/v1/analytics/*` — Dashboard analytics

Frontend API config: use `VITE_API_URL` (default `http://localhost:8000`) and `VITE_API_KEY` for `X-API-Key` header.

### What to Reference from Legacy UI

The legacy `suite-ui/aldeci/` has these reusable patterns:
- `src/lib/api.ts` — axios client with API key header (copy this pattern)
- `src/components/ui/` — shadcn/ui component library (reuse or reinstall)
- `src/stores/` — Zustand store patterns
- `src/components/ErrorBoundary.tsx` — Error boundary component
- `src/components/CommandPalette.tsx` — Command palette (⌘K) component

**Don't fork the legacy UI.** Build fresh in `aldeci-ui-new/` (top-level, next to `suite-ui/`) with the 5 Workflow Spaces as the foundational navigation pattern.

---

## 12. FAIL Engine (Unique Differentiator)

Engine: `suite-core/core/fail_engine.py` (711 LOC)

**Concept**: Netflix Chaos Monkey for AppSec. Inject real security faults into applications, grade team response time and quality. Generates labeled training data automatically.

**No competitor has this.** It's a chaos engineering approach applied to security operations — testing whether teams can detect and respond to threats, not just whether tools can find vulnerabilities.

---

## 13. MCP Gateway (Model Context Protocol)

- **Server**: `suite-core/core/mcp_server.py` (978 LOC)
- **Router**: `suite-integrations/api/mcp_router.py` (468 LOC)
- **Transport**: stdio, SSE, WebSocket
- **Auto-discovery**: Crawls all FastAPI routes and exposes as MCP tools
- **Status**: Tool registration and discovery work. Execution layer is scaffold — tool calls route but don't all execute cleanly

First AppSec platform that AI agents (Copilot, Cursor, Claude Code) can programmatically use.

---

## 14. Honest Status — Vision vs Reality (March 7, 2026)

### 60% REAL (Production-Quality Code)
- ✅ 12-step Brain Pipeline — all steps exist and execute (1,878 LOC)
- ✅ 5 standalone scanner engines (SAST, DAST, Secrets, Container, CSPM) — 4,162 LOC combined
- ✅ MPTE 19-phase exploit verification — 3,143 LOC
- ✅ AutoFix with 10 fix types — 1,534 LOC, LLM-powered
- ✅ 17 enterprise connectors (7 integration + 10 security tool) — 4,366 LOC
- ✅ RSA-SHA256 evidence signing — crypto.py 582 LOC
- ✅ Air-gapped mode — native scanners need zero internet
- ✅ 40+ React UI pages wired to real API endpoints (legacy UI)
- ✅ CLI with 22 commands — 5,911 LOC
- ✅ FAIL Engine — 711 LOC

### 25% PARTIAL (Works but Degrades)
- ⚠️ 3 scanners (API Fuzzer, Malware, LLM Monitor) are router-inline (~200 LOC each), not standalone engines
- ⚠️ LLM consensus (step 9) degrades to deterministic thresholds without API keys
- ⚠️ Threat enrichment (step 6) degrades to static data without feed connections
- ⚠️ Evidence signing disconnected from brain pipeline — packager exists (335 LOC) but step 12 outputs unsigned JSON
- ⚠️ MCP gateway — registration works, execution is scaffold
- ⚠️ Knowledge graph uses in-memory NetworkX, not FalkorDB

### 15% NOT YET (Marketing Claims Without Code)
- ❌ **Vision UI** — `aldeci-ui-new/` (top-level) does NOT exist on disk. 5 Workflow Spaces need to be built from scratch
- ❌ **Quantum-Secure ML-DSA** — `quantum_crypto.py` uses `secrets.token_bytes()` shaped like ML-DSA signatures, not real lattice math
- ❌ **Self-Learning V8** — zero code exists anywhere for the 5 feedback loops
- ❌ **vLLM Self-Hosted Single Agent** — `single_agent.py` is a stub, no vLLM integration
- ❌ **Zero-Gravity Data** — `zero_gravity.py` exists but 4-tier aging is not wired
- ❌ **25 personas** — legacy UI serves maybe 5 distinct workflows, not 25

---

## 15. What We Need Built (Goals & Priorities)

### 🔴 Priority 1 — Build the Vision UI (`aldeci-ui-new/`)
This is the biggest gap. The entire 5 Workflow Spaces UI needs to be created from scratch:
1. **Scaffold** — Vite + React 18 + TypeScript + Tailwind + shadcn/ui project in `aldeci-ui-new/` (top-level directory, NOT inside `suite-ui/`)
2. **Sidebar navigation** — 5 Workflow Spaces with collapsible sections (see Section 11)
3. **Mission Control space** — Command Dashboard, Executive View, SLA Dashboard, Live Feed
4. **Discover space** — Finding Explorer, Scanner Dashboard, Code/Secrets/IaC/Cloud/Container pages, Knowledge Graph, Attack Paths
5. **Validate space** — MPTE Console, Attack Simulation, FAIL Engine, Reachability, Sandbox
6. **Remediate space** — Remediation Center, AutoFix, Bulk Ops, Playbooks, Workflows, Collaboration
7. **Comply space** — Compliance Dashboard, Evidence Vault/Bundles, SOC2, SLSA, Audit Trail, Reports
8. **AI Copilot sidebar** — persistent chat interface available in every space
9. **Wire all pages to real APIs** on port 8000 (771 endpoints already exist)

### 🟡 Priority 2 — Close the 15% Backend Gap
10. **Real ML-DSA quantum signatures** — Replace `secrets.token_bytes()` in `quantum_crypto.py` with actual FIPS 204 lattice-based signatures (use `pqcrypto` or `oqs-python`)
11. **Self-Learning feedback loops (V8)** — Implement 5 loops: decision outcomes, MPTE results, false positive rates, remediation success, policy violations
12. **vLLM single agent** — Wire Llama 3.1 70B via vLLM for air-gapped LLM inference
13. **Zero-Gravity 4-tier data aging** — ZSTD compression + coreset selection + MinHash dedup for <1 GB/year storage

### 🟢 Priority 3 — Upgrade the 25% Partial
14. Wire live threat feeds (NVD/KEV/EPSS APIs) to brain pipeline step 6
15. Connect evidence packager to brain pipeline step 12 (sign evidence bundles)
16. Complete MCP execution layer (not just tool registration)
17. Promote 3 inline scanners (API Fuzzer, Malware, LLM Monitor) to standalone engines with dedicated `.py` files

### Priority 4 — Infrastructure & Quality
18. Test coverage 19.21% → 25% (CI gate currently FAILING)
19. Replace NetworkX with FalkorDB for production knowledge graph
20. Connect all legacy UI pages to real APIs (1 page still has demo data fallback: EvidenceBundles.tsx)

---

## 16. Codebase Navigation Guide

### What to Index (~522 source files)
```
suite-core/core/          # 120+ Python files — ALL engines, scanners, connectors
suite-core/api/           # 24 Python files — core API routers
suite-api/apps/api/       # 37 Python files — gateway routers + middleware
suite-attack/api/         # 13 Python files — offensive security routers
suite-feeds/              # ~15 Python files — threat feed services
suite-evidence-risk/      # ~30 Python files — evidence, risk, compliance
suite-integrations/api/   # ~10 Python files — MCP, webhooks, IaC, OSS
suite-ui/aldeci/src/      # 101 TSX/TS files — LEGACY React frontend (reference only)
sitecustomize.py          # Import mechanism (READ THIS FIRST)
pyproject.toml            # Test config, formatters
requirements.txt          # 32 Python dependencies
Makefile                  # Build commands
```

### What to SKIP (noise)
```
bash-5.1/                 # Vendored GNU Bash 5.1 C source code — NOT project code!
.claude/team-state/       # AI agent runtime state files (JSON, MD)
.claude/agents/           # Agent definitions (useful for understanding, not for code changes)
data/                     # Runtime SQLite databases
logs/                     # Runtime log files
node_modules/             # npm dependencies
__pycache__/              # Python cache
*.db                      # SQLite database files
pentagi-aldeci/           # Reference HTML, not active code
WIP/                      # Work-in-progress, excluded from linting
```

### Key Entry Points
| What | File | Why |
|------|------|-----|
| Backend entry | `suite-api/apps/api/app.py` | FastAPI app factory, 34 router mounts |
| Import mechanism | `sitecustomize.py` | Auto-adds all suite paths to sys.path |
| Decision engine | `suite-core/core/brain_pipeline.py` | 12-step CTEM pipeline |
| Legacy frontend | `suite-ui/aldeci/src/App.tsx` | All current React routes (reference for API patterns) |
| Legacy API client | `suite-ui/aldeci/src/lib/api.ts` | axios with X-API-Key header (copy this pattern for new UI) |

---

## 17. Commands

```bash
# Backend - start the server
pip install -r requirements.txt
python -m uvicorn apps.api.app:create_app --factory --port 8000 --reload

# Legacy Frontend (reference only — do NOT build vision UI here)
cd suite-ui/aldeci && npm install && npm run dev  # → http://localhost:3001

# New Vision UI (once created — top-level directory)
cd aldeci-ui-new && npm install && npm run dev  # → http://localhost:3002 (suggested)

# Run all tests
python -m pytest tests/ --timeout=10 -x -q

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=term --timeout=10

# Run specific test
pytest tests/test_brain_pipeline.py -v
pytest -k "test_integrations" -v

# Format code
make fmt  # runs isort + black

# Full demo pipeline
make demo

# Docker
docker compose -f docker/docker-compose.yml up

# Enterprise Docker
docker compose -f docker/docker-compose.enterprise.yml up
```

---

## 18. Dependencies (requirements.txt)

| Package | Version | Purpose |
|---------|---------|---------|
| fastapi | >=0.115, <0.128 | Web framework |
| uvicorn | >=0.30.0 | ASGI server |
| pydantic | >=2.6, <3.0 | Data validation |
| requests / httpx | >=2.32 / >=0.27 | HTTP clients |
| cryptography | >=46.0.5, <47.0 | RSA signing |
| PyJWT | >=2.8 | JWT auth |
| structlog | >=25.4.0 | Structured logging |
| networkx | >=3.5 | Knowledge graph (in-memory) |
| scikit-learn | >=1.3.0 | ML models |
| sqlalchemy | >=2.0.0 | Database ORM |
| opentelemetry-sdk | >=1.25 | Observability |
| PyYAML | >=6.0.1 | Config parsing |
| sarif-om | >=1.0.4 | SARIF format support |
| ssvc | >=1.2.0 | Stakeholder-Specific Vulnerability Categorization |
| tenacity | >=8.2.0 | Retry logic |
| + 14 more | ... | See requirements.txt |

---

## 19. AI Agent Swarm System

ALdeci is built by 19 AI agents + 30 junior swarm workers, all running **Claude Opus 4.6** via Claude Code CLI.

### Phase DAG (Execution Order)
```
Phase 0: agent-doctor (pre-flight health check)
Phase 1: context-engineer (codebase map, daily briefing)
Phase 2: ai-researcher + data-scientist + enterprise-architect (parallel research)
Phase 2.5: ux-architect (UI information architecture audit)
Phase 3: backend-hardener + frontend-craftsman + threat-architect (parallel build)
Phase 3.5: swarm-controller + 30 juniors (parallel micro-tasks)
Phase 4: security-analyst + qa-engineer (validate + test)
Phase 4.5: persona-api-validator (persona API flow validation)
Phase 5: devops-engineer (infrastructure)
Phase 6: Debate round (3 rounds of cross-agent review)
Phase 7: marketing-head + technical-writer + sales-engineer (go-to-market)
Phase 8: scrum-master (daily demo + coordination)
Phase 9: agent-doctor (post-run audit)
Phase 10: vision-agent (post-flight vision alignment)
```

### Shared Context Protocol
Every agent reads before work: `docs/CEO_VISION.md`, `docs/VISION_TO_ACCOMPLISH.MD`, `.claude/team-state/sprint-board.json`, `.claude/team-state/context_log.md`

Every agent writes after work: outcomes to `context_log.md`, status to `.claude/team-state/{agent}-status.md`

### Orchestration
- **Swarm script**: `scripts/run-ctem-swarm.sh` (7,518 LOC) — includes JARVIS controller, quota circuit breaker, fix-agent spawner
- **Launcher**: `scripts/jarvis-launcher.sh` (784 LOC) — immortal wrapper with auto-restart, exponential backoff
- **Monitor**: `scripts/jarvis-monitor.sh` (657 LOC) — status dashboard (`--watch`, `--failures`, `--report`)
- **Agent definitions**: `.claude/agents/*.md` (19 files)

---

## 20. Business Context

### Pricing

| Tier | Price | Target |
|------|-------|--------|
| Community | Free | Open-source teams, <10 devs |
| Professional | $3-5K/mo | Mid-market, 50-200 devs |
| Enterprise | $8-15K/mo | Large orgs, 200-2000 devs |
| Air-Gapped | $15-25K/mo | Gov/Defense/Financial |

### Revenue Path
- Year 1: 5-10 design partners → $150-500K ARR
- Year 2: 20-50 customers → $2-5M ARR
- Year 3: 100+ customers → $10M+ ARR

### 7-Point Competitive Moat
1. **Multi-LLM consensus** — Patent-pending approach
2. **Knowledge graph** — Gets smarter with more data
3. **Self-hosted AI** — Only player with zero-token option
4. **Quantum crypto** — 5-year head start
5. **MCP protocol** — First-mover in AI-native AppSec
6. **FAIL Engine** — Unique concept, no competitors
7. **Switzerland positioning** — Never threatens tool vendors

### Competitor Comparison

| Capability | ALdeci | Snyk | Wiz | Semgrep | Checkmarx |
|-----------|--------|------|-----|---------|-----------|
| SAST | ✅ | ✅ | ❌ | ✅ | ✅ |
| DAST | ✅ | ❌ | ❌ | ❌ | ✅ |
| Secrets | ✅ | ❌ | ✅ | ✅ | ❌ |
| Container | ✅ | ✅ | ✅ | ❌ | ❌ |
| CSPM/IaC | ✅ | ✅ | ✅ | ❌ | ❌ |
| API Fuzzer | ✅ | ❌ | ❌ | ❌ | ❌ |
| Multi-LLM Consensus | ✅ | ❌ | ❌ | ❌ | ❌ |
| MPTE Exploit Verify | ✅ | ❌ | ❌ | ❌ | ❌ |
| FAIL Engine | ✅ | ❌ | ❌ | ❌ | ❌ |
| AutoFix (10 types) | ✅ | ✅ (2) | ❌ | ✅ (1) | ✅ (1) |
| Air-Gapped | ✅ | ❌ | ❌ | ✅ | ✅ |
| Switzerland Orchestration | ✅ | ❌ | ❌ | ❌ | ❌ |
| 12-Step CTEM Pipeline | ✅ | ❌ | ❌ | ❌ | ❌ |
| MCP Gateway | ✅ | ❌ | ❌ | ❌ | ❌ |

---

## 21. Testing

- **392 test files** in `tests/` directory
- **13,949 tests collected** (0 collection errors)
- **19.21% coverage** (gate: 25% — currently FAILING in CI)
- **pytest-timeout**: 10s per test (prevents hanging)
- **Markers**: `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.e2e`, `@pytest.mark.security`

---

## 22. Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `FIXOPS_MODE` | `enterprise` | Operating mode |
| `FIXOPS_API_TOKEN` | — | API authentication key |
| `FIXOPS_JWT_SECRET` | auto-generated | JWT signing secret |
| `FIXOPS_DATA_DIR` | `.fixops_data` | Data storage directory |
| `FIXOPS_DISABLE_RATE_LIMIT` | `0` | Disable rate limiting |
| `FIXOPS_ALLOWED_ORIGINS` | — | CORS allowed origins |
| `MPTE_BASE_URL` | `https://localhost:8443` | MPTE service URL |
| `OPENAI_API_KEY` | — | OpenAI for LLM consensus |
| `ANTHROPIC_API_KEY` | — | Anthropic for LLM consensus |
| `VITE_API_URL` | — | Frontend API URL |
| `VITE_API_KEY` | — | Frontend API key |

---

## 23. Key Architectural Diagrams

### Data Flow — Scanner to Decision

```
External Scanners          Native Scanners (Air-Gapped)
  Snyk, Trivy, Wiz...       SAST, DAST, Secrets...
       │                          │
       ▼                          ▼
  ┌───────────────────────────────────────┐
  │     Scanner Ingest API (7 endpoints)   │
  │  POST /api/v1/scanner-ingest/upload    │
  │  Formats: SARIF, SBOM, CVE, VEX, CNAPP│
  └───────────────────┬───────────────────┘
                      ▼
  ┌───────────────────────────────────────┐
  │         12-Step Brain Pipeline         │
  │  Normalize → Dedup → Graph → Enrich → │
  │  Score → Policy → Consensus → MPTE →   │
  │  AutoFix → Evidence                    │
  └───────────────────┬───────────────────┘
                      ▼
  ┌───────────────────────────────────────┐
  │          Output Actions                │
  │  • Jira tickets (with SLA)            │
  │  • GitHub PRs (AutoFix)               │
  │  • Slack alerts                        │
  │  • Signed evidence bundles             │
  │  • Compliance reports                  │
  │  • UI dashboards                       │
  └───────────────────────────────────────┘
```

### Connector Architecture

```
  ┌─── Integration Connectors (3,030 LOC) ───┐
  │  Jira · Confluence · Slack · ServiceNow   │
  │  GitLab · Azure DevOps · GitHub           │
  │  All: circuit breaker + retry + rate limit│
  └───────────────────────────────────────────┘
           ↕ _BaseConnector ↕
  ┌─── Security Connectors (1,336 LOC) ──────┐
  │  Snyk · SonarQube · Dependabot            │
  │  AWS SecurityHub · Azure Defender         │
  │  Wiz · Prisma · Orca · Lacework           │
  │  ThreatMapper                             │
  └───────────────────────────────────────────┘
```

### Deployment Options

```
┌──────────────────────────────────────────┐
│  1. Local Dev                             │
│     Backend: uvicorn on port 8000         │
│     Frontend: Vite on port 3001 (legacy)  │
│              or port 3002 (vision — new)  │
│                                           │
│  2. Docker                                │
│     docker-compose.yml (standard)         │
│     docker-compose.enterprise.yml         │
│     docker-compose.air-gapped-test.yml    │
│                                           │
│  3. Kubernetes                            │
│     docker/kubernetes/ (Helm chart)       │
│                                           │
│  4. Air-Gapped                            │
│     All native scanners work offline      │
│     SQLite (no external DB needed)        │
│     vLLM for LLM inference (planned)      │
└──────────────────────────────────────────┘
```

---

*This document reflects the honest state of ALdeci/FixOps as of March 7, 2026. It includes both what works and what doesn't, because any AI working on this codebase needs ground truth, not marketing. The #1 build priority is the Vision UI in `aldeci-ui-new/` (top-level directory).*
