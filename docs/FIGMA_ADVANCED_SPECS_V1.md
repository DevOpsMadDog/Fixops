# ALdeci — Advanced Figma Specifications V1
## Zero-Friction Security Intelligence · 526 APIs · 8 Screens · 4 Phases

> **Design mantra:** Data flows IN automatically. AI triages. Humans decide. Evidence generates itself.
> **Ultimate vision:** One intelligent AI that orchestrates tools, talks to humans, and runs your security program.

---

# PART 0: PRODUCT VISION — 4 PHASES TO AUTONOMOUS SECURITY

```
PHASE 1 (NOW)          PHASE 2 (3-6mo)         PHASE 3 (6-12mo)        PHASE 4 (1-2yr)
──────────────         ──────────────          ──────────────          ──────────────
CONNECT                DISCOVER                ADAPT                   AUTONOMY
──────────────         ──────────────          ──────────────          ──────────────
Manual upload          Auto-discover           AI Connectors           One Brain
CLI wrapper            installed tools         Self-healing            Orchestrates
CI/CD connectors       Cloud provider          integrations            everything
Webhook receivers      direct pull             Predictive              Talks to humans
                       (AWS/Azure/GCP)         suggestions             and tools
                       CNAPP auto-detect       Cross-tool              Self-improving
                       (Wiz/Prisma/            correlation AI          Autonomous triage
                       Lacework)                                       + remediation
                       MCP for IDE             Agent mode              + communication
                       Smart onboarding        (multi-step)            + evidence

UI: 8 screens          UI: + Auto-Discovery    UI: + AI Connector      UI: The Brain
    Copilot chat           tab in Connect          Studio              replaces most
    Manual setup           Cloud Providers      Copilot → Agent        screens. Humans
                           CNAPP tab            Self-Monitoring        only approve
                           Onboarding Wizard    Dashboard              critical decisions
```

### What each phase unlocks per persona

| Persona | Phase 1 (Now) | Phase 2 (3-6mo) | Phase 3 (6-12mo) | Phase 4 (1-2yr) |
|---------|--------------|-----------------|-------------------|-----------------|
| **Sarah** 🔴 Security Architect | Dashboard + manual triage | Auto-ingestion = backlog shrinks 80% | AI pre-triages, Sarah handles exceptions only | Brain runs program, Sarah sets policy |
| **David** 🟢 DevSecOps | CI/CD connectors + CLI | Cloud auto-pull + CNAPP = zero setup | AI adapts when tools change, self-heals | Brain manages pipeline |
| **Catherine** 🔵 Compliance | Evidence download | Auto-collected evidence from cloud | AI pre-assembles audit packs | Brain passes audits autonomously |
| **Alex** 🟡 AppSec Manager | Dashboard metrics | Metrics auto-populated from all sources | AI predicts risks, suggests budget | Brain optimizes program |
| **Pete** ⚪ Platform Engineer | API + CLI setup | Smart onboarding = 5-min vs 2-day | AI maintains integrations | Brain self-operates |
| **Dana** ⚫ Developer | Gets Jira tickets | MCP in IDE = fix without leaving editor | AI suggests fixes at commit time | Brain auto-fixes trivial vulns |

---

# PART 1: STRATEGIC DECISIONS

| Question | Decision | Phase | Rationale |
|----------|----------|-------|-----------|
| **CI/CD Connectors?** | ✅ YES — BUILD FIRST | 1 | Manual SBOM/SARIF upload is the #1 adoption killer. GitHub Actions + GitLab CI + Jenkins must push automatically. |
| **CLI Tool?** | ✅ YES — DAY 1 | 1 | `aldeci scan --tool=snyk --push` wraps existing scanners. Pete and David need this. |
| **Webhook Receivers?** | ✅ YES — DAY 1 | 1 | Listen for Snyk/SonarQube/Wiz webhooks → auto-ingest. Zero human intervention. |
| **Cloud Provider Direct Pull?** | ✅ YES | 2 | Connect to AWS SecurityHub, Azure Defender, GCP SCC. Pull findings directly — no scanner needed. |
| **CNAPP Auto-Detect?** | ✅ YES | 2 | Scan environment → detect Wiz/Prisma/Lacework/Orca → auto-configure connectors. |
| **MCP (Model Context Protocol)?** | ✅ YES — DIFFERENTIATOR | 2 | AI-native integration. Claude/Cursor/Windsurf query ALdeci. No competitor has this. |
| **Smart Onboarding Wizard?** | ✅ YES | 2 | First-run: detect AWS, GitHub orgs, scanners → suggest connections → one-click setup. |
| **IDE Extensions (VS Code)?** | ⏳ PHASE 2+ | 2 | Start with MCP (covers Cursor/Windsurf). VS Code extension after MCP proves value. |
| **AI Connectors?** | ✅ YES | 3 | AI reads API docs, generates adapter code, tests connection for unknown tools. |
| **Self-Healing Integrations?** | ✅ YES | 3 | When connector breaks (API changed, token expired), AI diagnoses and fixes. |
| **Predictive Suggestions?** | ✅ YES | 3 | "You have AWS + Snyk but no container scanning. Recommend Trivy." |
| **One AI Brain?** | ✅ YES — ULTIMATE GOAL | 4 | Triages, tickets, assigns, generates evidence, passes audits, communicates. Humans approve critical only. |
| **Manual SBOM Upload?** | ✅ KEEP (fallback) | 1 | Air-gapped environments need it. LAST tab in Connect, not primary flow. |

### Ingestion Priority Pyramid (build bottom-up)

```
                    ┌─────────────────┐
                    │  Manual Upload   │  ← Last resort (air-gap)
                  ┌─┴─────────────────┴─┐
                  │  CLI Wrapper          │  ← Pete/David in terminal
                ┌─┴───────────────────────┴─┐
                │  Webhook Receivers          │  ← Auto-ingest from scanners
              ┌─┴─────────────────────────────┴─┐
              │  CI/CD Connectors                 │  ← GitHub Actions, GitLab, Jenkins
            ┌─┴───────────────────────────────────┴─┐
            │  Cloud Provider Direct Pull              │  ← AWS SecurityHub, Azure, GCP (P2)
          ┌─┴─────────────────────────────────────────┴─┐
          │  CNAPP Auto-Detect                              │  ← Wiz, Prisma, Lacework (P2)
        ┌─┴───────────────────────────────────────────────┴─┐
        │  AI Connectors                                        │  ← Learns any tool (P3)
      ┌─┴─────────────────────────────────────────────────────┴─┐
      │  MCP + IDE                                                  │  ← Findings in IDE (P2)
    ┌─┴───────────────────────────────────────────────────────────┴─┐
    │  🧠 THE BRAIN — Autonomous Security Intelligence                  │  ← One AI (P4)
    └───────────────────────────────────────────────────────────────────┘
```

**Bottom = highest leverage.** Build up. Phase 4 is the moat no competitor can replicate.

---

# PART 2: PERSONAS → SCREENS → ZERO-CLICK WORKFLOWS

## 2.1 Persona-Screen Matrix

| Screen | Sarah 🔴 | David 🟢 | Catherine 🔵 | Alex 🟡 | Pete ⚪ | Dana ⚫ | Phase |
|--------|----------|----------|-------------|---------|--------|--------|-------|
| S1: Command Center | ★ | ○ | ○ | ★ | | | 1 |
| S2: Findings Hub | ★ | ★ | | ○ | | | 1 |
| S3: Attack Lab | ○ | ★ | | | | | 1 |
| S4: Connect | | ★ | | | ★ | | 1-3 |
| S5: Evidence | ○ | | ★ | ★ | | | 1 |
| S6: Pipeline | ★ | ○ | | | | | 1 |
| S7: The Brain (Copilot→AI) | ○ | ○ | ○ | ○ | | | 1-4 |
| S8: Settings | ○ | | | ○ | ★ | | 1 |
| 🔌 MCP / IDE | | | | | | ★ | 2 |
| 🖥️ CLI | | ★ | | | ★ | | 1 |

★ = Primary screen  ○ = Uses occasionally  blank = Never opens

**Key insight:** Dana and Pete should NEVER need to open the UI. The Brain eventually makes even Sarah and Alex's interaction minimal.

## 2.2 Persona Workflows (Zero-Click Target)

### Sarah (Security Architect) 🔴 — "Show me what's real"
```
P1: Auto-connector pushes findings → Command Center shows posture 78/100, 12 critical
    → click "12 critical" → Findings Hub (evidence chain) → Create Case → done (3 clicks)
P2: Cloud auto-pull enriches findings → only verified exploitable reach Sarah
P3: AI pre-triages → Sarah only reviews exceptions → 95% automated
P4: Brain runs security program → Sarah sets policy quarterly
```

### David (DevSecOps) 🟢 — "Wire it and forget it"
```
P1: Connect → Add GitHub Actions connector → findings auto-appear → done
P2: Smart onboarding detects Snyk+Trivy+AWS → one-click connect → CNAPP auto-detected
P3: AI maintains integrations → Snyk API changes, AI adapts → David never firefights
P4: Brain manages entire pipeline → David focuses on architecture
```

### Catherine (Compliance) 🔵 — "Give me the evidence"
```
P1: Evidence → SOC2 tab → Generate Pack → Download → done (2 clicks)
P2: Cloud provider data auto-fills compliance evidence → Catherine reviews, not collects
P3: AI pre-assembles audit packs, maps gaps → Catherine approves
P4: Brain passes audits autonomously → Catherine reviews quarterly
```

### Alex (AppSec Manager) 🟡 — "Show me the metrics"
```
P1: Command Center → MTTR 4.2d, noise -67%, ROI 340% → Export → done (2 clicks)
P2: Metrics auto-populated from ALL connected sources → no manual collection
P3: AI predicts risks, suggests budget allocation, generates board reports
P4: Brain optimizes security program → Alex steers strategy annually
```

### Pete (Platform Engineer) ⚪ — "API and done"
```
P1: CLI: aldeci connect github --org=myorg → aldeci webhook add → done (never opens UI)
P2: aldeci setup --auto-detect → finds everything → done (1 command)
P3: AI maintains infrastructure → self-heals broken integrations
P4: Brain self-operates → Pete sets infra policy
```

### Dana (Developer) ⚫ — "Fix in my IDE"
```
P1: Gets Jira ticket with evidence link → fix → close ticket
P2: MCP: Cursor shows inline finding → AI explains + suggests fix → apply → done
P3: AI auto-suggests fixes at commit time → PR created automatically
P4: Brain auto-fixes trivial vulns → Dana reviews PRs for complex ones
```

---

# PART 3: 8-SCREEN ARCHITECTURE

## Navigation Sidebar

```
┌──────────────────────────────┐
│  🛡️  ALdeci                  │
│                              │
│  📊  Command Center     (S1) │  ← Default landing
│  🔍  Findings Hub       (S2) │  ← THE CENTER of everything
│  ⚔️   Attack Lab        (S3) │
│  🔌  Connect            (S4) │  ← Phase 1-3 evolution
│  📋  Evidence           (S5) │
│  ⚙️   Pipeline          (S6) │
│  🧠  The Brain          (S7) │  ← Copilot → Agent → Brain
│  ──────────────────────────  │
│  ⚙️   Settings          (S8) │
└──────────────────────────────┘
```

### Route Table

| Route | Screen | Phase | Notes |
|-------|--------|-------|-------|
| `/` | S1: Command Center | 1 | Redirect from login |
| `/findings` | S2: Findings Hub | 1 | Unified findings list |
| `/findings/:id` | S2: Finding Detail | 1 | Slide-over or full page |
| `/attack` | S3: Attack Lab | 1 | Micro-pentest + simulation |
| `/attack/:id` | S3: Attack Detail | 1 | Attack session detail |
| `/connect` | S4: Connect | 1 | CI/CD, webhooks, manual upload |
| `/connect/cloud` | S4: Cloud Providers | 2 | AWS/Azure/GCP |
| `/connect/cnapp` | S4: CNAPP | 2 | Wiz/Prisma/Lacework |
| `/connect/ai` | S4: AI Connectors | 3 | Self-learning adapters |
| `/evidence` | S5: Evidence | 1 | Bundles + compliance |
| `/evidence/:id` | S5: Evidence Detail | 1 | Bundle detail |
| `/pipeline` | S6: Pipeline | 1 | Brain pipeline + remediation |
| `/brain` | S7: The Brain | 1 | Copilot chat → Agent → AI |
| `/settings` | S8: Settings | 1 | Users, teams, system |
| `/onboarding` | Onboarding Wizard | 2 | First-run only |

**15 routes → 8 screens.** 82% reduction from original 68 routes / 45 screens.

---

## S1: Command Center `/`

> Sarah and Alex's home. Posture at a glance. Every number is clickable.

### Layout
```
┌─────────────────────────────────────────────────────────────────┐
│ Security Posture Score: 78/100 ████████░░         [↗ trending]  │
├──────────┬──────────┬──────────┬──────────┬────────────────────┤
│ Critical │  High    │  Medium  │   Low    │  Noise Reduced     │
│    12    │   47     │   234    │   891    │    -67% ↓          │
│ [click → S2 filtered]                     │                    │
├──────────────────────────────────────────┬────────────────────┤
│ MTTR Trend (30d sparkline)               │ Top 5 Risky Assets │
│ ████▇▆▅▃▂▁  4.2d avg                    │ 1. api-gateway      │
│                                          │ 2. auth-service     │
│                                          │ 3. payment-svc      │
├──────────────────────────────────────────┤ [click → S2]       │
│ Active Cases: 23 open, 7 in-progress     │                    │
│ Pipeline: 3 running, 1 failed            │                    │
│ Connectors: 5 active, 1 degraded ⚠       │                    │
├──────────────────────────────────────────┴────────────────────┤
│ 🧠 AI Insight: "12 critical findings share CVE-2024-3094.     │
│    Recommend: batch remediation via Pipeline."  [→ S7]        │
└───────────────────────────────────────────────────────────────┘
```

### API Map
| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/dashboard/overview` | Posture score, counts by severity |
| `GET /api/v1/dashboard/metrics` | MTTR, noise reduction, ROI |
| `GET /api/v1/dashboard/trends` | 30-day sparkline data |
| `GET /api/v1/dashboard/top-risks` | Top 5 risky assets |
| `GET /api/v1/exposure-cases/stats` | Open/in-progress case counts |
| `GET /api/v1/brain-pipeline/status` | Pipeline run status |
| `GET /api/v1/integrations/status` | Connector health |
| `GET /api/v1/copilot/insight` | AI-generated insight banner |
| `GET /api/v1/nerve-center/pulse` | Real-time system pulse |

### Cross-links from S1
- Click severity count → S2 (Findings Hub, pre-filtered)
- Click risky asset → S2 (filtered by asset)
- Click case count → S2 (cases tab)
- Click pipeline status → S6 (Pipeline)
- Click connector status → S4 (Connect)
- Click AI insight → S7 (The Brain)

---

## S2: Findings Hub `/findings`

> THE CENTER of ALdeci. Every finding from every source, every scanner, every cloud provider. Unified view. Sarah and David live here.

### Layout
```
┌───────────────────────────────────────────────────────────────────┐
│ Findings Hub                    [Bulk Actions ▼]  [Export]  🔍    │
├─── Tabs ──────────────────────────────────────────────────────────┤
│ [All] [Code] [Secrets] [IaC] [Container] [Cloud] [Cases] [Graph] │
├───────────────────────────────────────────────────────────────────┤
│ Filters: Severity ▼ | Source ▼ | Asset ▼ | Status ▼ | Exploitable│
├───┬──────────┬──────────┬────────┬─────────┬──────────┬──────────┤
│ ☐ │ CVE-ID   │ Severity │ Asset  │ Source  │ Status   │ AI Triage│
├───┼──────────┼──────────┼────────┼─────────┼──────────┼──────────┤
│ ☐ │ CVE-2024 │ CRITICAL │ api-gw │ Snyk+NVD│ Open     │ 🔴 Real  │
│ ☐ │ CVE-2024 │ HIGH     │ auth   │ Trivy   │ Triaging │ 🟡 Check │
│ ☐ │ GHSA-xxx │ MEDIUM   │ web-ui │ GitHub  │ FP       │ 🟢 FP    │
│   │  ...     │          │        │         │          │          │
├───┴──────────┴──────────┴────────┴─────────┴──────────┴──────────┤
│ [← Prev]  Page 1 of 47  (2,341 findings)           [Next →]     │
└───────────────────────────────────────────────────────────────────┘

Finding Detail (slide-over on click):
┌─────────────────────────────────────────┐
│ CVE-2024-3094 · CRITICAL                │
│ xz-utils backdoor                       │
├─────────────────────────────────────────┤
│ [Overview] [Evidence] [Attack] [Graph]  │
│                                         │
│ Multi-LLM Consensus: 3/3 → REAL        │
│ ├ GPT-4: Critical, exploitable          │
│ ├ Claude: Critical, reachable           │
│ └ Gemini: Critical, in attack path      │
│                                         │
│ EPSS: 0.94 │ CISA KEV: Yes │ NVD: 10.0 │
│ Reachable: Yes │ Exploit: Public        │
│                                         │
│ Affected: api-gateway v1.2.3            │
│ Fix: Upgrade to v5.6.1                  │
│                                         │
│ [🎯 Attack] [📋 Evidence] [🔧 Fix Now] │
│ [Create Case] [Add to Pipeline]         │
└─────────────────────────────────────────┘
```

### Tabs Detail
| Tab | What it shows | Source APIs |
|-----|--------------|-------------|
| **All** | Unified cross-source findings, deduplicated | `/findings`, `/dedup/*` |
| **Code** | SAST + SBOM + dependency findings | `/code/scan/*`, `/sast/*` |
| **Secrets** | Leaked credentials, API keys, tokens | `/code/secrets/*` |
| **IaC** | Terraform, CloudFormation, Kubernetes misconfigs | `/code/iac/*` |
| **Container** | Docker image vulns, runtime threats | `/cloud/containers/*` |
| **Cloud** | CSPM findings, misconfigurations | `/cloud/cspm/*` |
| **Cases** | Exposure cases (grouped findings) | `/exposure-cases/*` |
| **Graph** | Knowledge graph visualization (React Flow) | `/gnn/*`, `/reachability/*` |

### API Map
| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/findings` | Paginated findings list with filters |
| `GET /api/v1/findings/:id` | Single finding with full evidence |
| `POST /api/v1/findings/bulk` | Bulk status change, assign, export |
| `GET /api/v1/code/scan/results` | Code scan findings |
| `GET /api/v1/code/secrets` | Secret detection results |
| `GET /api/v1/code/iac/results` | IaC misconfig results |
| `GET /api/v1/cloud/containers` | Container vulnerabilities |
| `GET /api/v1/cloud/cspm` | Cloud security posture |
| `GET /api/v1/dedup/status` | Deduplication results |
| `GET /api/v1/dedup/clusters` | Duplicate clusters |
| `POST /api/v1/multi-llm/consensus` | Multi-LLM triage verdict |
| `GET /api/v1/feeds/nvd/lookup` | NVD enrichment |
| `GET /api/v1/feeds/epss/score` | EPSS probability |
| `GET /api/v1/feeds/kev/check` | CISA KEV status |
| `GET /api/v1/reachability/analyze` | Reachability analysis |
| `GET /api/v1/gnn/graph` | Knowledge graph data |
| `GET /api/v1/exposure-cases` | Exposure cases list |
| `POST /api/v1/exposure-cases` | Create new case |
| `GET /api/v1/exposure-cases/:id/timeline` | Case timeline |
| `GET /api/v1/fuzzy-identity` | Cross-scanner identity resolution |
| `SSE /api/v1/stream/findings` | Real-time finding updates |

### Cross-links from S2
- Click finding → S2 slide-over (detail)
- Click "Attack" → S3 (Attack Lab, pre-loaded)
- Click "Evidence" → S5 (Evidence, finding context)
- Click "Fix Now" → S6 (Pipeline, auto-remediation)
- Click "Graph" tab → S2 graph sub-view (inline)
- Click asset name → S2 (re-filtered by asset)
- Click source → S4 (Connect, source status)

---

## S3: Attack Lab `/attack`

> David's playground. Validate findings with real attack simulation. Prove exploitability.

### Layout
```
┌───────────────────────────────────────────────────────────┐
│ Attack Lab                      [New Micro-Pentest] [New Sim] │
├─── Tabs ──────────────────────────────────────────────────┤
│ [Micro-Pentest] [Attack Simulation] [Reachability] [DAST] │
├───────────────────────────────────────────────────────────┤
│ Active Sessions                                           │
│ ┌─────────────────────────────────────────────────────┐   │
│ │ MP-001 │ CVE-2024-3094 │ Running ◉ │ 3/5 stages   │   │
│ │ MP-002 │ Log4Shell     │ Complete ✓ │ EXPLOITABLE  │   │
│ │ SIM-01 │ Lateral Move  │ Complete ✓ │ 4 paths found│   │
│ └─────────────────────────────────────────────────────┘   │
│                                                           │
│ Attack Detail (expand):                                   │
│ ┌─────────────────────────────────────────────────────┐   │
│ │ Stage 1: Recon        ✓  Found service on port 443 │   │
│ │ Stage 2: Exploit      ✓  RCE confirmed             │   │
│ │ Stage 3: Post-exploit ◉  Checking lateral movement  │   │
│ │ Stage 4: Evidence     ○  Pending                    │   │
│ │ Stage 5: Report       ○  Pending                    │   │
│ │                                                     │   │
│ │ [Live Terminal Output] [AI Analysis] [Evidence]     │   │
│ └─────────────────────────────────────────────────────┘   │
│                                                           │
│ 🧠 "This CVE is reachable via api-gateway → auth-svc.    │
│    Attack path confirmed. Recommend Priority 1 fix."      │
└───────────────────────────────────────────────────────────┘
```

### API Map
| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/micro-pentest/run` | Start micro-pentest session |
| `GET /api/v1/micro-pentest/sessions` | List all sessions |
| `GET /api/v1/micro-pentest/sessions/:id` | Session detail + stages |
| `GET /api/v1/micro-pentest/sessions/:id/verdict` | 4-state verdict |
| `POST /api/v1/attack-simulation/run` | Start attack simulation |
| `GET /api/v1/attack-simulation/results` | Simulation results |
| `GET /api/v1/reachability/analyze` | Reachability paths |
| `GET /api/v1/reachability/graph` | Attack path graph |
| `POST /api/v1/dast/scan` | DAST scan trigger |
| `GET /api/v1/dast/results` | DAST findings |
| `POST /api/v1/api-fuzzer/run` | API fuzzing |
| `GET /api/v1/mpte/analyze` | MPTE deep analysis |
| `SSE /api/v1/stream/attack` | Real-time attack progress |

### Cross-links from S3
- Click finding CVE → S2 (Finding Detail)
- Click "Evidence" → S5 (auto-create evidence bundle)
- Click "AI Analysis" → S7 (The Brain, attack context)
- Click reachability graph → S2 (Graph tab)

---

## S4: Connect `/connect` ← MOST IMPORTANT EVOLUTION SCREEN

> David and Pete's setup hub. Evolves across all 4 phases. This is where zero-friction happens.

### Phase Evolution
```
Phase 1: [CI/CD] [Webhooks] [Manual Upload]
Phase 2: [CI/CD] [Webhooks] [Cloud ☁️] [CNAPP 🛡️] [MCP 🤖] [Manual Upload]
Phase 3: [CI/CD] [Webhooks] [Cloud ☁️] [CNAPP 🛡️] [MCP 🤖] [AI Connectors 🧠] [Manual]
Phase 4: The Brain manages all connections autonomously. This screen becomes monitoring-only.
```

### Layout (Phase 2 — full vision)
```
┌───────────────────────────────────────────────────────────────────┐
│ Connect                              [+ Add Connector]  [Health]  │
├─── Tabs ──────────────────────────────────────────────────────────┤
│ [CI/CD] [Webhooks] [Cloud ☁️] [CNAPP 🛡️] [MCP 🤖] [Manual ↑]  │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│ CI/CD Tab:                                                        │
│ ┌────────────┬────────────┬────────────┬────────────┐             │
│ │ ⚫ GitHub   │ 🦊 GitLab  │ 🔵 Jenkins │ ⭕ CircleCI │             │
│ │ Actions    │ CI         │            │            │             │
│ │ Connected ✓│ Available  │ Available  │ Available  │             │
│ │ 3 repos    │ [Connect]  │ [Connect]  │ [Connect]  │             │
│ └────────────┴────────────┴────────────┴────────────┘             │
│                                                                   │
│ Cloud Tab (Phase 2):                                              │
│ ┌────────────┬────────────┬────────────┐                          │
│ │ 🟠 AWS      │ 🔵 Azure   │ 🔴 GCP     │                          │
│ │ SecurityHub│ Defender   │ SCC        │                          │
│ │ [Connect]  │ [Connect]  │ [Connect]  │                          │
│ │ Auto-pull  │ Auto-pull  │ Auto-pull  │                          │
│ │ every 15m  │ every 15m  │ every 15m  │                          │
│ └────────────┴────────────┴────────────┘                          │
│                                                                   │
│ CNAPP Tab (Phase 2):                                              │
│ ┌────────────┬────────────┬────────────┬────────────┐             │
│ │ 🟣 Wiz      │ 🔶 Prisma   │ 🟤 Lacework│ 🐋 Orca    │             │
│ │ Auto-found │ [Connect]  │ Not found  │ Not found  │             │
│ │ 12 findings│            │            │            │             │
│ └────────────┴────────────┴────────────┴────────────┘             │
│ 🧠 "Detected Wiz in your AWS account. Auto-configured."          │
│                                                                   │
│ MCP Tab (Phase 2):                                                │
│ ┌──────────────────────────────────────────────────┐              │
│ │ MCP Server Status: ● Running on port 8100        │              │
│ │ Connected Clients:                                │              │
│ │  · Cursor IDE (developer-1)  ● Active             │              │
│ │  · Claude Desktop (sarah)    ● Active             │              │
│ │  · Windsurf (developer-2)    ○ Disconnected       │              │
│ │                                                   │              │
│ │ Available Tools: findings, triage, evidence, scan │              │
│ │ [Configure] [View Logs] [Test Connection]         │              │
│ └──────────────────────────────────────────────────┘              │
│                                                                   │
│ Connector Health Summary:                                         │
│ ┌──────────┬──────────┬──────────┐                                │
│ │ Active: 5│Degraded:1│ Failed: 0│                                │
│ │    ●●●●● │    ⚠     │          │                                │
│ └──────────┴──────────┴──────────┘                                │
└───────────────────────────────────────────────────────────────────┘
```

### API Map
| Endpoint | Purpose | Phase |
|----------|---------|-------|
| `GET /api/v1/integrations` | List all connectors | 1 |
| `POST /api/v1/integrations` | Add new connector | 1 |
| `GET /api/v1/integrations/:id/status` | Connector health | 1 |
| `DELETE /api/v1/integrations/:id` | Remove connector | 1 |
| `GET /api/v1/webhooks` | List webhook endpoints | 1 |
| `POST /api/v1/webhooks` | Create webhook listener | 1 |
| `POST /api/v1/webhooks/test` | Test webhook | 1 |
| `POST /api/v1/code/sbom/upload` | Manual SBOM upload | 1 |
| `POST /api/v1/code/scan/upload` | Manual SARIF upload | 1 |
| `GET /api/v1/cloud/providers` | List cloud accounts | 2 |
| `POST /api/v1/cloud/providers/connect` | Connect cloud provider | 2 |
| `GET /api/v1/cloud/providers/:id/pull` | Trigger manual pull | 2 |
| `GET /api/v1/cnapp/detect` | Auto-detect CNAPP tools | 2 |
| `POST /api/v1/cnapp/connect` | Connect detected CNAPP | 2 |
| `GET /api/v1/mcp/status` | MCP server status | 2 |
| `GET /api/v1/mcp/clients` | Connected MCP clients | 2 |
| `POST /api/v1/mcp/configure` | Configure MCP tools | 2 |
| `GET /api/v1/ai-connectors` | List AI-learned connectors | 3 |
| `POST /api/v1/ai-connectors/learn` | AI learns new tool | 3 |
| `GET /api/v1/ai-connectors/:id/health` | AI connector health | 3 |
| `POST /api/v1/ai-connectors/:id/heal` | Self-heal broken connector | 3 |
| `GET /api/v1/marketplace` | Marketplace connectors | 1 |
| `POST /api/v1/marketplace/install` | Install marketplace plugin | 1 |

### Cross-links from S4
- Connector findings count → S2 (filtered by source)
- Health alerts → S8 (Settings, system health)
- MCP client activity → S7 (Brain, client queries)

---

## S5: Evidence `/evidence`

> Catherine's domain. Auto-generated, cryptographically signed, audit-ready evidence.

### Layout
```
┌───────────────────────────────────────────────────────────────────┐
│ Evidence                              [Generate Pack] [Export All] │
├─── Tabs ──────────────────────────────────────────────────────────┤
│ [Bundles] [SOC2] [ISO27001] [PCI-DSS] [SLSA] [Custom]           │
├───────────────────────────────────────────────────────────────────┤
│ Evidence Bundles                                                   │
│ ┌───────────────┬──────────┬────────────┬────────────────────┐    │
│ │ Bundle ID     │ Type     │ Created    │ Status             │    │
│ │ EVD-001       │ SOC2     │ 2026-02-14 │ ✓ Signed, complete │    │
│ │ EVD-002       │ Finding  │ 2026-02-13 │ ✓ Signed           │    │
│ │ EVD-003       │ Attack   │ 2026-02-12 │ ◉ Generating       │    │
│ └───────────────┴──────────┴────────────┴────────────────────┘    │
│                                                                   │
│ Compliance Dashboard:                                             │
│ ┌──────────────────────────────────────────────────┐              │
│ │ SOC2: 87% coverage  ████████▒▒                   │              │
│ │ ISO27001: 72%        ███████▒▒▒                  │              │
│ │ PCI-DSS: 94%         █████████▒                  │              │
│ │ SLSA Level 3: ✓      Provenance verified         │              │
│ └──────────────────────────────────────────────────┘              │
│                                                                   │
│ 🧠 "SOC2 gap: 3 controls missing evidence. Auto-generating      │
│    from connected AWS SecurityHub data."                          │
└───────────────────────────────────────────────────────────────────┘
```

### API Map
| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/evidence/bundles` | List evidence bundles |
| `POST /api/v1/evidence/bundles` | Create evidence bundle |
| `GET /api/v1/evidence/bundles/:id` | Bundle detail with artifacts |
| `POST /api/v1/evidence/bundles/:id/sign` | Cryptographically sign |
| `GET /api/v1/evidence/slsa` | SLSA provenance data |
| `GET /api/v1/compliance/soc2` | SOC2 compliance status |
| `GET /api/v1/compliance/iso27001` | ISO27001 status |
| `GET /api/v1/compliance/pci-dss` | PCI-DSS status |
| `POST /api/v1/compliance/reports/generate` | Generate compliance report |
| `GET /api/v1/compliance/reports` | List generated reports |
| `GET /api/v1/provenance/verify` | Verify provenance chain |
| `GET /api/v1/audit/log` | Audit log for evidence actions |

### Cross-links from S5
- Click finding in bundle → S2 (Finding Detail)
- Click "Generate from Attack" → S3 (Attack Lab results)
- Click compliance gap → S2 (findings causing gap)
- Click "AI fill gaps" → S7 (Brain auto-generates)

---

## S6: Pipeline `/pipeline`

> Sarah's automation engine. Ingest → Triage → Remediate → Evidence — all automated.

### Layout
```
┌───────────────────────────────────────────────────────────────────┐
│ Pipeline                              [+ New Run] [Templates]     │
├─── Tabs ──────────────────────────────────────────────────────────┤
│ [Active Runs] [Remediation] [Workflows] [Policies] [History]     │
├───────────────────────────────────────────────────────────────────┤
│ Active Pipeline Runs                                              │
│ ┌──────────────────────────────────────────────────────────────┐  │
│ │ RUN-042 │ Full Triage   │ ████████▒▒ 80% │ 3m remaining    │  │
│ │ RUN-041 │ Critical Only │ ██████████ 100%│ ✓ Complete       │  │
│ └──────────────────────────────────────────────────────────────┘  │
│                                                                   │
│ Pipeline Steps (expand RUN-042):                                  │
│ ┌──────────────────────────────────────────────────────────────┐  │
│ │ 1. Ingest    ✓  2,341 findings from 5 connectors           │  │
│ │ 2. Dedup     ✓  Reduced to 1,847 unique (21% noise)        │  │
│ │ 3. Enrich    ✓  NVD + EPSS + KEV enriched                  │  │
│ │ 4. AI Triage ◉  Multi-LLM consensus running...             │  │
│ │ 5. Risk      ○  GNN risk scoring pending                    │  │
│ │ 6. Remediate ○  Auto-fix + ticket creation pending          │  │
│ │ 7. Evidence  ○  Bundle generation pending                   │  │
│ └──────────────────────────────────────────────────────────────┘  │
│                                                                   │
│ Remediation Queue:                                                │
│ ┌────────────┬──────────┬──────────┬─────────────────────┐       │
│ │ Finding    │ Fix Type │ Target   │ Status              │       │
│ │ CVE-2024-x │ AutoFix  │ PR #423  │ ✓ Merged            │       │
│ │ CVE-2024-y │ Jira     │ SEC-891  │ ◉ In Progress       │       │
│ │ CVE-2024-z │ Manual   │ David    │ ○ Assigned          │       │
│ └────────────┴──────────┴──────────┴─────────────────────┘       │
└───────────────────────────────────────────────────────────────────┘
```

### API Map
| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/brain-pipeline/run` | Start pipeline run |
| `GET /api/v1/brain-pipeline/runs` | List pipeline runs |
| `GET /api/v1/brain-pipeline/runs/:id` | Run detail with steps |
| `GET /api/v1/brain-pipeline/status` | Current pipeline status |
| `GET /api/v1/remediation/queue` | Remediation queue |
| `POST /api/v1/remediation/autofix` | Trigger auto-fix |
| `POST /api/v1/remediation/ticket` | Create Jira/Linear ticket |
| `GET /api/v1/workflows` | List automation workflows |
| `POST /api/v1/workflows` | Create workflow |
| `GET /api/v1/policies` | Remediation policies |
| `POST /api/v1/policies` | Create policy |
| `GET /api/v1/nerve-center/state` | Nerve center state |
| `GET /api/v1/decision/algorithms` | Decision engine status |
| `SSE /api/v1/stream/pipeline` | Real-time pipeline progress |

### Cross-links from S6
- Click finding in remediation → S2 (Finding Detail)
- Click Jira ticket → external Jira (new tab)
- Click PR link → external GitHub (new tab)
- Click "View Evidence" → S5 (generated bundle)
- Click pipeline AI step → S7 (Brain, triage details)

---

## S7: The Brain `/brain` ← ULTIMATE EVOLUTION SCREEN

> Starts as a Copilot chat (Phase 1). Becomes an Agent (Phase 3). Becomes THE BRAIN (Phase 4).

### Phase Evolution
```
Phase 1: Copilot — Chat-based Q&A. "What are my critical findings?" "Explain CVE-2024-3094."
Phase 2: Smart Copilot — Context-aware. Knows your connectors, findings, compliance gaps.
Phase 3: Agent — Multi-step execution. "Triage all critical findings and create Jira tickets."
Phase 4: THE BRAIN — Autonomous orchestrator. Runs security program. Humans approve decisions.
```

### Layout (Phase 3 — Agent Mode)
```
┌───────────────────────────────────────────────────────────────────┐
│ The Brain                           [Mode: Agent ▼]  [Settings]   │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│ Agent Activity Feed:                                              │
│ ┌──────────────────────────────────────────────────────────────┐  │
│ │ 🧠 14:32 — Ingested 47 new findings from GitHub Actions     │  │
│ │ 🧠 14:33 — Deduplicated: 47 → 31 unique                    │  │
│ │ 🧠 14:34 — Multi-LLM triage complete: 4 critical, 12 high  │  │
│ │ 🧠 14:35 — Created Jira tickets: SEC-892 through SEC-895   │  │
│ │ 🧠 14:36 — Auto-fix PR created for CVE-2024-xxxx (#424)    │  │
│ │ ⚠️ 14:37 — NEEDS APPROVAL: CVE-2024-3094 affects prod.     │  │
│ │           Recommend: emergency patch + rollback plan.        │  │
│ │           [✓ Approve] [✗ Reject] [💬 Discuss]               │  │
│ └──────────────────────────────────────────────────────────────┘  │
│                                                                   │
│ Chat:                                                             │
│ ┌──────────────────────────────────────────────────────────────┐  │
│ │ You: "What's the blast radius of CVE-2024-3094?"            │  │
│ │                                                              │  │
│ │ 🧠: Based on reachability analysis:                          │  │
│ │ • 3 services directly affected (api-gw, auth, payment)     │  │
│ │ • 2 downstream services at risk (billing, notifications)    │  │
│ │ • EPSS: 0.94 — active exploitation in the wild             │  │
│ │ • CISA KEV: Listed since 2024-03-29                        │  │
│ │ • Attack path: internet → api-gw → auth-svc (2 hops)      │  │
│ │                                                              │  │
│ │ Recommendation: Immediate patching. I've prepared:          │  │
│ │ 1. Auto-fix PR #424 (ready to merge)                       │  │
│ │ 2. Jira ticket SEC-895 (assigned to David)                 │  │
│ │ 3. Evidence bundle EVD-004 (for audit trail)               │  │
│ │                                                              │  │
│ │ [View PR] [View Ticket] [View Evidence] [Run Attack]       │  │
│ └──────────────────────────────────────────────────────────────┘  │
│                                                                   │
│ [Type a message...                              ] [Send] [🎤]    │
└───────────────────────────────────────────────────────────────────┘
```

### API Map
| Endpoint | Purpose | Phase |
|----------|---------|-------|
| `POST /api/v1/copilot/sessions` | Create chat session | 1 |
| `POST /api/v1/copilot/sessions/:id/message` | Send message | 1 |
| `GET /api/v1/copilot/sessions/:id/messages` | Chat history | 1 |
| `GET /api/v1/copilot/agents` | Available agent capabilities | 2 |
| `POST /api/v1/copilot/agents/execute` | Execute multi-step action | 3 |
| `GET /api/v1/copilot/insight` | Proactive AI insight | 2 |
| `POST /api/v1/multi-llm/consensus` | Multi-LLM consensus | 1 |
| `GET /api/v1/multi-llm/providers` | Available LLM providers | 1 |
| `GET /api/v1/intelligent-engine/status` | AI engine status | 2 |
| `POST /api/v1/intelligent-engine/predict` | Predictive analysis | 3 |
| `GET /api/v1/nerve-center/intelligence-map` | System intelligence map | 2 |
| `POST /api/v1/learning-middleware/feedback` | Learning from decisions | 2 |
| `GET /api/v1/brain/decisions` | Pending approval queue | 4 |
| `POST /api/v1/brain/decisions/:id/approve` | Approve Brain action | 4 |
| `GET /api/v1/brain/activity` | Brain activity feed | 4 |
| `SSE /api/v1/stream/copilot` | Real-time chat + activity | 1 |

### Cross-links from S7
- Click finding reference → S2 (Finding Detail)
- Click PR link → external GitHub (new tab)
- Click Jira ticket → external Jira (new tab)
- Click evidence bundle → S5 (Evidence Detail)
- Click "Run Attack" → S3 (Attack Lab, pre-loaded)
- Click pipeline status → S6 (Pipeline)

---

## S8: Settings `/settings`

> Pete's domain. System configuration, users, teams, API keys, health monitoring.

### Layout
```
┌───────────────────────────────────────────────────────────────────┐
│ Settings                                                          │
├─── Tabs ──────────────────────────────────────────────────────────┤
│ [General] [Users & Teams] [API Keys] [Notifications] [System]    │
├───────────────────────────────────────────────────────────────────┤
│ General: Organization name, default severity thresholds, timezone │
│ Users & Teams: RBAC, team assignments, SSO configuration         │
│ API Keys: Generate/revoke API keys, scoped permissions           │
│ Notifications: Slack/email/webhook notification rules             │
│ System: Health dashboard, logs, resource usage, version info      │
└───────────────────────────────────────────────────────────────────┘
```

### API Map
| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/users` | List users |
| `POST /api/v1/users` | Create user |
| `GET /api/v1/teams` | List teams |
| `POST /api/v1/teams` | Create team |
| `GET /api/v1/health` | System health |
| `GET /api/v1/health/detailed` | Detailed health per suite |
| `GET /api/v1/system/logs` | System logs |
| `GET /api/v1/system/config` | Runtime configuration |
| `POST /api/v1/system/config` | Update configuration |

---

## Onboarding Wizard `/onboarding` (Phase 2 — First-Run Only)

> Smart setup that detects what you have and connects it in minutes, not days.

### Flow
```
Step 1: Welcome                    Step 2: Auto-Detect
┌─────────────────────────┐       ┌─────────────────────────────────┐
│ Welcome to ALdeci 🛡️     │       │ Scanning your environment...    │
│                         │       │                                 │
│ Let's set up your       │       │ ✓ Found: AWS (3 accounts)      │
│ security intelligence   │  →    │ ✓ Found: GitHub (org: myco)    │
│ in under 5 minutes.     │       │ ✓ Found: Snyk (via API key)    │
│                         │       │ ✓ Found: Wiz (in AWS)          │
│ [Get Started]           │       │ ○ SonarQube: not detected       │
└─────────────────────────┘       │                                 │
                                  │ [Connect All] [Customize]       │
                                  └─────────────────────────────────┘

Step 3: Connect                    Step 4: First Results
┌─────────────────────────────┐   ┌─────────────────────────────────┐
│ Connecting 4 sources...     │   │ 🎉 Setup Complete!              │
│                             │   │                                 │
│ AWS SecurityHub    ✓ Done   │   │ Ingested: 1,247 findings       │
│ GitHub Actions     ✓ Done   │   │ Deduplicated: 892 unique       │
│ Snyk               ✓ Done   │   │ AI Triaged: 4 critical         │
│ Wiz                ✓ Done   │   │                                 │
│                             │   │ Time: 4 minutes 32 seconds     │
│ Importing findings...       │   │                                 │
│ ████████████▒▒▒▒ 78%       │   │ [→ Command Center]              │
└─────────────────────────────┘   └─────────────────────────────────┘
```

### API Map
| Endpoint | Purpose | Phase |
|----------|---------|-------|
| `POST /api/v1/onboarding/detect` | Auto-detect environment | 2 |
| `POST /api/v1/onboarding/connect-all` | Batch-connect detected sources | 2 |
| `GET /api/v1/onboarding/status` | Onboarding progress | 2 |
| `POST /api/v1/onboarding/complete` | Mark onboarding done | 2 |

---

# PART 4: AUTO-INGESTION ARCHITECTURE

## How data flows into ALdeci (by phase)

### Phase 1: Manual + CI/CD + Webhooks
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ GitHub      │     │ Scanner     │     │ CLI         │     │ Manual      │
│ Actions     │     │ Webhook     │     │ Wrapper     │     │ Upload      │
│ aldeci-     │     │ Snyk/Wiz/   │     │ aldeci scan │     │ SBOM/SARIF  │
│ action@v1   │     │ SonarQube   │     │ --push      │     │ drag & drop │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       └───────────┬───────┴───────────┬───────┘                   │
                   │                   │                           │
                   ▼                   ▼                           ▼
          ┌────────────────────────────────────────────────────────────┐
          │                    ALdeci Ingestion Engine                  │
          │  Normalize → Deduplicate → Enrich → AI Triage → Store     │
          └────────────────────────────────────────────────────────────┘
```

### Phase 2: + Cloud + CNAPP + MCP
```
┌─────────┐  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────┐
│ AWS     │  │ Azure   │  │ GCP      │  │ Wiz     │  │ MCP      │
│ Security│  │ Defender│  │ SCC      │  │ Prisma  │  │ Cursor   │
│ Hub     │  │         │  │          │  │ Lacework│  │ Claude   │
└────┬────┘  └────┬────┘  └────┬─────┘  └────┬────┘  └────┬─────┘
     │            │            │             │            │
     └────────────┼────────────┼─────────────┘            │
                  ▼            ▼                          ▼
    ┌──────────────────────────────────────────┐  ┌──────────────┐
    │        Auto-Pull Engine (every 15m)      │  │  MCP Server  │
    │  Scheduled → Diff → Normalize → Ingest   │  │  Port 8100   │
    └──────────────────┬───────────────────────┘  └──────┬───────┘
                       │                                 │
                       ▼                                 ▼
          ┌────────────────────────────────────────────────────────┐
          │                    ALdeci Ingestion Engine              │
          └────────────────────────────────────────────────────────┘
```

### Phase 3: + AI Connectors + Self-Healing
```
┌──────────────────────────────────────────────────────────────────┐
│                     AI Connector Layer                            │
│                                                                  │
│  Unknown Tool → AI reads API docs → Generates adapter → Tests    │
│  Broken API → AI detects failure → Diagnoses → Patches adapter   │
│  New Tool → User says "Connect FooSec" → AI figures it out       │
│                                                                  │
│  Self-Monitoring: checks all connectors every 5m                 │
│  Self-Healing: auto-patches when APIs change                     │
│  Learning: improves adapters from usage patterns                 │
└──────────────────────────────────────────────────────────────────┘
```

### CLI Examples
```bash
# Phase 1: Manual connect
aldeci connect github --org=mycompany --token=$GITHUB_TOKEN
aldeci connect snyk --org-id=xxx --api-key=$SNYK_TOKEN
aldeci webhook add --source=wiz --url=https://aldeci.myco.com/api/v1/webhooks/wiz

# Phase 1: Scan wrapper
aldeci scan --tool=trivy --target=./Dockerfile --push
aldeci scan --tool=semgrep --target=./src --push
aldeci scan --tool=snyk --target=. --push

# Phase 2: Auto-detect
aldeci setup --auto-detect      # Finds AWS, GitHub, Snyk, Wiz...
aldeci connect --all             # Connect everything found

# Phase 1: Pipeline trigger
aldeci pipeline run --template=full-triage
aldeci pipeline status
```


---

# PART 5: THE BRAIN EVOLUTION — 4 PHASES

## From Copilot to Autonomous Security Operator

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         THE BRAIN EVOLUTION                                 │
│                                                                             │
│  Phase 1          Phase 2            Phase 3            Phase 4             │
│  COPILOT          SMART COPILOT      AGENT              THE BRAIN           │
│  ──────           ─────────────      ─────              ─────────           │
│  Chat Q&A         Context-aware      Multi-step         Autonomous          │
│  Manual trigger   Proactive alerts   execution          orchestration       │
│  Single-turn      Session memory     Tool calling       Self-improving      │
│  Read-only        Suggestions        Write actions       Approval gates     │
│                                                                             │
│  "What are my     "3 critical        "Triage all        Brain triages,      │
│   critical         findings from      criticals,         creates tickets,   │
│   findings?"       today's CI/CD      create Jira        assigns devs,      │
│                    push need          tickets, run        runs pentests,     │
│                    attention"         pentests,           generates evidence,│
│                                       generate           passes audits.     │
│                                       evidence"          Humans approve     │
│                                                          critical only.     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Phase 1: Copilot (NOW)
**Capabilities:**
- Chat-based Q&A about findings, CVEs, compliance
- Explain CVE impact using EPSS, KEV, NVD data
- Summarize dashboard metrics on demand
- Multi-LLM consensus for triage recommendations
- Manual trigger only — user asks, Brain answers

**UI:** Simple chat interface in S7 (The Brain)
**APIs:** `POST /copilot/sessions`, `POST /copilot/sessions/:id/message`, `POST /multi-llm/consensus`

### Phase 2: Smart Copilot (3-6mo)
**Capabilities:**
- Context-aware: knows your connectors, assets, compliance gaps
- Proactive notifications: "3 critical findings from today's CI/CD push"
- Session memory: remembers past conversations and decisions
- Suggests actions: "You should run a pentest on CVE-2024-3094"
- Intelligence map: visualizes what Brain knows about your environment

**UI:** Chat + Activity Feed + Intelligence Map in S7
**APIs:** `GET /copilot/insight`, `GET /copilot/agents`, `GET /nerve-center/intelligence-map`, `POST /learning-middleware/feedback`

### Phase 3: Agent (6-12mo)
**Capabilities:**
- Multi-step execution: "Triage all critical findings and create Jira tickets"
- Tool calling: can invoke pipeline, create evidence, run pentests
- Approval gates: asks permission for high-impact actions
- Learning: improves from user approvals/rejections
- Cross-tool correlation: connects findings from different sources

**UI:** Chat + Agent Activity Feed + Approval Queue in S7
**APIs:** `POST /copilot/agents/execute`, `POST /intelligent-engine/predict`, `POST /brain/decisions/:id/approve`

### Phase 4: THE BRAIN (1-2yr)
**Capabilities:**
- Autonomous orchestration: runs the entire security program
- Proactive: scans, triages, tickets, evidence, audits — all without prompting
- Self-improving: learns from every decision, gets better over time
- Human-in-the-loop: only escalates critical decisions for human approval
- Multi-channel communication: Slack, Jira, email, IDE, reports
- Compliance autopilot: continuously monitors and fills evidence gaps

**UI:** Brain Dashboard (replaces most manual screens) + Approval Queue
**APIs:** `GET /brain/activity`, `GET /brain/decisions`, `POST /brain/decisions/:id/approve`

### Brain Decision Framework
```
┌─────────────────────────────────────────────────────────┐
│                 Brain Decision Matrix                     │
├──────────────────┬──────────┬──────────┬────────────────┤
│ Action           │ Risk     │ Phase 3  │ Phase 4        │
├──────────────────┼──────────┼──────────┼────────────────┤
│ Triage finding   │ Low      │ Auto     │ Auto           │
│ Create Jira      │ Low      │ Auto     │ Auto           │
│ Run scan         │ Low      │ Auto     │ Auto           │
│ Generate evidence│ Low      │ Auto     │ Auto           │
│ Auto-fix (deps)  │ Medium   │ Approve  │ Auto           │
│ Auto-fix (code)  │ High     │ Approve  │ Approve        │
│ Deploy patch     │ Critical │ Approve  │ Approve        │
│ Escalate to mgmt │ High     │ Auto     │ Auto           │
│ Pass audit       │ Critical │ N/A      │ Approve        │
└──────────────────┴──────────┴──────────┴────────────────┘
```


---

# PART 6: API COVERAGE AUDIT — 526 ENDPOINTS → 8 SCREENS

## Suite-to-Screen Mapping

| Suite | Port | Primary Screen | Secondary Screen(s) |
|-------|------|---------------|---------------------|
| **suite-api** | 8000 | S1 Command Center | S8 Settings |
| **suite-core** | 8001 | S2 Findings Hub | S6 Pipeline, S7 Brain |
| **suite-attack** | 8002 | S3 Attack Lab | S2 Findings Hub |
| **suite-feeds** | 8003 | S2 Findings Hub | S1 Command Center |
| **suite-evidence-risk** | 8004 | S5 Evidence | S1 Command Center |
| **suite-integrations** | 8005 | S4 Connect | S8 Settings |

## Endpoint Coverage by Screen

| Screen | Phase 1 APIs | Phase 2 APIs | Phase 3 APIs | Phase 4 APIs | Total |
|--------|-------------|-------------|-------------|-------------|-------|
| **S1** Command Center | 9 | 2 | 1 | 2 | 14 |
| **S2** Findings Hub | 22 | 4 | 2 | 0 | 28 |
| **S3** Attack Lab | 13 | 2 | 1 | 0 | 16 |
| **S4** Connect | 10 | 7 | 4 | 2 | 23 |
| **S5** Evidence | 12 | 2 | 1 | 1 | 16 |
| **S6** Pipeline | 14 | 2 | 1 | 1 | 18 |
| **S7** The Brain | 8 | 4 | 3 | 3 | 18 |
| **S8** Settings | 9 | 2 | 1 | 1 | 13 |
| **Onboarding** | 0 | 4 | 0 | 0 | 4 |
| **Total** | **97** | **29** | **14** | **10** | **150** |

> **Note:** 150 unique screen-mapped endpoints cover the entire UI surface. The remaining ≈376 endpoints
> are internal/backend-only (health checks, ML training, feed refresh, graph algorithms, batch processing,
> streaming/SSE, deduplication engine, etc.) — they power the platform but don't need dedicated UI screens.

## API Categories → Screen Mapping

| Category | Endpoints | Screen | Phase |
|----------|-----------|--------|-------|
| Dashboard / Analytics | 14 | S1 | 1 |
| Copilot + Agents | 17 | S7 | 1-4 |
| Code Scanning (SBOM/SARIF/SAST) | 8 | S2 | 1 |
| Secrets Detection | 6 | S2 | 1 |
| IaC Scanning | 5 | S2 | 1 |
| Asset Inventory | 3 | S2 | 1 |
| Feeds (NVD/KEV/EPSS) | 6 | S2 (enrichment) | 1 |
| Deduplication Engine | 4 | S6 (pipeline step) | 1 |
| MPTE / Micro-Pentest | 9 | S3 | 1 |
| Attack Simulation | 4 | S3 | 1 |
| Reachability Analysis | 3 | S3 | 1 |
| GNN / Graph Analytics | 3 | S2 (Graph tab) | 1 |
| Decision / Algorithms | 6 | S6 | 1 |
| Multi-LLM Consensus | 5 | S7 | 1 |
| Nerve Center | 8 | S1, S7 | 1 |
| Brain Pipeline | 4 | S6 | 1 |
| Exposure Cases | 8 | S2 (Cases tab) | 1 |
| Remediation | 6 | S6 | 1 |
| Workflows / Automation | 6 | S6 | 1 |
| Policies | 3 | S6 | 1 |
| Evidence Bundles | 7 | S5 | 1 |
| Compliance / Reports | 6 | S5 | 1 |
| Audit Log | 2 | S5 | 1 |
| Integrations | 6 | S4 | 1 |
| Webhooks | 14 | S4 | 1 |
| Marketplace | 2 | S4 | 1 |
| Auth / Users / Teams | 4 | S8 | 1 |
| Health / System | 4 | S8 | 1 |
| Streaming / SSE | 3 | S6, S7 (real-time) | 1 |
| Cloud Providers | 3 | S4 | 2 |
| CNAPP Auto-Detect | 2 | S4 | 2 |
| MCP Server | 3 | S4 | 2 |
| Onboarding | 4 | Wizard | 2 |
| AI Connectors | 4 | S4 | 3 |
| Intelligent Engine | 4 | S7 | 3 |
| Brain Autonomous | 3 | S7 | 4 |
| Learning Middleware | 2 | S7 | 2 |


---

# PART 7: IMPLEMENTATION ROADMAP

## Phase 1 — CONNECT (Now → 3 months)

### Priority Order (build in this sequence)
```
Week 1-2:   S1 Command Center + S8 Settings (foundation + health)
Week 3-4:   S2 Findings Hub (THE CENTER — most critical screen)
Week 5-6:   S4 Connect (CI/CD + Webhooks + Manual Upload)
Week 7-8:   S6 Pipeline (Ingest → Triage → Remediate → Evidence)
Week 9-10:  S3 Attack Lab (Micro-Pentest + Attack Sim)
Week 11-12: S5 Evidence (Compliance + Bundles + Signing)
Week 13:    S7 The Brain (Copilot chat — Phase 1 version)
Week 14:    Integration testing + polish
```

### Phase 1 Deliverables
- [ ] 8 functional screens with real API integration
- [ ] GitHub Actions connector (aldeci-action@v1)
- [ ] CLI wrapper (aldeci scan --push)
- [ ] Webhook receivers (Snyk, Wiz, SonarQube)
- [ ] Manual SBOM/SARIF upload (drag & drop)
- [ ] Copilot chat (Phase 1 — Q&A mode)
- [ ] Pipeline running end-to-end
- [ ] Evidence bundle generation + signing

## Phase 2 — DISCOVER (3-6 months)

### Priority Order
```
Month 4:    Onboarding Wizard + Auto-Detect engine
Month 5:    Cloud Provider connectors (AWS SecurityHub, Azure Defender, GCP SCC)
Month 5:    CNAPP auto-detect (Wiz, Prisma, Lacework, Orca)
Month 6:    MCP Server (port 8100) + IDE integration
Month 6:    Smart Copilot upgrade (context-aware, proactive)
```

### Phase 2 Deliverables
- [ ] Onboarding Wizard (5-minute zero-to-value setup)
- [ ] AWS SecurityHub direct pull (every 15m)
- [ ] Azure Defender direct pull
- [ ] GCP Security Command Center direct pull
- [ ] CNAPP auto-detection + auto-configuration
- [ ] MCP server for Cursor/Claude/Windsurf
- [ ] Smart Copilot with proactive insights
- [ ] S4 Connect evolves with Cloud + CNAPP + MCP tabs

## Phase 3 — ADAPT (6-12 months)

### Priority Order
```
Month 7-8:  AI Connector Engine (reads API docs, generates adapters)
Month 9:    Self-healing integrations (auto-patches when APIs change)
Month 10:   Agent mode for The Brain (multi-step execution)
Month 11:   Predictive analytics (risk prediction, budget optimization)
Month 12:   Cross-tool correlation AI
```

### Phase 3 Deliverables
- [ ] AI Connector Studio (S4 new tab)
- [ ] Self-monitoring + self-healing for all connectors
- [ ] The Brain Agent mode (multi-step execution)
- [ ] Intelligent prediction engine
- [ ] Cross-tool finding correlation

## Phase 4 — AUTONOMY (1-2 years)

### Priority Order
```
Year 1 H2:  Autonomous triage + ticket creation
Year 2 H1:  Autonomous evidence generation + compliance monitoring
Year 2 H1:  Human approval gates for critical actions
Year 2 H2:  Autonomous audit preparation + communication
```

### Phase 4 Deliverables
- [ ] The Brain runs security program autonomously
- [ ] Human approval gates for critical decisions only
- [ ] Compliance autopilot (monitors + fills gaps continuously)
- [ ] Multi-channel communication (Slack, Jira, email, IDE)
- [ ] Self-improving from every decision


---

# PART 8: DESIGN SYSTEM — shadcn/ui + Radix + Tailwind

> **Framework:** shadcn/ui (NOT a component library — copy/paste components you OWN)
> **Primitives:** Radix UI (accessible, unstyled headless components)
> **Styling:** Tailwind CSS 3.4 + CSS variables (HSL) + class-variance-authority (cva)
> **Icons:** lucide-react (consistent, tree-shakeable)
> **Animation:** framer-motion (layout, presence, gestures) + tailwindcss-animate (micro)
> **Charts:** recharts (declarative, responsive)
> **Tables:** @tanstack/react-table (headless, sortable, filterable, virtual)
> **Forms:** react-hook-form + zod (type-safe validation)
> **Graph:** @xyflow/react (Knowledge Graph, attack paths, pipeline DAG)

---

## 8.1 Tech Stack (already in package.json)

```
suite-ui1/aldeci/
├── React 18.2 + TypeScript 5.3 + Vite 5.0
├── shadcn/ui (Radix primitives + Tailwind + cva)
│   ├── @radix-ui/react-accordion
│   ├── @radix-ui/react-alert-dialog
│   ├── @radix-ui/react-avatar
│   ├── @radix-ui/react-checkbox
│   ├── @radix-ui/react-dialog
│   ├── @radix-ui/react-dropdown-menu
│   ├── @radix-ui/react-hover-card
│   ├── @radix-ui/react-label
│   ├── @radix-ui/react-popover
│   ├── @radix-ui/react-progress
│   ├── @radix-ui/react-scroll-area
│   ├── @radix-ui/react-select
│   ├── @radix-ui/react-separator
│   ├── @radix-ui/react-slot
│   ├── @radix-ui/react-switch
│   ├── @radix-ui/react-tabs
│   ├── @radix-ui/react-toast
│   └── @radix-ui/react-tooltip
├── class-variance-authority (cva) — variant-based component styling
├── clsx + tailwind-merge — conditional class composition
├── cmdk — Command Palette (⌘K)
├── @tanstack/react-query — data fetching + caching
├── @tanstack/react-table — headless data tables
├── @xyflow/react — graph/flow visualization
├── recharts — charts
├── react-hook-form + zod — forms
├── framer-motion — animation
├── react-dropzone — file upload
├── react-markdown — chat message rendering
├── sonner — toast notifications
├── zustand — state management
├── axios — HTTP client
├── date-fns — date formatting
└── lucide-react — icons
```

---

## 8.2 shadcn/ui Components — Installed vs Needed

### Already installed (8 components in `src/components/ui/`)
| Component | File | Radix Primitive | Status |
|-----------|------|-----------------|--------|
| Badge | `badge.tsx` | None (HTML div + cva) | ✅ Has severity variants (critical/high/medium/low/info/success) |
| Button | `button.tsx` | `@radix-ui/react-slot` | ✅ Has 6 variants + 4 sizes |
| Card | `card.tsx` | None (HTML div) | ✅ Card/Header/Title/Description/Content/Footer |
| Input | `input.tsx` | None (HTML input) | ✅ Basic |
| Progress | `progress.tsx` | `@radix-ui/react-progress` | ✅ Basic |
| ScrollArea | `scroll-area.tsx` | `@radix-ui/react-scroll-area` | ✅ Viewport + scrollbar |
| Tabs | `tabs.tsx` | `@radix-ui/react-tabs` | ✅ Root/List/Trigger/Content |
| Tooltip | `tooltip.tsx` | `@radix-ui/react-tooltip` | ✅ Provider/Root/Trigger/Content |

### Need to add via `npx shadcn-ui@latest add <name>`
| Component | Radix Primitive | Used In | Why Needed |
|-----------|-----------------|---------|------------|
| **Accordion** | `@radix-ui/react-accordion` | S2 finding detail, S6 pipeline steps | Expandable sections |
| **Alert Dialog** | `@radix-ui/react-alert-dialog` | S7 approval gates, S6 destructive actions | Confirmation dialogs |
| **Avatar** | `@radix-ui/react-avatar` | S7 chat, S8 users | User avatars with fallback |
| **Checkbox** | `@radix-ui/react-checkbox` | S2 bulk actions, S6 workflow builder | Multi-select |
| **Command** | `cmdk` | Global ⌘K | Command palette search |
| **Dialog** | `@radix-ui/react-dialog` | S2 finding detail, S4 connector config | Modal overlays |
| **Dropdown Menu** | `@radix-ui/react-dropdown-menu` | ALL screens | Context menus, action menus |
| **Hover Card** | `@radix-ui/react-hover-card` | S2 CVE hover, S1 metric hover | Rich hover previews |
| **Label** | `@radix-ui/react-label` | ALL forms | Accessible form labels |
| **Popover** | `@radix-ui/react-popover` | S2 filters, S4 connector details | Floating panels |
| **Select** | `@radix-ui/react-select` | ALL screens (filters, dropdowns) | Accessible dropdowns |
| **Separator** | `@radix-ui/react-separator` | ALL screens | Visual dividers |
| **Sheet** | `@radix-ui/react-dialog` | Global sidebar, S2 finding detail | Slide-out panels |
| **Skeleton** | None (HTML div) | ALL screens | Loading states |
| **Switch** | `@radix-ui/react-switch` | S4 connector toggle, S8 settings | Toggle switches |
| **Table** | None (HTML table) | S2, S3, S5, S6 | Styled table primitives |
| **Textarea** | None (HTML textarea) | S7 chat input, S4 webhook config | Multi-line input |
| **Toast** | `@radix-ui/react-toast` or `sonner` | ALL screens | Notifications |
| **Toggle** | `@radix-ui/react-toggle` | S2 view mode, S3 scan options | Toggle buttons |
| **Toggle Group** | `@radix-ui/react-toggle-group` | S2 severity filter, S1 time range | Grouped toggles |

### Installation command (run once)
```bash
cd suite-ui1/aldeci
npx shadcn-ui@latest init   # if not already initialized
npx shadcn-ui@latest add accordion alert-dialog avatar checkbox \
  command dialog dropdown-menu hover-card label popover select \
  separator sheet skeleton switch table textarea toast toggle \
  toggle-group
```


---

## 8.3 Custom ALdeci Components — shadcn/ui Composition Map

Every custom component is composed from shadcn/ui primitives + Radix + Tailwind. **No external UI libraries.**

| ALdeci Component | shadcn/ui Primitives Used | Radix | Props (key) |
|------------------|--------------------------|-------|-------------|
| **`<FindingCard />`** | `Card`, `Badge`, `HoverCard`, `Button`, `Tooltip` | hover-card | `finding`, `onClick`, `compact?` |
| **`<SeverityBadge />`** | `Badge` (custom cva variants) | — | `severity: 'critical'│'high'│'medium'│'low'│'info'` |
| **`<EvidenceChain />`** | `Card`, `Badge`, `Separator`, `Tooltip` | — | `steps[]`, `currentStep` |
| **`<ConnectorCard />`** | `Card`, `Badge`, `Switch`, `Button`, `Tooltip` | switch | `connector`, `onToggle`, `onConfigure` |
| **`<PipelineStep />`** | `Card`, `Progress`, `Badge`, `Tooltip` | progress | `step`, `status`, `progress%` |
| **`<MetricCard />`** | `Card`, `Tooltip` + recharts `Sparkline` | — | `title`, `value`, `trend`, `sparkData[]` |
| **`<ChatMessage />`** | `Card`, `Avatar`, `Button`, `Skeleton` + react-markdown | avatar | `message`, `role: 'user'│'ai'`, `actions[]` |
| **`<ApprovalCard />`** | `Card`, `Badge`, `Button`, `AlertDialog` | alert-dialog | `decision`, `onApprove`, `onReject`, `onDiscuss` |
| **`<ComplianceBar />`** | `Progress`, `Badge`, `Tooltip` | progress | `framework`, `percentage`, `controlCount` |
| **`<DataTable />`** | `Table`, `Checkbox`, `DropdownMenu`, `Select`, `Button`, `Input` | dropdown-menu, checkbox | `columns[]`, `data[]`, `onRowClick`, `filters` |
| **`<TabLayout />`** | `Tabs` | tabs | `tabs[]`, `defaultTab`, `urlParam` |
| **`<EmptyState />`** | `Card`, `Button` + lucide-react icon | — | `icon`, `title`, `description`, `cta`, `onAction` |
| **`<StatusDot />`** | None (Tailwind `div` + animation) | — | `status: 'healthy'│'degraded'│'failed'│'unknown'` |
| **`<CommandPalette />`** | `Command` (cmdk) | — | `open`, `onOpenChange`, `groups[]` |
| **`<GlobalSidebar />`** | `Sheet`, `Button`, `Separator`, `Tooltip`, `Badge` | dialog (sheet) | `collapsed`, `onToggle`, `activeRoute` |

### Component file structure
```
src/components/
├── ui/                      # shadcn/ui primitives (DO NOT EDIT)
│   ├── accordion.tsx
│   ├── alert-dialog.tsx
│   ├── avatar.tsx
│   ├── badge.tsx            ← has severity variants
│   ├── button.tsx           ← has 6 variants + 4 sizes
│   ├── card.tsx
│   ├── checkbox.tsx
│   ├── command.tsx
│   ├── dialog.tsx
│   ├── dropdown-menu.tsx
│   ├── hover-card.tsx
│   ├── input.tsx
│   ├── label.tsx
│   ├── popover.tsx
│   ├── progress.tsx
│   ├── scroll-area.tsx
│   ├── select.tsx
│   ├── separator.tsx
│   ├── sheet.tsx
│   ├── skeleton.tsx
│   ├── switch.tsx
│   ├── table.tsx
│   ├── tabs.tsx
│   ├── textarea.tsx
│   ├── toast.tsx
│   ├── toggle.tsx
│   ├── toggle-group.tsx
│   └── tooltip.tsx
├── aldeci/                  # Custom ALdeci components (EDIT FREELY)
│   ├── finding-card.tsx
│   ├── severity-badge.tsx
│   ├── evidence-chain.tsx
│   ├── connector-card.tsx
│   ├── pipeline-step.tsx
│   ├── metric-card.tsx
│   ├── chat-message.tsx
│   ├── approval-card.tsx
│   ├── compliance-bar.tsx
│   ├── data-table.tsx
│   ├── tab-layout.tsx
│   ├── empty-state.tsx
│   ├── status-dot.tsx
│   ├── command-palette.tsx
│   └── global-sidebar.tsx
├── charts/                  # recharts wrappers
│   ├── severity-donut.tsx
│   ├── trend-line.tsx
│   ├── sparkline.tsx
│   └── heatmap.tsx
└── layout/
    ├── main-layout.tsx      # GlobalSidebar + main content + CommandPalette
    ├── page-header.tsx      # Breadcrumbs + title + actions
    └── page-shell.tsx       # ScrollArea + loading/error states
```


---

## 8.4 CSS Design Tokens (HSL for shadcn/ui)

All tokens use HSL format to integrate with shadcn/ui's `hsl(var(--token))` convention.

```css
/* ========== Already in index.css (shadcn/ui defaults) ========== */
:root {
  --background: 222.2 84% 4.9%;
  --foreground: 210 40% 98%;
  --primary: 142.1 76.2% 36.3%;          /* ALdeci green */
  --destructive: 0 62.8% 30.6%;
  --radius: 0.5rem;
  /* ... full shadcn/ui palette already configured */
}

/* ========== ADD: ALdeci-specific semantic tokens ========== */
:root {
  /* Severity palette (HSL) */
  --severity-critical: 0 84% 60%;         /* red-500 */
  --severity-high: 25 95% 53%;            /* orange-500 */
  --severity-medium: 48 96% 53%;          /* yellow-500 */
  --severity-low: 217 91% 60%;            /* blue-500 */
  --severity-info: 220 9% 46%;            /* gray-500 */

  /* Phase indicators */
  --phase-1: 142 71% 45%;                 /* green-500  — NOW */
  --phase-2: 217 91% 60%;                 /* blue-500   — 3-6mo */
  --phase-3: 271 91% 65%;                 /* purple-500 — 6-12mo */
  --phase-4: 38 92% 50%;                  /* amber-500  — 1-2yr */

  /* Connector status */
  --status-healthy: 142 71% 45%;          /* green-500 */
  --status-degraded: 48 96% 53%;          /* yellow-500 */
  --status-failed: 0 84% 60%;             /* red-500 */
  --status-unknown: 220 9% 46%;           /* gray-500 */

  /* Spacing scale (matches Tailwind) */
  --space-xs: 0.25rem;
  --space-sm: 0.5rem;
  --space-md: 1rem;
  --space-lg: 1.5rem;
  --space-xl: 2rem;
  --space-2xl: 3rem;
}
```

### Using tokens in Tailwind (via tailwind.config.js extend)
```js
// Add to tailwind.config.js > theme > extend > colors
severity: {
  critical: "hsl(var(--severity-critical))",
  high:     "hsl(var(--severity-high))",
  medium:   "hsl(var(--severity-medium))",
  low:      "hsl(var(--severity-low))",
  info:     "hsl(var(--severity-info))",
},
phase: {
  1: "hsl(var(--phase-1))",
  2: "hsl(var(--phase-2))",
  3: "hsl(var(--phase-3))",
  4: "hsl(var(--phase-4))",
},
status: {
  healthy:  "hsl(var(--status-healthy))",
  degraded: "hsl(var(--status-degraded))",
  failed:   "hsl(var(--status-failed))",
  unknown:  "hsl(var(--status-unknown))",
},
```

Usage: `<Badge className="bg-severity-critical/10 text-severity-critical">Critical</Badge>`

---

## 8.5 Component Composition Pattern

All custom ALdeci components follow the same pattern:

```tsx
// src/components/aldeci/severity-badge.tsx
import { Badge, type BadgeProps } from "@/components/ui/badge"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const severityVariants = cva("", {
  variants: {
    severity: {
      critical: "bg-severity-critical/10 text-severity-critical border-severity-critical/20",
      high:     "bg-severity-high/10 text-severity-high border-severity-high/20",
      medium:   "bg-severity-medium/10 text-severity-medium border-severity-medium/20",
      low:      "bg-severity-low/10 text-severity-low border-severity-low/20",
      info:     "bg-severity-info/10 text-severity-info border-severity-info/20",
    },
  },
  defaultVariants: { severity: "info" },
})

interface SeverityBadgeProps extends VariantProps<typeof severityVariants> {
  className?: string
  children?: React.ReactNode
}

export function SeverityBadge({ severity, className, children }: SeverityBadgeProps) {
  return (
    <Badge className={cn(severityVariants({ severity }), className)}>
      {children ?? severity}
    </Badge>
  )
}
```

**Pattern rules:**
1. Import shadcn/ui primitives from `@/components/ui/*`
2. Define variants with `cva` when component has visual states
3. Use `cn()` for conditional class merging
4. Export named (not default) for tree-shaking
5. Props extend the shadcn primitive's props when possible
6. Keep components < 100 lines — split into sub-components if larger

---

## 8.6 URL State Convention

All filters, tabs, and selections persist in URL for shareability and browser back/forward:

```
/                                            → S1 Command Center
/findings?severity=critical&source=snyk&tab=code  → S2 Findings Hub, Code tab, filtered
/findings/CVE-2024-1234                      → S2 Finding detail (slide-out Sheet)
/attack?tab=micro-pentest&target=example.com → S3 Attack Lab, Micro-Pentest tab
/connect?tab=cloud                           → S4 Connect, Cloud tab
/evidence?framework=soc2&status=signed       → S5 Evidence, SOC2 filtered
/pipeline?run=RUN-042&step=ai-triage         → S6 Pipeline, specific run
/brain?session=abc123                        → S7 The Brain, resume session
/settings?tab=api-keys                       → S8 Settings, API Keys tab
/onboarding                                  → Onboarding Wizard (Phase 2)
```

**Implementation:** Use `useSearchParams()` from react-router-dom. Sync tab state with `?tab=` param. All `<TabLayout />` components do this automatically.

---

## 8.7 Cross-Screen Navigation Rules

1. **Every finding reference is a link** → clicks navigate to S2 (Findings Hub) with finding pre-loaded
2. **Every CVE is enrichable** → hover shows `<HoverCard>` with EPSS + KEV + NVD data
3. **Every evidence reference is a link** → clicks navigate to S5 (Evidence) with bundle pre-loaded
4. **⌘K from anywhere** → opens `<CommandPalette />` to search findings, screens, CVEs, settings
5. **Breadcrumbs track context** → `S1 → S2 → Finding Detail → S3 Attack → Back to S2`
6. **SSE for real-time** → Pipeline progress, Brain activity, connector health — all live `useSSE()` hook
7. **Toast notifications (sonner)** → "New critical finding from GitHub Actions" — background events
8. **Deep links from external** → CLI output, Slack messages, Jira tickets all link directly to findings/evidence


---

# PART 9: DATA ARCHITECTURE — MINDSDB AS UNIFIED AI LAYER

> **User question:** "Does data in MindsDB and our VectorDB and other DBs help? Can it be consolidated to MindsDB and AI can work on that as single layer?"
>
> **Answer: YES — MindsDB becomes THE SINGLE AI INTERFACE to all data.**

---

## 9.1 Current State — Data Sprawl (10+ Databases)

```
┌─────────────────────────────────────────────────────────────────┐
│                    CURRENT: Fragmented Data                      │
├─────────────────┬──────────────┬────────────────────────────────┤
│ Database        │ File         │ What It Stores                 │
├─────────────────┼──────────────┼────────────────────────────────┤
│ AnalyticsDB     │ analytics.db │ Findings, decisions, metrics   │
│ InventoryDB     │ inventory.db │ Applications, services, deps   │
│ SecretsDB       │ secrets.db   │ Secret findings, scan configs  │
│ IaCDB           │ iac.db       │ IaC findings, scan configs     │
│ ReportDB        │ reports.db   │ Reports, schedules, templates  │
│ IntegrationDB   │ integrations.db│ Connectors, sync status      │
│ AuditDB         │ audit.db     │ Audit logs, compliance, controls│
│ AuthDB          │ auth.db      │ Users, SSO, API keys           │
│ UserDB          │ users.db     │ Users, teams                   │
│ MPTEDB          │ mpte.db      │ Pentest requests, results      │
├─────────────────┼──────────────┼────────────────────────────────┤
│ ChromaDB        │ chromadb/    │ Security pattern embeddings    │
│ InMemoryVector  │ (RAM)        │ Fallback vector store          │
├─────────────────┼──────────────┼────────────────────────────────┤
│ MindsDB Agents  │ (external)   │ 5 AI agents, ML models, KBs   │
└─────────────────┴──────────────┴────────────────────────────────┘

PROBLEM: AI agents query 10+ separate SQLite DBs. No unified view.
         Each DB has its own schema. Cross-domain queries impossible.
         The Brain cannot "think" across all data simultaneously.
```

---

## 9.2 Target State — MindsDB as Unified AI Layer

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│                    ┌──────────────────┐                          │
│                    │   THE BRAIN (S7) │                          │
│                    │   Natural Language│                          │
│                    └────────┬─────────┘                          │
│                             │                                    │
│                    ┌────────▼─────────┐                          │
│                    │     MindsDB      │  ← SINGLE AI INTERFACE   │
│                    │  SQL + AI + ML   │                          │
│                    │                  │                          │
│                    │  ┌────────────┐  │                          │
│                    │  │ ML Models  │  │  severity_predictor      │
│                    │  │            │  │  exploit_predictor       │
│                    │  │            │  │  epss_model              │
│                    │  │            │  │  anomaly_detector        │
│                    │  └────────────┘  │                          │
│                    │                  │                          │
│                    │  ┌────────────┐  │                          │
│                    │  │ Knowledge  │  │  CVE KB (ChromaDB)       │
│                    │  │ Bases      │  │  Attack Patterns KB      │
│                    │  │ (Vector)   │  │  Compliance KB           │
│                    │  └────────────┘  │  Remediation KB          │
│                    │                  │                          │
│                    │  ┌────────────┐  │                          │
│                    │  │ AI Agents  │  │  5 specialized agents    │
│                    │  └────────────┘  │                          │
│                    └────────┬─────────┘                          │
│                             │                                    │
│              ┌──────────────┼──────────────┐                     │
│              │              │              │                      │
│     ┌────────▼───┐  ┌──────▼─────┐  ┌─────▼──────┐             │
│     │  SQLite    │  │  ChromaDB  │  │  External  │             │
│     │ (10 DBs)   │  │ (Vectors)  │  │  APIs      │             │
│     │ via        │  │ via        │  │ NVD, CISA  │             │
│     │ data source│  │ vector_db  │  │ EPSS, OSV  │             │
│     └────────────┘  └────────────┘  └────────────┘             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### How it works:

**MindsDB connects to ALL data sources as "data sources" — AI queries ONE interface.**

```sql
-- MindsDB treats SQLite DBs as data sources
CREATE DATABASE aldeci_findings
ENGINE = 'sqlite'
PARAMETERS = { "db_file": "data/analytics.db" };

CREATE DATABASE aldeci_inventory
ENGINE = 'sqlite'
PARAMETERS = { "db_file": "data/inventory.db" };

-- MindsDB treats ChromaDB as vector storage for Knowledge Bases
CREATE KNOWLEDGE BASE cve_knowledge
USING
  model = 'gpt-4',
  storage = 'chromadb';

-- Now AI can query ACROSS all data with one SQL:
SELECT f.*, i.criticality, kb.related_attacks
FROM aldeci_findings.findings f
JOIN aldeci_inventory.applications i ON f.application_id = i.id
JOIN cve_knowledge kb ON f.cve_id = kb.cve_id
WHERE f.severity = 'critical'
ORDER BY f.epss_score DESC;
```

---

## 9.3 Consolidation Strategy — 3 Phases

| Phase | Action | Benefit |
|-------|--------|---------|
| **Phase 1 (Now)** | Keep 10 SQLite DBs as-is. MindsDB connects to each as a data source. ChromaDB stays as vector backend. | Zero migration risk. AI gets unified view immediately. |
| **Phase 2 (3-6mo)** | Consolidate SQLite → 2-3 DBs: `operational.db` (findings, inventory, integrations), `auth.db` (users, keys, audit), `ml.db` (models, predictions). ChromaDB → MindsDB Knowledge Bases. | Simpler ops. Better cross-domain queries. |
| **Phase 3 (6-12mo)** | Migrate to PostgreSQL + pgvector. MindsDB as the AI middleware. All agents query through MindsDB. | Production scale. Real vector similarity search. ACID transactions. |

### Phase 1 MindsDB Data Source Registration (do now)
```sql
-- Register all 10 SQLite databases as MindsDB data sources
CREATE DATABASE findings_ds ENGINE='sqlite' PARAMETERS={"db_file":"data/analytics.db"};
CREATE DATABASE inventory_ds ENGINE='sqlite' PARAMETERS={"db_file":"data/inventory.db"};
CREATE DATABASE secrets_ds   ENGINE='sqlite' PARAMETERS={"db_file":"data/secrets.db"};
CREATE DATABASE iac_ds       ENGINE='sqlite' PARAMETERS={"db_file":"data/iac.db"};
CREATE DATABASE reports_ds   ENGINE='sqlite' PARAMETERS={"db_file":"data/reports.db"};
CREATE DATABASE integrations_ds ENGINE='sqlite' PARAMETERS={"db_file":"data/integrations.db"};
CREATE DATABASE audit_ds     ENGINE='sqlite' PARAMETERS={"db_file":"data/audit.db"};
CREATE DATABASE auth_ds      ENGINE='sqlite' PARAMETERS={"db_file":"data/auth.db"};
CREATE DATABASE users_ds     ENGINE='sqlite' PARAMETERS={"db_file":"data/users.db"};
CREATE DATABASE mpte_ds      ENGINE='sqlite' PARAMETERS={"db_file":"data/mpte.db"};

-- Register ChromaDB as vector storage
CREATE DATABASE vector_ds ENGINE='chromadb' PARAMETERS={"persist_directory":"data/chromadb"};

-- Create unified Knowledge Bases
CREATE KNOWLEDGE BASE aldeci_cve_kb USING model='gpt-4', storage=vector_ds;
CREATE KNOWLEDGE BASE aldeci_attack_kb USING model='gpt-4', storage=vector_ds;
CREATE KNOWLEDGE BASE aldeci_compliance_kb USING model='gpt-4', storage=vector_ds;
CREATE KNOWLEDGE BASE aldeci_remediation_kb USING model='gpt-4', storage=vector_ds;
```

---

## 9.4 What This Enables for The Brain (S7)

| Without MindsDB Layer | With MindsDB Layer |
|-----------------------|-------------------|
| Brain asks each DB separately | Brain writes ONE SQL query across all data |
| "How many critical vulns?" → query analytics.db | "Show critical vulns in prod apps with known exploits" → ONE query |
| Cross-domain = custom code | Cross-domain = SQL JOIN |
| Vector search = separate API | Vector search = `SELECT * FROM knowledge_base WHERE ...` |
| ML prediction = separate API | ML prediction = `SELECT * FROM model WHERE ...` |
| Each agent has different data access | All agents query the same MindsDB interface |

### Brain Query Examples (Phase 1)
```sql
-- "What are the most critical findings in production?"
SELECT f.title, f.severity, f.epss_score, a.name as app, a.environment
FROM findings_ds.findings f
JOIN inventory_ds.applications a ON f.application_id = a.id
WHERE f.severity = 'critical' AND a.environment = 'production'
ORDER BY f.epss_score DESC LIMIT 10;

-- "Are any of our critical CVEs in CISA KEV?"
SELECT f.cve_id, f.title, kb.content as threat_intel
FROM findings_ds.findings f
JOIN aldeci_cve_kb kb ON f.cve_id = kb.cve_id
WHERE f.severity = 'critical';

-- "Predict which findings will be exploited next week"
SELECT f.*, m.exploit_probability, m.confidence
FROM findings_ds.findings f
JOIN exploit_predictor m ON f.id = m.finding_id
WHERE m.exploit_probability > 0.7
ORDER BY m.exploit_probability DESC;
```


---

# END OF SPECIFICATION

**Document stats:**
- **10 parts** covering product vision through data architecture
- **8 screens** (82% reduction from original 45)
- **15 routes** (78% reduction from original 68)
- **≈150 screen-mapped API endpoints** (covering ≈526 total backend endpoints)
- **4-phase roadmap** to autonomous security
- **6 personas** with zero-click workflow targets
- **28 shadcn/ui components** (8 installed + 20 to add)
- **15 custom ALdeci components** with shadcn/ui composition map
- **10 databases** → unified MindsDB AI layer
- **4 Knowledge Bases** (CVE, Attack, Compliance, Remediation) backed by ChromaDB
- **0 functionality lost** — everything from 45 screens compressed into 8 tabbed interfaces

**Next step:** Build suite-ui1/aldeci following Phase 1 roadmap (Weeks 1-14).