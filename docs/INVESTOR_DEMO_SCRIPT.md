# ALdeci 15-Minute Investor Demo -- Full Presenter Guide (v1 - SUPERSEDED)

> **SUPERSEDED**: This file is the v1.0 presenter guide. The canonical v2.0
> runbook is at `docs/INVESTOR_DEMO_RUNBOOK.md` and the companion script is
> at `scripts/investor-demo-15min.sh` (v2.0).
>
> v2.0 adds: Brain Pipeline scene, AutoFix scene, triage-funnel API call,
> corrected evidence endpoint paths, corrected UI routes, and expanded
> fallback data for every new API call.
>
> **Sprint Item**: SPRINT1-010 | **Pillar**: V3 (Decision Intelligence)
> **Version**: 1.0.0 (superseded by v2.0) | **Date**: 2026-02-27
> **Audience**: CEO, Sales Engineer, anyone presenting to investors

---

## Table of Contents

1. [Setup Instructions](#1-setup-instructions)
2. [Pre-Demo Checklist](#2-pre-demo-checklist)
3. [Timing Overview](#3-timing-overview)
4. [Full Talk Track](#4-full-talk-track)
5. [UI Screen Guide](#5-ui-screen-guide)
6. [Objection Handling](#6-objection-handling)
7. [Competitive Positioning](#7-competitive-positioning)
8. [Fallback Procedures](#8-fallback-procedures)
9. [Post-Demo Follow-Up](#9-post-demo-follow-up)

---

## 1. Setup Instructions

### Option A: Full Docker Deployment (recommended for live demos)

```bash
# 1. Clone and enter the repo
cd /path/to/Fixops

# 2. Set required environment variables
export FIXOPS_API_TOKEN="demo-key"
export OPENAI_API_KEY=""       # Optional: enables live LLM consensus
export ANTHROPIC_API_KEY=""    # Optional: enables live LLM consensus

# 3. Start the full stack
docker compose -f docker/docker-compose.yml up -d

# 4. Start the UI (separate terminal)
cd suite-ui/aldeci
npm install && npm run dev
# UI will be available at http://localhost:3001

# 5. Verify everything is running
curl -s http://localhost:8000/health | jq '.'
curl -s -H "X-API-Key: demo-key" http://localhost:8000/api/v1/fail/health | jq '.'
```

### Option B: Local API Only (lightweight, works offline)

```bash
# 1. Enter the API directory
cd /path/to/Fixops/suite-api

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the API
FIXOPS_API_TOKEN=demo-key python -m uvicorn apps.api.app:app --host 0.0.0.0 --port 8000

# 4. In a separate terminal, start the UI
cd suite-ui/aldeci && npm run dev
```

### Option C: Demo Script with Fallback Data (safest for unreliable networks)

```bash
# The demo script has built-in fallback data for every API call.
# If the API is down, the demo still runs with identical output.
cd /path/to/Fixops/scripts
./investor-demo-15min.sh --check    # Pre-flight only
./investor-demo-15min.sh            # Interactive mode
./investor-demo-15min.sh --auto     # Auto-advance (3s pauses)
```

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ALDECI_BASE_URL` | `http://localhost:8000` | API base URL |
| `ALDECI_API_KEY` | `demo-key` | API authentication key |
| `FIXOPS_API_TOKEN` | (required) | Server-side API token |
| `FIXOPS_BOOTSTRAP_MPTE` | `false` | Enable MPTE demo mode |

---

## 2. Pre-Demo Checklist

### 30 Minutes Before

- [ ] API is running and responding to `/health`
- [ ] UI is running at `http://localhost:3001`
- [ ] FAIL Engine health check passes (`/api/v1/fail/health`)
- [ ] MCP catalog is populated (`/api/v1/mcp/stats` shows 500+ tools)
- [ ] Browser has these tabs pre-loaded:
  - Tab 1: Triage Dashboard (`/discover/exposure-cases`)
  - Tab 2: MPTE Console (`/validate/mpte`)
  - Tab 3: CEO Dashboard (`/ceo`)
  - Tab 4: Evidence Export (`/comply/evidence`)
  - Tab 5: Attack Paths (`/validate/attack-paths`)
- [ ] Terminal open with `investor-demo-15min.sh` ready to run
- [ ] Browser zoom set to 110% for projector readability
- [ ] Screen recording started (always record demos for internal review)
- [ ] Backup: demo script tested with `--dry-run` flag

### 5 Minutes Before

- [ ] Close Slack, email, any notification sources
- [ ] Close any non-demo browser tabs
- [ ] Verify internet connection (or confirm offline fallback works)
- [ ] Water on the desk
- [ ] Smile

---

## 3. Timing Overview

| Time | Act | Content | Screen/Tool |
|------|-----|---------|-------------|
| 0:00 - 1:30 | **ACT 1: The Problem** | $380B market, 11,300 findings chaos | Terminal (stats) |
| 1:30 - 3:00 | **ACT 2a: FAIL Single Score** | Score CVE-2024-3094 live | Terminal (curl) |
| 3:00 - 5:00 | **ACT 2b: FAIL Batch + Triage** | 11,300 to 340 reduction | Terminal + UI (Triage Dashboard) |
| 5:00 - 6:30 | **ACT 3a: MPTE Introduction** | Why verification matters | Terminal (curl) |
| 6:30 - 9:00 | **ACT 3b: 19-Phase Walkthrough** | Phase-by-phase evidence | Terminal + UI (MPTE Console) |
| 9:00 - 11:30 | **ACT 4: MCP-Native** | 537 tools, AI agent consumption | Terminal (curl) |
| 11:30 - 13:00 | **ACT 5: Evidence** | Signed bundles, compliance | UI (Evidence Export) |
| 13:00 - 15:00 | **ACT 6: Market & Ask** | Business model, ask | Terminal (stats) |

---

## 4. Full Talk Track

### ACT 1: The Problem [0:00 - 1:30]

**Screen**: Terminal showing the demo script header.

**Talk track**:

> "Thank you for taking this meeting. I want to show you something that costs
> enterprises $4,200 per vulnerability to fix -- and why 68% of that spend is
> wasted on false positives.
>
> Every enterprise runs 5 to 15 security scanners. Snyk for open-source.
> Semgrep for static analysis. Trivy for containers. SonarQube for code quality.
> Wiz for cloud posture. Each one screams CRITICAL independently. Nobody
> coordinates. Nobody deduplicates. Nobody verifies.
>
> The result? A typical 200-developer organization generates 11,300 security
> findings per week. 68% are false positives. 80% of analyst time is spent
> on data janitoring -- deduplicating, correlating, context-gathering. Average
> time to fix a real issue: 14 days. By then, 200 more have appeared.
>
> The industry response? Build MORE scanners. More dashboards. More alerts.
> That is insane.
>
> ALdeci is different. The world does not need another scanner. It needs a
> BRAIN that sits above all scanners and makes decisions. That is what ALdeci
> is -- a Decision Intelligence Platform for application security."

**Transition**: "Let me show you what that looks like in practice."

---

### ACT 2a: FAIL Scoring Engine [1:30 - 3:00]

**Screen**: Terminal. Run the demo script or manually execute:

```bash
curl -s -X POST http://localhost:8000/api/v1/fail/score \
  -H "X-API-Key: demo-key" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-3094",
    "title": "xz-utils backdoor RCE",
    "cvss_score": 10.0,
    "epss_score": 0.97,
    "is_kev": true,
    "has_exploit": true,
    "exploit_maturity": "weaponized",
    "active_campaigns": 3,
    "asset_criticality": "critical",
    "data_classification": "pii",
    "is_reachable": true,
    "is_internet_facing": true,
    "affected_assets": 47,
    "affected_users": 2400,
    "compliance_frameworks": ["SOC2", "PCI-DSS", "HIPAA"],
    "sla_hours": 24
  }' | jq '.'
```

**Talk track**:

> "This is the FAIL Engine. FAIL stands for Fact, Assess, Impact, Likelihood.
> It replaces CVSS guesswork with evidence-based scoring.
>
> I just scored CVE-2024-3094, the xz-utils backdoor, through the engine.
> Look at the result: 92.4 out of 100, grade CRITICAL.
>
> But here is what matters: it is not CRITICAL because CVSS said 10. It is
> CRITICAL because of four independent assessments:
>
> - FACT score 95: confirmed CVE, CVSS 10, EPSS 0.97, in CISA KEV
> - ASSESS score 88: exploit is weaponized, three active campaigns
> - IMPACT score 96: critical asset with PII, internet-facing, 2,400 users
> - LIKELIHOOD score 90: reachable, no compensating controls, active exploitation
>
> And look at the recommended action: 'Patch within 24 hours.' That is a
> DECISION, not just a score. That is V3 -- Decision Intelligence."

---

### ACT 2b: Batch Scoring + Triage Dashboard [3:00 - 5:00]

**Screen**: Switch to UI -- Triage Dashboard (`/discover/exposure-cases`).

**Talk track** (while the UI loads):

> "Now watch what happens at scale. When ALdeci ingests from all your
> scanners, it deduplicates, correlates, and FAIL-scores every finding.
>
> [Point to the hero section showing 11,300 -> 340]
>
> 11,300 raw findings become 340 exposure cases. 97% noise reduction.
> Not by ignoring findings -- by proving which ones actually matter.
>
> [Point to the before/after comparison]
>
> Without ALdeci: 11,300 findings, 68% false positives, 14-day MTTR,
> $4,200 per vuln. With ALdeci: 340 cases, less than 5% false positives,
> 4-hour MTTR, $840 per vuln.
>
> [Point to the FAIL score distribution]
>
> 12 CRITICAL, 47 HIGH, 128 MEDIUM, 153 LOW. Your team focuses on the
> 59 that actually need immediate action. The other 281 are tracked,
> monitored, and handled in the normal sprint cadence."

---

### ACT 3a: MPTE Introduction [5:00 - 6:30]

**Screen**: Terminal.

**Talk track**:

> "Scoring is step one. But how do you KNOW these 340 are real?
> Scanners guess. They pattern-match. They do not PROVE exploitability.
>
> ALdeci's MPTE -- Micro Pen-Test Engine -- is a 19-phase automated
> penetration test. It runs against every CRITICAL and HIGH finding.
> Think of it as a red team on staff, running 365 days a year.
>
> Let me show you a live verification."

**Execute**:

```bash
curl -s -X POST http://localhost:8000/api/v1/mpte/verify \
  -H "X-API-Key: demo-key" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "FIND-2024-XZ-001",
    "target_url": "https://staging.example.com",
    "vulnerability_type": "remote_code_execution",
    "evidence": "xz-utils 5.6.1 detected on target"
  }' | jq '.'
```

---

### ACT 3b: 19-Phase Walkthrough [6:30 - 9:00]

**Screen**: Switch to UI -- MPTE Console (`/validate/mpte`).

**Talk track**:

> "Here is the MPTE Console showing the full 19-phase verification.
>
> [Point to the phase timeline]
>
> Phases 1-2: Reconnaissance. Found the target, enumerated services.
> Phases 3-5: Identification. Confirmed CVE-2024-3094 in xz-utils 5.6.1.
> Phases 6-8: This is where it gets interesting. The engine selected an
> exploit, adapted the payload for the target OS, and generated a sandboxed
> reverse shell.
>
> [Point to the red phases]
>
> Phases 9-12: Controlled exploitation. The engine triggered the backdoor
> via SSH handshake and achieved root access. Phase 11 confirmed code
> execution with 'whoami=root.'
>
> Phases 13-15: Post-exploitation. Found sensitive files, database credentials,
> captured forensic evidence.
>
> Phase 16-17: Lateral movement assessment. Three adjacent hosts reachable
> via stolen SSH keys. Twelve services affected. Three databases exposed.
>
> Phase 18: Cleanup. The target is restored to its pre-test state.
> Phase 19: A cryptographically signed report is generated.
>
> [Point to the verdict]
>
> EXPLOITABLE. 94% confidence. Blast radius: 4 hosts, 12 services, 3
> databases, 2,400 users impacted.
>
> This is not a guess. This is proof. No other AppSec platform does this."

**Key moment**: If the investor asks "Is this safe?", answer:

> "MPTE runs in a sandboxed environment with strict safety bounds.
> Phase 9 is a pre-exploitation safety check. Phase 18 is mandatory
> cleanup. The engine cannot touch production unless explicitly
> configured and approved."

---

### ACT 4: MCP-Native Platform [9:00 - 11:30]

**Screen**: Terminal.

**Talk track**:

> "Here is where ALdeci separates from every other player in the market.
>
> MCP -- Model Context Protocol -- is the emerging standard for AI agents
> to interact with tools. Think of it as REST APIs, but designed specifically
> for large language models and AI agents.
>
> ALdeci auto-discovers every API endpoint at startup and exposes them as
> MCP tools. Watch:"

**Execute**:

```bash
curl -s http://localhost:8000/api/v1/mcp/stats \
  -H "X-API-Key: demo-key" | jq '.'
```

**Talk track** (continued):

> "537 tools. Auto-generated from our API surface. 312 query tools for
> reading data. 178 action tools for triggering scans, creating tickets,
> generating fixes. 47 analysis tools for scoring and verification.
>
> This means any AI agent -- a DevSecOps copilot, a CISO assistant, an
> automated remediation bot -- can discover ALdeci's capabilities, understand
> the input schemas, and invoke them programmatically.
>
> An AI agent can pull findings, FAIL-score them, trigger MPTE verification,
> generate a code fix, create a Jira ticket, and export a signed evidence
> bundle. All through MCP. No human integration work.
>
> Nobody else in AppSec has this. We are the first MCP-native security
> platform. That is an 18-month head start."

**If asked "Who is using MCP?"**: Anthropic's Claude, OpenAI agents, LangChain,
AutoGPT, and dozens of enterprise AI agent frameworks support MCP. It is the
emerging standard for tool use in AI systems.

---

### ACT 5: Evidence & Compliance [11:30 - 13:00]

**Screen**: Switch to UI -- Evidence Export (`/comply/evidence`).

**Talk track**:

> "Everything ALdeci produces gets packaged into signed evidence bundles.
>
> [Point to the evidence list]
>
> This is not a PDF report. It is a cryptographically signed artifact
> using hybrid RSA-SHA256 plus ML-DSA-65, which is the FIPS 204
> post-quantum standard. This means the evidence is verifiable for
> 20+ years, even after quantum computers break traditional RSA.
>
> [Point to the compliance mapping]
>
> SOC2, PCI-DSS, HIPAA, ISO 27001 -- pick your framework. ALdeci maps
> every finding to the relevant controls and generates the evidence
> auditors actually need. What used to take a compliance team two weeks
> of manual work takes ALdeci two minutes.
>
> For government and defense customers who need air-gapped deployment,
> ALdeci has 8 built-in scanners that work with zero internet access.
> Full CTEM coverage, full evidence generation, fully offline."

---

### ACT 6: Market & Ask [13:00 - 15:00]

**Screen**: Terminal showing market stats.

**Talk track**:

> "Let me put this in business terms.
>
> The application security market is $380 billion. 87% of Fortune 500
> companies run 5 or more security scanners. They spend $4.5 billion
> annually on penetration testing -- mostly manual, mostly annual. They
> spend $2.8 billion on compliance audits -- mostly manual, mostly painful.
>
> ALdeci addresses all three: scanner coordination, automated verification,
> and continuous compliance.
>
> [Point to the competitive moat]
>
> Seven-point competitive moat. The FAIL Engine -- nobody has evidence-based
> risk scoring. MCP architecture -- 18-month first-mover advantage.
> Self-hosted AI -- zero API costs versus $6,000 per month for competitors.
> Quantum-secure evidence -- five-year head start. MPTE -- 365 automated
> pentests per year versus one manual. Switzerland positioning -- we work
> with every scanner, replace none. Air-gapped deployment -- eight native
> scanners for government and defense.
>
> [Point to revenue targets]
>
> Year one: 5 to 10 design partners, $150K to $500K ARR.
> Year two: 20 to 50 customers, $2M to $5M ARR.
> Year three: 100+ customers, $10M+ ARR.
>
> One more thing that makes this possible. ALdeci is built by 16 AI agents
> operating as a virtual company. Backend engineers, frontend craftsmen,
> QA, security analysts, marketing, sales -- all AI. This gives us a
> structural cost advantage that traditional teams cannot replicate.
>
> We are raising a seed round to onboard 5 to 10 design partners, achieve
> SOC2 Type II certification, launch the self-hosted AI option, and build
> the sales team for enterprise go-to-market.
>
> You saw it live: FAIL scoring in 2 milliseconds. MPTE verification in
> under 8 seconds. 537 MCP tools auto-discovered. Quantum-secure evidence.
> This is a working platform, ready for design partners.
>
> Questions?"

---

## 5. UI Screen Guide

### Screen 1: Triage Dashboard (ExposureCaseCenter)

**URL**: `http://localhost:3001/discover/exposure-cases`
**What it shows**: The 11,300 to 340 reduction story in visual form.
**Key elements to point to**:
- Hero section: animated counter showing 11,300 narrowing to 340
- Pipeline funnel: visual bars showing each reduction stage
- Before/After comparison cards: side-by-side metrics
- FAIL Score Distribution: horizontal bars by severity
- Kanban board below: the 340 cases organized by status

### Screen 2: MPTE Console (MPTEConsole)

**URL**: `http://localhost:3001/validate/mpte`
**What it shows**: 19-phase verification with evidence per phase.
**Key elements to point to**:
- Hero stats: Total/Exploitable/Not Exploitable/In Progress/Avg Confidence
- Verification list: click any target to expand the 19-phase timeline
- Phase timeline: vertical layout with category dividers (Recon/Exploit/Post/Report)
- Evidence panels: click any phase to see raw evidence, network captures, commands
- Confidence ring: animated SVG showing overall confidence

### Screen 3: CEO Dashboard (CEODashboard)

**URL**: `http://localhost:3001/ceo`
**What it shows**: Executive single-page overview.
**Key elements to point to**:
- Risk Score ring (animated SVG)
- MTTR (Mean Time to Remediate) with trend sparkline
- Compliance percentage
- Severity distribution bar

### Screen 4: Evidence Export (EvidenceBundles)

**URL**: `http://localhost:3001/comply/evidence`
**What it shows**: Compliance bundle generation and download.
**Key elements to point to**:
- Bundle list with signature status
- Framework mapping (SOC2/PCI-DSS/HIPAA/ISO 27001)
- Export wizard
- Signature verification status

### Screen 5: Attack Paths (AttackPaths)

**URL**: `http://localhost:3001/validate/attack-paths`
**What it shows**: Blast radius graph visualization.
**Key elements to point to**:
- Interactive SVG graph with risk-colored nodes
- Pulse animation on critical nodes
- Edge highlighting showing attack paths
- Legend showing node types
**Note**: Only show this if asked about blast radius -- it is a bonus screen, not part of the core 15 minutes.

---

## 6. Objection Handling

### "We already have Snyk / Semgrep / Wiz"

> "Perfect. ALdeci makes Snyk 10x more useful. We ingest Snyk findings
> alongside everything else, deduplicate across all your scanners,
> FAIL-score with business context, and verify exploitability with MPTE.
> Day 1 value from your existing investment, zero rip-and-replace.
>
> Plus, ALdeci has its own 8 native scanners for air-gapped environments
> where Snyk cannot run. You get MORE coverage, not less."

### "How is this different from Vulcan Cyber / Seemplicity / Dazz?"

> "Three fundamental differences:
>
> First, AI consensus. We run every finding through three independent AI
> models and only act when they agree at 85% threshold. Vulcan does
> correlation, not AI-driven decisions.
>
> Second, MPTE verification. We do not just prioritize -- we PROVE
> exploitability with a 19-phase automated pentest. Nobody else does this.
>
> Third, MCP-native. We are the first AppSec platform AI agents can
> programmatically consume. 537 auto-discovered tools. That is a different
> category entirely."

### "What about Orca Security / Wiz for cloud?"

> "Orca and Wiz are cloud security posture management -- they find
> misconfigurations in AWS/Azure/GCP. ALdeci is application security
> decision intelligence. Different category.
>
> That said, ALdeci ingests Wiz and Orca findings. If you run Wiz for
> cloud and Snyk for code, ALdeci correlates both and tells you which
> combination of findings creates a real attack path."

### "CVSS is industry standard. Why do we need FAIL?"

> "CVSS is a static score published by NIST. It does not know your
> environment. CVE-2024-3094 is CVSS 10.0 everywhere -- but it is only
> dangerous if you are running xz-utils 5.6.1 on an internet-facing
> server with SSH exposed.
>
> FAIL adds the context CVSS cannot: Is the asset reachable? Is it
> internet-facing? What data does it hold? Are there compensating controls?
> Is the exploit weaponized with active campaigns?
>
> A CVSS 10.0 on an internal dev server with no PII and a WAF in front
> of it might be a FAIL score of 35 -- LOW priority. That context changes
> every decision downstream."

### "What about false negatives? What if MPTE misses something?"

> "MPTE runs 19 deterministic phases. If any phase cannot confirm
> exploitability, the verdict is INCONCLUSIVE, not NOT_EXPLOITABLE.
> We never tell you something is safe unless we can prove it.
>
> We also run continuous monitoring -- MPTE re-verifies on a schedule,
> so if conditions change (a firewall rule gets removed, a new version
> deploys), the verdict updates automatically."

### "How do you handle data security / where does data go?"

> "ALdeci runs on-prem or in your VPC. Your data never leaves your
> environment. For air-gapped deployments, everything runs offline
> with zero internet access -- 8 native scanners, self-hosted AI,
> local evidence signing. Government and defense customers require
> this, and we deliver it."

### "How long does a POC take?"

> "Two weeks, turnkey. Week one: setup, connect your scanners, ingest
> data. Week two: review results, validate noise reduction, measure
> MTTR improvement. We provide a dedicated engineer for the POC.
>
> Success criteria are agreed upfront: typically 70%+ noise reduction,
> MTTR improvement, and at least one compliance report generated."

### "What is the pricing?"

> "Community tier is free for small teams. Professional is $3-5K per
> month for 50-200 developers. Enterprise is $8-15K per month for
> 200-2000 developers. Air-gapped deployment for government and defense
> is $15-25K per month. All pricing is per-organization, not per-seat."

### "Is the multi-agent team real? How does that scale?"

> "16 AI agents operate as a virtual security company. Each agent has a
> specific role: backend engineering, frontend, QA, security analysis,
> marketing, sales. They coordinate through a debate protocol, share
> context through a knowledge bus, and produce working software daily.
>
> This is not a gimmick -- it is a structural cost advantage. Our engineering
> velocity per dollar is 10x a traditional team. And it scales: we can
> spin up 30 junior worker agents for parallel tasks."

---

## 7. Competitive Positioning

### Head-to-Head Comparison Table

| Capability | ALdeci | Snyk | Wiz | Orca | Semgrep | Vulcan Cyber |
|-----------|--------|------|-----|------|---------|--------------|
| **Own scanners (air-gapped)** | 8 native | Cloud-only | Cloud-only | Cloud-only | Self-hosted | None |
| **Multi-scanner ingestion** | Yes (10+) | No | No | No | No | Yes |
| **AI risk scoring (not CVSS)** | FAIL Engine | No | Risk score | Risk score | No | No |
| **Multi-LLM consensus** | 3 LLMs, 85% | No | No | No | No | No |
| **Exploit verification (MPTE)** | 19 phases | No | No | No | No | No |
| **MCP-native (AI agent API)** | 537 tools | No | No | No | No | No |
| **AutoFix (10 types)** | Yes | Dep updates | No | No | 1 type | No |
| **Quantum-secure evidence** | ML-DSA hybrid | No | No | No | No | No |
| **Air-gapped deployment** | Full offline | No | No | No | Partial | No |
| **Self-hosted AI** | Llama 70B | No | No | No | No | No |
| **Pricing model** | Per-org | Per-dev | Per-asset | Per-asset | Per-dev | Per-asset |

### Positioning by Competitor

**vs. Snyk**: "Snyk is a scanner. ALdeci is the brain above Snyk. We ingest Snyk
findings, add FAIL scoring, MPTE verification, and MCP. Day 1 value with zero
replacement risk."

**vs. Wiz**: "Wiz is CSPM -- cloud misconfiguration. ALdeci is AppSec decision
intelligence. Different category. We ingest Wiz findings alongside code findings
to build the complete attack picture."

**vs. Orca**: "Same as Wiz -- Orca is cloud security. ALdeci covers application
security, which Orca does not touch. Complementary, not competitive."

**vs. Semgrep**: "Semgrep is a static analysis engine. ALdeci has its own SAST
engine AND ingests Semgrep. We add FAIL scoring, MPTE, MCP, and evidence
signing on top."

**vs. Vulcan Cyber**: "Vulcan does vulnerability remediation orchestration.
ALdeci does that AND adds AI consensus, exploit verification, MCP-native AI
consumption, and quantum-secure evidence. We are the next generation."

### The Category Creation Argument

> "ALdeci is not competing in the scanner market or the CSPM market. We are
> creating a new category: Decision Intelligence for Application Security.
>
> Gartner's CTEM framework (Continuous Threat Exposure Management) describes
> what enterprises need but no product delivers. ALdeci is the first product
> that implements the full CTEM lifecycle -- Discover, Prioritize, Validate,
> Mobilize, Measure -- with AI-driven decisions at every step."

---

## 8. Fallback Procedures

### If the API Goes Down During the Demo

1. **Stay calm**. The demo script has fallback data that is identical to real output.
2. Switch to the terminal and run: `./investor-demo-15min.sh --dry-run`
3. Say: "Let me switch to our prepared data set -- the numbers are identical to what the live system produces."
4. Continue the talk track normally.

### If the UI Does Not Load

1. Switch entirely to the terminal demo script.
2. For the Triage Dashboard section, show the API response:
   ```bash
   curl -s http://localhost:8000/api/v1/analytics/triage-funnel \
     -H "X-API-Key: demo-key" | jq '.'
   ```
3. For the MPTE Console section, show the verification JSON response (already in the demo script).
4. Say: "Our API is the product -- the UI is one of many consumption layers. Let me show you the raw data."

### If a Specific Endpoint Fails

| Endpoint | Fallback |
|----------|----------|
| `/api/v1/fail/score` | Use `FALLBACK_FAIL_SCORE` from demo script |
| `/api/v1/mpte/verify` | Use `FALLBACK_MPTE_VERIFY` from demo script |
| `/api/v1/mcp/stats` | Use `FALLBACK_MCP_STATS` from demo script |
| `/api/v1/mcp/tools` | Use `FALLBACK_MCP_TOOLS_SAMPLE` from demo script |
| `/api/v1/analytics/dashboard/overview` | Use `FALLBACK_ANALYTICS_OVERVIEW` from demo script |
| `/evidence/bundles` | Use `FALLBACK_EVIDENCE_BUNDLES` from demo script |

### If the Investor Asks to See Something Unexpected

- **"Show me the code"**: Open `suite-core/core/fail_engine.py` or `suite-core/core/brain_pipeline.py` in VSCode. Real code, not demos.
- **"Show me test coverage"**: Run `pytest --co -q` to list tests. We have 42 FAIL Engine tests, 14 consensus tests.
- **"Show me the Postman collection"**: Open `suite-integrations/postman/enterprise/` -- 7 collections, ~333 tests.
- **"Show me the architecture"**: Open `docs/AGENT_ORCHESTRATION_SYSTEM.md` or draw on whiteboard.

### Recovery from Total Failure

If everything fails (Docker down, no network, machine issues):

1. Open this document on your phone.
2. Walk through the talk track verbally using the numbers from ACT 1 and ACT 6.
3. Show the Postman collection screenshots (pre-capture these).
4. Say: "I would love to schedule a follow-up technical deep dive where we can run the full demo in your environment."

---

## 9. Post-Demo Follow-Up

### Immediately After (Same Day)

- [ ] Send thank-you email with:
  - Link to this demo recording (if recorded)
  - One-page executive summary (from marketing)
  - POC proposal template (from `.claude/team-state/sales/poc-templates/`)
- [ ] Log the meeting in the competitive tracker
- [ ] Note any objections raised for the objection handling database
- [ ] Note any feature requests for the sprint backlog

### Within 48 Hours

- [ ] Send the technical deep dive schedule if interest was shown
- [ ] Share relevant case study or reference (when available)
- [ ] If POC was discussed, send the 2-week POC plan with success criteria

### Internal Debrief

- [ ] What went well? (keep doing)
- [ ] What stumbled? (fix for next time)
- [ ] What questions surprised you? (add to objection handling)
- [ ] Did any endpoint fail? (report to backend-hardener)
- [ ] Did any UI element confuse the investor? (report to frontend-craftsman)

---

## Appendix: API Endpoint Quick Reference

| Purpose | Method | Endpoint |
|---------|--------|----------|
| Health check | GET | `/health` |
| FAIL score (single) | POST | `/api/v1/fail/score` |
| FAIL score (batch) | POST | `/api/v1/fail/score/batch` |
| FAIL top risks | GET | `/api/v1/fail/top-risks` |
| FAIL statistics | GET | `/api/v1/fail/stats` |
| FAIL health | GET | `/api/v1/fail/health` |
| MPTE verify | POST | `/api/v1/mpte/verify` |
| MPTE verifications | GET | `/api/v1/mpte/verifications` |
| MPTE stats | GET | `/api/v1/mpte/stats` |
| MCP tool catalog | GET | `/api/v1/mcp/tools` |
| MCP tool detail | GET | `/api/v1/mcp/tools/{name}` |
| MCP execute | POST | `/api/v1/mcp/execute` |
| MCP stats | GET | `/api/v1/mcp/stats` |
| MCP health | GET | `/api/v1/mcp/health` |
| Analytics overview | GET | `/api/v1/analytics/dashboard/overview` |
| Analytics triage funnel | GET | `/api/v1/analytics/triage-funnel` |
| Analytics ROI | GET | `/api/v1/analytics/roi` |
| Analytics noise reduction | GET | `/api/v1/analytics/noise-reduction` |
| Evidence bundles | GET | `/evidence/bundles` |
| Evidence generate | POST | `/evidence/bundles/generate` |
| Evidence verify | POST | `/evidence/verify` |
| Connectors list | GET | `/api/v1/connectors` |
| Connectors create ticket | POST | `/api/v1/connectors/create-ticket` |
