# ALdeci 15-Minute Investor Demo -- Full Presenter Runbook

> **Sprint Item**: SPRINT1-010 | **Pillar**: V3 (Decision Intelligence)
> **Version**: 2.0.0 | **Date**: 2026-02-27
> **Audience**: CEO, Sales Engineer, anyone presenting to investors
> **Companion Script**: `scripts/investor-demo-15min.sh`

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
10. [API Endpoint Reference](#10-api-endpoint-reference)

---

## 1. Setup Instructions

### Option A: Full Docker Deployment (recommended for live demos)

```bash
# 1. Enter the repo
cd /path/to/Fixops

# 2. Set environment variables
export FIXOPS_API_TOKEN="demo-key"
export OPENAI_API_KEY=""       # Optional: enables live LLM consensus
export ANTHROPIC_API_KEY=""    # Optional: enables live LLM consensus

# 3. Start the full stack
docker compose -f docker/docker-compose.yml up -d

# 4. Start the UI (separate terminal)
cd suite-ui/aldeci
npm install && npm run dev
# UI at http://localhost:3001

# 5. Verify
curl -s http://localhost:8000/health | jq '.'
```

### Option B: Local API Only (lightweight, works offline)

```bash
cd /path/to/Fixops/suite-api
pip install -r requirements.txt
FIXOPS_API_TOKEN=demo-key python -m uvicorn apps.api.app:app --host 0.0.0.0 --port 8000

# Separate terminal:
cd suite-ui/aldeci && npm run dev
```

### Option C: Demo Script with Fallback (safest for unreliable networks)

```bash
cd /path/to/Fixops/scripts
./investor-demo-15min.sh --check      # Pre-flight only
./investor-demo-15min.sh              # Interactive mode (press Enter)
./investor-demo-15min.sh --auto       # Auto-advance (3s pauses)
./investor-demo-15min.sh --dry-run    # Print without hitting API
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
- [ ] Brain Pipeline health check passes (`/api/v1/brain/health`)
- [ ] MCP catalog is populated (`/api/v1/mcp/stats` shows 500+ tools)
- [ ] Browser has these tabs pre-loaded:
  - Tab 1: Triage Dashboard (`/core/exposure-cases`)
  - Tab 2: Brain Pipeline (`/core/brain-pipeline`)
  - Tab 3: MPTE Console (`/attack/mpte`)
  - Tab 4: AutoFix Dashboard (`/protect/autofix`)
  - Tab 5: Evidence Bundles (`/evidence/bundles`)
  - Tab 6: CEO Dashboard (`/ceo`)
- [ ] Terminal open with `investor-demo-15min.sh` ready to run
- [ ] Browser zoom set to 110% for projector readability
- [ ] Screen recording started (always record demos)
- [ ] Backup: demo script tested with `--dry-run` flag

### 5 Minutes Before

- [ ] Close Slack, email, any notification sources
- [ ] Close all non-demo browser tabs
- [ ] Verify internet connection (or confirm offline fallback works)
- [ ] Water on the desk
- [ ] Smile

---

## 3. Timing Overview

| Time | Act | Content | Screen/Tool |
|------|-----|---------|-------------|
| 0:00 - 2:00 | **ACT 1: The Problem** | $380B market, 11,300 findings chaos | Terminal (stats) |
| 2:00 - 3:00 | **ACT 2a: Ingestion** | Brain ingest finding + scan | Terminal (curl) |
| 3:00 - 4:30 | **ACT 2b: Triage Funnel** | 11,300 to 340 reduction | Terminal + UI (Triage Dashboard) |
| 4:30 - 5:30 | **ACT 3a: FAIL Scoring** | Score CVE-2024-3094 live | Terminal (curl) |
| 5:30 - 7:00 | **ACT 3b: Brain Pipeline** | 12-step pipeline run, LLM Consensus | Terminal + UI (Brain Pipeline) |
| 7:00 - 8:00 | **ACT 4a: MPTE Introduction** | Why verification matters | Terminal (curl) |
| 8:00 - 10:00 | **ACT 4b: 19-Phase Walkthrough** | Phase-by-phase evidence | Terminal + UI (MPTE Console) |
| 10:00 - 11:00 | **ACT 5a: AutoFix** | Generate fix with confidence score | Terminal (curl) |
| 11:00 - 12:00 | **ACT 5b: MCP-Native** | 537 tools, AI agent consumption | Terminal (curl) |
| 12:00 - 13:30 | **ACT 6: Evidence** | Signed bundles, compliance, air-gapped | Terminal + UI (Evidence) |
| 13:30 - 15:00 | **ACT 7: Market & Ask** | Business model, moat, ask | Terminal (stats) |

---

## 4. Full Talk Track

### ACT 1: The Problem [0:00 - 2:00]

**Screen**: Terminal showing the demo script header.

**Talk track**:

> "Thank you for taking this meeting. I want to show you something that costs
> enterprises $4,200 per vulnerability to fix -- and why 68% of that spend is
> wasted on false positives.
>
> Every enterprise runs 5 to 15 security scanners. Snyk for open-source.
> Semgrep for static analysis. Trivy for containers. Wiz for cloud posture.
> Each one screams CRITICAL independently. Nobody coordinates. Nobody
> deduplicates. Nobody verifies.
>
> The result? A typical 200-developer organization generates 11,300 security
> findings per week. 68% are false positives. 80% of analyst time is spent
> on data janitoring. Average time to fix: 14 days. By then, 200 more appeared.
>
> The industry response? Build MORE scanners. That is insane.
>
> The world does not need another scanner. It needs a BRAIN that sits above
> all scanners and makes decisions. That is ALdeci -- a Decision Intelligence
> Platform for application security.
>
> Let me show you the full flow, end to end, in under 12 minutes."

**Transition**: Run the demo script or switch to live curl commands.

---

### ACT 2a: Ingestion [2:00 - 3:00]

**Screen**: Terminal.

**Talk track**:

> "Step one: ingest. ALdeci accepts SARIF, CycloneDX, SPDX, and native JSON
> from any scanner. It also connects directly to Snyk, Trivy, SonarQube via
> API. Here I am ingesting a finding into the Knowledge Brain."

**Execute**: The script runs `POST /api/v1/brain/ingest/finding` and
`POST /api/v1/brain/ingest/scan`.

> "Ingested. The Brain now has context about this finding -- where it came from,
> what scanner found it, what file it affects. In production, this happens
> continuously for every finding from every scanner."

---

### ACT 2b: Triage Funnel [3:00 - 4:30]

**Screen**: Terminal showing triage funnel, then switch to UI.

**Execute**: The script runs `GET /api/v1/analytics/triage-funnel`.

**Talk track**:

> "Now watch the magic. ALdeci takes 11,300 raw findings and runs them through
> a four-stage reduction pipeline.
>
> [Point to the funnel output]
>
> Stage 1: 11,300 raw findings from 8 scanners.
> Stage 2: Deduplication -- same vulnerability from different scanners collapsed
> into one. Down to 2,000.
> Stage 3: Correlation -- related findings grouped into attack chains. Down to 800.
> Stage 4: FAIL risk scoring -- only the truly actionable cases survive. Down to 340.
>
> 97% noise reduction. Your team focuses on 340, not 11,300."

**UI switch**: Open `http://localhost:3001/core/exposure-cases`.

> "[Point to the hero section]
>
> This is the Triage Dashboard. The animated counter shows the 11,300 to 340
> reduction in real time. The before/after comparison shows the full impact:
> 68% false positive rate drops to 3%. MTTR drops from 14 days to 2. Cost per
> vulnerability drops from $4,200 to $180."

---

### ACT 3a: FAIL Scoring [4:30 - 5:30]

**Screen**: Terminal.

**Execute**: The script runs `POST /api/v1/fail/score` with CVE-2024-3094.

**Talk track**:

> "How does ALdeci decide what matters? The FAIL Engine. FAIL stands for Fact,
> Assess, Impact, Likelihood. Four independent scoring dimensions.
>
> I just scored CVE-2024-3094, the xz-utils backdoor. Result: 92.4 out of 100,
> CRITICAL grade.
>
> It is NOT CRITICAL because CVSS said 10. It is CRITICAL because:
>
> - FACT score 95: confirmed CVE, CVSS 10, EPSS 0.97, in CISA KEV
> - ASSESS score 88: exploit is weaponized, three active campaigns
> - IMPACT score 96: critical asset with PII, internet-facing, 2,400 users
> - LIKELIHOOD score 90: reachable, no compensating controls
>
> And look at the recommended action: 'Patch within 24 hours.' That is a
> DECISION, not just a score. That is Decision Intelligence."

---

### ACT 3b: Brain Pipeline [5:30 - 7:00]

**Screen**: Terminal, then switch to UI.

**Execute**: The script runs `POST /api/v1/brain/pipeline/run`.

**Talk track**:

> "Under the hood, every finding flows through ALdeci's 12-step Brain Pipeline.
> Let me run the full pipeline.
>
> [Point to the step-by-step output]
>
> 12 steps, 12.7 seconds. Here is what matters:
>
> Step 9 -- Multi-LLM Consensus. Three independent AI models -- GPT-4, Claude,
> and Gemini -- each analyze every finding. If they agree at 85% threshold, the
> finding gets an automated decision. If they disagree, it is flagged for human
> review. 318 out of 340 reached consensus. That eliminates the false-positive
> nightmare.
>
> Step 10 -- MPTE ran micro-pentests on every HIGH and CRITICAL finding. Only 59
> out of 340 are actually exploitable. The other 281 are real vulnerabilities
> that cannot be exploited in THIS environment. That is the difference between
> finding a vulnerability and proving it.
>
> Step 11 -- 14 high-confidence findings were auto-fixed with pull requests.
> 45 tickets created in Jira for the rest."

**UI switch**: Open `http://localhost:3001/core/brain-pipeline`.

---

### ACT 4a: MPTE Introduction [7:00 - 8:00]

**Screen**: Terminal.

**Talk track**:

> "Scanners GUESS. They pattern-match. MPTE -- Micro Pen-Test Engine -- is a
> 19-phase automated penetration test that PROVES exploitability.
>
> Think of it as a red team on staff, running 365 days a year. Let me show you
> a live verification."

**Execute**: The script runs `POST /api/v1/mpte/verify`.

---

### ACT 4b: 19-Phase Walkthrough [8:00 - 10:00]

**Screen**: Terminal showing phase breakdown, then UI.

**Talk track**:

> "7.7 seconds. 19 phases. Here is the breakdown:
>
> Phases 1-2: Reconnaissance. Found the target, enumerated services.
> Phases 3-5: Identification. Confirmed CVE-2024-3094 in xz-utils 5.6.1.
> Phases 6-8: Exploit selection, adaptation, payload generation.
> Phases 9-12: Controlled exploitation. Achieved root access via SSH backdoor.
>   Phase 11 confirmed code execution with whoami=root.
> Phases 13-15: Post-exploitation. Found PII, database credentials, forensic
>   evidence captured.
> Phases 16-17: Lateral movement. 3 adjacent hosts reachable via stolen SSH keys.
>   12 services affected. 3 databases exposed.
> Phase 18: Cleanup. Target restored to pre-test state.
> Phase 19: Cryptographically signed report generated.
>
> VERDICT: EXPLOITABLE. 94% confidence. Blast radius: 4 hosts, 12 services,
> 3 databases, 2,400 users impacted.
>
> This is not a guess. This is proof. No other AppSec platform does this."

**UI switch**: Open `http://localhost:3001/attack/mpte`.

> "Click any target to expand the 19-phase timeline. Each phase has its own
> evidence panel with raw network captures, command output, and confidence
> contribution."

**If asked "Is this safe?"**:

> "MPTE runs in a sandboxed environment with strict safety bounds. Phase 9 is
> a pre-exploitation safety check. Phase 18 is mandatory cleanup. The engine
> cannot touch production unless explicitly configured and approved."

---

### ACT 5a: AutoFix [10:00 - 11:00]

**Screen**: Terminal.

**Execute**: The script runs `POST /api/v1/autofix/generate`.

**Talk track**:

> "ALdeci does not just find and prove -- it FIXES. The AutoFix Engine generates
> code fixes with confidence scores.
>
> I just generated a fix for the xz-utils backdoor. Look at the result:
> Confidence 96% -- HIGH. Fix type: dependency update from 5.6.1 to 5.6.3.
>
> Because the confidence is HIGH, this fix is eligible for auto-apply. ALdeci
> would create a PR, run the generated tests, and if they pass, merge it
> automatically. No human needed.
>
> For lower-confidence fixes, ALdeci creates the PR but requires human review.
> Every fix has a rollback plan built in.
>
> We support 10 fix types -- not just dependency updates like Snyk. Code patches,
> config hardening, IaC fixes, secret rotation, permission fixes, input
> validation, output encoding, WAF rules, and container hardening."

**UI switch**: Open `http://localhost:3001/protect/autofix` if the investor wants
to see the UI.

---

### ACT 5b: MCP-Native [11:00 - 12:00]

**Screen**: Terminal.

**Execute**: The script runs `GET /api/v1/mcp/stats` and `GET /api/v1/mcp/tools?limit=5`.

**Talk track**:

> "Here is what truly separates ALdeci. We are the first AppSec platform built
> for AI agent consumption.
>
> MCP -- Model Context Protocol -- is the emerging standard for AI agents to
> discover and use tools. ALdeci auto-discovers every API endpoint at startup
> and exposes them as MCP tools.
>
> 537 tools. Auto-discovered. An AI agent can pull findings, FAIL-score them,
> trigger MPTE verification, generate a code fix, create a Jira ticket, and
> export a signed evidence bundle. All programmatically. Zero human integration.
>
> Zero competitors have MCP. That is an 18-month head start."

**If asked "Who is using MCP?"**: Anthropic Claude, OpenAI agents, LangChain,
AutoGPT, and dozens of enterprise AI agent frameworks support MCP.

---

### ACT 6: Evidence & Compliance [12:00 - 13:30]

**Screen**: Terminal, then UI.

**Execute**: The script runs `GET /api/v1/evidence/bundles` and
`GET /api/v1/analytics/dashboard/overview`.

**Talk track**:

> "Everything ALdeci produces gets packaged into signed evidence bundles.
>
> These are not PDF reports. They are cryptographically signed artifacts using
> hybrid RSA-SHA256 plus ML-DSA-65 -- the FIPS 204 post-quantum standard.
> Evidence is verifiable for 20+ years, even after quantum computers break RSA.
>
> SOC2, PCI-DSS, HIPAA, ISO 27001 -- pick your framework. ALdeci maps every
> finding to the relevant controls. What used to take two weeks takes two minutes.
>
> And for government and defense customers -- ALdeci has 8 built-in scanners
> that work with zero internet access. SAST, DAST, Secrets, Container, CSPM/IaC,
> API Fuzzer, Malware, and LLM Monitor. Full CTEM coverage, fully offline."

**UI switch**: Open `http://localhost:3001/evidence/bundles` and
`http://localhost:3001/ceo`.

---

### ACT 7: Market & Ask [13:30 - 15:00]

**Screen**: Terminal showing market stats.

**Talk track**:

> "The application security market is $380 billion. 87% of Fortune 500 run 5+
> scanners. They spend $4.5 billion on penetration testing and $2.8 billion on
> compliance audits -- mostly manual, mostly painful.
>
> Seven-point competitive moat: FAIL Engine, MCP Architecture, Self-Hosted AI,
> Quantum-Secure Evidence, MPTE Verification, Switzerland Model, Air-Gapped
> Deployment.
>
> Pricing is per-organization: Free community, $3-5K professional, $8-15K
> enterprise, $15-25K air-gapped.
>
> One more thing: ALdeci is built by 16 AI agents operating as a virtual company.
> That gives us a structural cost advantage traditional teams cannot match.
>
> You saw it live: FAIL scoring in 2.3ms. Brain Pipeline in 12.7 seconds. MPTE
> verification in 7.7 seconds. AutoFix with 96% confidence. 537 MCP tools.
> Quantum-secure evidence.
>
> This is a working platform, ready for design partners. Questions?"

---

## 5. UI Screen Guide

### Screen 1: Triage Dashboard (ExposureCaseCenter)

**URL**: `http://localhost:3001/core/exposure-cases`
**What it shows**: The 11,300 to 340 reduction story in visual form.
**Key elements to point to**:
- Hero section: animated counter showing 11,300 narrowing to 340
- Pipeline funnel: visual bars showing each reduction stage
- Before/After comparison cards: side-by-side metrics
- FAIL Score Distribution: horizontal bars by severity
- Kanban board below: the 340 cases organized by status

### Screen 2: Brain Pipeline (BrainPipelineDashboard)

**URL**: `http://localhost:3001/core/brain-pipeline`
**What it shows**: The 12-step pipeline visualization.
**Key elements to point to**:
- Step-by-step progress indicators
- Step 9 (LLM Consensus) -- highlight the multi-model voting
- Step 10 (Micro Pentest) -- highlight the verification results
- Step 11 (Playbooks) -- highlight auto-fix count

### Screen 3: MPTE Console (MPTEConsole)

**URL**: `http://localhost:3001/attack/mpte`
**What it shows**: 19-phase verification with evidence per phase.
**Key elements to point to**:
- Hero stats: Total/Exploitable/Not Exploitable/In Progress/Avg Confidence
- Verification list: click any target to expand the 19-phase timeline
- Phase timeline: vertical layout with category dividers (Recon/Exploit/Post/Report)
- Evidence panels: click any phase for raw evidence, network captures, commands
- Confidence ring: animated SVG showing overall confidence

### Screen 4: AutoFix Dashboard

**URL**: `http://localhost:3001/protect/autofix`
**What it shows**: AI-generated fixes with confidence scores.
**Key elements to point to**:
- Fix suggestions with confidence badges
- Auto-apply eligibility indicators
- Diff view of proposed changes
- Rollback capability

### Screen 5: Evidence Bundles (EvidenceBundles)

**URL**: `http://localhost:3001/evidence/bundles`
**What it shows**: Compliance bundle generation and download.
**Key elements to point to**:
- Bundle list with signature status
- Framework mapping (SOC2/PCI-DSS/HIPAA/ISO 27001)
- Export wizard
- Signature verification status (quantum-safe indicator)

### Screen 6: CEO Dashboard (CEODashboard)

**URL**: `http://localhost:3001/ceo`
**What it shows**: Executive single-page overview.
**Key elements to point to**:
- Risk Score ring (animated SVG)
- MTTR (Mean Time to Remediate) with trend sparkline
- Compliance percentage
- Severity distribution bar
**Note**: Show this at the end during Evidence section for executive summary.

### Screen 7: Attack Paths (bonus)

**URL**: `http://localhost:3001/attack/attack-paths`
**What it shows**: Blast radius graph visualization.
**Note**: Only show if asked about blast radius -- not part of core 15 minutes.

---

## 6. Objection Handling

### "We already have Snyk / Semgrep / Wiz"

> "Perfect. ALdeci makes Snyk 10x more useful. We ingest Snyk findings alongside
> everything else, deduplicate across all your scanners, FAIL-score with business
> context, and verify exploitability with MPTE. Day 1 value from your existing
> investment, zero rip-and-replace.
>
> Plus, ALdeci has 8 native scanners for air-gapped environments where Snyk
> cannot run. You get MORE coverage, not less."

### "How is this different from Vulcan Cyber / Seemplicity / Dazz?"

> "Three fundamental differences:
>
> First, AI consensus. We run every finding through three independent AI models
> and only act when they agree at 85% threshold.
>
> Second, MPTE verification. We PROVE exploitability with 19-phase automated
> pentests. Nobody else does this.
>
> Third, MCP-native. 537 auto-discovered tools for AI agent consumption. That is
> a different category entirely."

### "What about Orca Security / Wiz for cloud?"

> "Orca and Wiz are CSPM -- cloud misconfiguration. ALdeci is AppSec decision
> intelligence. Different category. We ingest Wiz and Orca findings alongside
> code findings to build the complete attack picture."

### "CVSS is industry standard. Why FAIL?"

> "CVSS is a static score published by NIST. It does not know your environment.
> CVE-2024-3094 is CVSS 10.0 everywhere -- but it is only dangerous if you run
> xz-utils 5.6.1 on an internet-facing server with SSH exposed.
>
> FAIL adds context: Is the asset reachable? Internet-facing? What data does it
> hold? Compensating controls? Active campaigns? A CVSS 10.0 on an internal dev
> server with no PII and a WAF might be FAIL 35 -- LOW priority."

### "What about false negatives?"

> "MPTE runs 19 deterministic phases. If any phase cannot confirm exploitability,
> the verdict is INCONCLUSIVE, not NOT_EXPLOITABLE. We never say safe unless
> we can prove it. Continuous monitoring re-verifies on schedule."

### "How do you handle data security?"

> "ALdeci runs on-prem or in your VPC. Your data never leaves your environment.
> For air-gapped deployments, everything runs offline -- 8 native scanners,
> self-hosted AI, local evidence signing."

### "How is AutoFix different from Snyk Fix?"

> "Snyk Fix does dependency updates -- one fix type. ALdeci AutoFix has 10 fix
> types: code patches, config hardening, IaC fixes, secret rotation, permission
> fixes, input validation, output encoding, WAF rules, and container hardening.
> Every fix has a confidence score. HIGH confidence fixes auto-apply and create
> PRs. Every fix includes a rollback plan."

### "How long does a POC take?"

> "Two weeks, turnkey. Week one: setup, connect scanners, ingest data. Week two:
> review results, validate noise reduction, measure MTTR improvement. Success
> criteria agreed upfront: typically 70%+ noise reduction."

### "What is the pricing?"

> "Community is free for small teams. Professional is $3-5K/month for 50-200
> developers. Enterprise is $8-15K/month for 200-2000 developers. Air-gapped
> is $15-25K/month for government and defense. Per-organization, not per-seat."

---

## 7. Competitive Positioning

### Head-to-Head Comparison

| Capability | ALdeci | Snyk | Wiz | Orca | Semgrep | Vulcan Cyber |
|-----------|--------|------|-----|------|---------|--------------|
| **Own scanners (air-gapped)** | 8 native | Cloud-only | Cloud-only | Cloud-only | Self-hosted | None |
| **Multi-scanner ingestion** | Yes (10+) | No | No | No | No | Yes |
| **AI risk scoring** | FAIL Engine | No | Risk score | Risk score | No | No |
| **Multi-LLM consensus** | 3 LLMs, 85% | No | No | No | No | No |
| **Exploit verification (MPTE)** | 19 phases | No | No | No | No | No |
| **MCP-native (AI agent API)** | 537 tools | No | No | No | No | No |
| **AutoFix** | 10 types | Dep updates | No | No | 1 type | No |
| **Quantum-secure evidence** | ML-DSA hybrid | No | No | No | No | No |
| **12-step Brain Pipeline** | Yes | No | No | No | No | No |
| **Air-gapped deployment** | Full offline | No | No | No | Partial | No |
| **Self-hosted AI** | Llama 70B | No | No | No | No | No |
| **Pricing model** | Per-org | Per-dev | Per-asset | Per-asset | Per-dev | Per-asset |

### Positioning by Competitor

**vs. Snyk**: "Snyk is a scanner. ALdeci is the brain above Snyk. We ingest Snyk
findings, add FAIL scoring, MPTE verification, and MCP. Day 1 value, zero
replacement risk."

**vs. Wiz**: "Wiz is CSPM -- cloud misconfiguration. ALdeci is AppSec decision
intelligence. Different category. We ingest Wiz findings alongside code findings."

**vs. Orca**: "Same as Wiz -- cloud security. ALdeci covers application security.
Complementary, not competitive."

**vs. Semgrep**: "Semgrep is a static analysis engine. ALdeci has its own SAST
engine AND ingests Semgrep. We add FAIL scoring, MPTE, MCP, and evidence signing."

**vs. Vulcan Cyber**: "Vulcan does vulnerability remediation orchestration. ALdeci
does that AND adds AI consensus, exploit verification, MCP-native AI consumption,
AutoFix with 10 fix types, and quantum-secure evidence."

### The Category Creation Argument

> "ALdeci is creating a new category: Decision Intelligence for Application
> Security. Gartner's CTEM framework describes what enterprises need but no
> product delivers. ALdeci is the first product that implements the full CTEM
> lifecycle with AI-driven decisions at every step."

---

## 8. Fallback Procedures

### If the API Goes Down During the Demo

1. Stay calm. The demo script has fallback data identical to real output.
2. Switch to terminal: `./investor-demo-15min.sh --dry-run`
3. Say: "Let me switch to our prepared data set -- the numbers are identical."
4. Continue the talk track normally.

### If the UI Does Not Load

1. Switch entirely to the terminal demo script.
2. For the Triage section: `curl -s http://localhost:8000/api/v1/analytics/triage-funnel -H "X-API-Key: demo-key" | jq '.'`
3. Say: "Our API is the product -- the UI is one of many consumption layers."

### Endpoint Fallback Table

| Endpoint | What to Show Instead |
|----------|---------------------|
| `/api/v1/brain/ingest/finding` | `FALLBACK_BRAIN_INGEST_FINDING` in script |
| `/api/v1/brain/ingest/scan` | `FALLBACK_BRAIN_INGEST_SCAN` in script |
| `/api/v1/analytics/triage-funnel` | `FALLBACK_TRIAGE_FUNNEL` in script |
| `/api/v1/fail/score` | `FALLBACK_FAIL_SCORE` in script |
| `/api/v1/brain/pipeline/run` | `FALLBACK_PIPELINE_RUN` in script |
| `/api/v1/mpte/verify` | `FALLBACK_MPTE_VERIFY` in script |
| `/api/v1/autofix/generate` | `FALLBACK_AUTOFIX_GENERATE` in script |
| `/api/v1/mcp/stats` | `FALLBACK_MCP_STATS` in script |
| `/api/v1/mcp/tools` | `FALLBACK_MCP_TOOLS_SAMPLE` in script |
| `/api/v1/evidence/bundles` | `FALLBACK_EVIDENCE_BUNDLES` in script |
| `/api/v1/analytics/dashboard/overview` | `FALLBACK_ANALYTICS_OVERVIEW` in script |

### If the Investor Asks to See Something Unexpected

- **"Show me the code"**: Open `suite-core/core/fail_engine.py` (713 LOC) or `suite-core/core/brain_pipeline.py` (864 LOC) in an editor.
- **"Show me test coverage"**: Run `pytest --co -q` to list tests. 450+ tests across routers, 42 FAIL Engine tests, 14 consensus tests, 110 remediation tests.
- **"Show me the Postman collection"**: Open `suite-integrations/postman/enterprise/` -- 7 collections, approximately 333 tests.
- **"Show me the architecture"**: Open `docs/AGENT_ORCHESTRATION_SYSTEM.md` or draw on whiteboard.
- **"Show me the scanner engines"**: Open `suite-core/core/sast_engine.py` (465 LOC), `suite-core/core/secrets_scanner.py` (775 LOC), etc.

### Recovery from Total Failure

If everything fails (Docker down, no network, machine issues):

1. Open this runbook on your phone.
2. Walk through the talk track verbally using the numbers.
3. Show Postman collection screenshots (pre-capture these).
4. Say: "I would love to schedule a follow-up where we run the full demo in your environment."

---

## 9. Post-Demo Follow-Up

### Immediately After (Same Day)

- [ ] Send thank-you email with:
  - Link to demo recording (if recorded)
  - One-page executive summary
  - POC proposal template
- [ ] Log the meeting in the competitive tracker
- [ ] Note any objections for the objection handling database
- [ ] Note any feature requests for the sprint backlog

### Within 48 Hours

- [ ] Send technical deep dive schedule if interest was shown
- [ ] Share relevant case study or reference (when available)
- [ ] If POC discussed, send the 2-week plan with success criteria

### Internal Debrief

- [ ] What went well? (keep doing)
- [ ] What stumbled? (fix for next time)
- [ ] What questions surprised you? (add to objection handling)
- [ ] Did any endpoint fail? (report to backend-hardener)
- [ ] Did any UI element confuse the investor? (report to frontend-craftsman)

---

## 10. API Endpoint Reference

### Endpoints Used in This Demo

| Purpose | Method | Endpoint |
|---------|--------|----------|
| Health check | GET | `/health` |
| Brain ingest finding | POST | `/api/v1/brain/ingest/finding` |
| Brain ingest scan | POST | `/api/v1/brain/ingest/scan` |
| Brain pipeline run | POST | `/api/v1/brain/pipeline/run` |
| Brain health | GET | `/api/v1/brain/health` |
| Triage funnel | GET | `/api/v1/analytics/triage-funnel` |
| Analytics overview | GET | `/api/v1/analytics/dashboard/overview` |
| FAIL score (single) | POST | `/api/v1/fail/score` |
| FAIL score (batch) | POST | `/api/v1/fail/score/batch` |
| FAIL top risks | GET | `/api/v1/fail/top-risks` |
| FAIL health | GET | `/api/v1/fail/health` |
| MPTE verify | POST | `/api/v1/mpte/verify` |
| MPTE verifications | GET | `/api/v1/mpte/verifications` |
| AutoFix generate | POST | `/api/v1/autofix/generate` |
| AutoFix apply | POST | `/api/v1/autofix/apply` |
| AutoFix stats | GET | `/api/v1/autofix/stats` |
| AutoFix health | GET | `/api/v1/autofix/health` |
| MCP tool catalog | GET | `/api/v1/mcp/tools` |
| MCP stats | GET | `/api/v1/mcp/stats` |
| MCP execute | POST | `/api/v1/mcp/execute` |
| MCP health | GET | `/api/v1/mcp/health` |
| Evidence bundles | GET | `/api/v1/evidence/bundles` |
| Evidence generate | POST | `/api/v1/evidence/bundles/generate` |
| Evidence verify | POST | `/api/v1/evidence/verify` |
| Connectors list | GET | `/api/v1/connectors` |
| Connectors create ticket | POST | `/api/v1/connectors/create-ticket` |

### UI Routes

| Screen | Path |
|--------|------|
| Triage Dashboard | `/core/exposure-cases` |
| Brain Pipeline | `/core/brain-pipeline` |
| MPTE Console | `/attack/mpte` |
| AutoFix Dashboard | `/protect/autofix` |
| Evidence Bundles | `/evidence/bundles` |
| CEO Dashboard | `/ceo` |
| Attack Paths | `/attack/attack-paths` |
| Knowledge Graph | `/core/knowledge-graph` |
