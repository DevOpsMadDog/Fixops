# ALdeci POC Playbook — Day 0 Prospect Guide

**Version**: 1.0  
**Valid**: 2026-05-06+  
**Target**: Enterprise security teams ($50M–$500M+ revenue)  
**Goal**: Convert POC completers → licenses in 7 days, $0 cost, no commitment

---

## Executive Summary

ALdeci replaces **$50K–$500K/year** of fragmented security tools with a unified, self-hosted, AI-native platform. You get:
- **One dashboard** for all findings (apps, cloud, containers, data)
- **AI consensus** — 3 independent models vote on severity (no false alarms)
- **Instant compliance** — SOC2, ISO27001, PCI-DSS, HIPAA mapped out-of-the-box
- **Remediation** — AI-generated fixes with confidence scores, auto-apply on HIGH
- **Your data stays yours** — self-hosted, zero internet required

**This POC proves it in 7 days.**

---

## Pre-POC Qualification (5 Minutes)

**Ask these FIRST** — if answers don't align, reschedule:

| Question | Red Flag | Green Light |
|----------|----------|-------------|
| **Repos/clouds?** | "We don't know" | 3–100+ repos OR 2–5 cloud accounts |
| **Existing tools?** | "None, we're greenfield" | Snyk, Tenable, Qualys, Wiz, Prisma, AWS native |
| **Compliance?** | "Not yet" | SOC2, ISO27001, PCI-DSS, HIPAA, FedRAMP |
| **Team size?** | <5 engineers | 10–1000+ across orgs |
| **Decision timeline?** | "Someday" | "By end of Q2" or "Proof before renewal" |

**If all green**: Send this playbook + calendar invite for Day 1.

---

## 7-Day POC Plan

### Day 1: Install + Executive Dashboard (1 hour)

**Before meeting** (customer does, we support):

1. **Environment check** (5 min)
   ```bash
   # ALDECI requires:
   - Docker 24+ & Docker Compose 2+
   - 8+ GB RAM, 20+ GB disk
   - Linux/macOS (Windows via WSL2)
   - Network: outbound HTTPS (or air-gapped if available)
   ```

2. **Clone + compose** (10 min)
   ```bash
   git clone https://github.com/aldeci/platform.git
   cd platform
   docker-compose -f docker/docker-compose.yml up -d
   # Wait for: API 8000, UI 3000, Postgres 5432
   ```

3. **Onboarding wizard** (3 min at http://localhost:3000/onboard)
   - Org name
   - Admin email
   - Default compliance framework (pick 1: SOC2 / ISO27001 / PCI-DSS / HIPAA)
   - Timezone

4. **First import** (15 min)
   - Visit `/import`
   - Upload sample SARIF/JSON/XML report OR
   - Connect GitHub repo (OAuth), ALdeci scans it live
   - Observe findings in real-time: `/executive` → `/vuln-intel`

5. **Smoke test checklist**
   - [ ] Dashboard loads (http://localhost:3000)
   - [ ] At least 1 finding visible
   - [ ] Sidebar shows 21 main nav items (all live)
   - [ ] Admin panel reachable (`/admin/system`)

**Hand off to customer**: `/docs/INSTALL.md` + Discord/Slack invite + **we do Day 2 kickoff call**

**Talking points**: "Your data never leaves your VPC. One server. We'll help."

---

### Day 2–3: Multi-Source Ingestion (Real Data)

**Goal**: Connect THEIR tools, see THEIR findings, eliminate alerts fatigue

**Connectors available** (pick 3—customer chooses):

| Source | Setup time | Value |
|--------|-----------|-------|
| **GitHub** | 2 min (OAuth) | Find secrets, vulnerable patterns |
| **GitLab** | 2 min (token) | Same as GitHub |
| **Snyk** | 5 min (API key) | Import existing findings + our re-scoring |
| **AWS** | 10 min (IAM role or keys) | Cloud posture + compliance gaps |
| **Azure** | 10 min (SP + app reg) | Cloud findings + cost anomalies |
| **Jira** | 5 min (API token) | Link findings to tickets |
| **Qualys** | 5 min (API key) | VMDR findings + our AI triage |
| **Tenable** | 5 min (API key) | Nessus findings normalized + re-scored |

**Setup call agenda**:
1. **Customer picks 3 connectors** (prefer: GitHub + 1 cloud + 1 scanner)
2. **We walk through each setup** (share screen, 15 min total)
3. **First sync kicks off** → findings land in 2–5 min
4. **Live demo**: Show findings flowing through AI consensus → /board updates live

**Post-sync checkpoint**:
- [ ] 20+ findings visible
- [ ] Multi-source (≥3 scanners) represented
- [ ] Each finding shows: Severity, Source, Fix hint
- [ ] No "404 Not Found" on detail pages

**Objection handling** (if raised today):
- *"Snyk already works for us"* → "Exactly. We ingest Snyk AND 27 other sources. One pane. Better scoring."
- *"We're worried about data exfil"* → "Self-hosted. Your data never touches our cloud. Want air-gapped? We have offline mode."

---

### Day 4–5: Compliance Report + Remediation

**Goal**: Show compliance mapping + AI-generated fixes

**Compliance walkthrough** (30 min call):

1. **Customer's framework** (what they selected on Day 1 loads automatically)
   - SOC2, ISO27001, PCI-DSS, or HIPAA
   - ALdeci maps ALL findings → compliance controls
   - `/compliance` shows: Which controls pass ✓ / at-risk ⚠ / failing ✗

2. **Gap analysis** (3 min)
   - "You have 87 findings across 12 controls. Critical: 5. High: 23."
   - Sort by business impact (AI consensus score, not just CVSS)
   - Show which controls are at-risk (e.g., "Auth is failing 3/8 checks")

3. **Remediation playbook** (10 min)
   - Pick a HIGH or CRITICAL finding
   - Click `→ View Fix`
   - ALdeci shows:
     - **What**: Vulnerability type + context
     - **Why**: Business risk + compliance mapping
     - **How**: AI-generated code patch + confidence %
   - If confidence ≥ 80%: "Auto-Apply" creates PR automatically

4. **Evidence bundle** (5 min)
   - `/evidence` shows signed compliance snapshot
   - Download PDF: "SOC2 Readiness Report — for your audit"
   - Timestamp + hash (quantum-safe HMAC-SHA256)

**Talking points**:
- "Not every finding is equal. We re-score using business impact + exploitability."
- "AI doesn't replace humans—it shows reasoning. You decide."
- "High-confidence fixes auto-create PRs. Low-confidence? You review first."

---

### Day 6: Multi-Persona Walkthrough

**Goal**: Show it works for CISO + SOC analyst + DevSecOps engineer

**Split-screen demo** (45 min, each persona gets 10 min):

**CISO view** (`/board` + `/executive`):
- Risk heat map (30-day trend)
- Top 10 exposures by business impact
- Compliance status (controls passing %) 
- "CFO, this is your board summary. 3 findings block SOC2 renewal. Estimated fix cost: $X."

**SOC Analyst view** (`/threat-intelligence` + `/incident-response`):
- Threat feeds (28+ sources) with correlation graph
- Incident timeline (when did this finding appear, who touched it)
- Alert triage workflow (bulk actions: Remediate / Defer / Accept-risk)

**DevSecOps Engineer view** (`/custom-workflows` + `/vuln-intel`):
- Dev-friendly detail page (code snippet, fix diff)
- Jira integration (auto-create tickets)
- Slack notifications (high severity + auto-fixes)
- "Push this fix to branch X?" → Click → PR created

**Checkpoint**:
- [ ] All 3 personas see same finding, different data cuts
- [ ] No MOCK_ strings, no lorem ipsum
- [ ] At least one persona's workflow shows real API call to backend

---

### Day 7: Exec Readout + Commercial Conversation

**What you're presenting**:

1. **Security posture snapshot**
   - Baseline findings count (before POC)
   - After 7 days: Coverage + noise reduction %
   - Compliance readiness (pre/post)
   - Example: "Was 2000 alerts. Now 120 actionable findings. SOC2 ready in 10 days."

2. **ROI calculation** (use their data)
   ```
   Current state:
   - 3 engineers @ $250K/yr = $750K
   - Snyk @ $100K/yr + Tenable @ $120K/yr + Wiz @ $150K/yr = $370K/yr
   - Manual triage = 2 hours/day × 250 days = 500 hrs/yr @ $125/hr = $62.5K
   Total: $1.18M/yr
   
   ALdeci state:
   - ALdeci Pro @ $50K/yr (or Enterprise @ $150K/yr)
   - 1 engineer for ops/triage = $250K/yr
   Total: $300K/yr (or $400K/yr)
   
   Savings: $880K/yr (or $780K/yr) + 600 hrs security work freed up
   ```

3. **Next steps** (commercial)
   - Choose: Starter ($199/mo) / Pro ($499/mo) / Enterprise ($1.5K/mo)
   - Deployment: Self-hosted (your VPC) or SCIF-ready (FedRAMP)
   - Contract: 1–3 year, auto-renew, 30-day exit
   - Support: Slack/Discord + weekly check-in (Pro+)

**Close strategy**:
- "You've proven it works. Next: let's talk commercial terms."
- "If we can hit $X/year, are you ready to sign?" (closes on commitment, not price)

---

## Day-1 Install Runbook (Customer Hands-On)

### Prerequisites Check
```bash
# Run this first
docker --version     # Need 24+
docker-compose --version  # Need 2+
free -h | head -3    # Need 8+ GB
df -h | grep -E '/$|/var'  # Need 20+ GB
```

**If any fails**: We help troubleshoot (email or Slack).

### One-Command Setup
```bash
# Clone repo (or use your fork if air-gapped)
git clone https://github.com/aldeci/platform.git
cd platform

# Start services
docker-compose -f docker/docker-compose.yml up -d

# Wait 30 sec, then check
curl http://localhost:3000         # UI (React)
curl http://localhost:8000/health  # API (FastAPI)

# View logs
docker-compose logs -f api
```

### Onboarding Walkthrough
1. Open http://localhost:3000
2. Fill: Org name, email, compliance framework, timezone
3. Save → gets API token + stored in `~/.aldeci/config.json`

### First Import
- **Option A (Easy)**: Upload a SARIF/JSON file from existing scan
- **Option B (Live)**: Connect GitHub → ALdeci scans a real repo
- **Option C (Demo)**: Load sample data (10 findings pre-loaded)

Choose one. Findings appear in `/vuln-intel` in 30 sec.

### Smoke Test Checklist
```
[ ] Localhost:3000 loads (no blank page)
[ ] Sidebar has 21 items (all clickable)
[ ] Executive dashboard shows ≥1 finding
[ ] Click a finding → detail page loads with code context
[ ] Admin > System Health shows green checks
[ ] No red errors in browser console (F12)
```

**If any fail**: Email screenshot + logs to support@aldeci.com. We'll debug.

---

## Email Templates

### Template 1: Initial Outreach
**Subject**: "Replace your $500K security stack with ALdeci [POC offer]"

```
Hi [Name],

Your team is drowning in alerts. 2000+ findings, but which 10 matter?

ALdeci turns noise into decisions—in 7 days, $0 cost, no commitment.

Here's what you'll get:
✓ One dashboard for all your findings (apps, cloud, containers)
✓ AI consensus—3 models vote on severity, no false alarms
✓ Instant compliance—SOC2, ISO, PCI-DSS mapped today
✓ Remediation—AI fixes with confidence scores, auto-apply on HIGH

Your data stays in your VPC. Self-hosted. Air-gapped if you need it.

Free POC starts Monday. Takes 1 hour to install, 1 week to prove ROI.

Ready?
[Calendar link for Day 1 kickoff]

—[Your name]
ALdeci Sales Engineer
```

### Template 2: Day-3 Nurture
**Subject**: "How's Day 2 looking? 3 things to try"

```
Hi [Name],

Hope your team is seeing the multi-source magic by now—findings from Snyk + AWS + GitHub all in one view.

Three things to unlock Day 4:

1. **Sort by Business Impact** (not CVSS)
   Go to /board, toggle "Consensus Score" — you'll see AI re-ranked your findings.
   The vuln that looks Critical in Tenable might be Medium in context.

2. **Try an Auto-Fix**
   Pick a HIGH+ finding → View Fix → if confidence > 80%, click Auto-Apply.
   Watch it create a PR on your repo. No human code review needed (you can set it).

3. **Map Compliance**
   Go to /compliance, pick your framework (SOC2 / ISO / PCI).
   You'll see which controls are passing vs at-risk. Screenshot for your auditor.

Questions? Jump in our Slack channel or reply here.

—[Your name]
```

### Template 3: Day-7 Exec Readout
**Subject**: "ALdeci POC Results — Your 7-Day Summary"

```
Hi [Name],

Your POC is complete. Results in attached deck + spreadsheet.

Key wins:
• 87 findings across 3 sources (Snyk + AWS + GitHub), now prioritized to 12 actionable
• Compliance gaps mapped (3 SOC2 controls at-risk, estimated 10-day remediation)
• Auto-generated fixes: 8 HIGH+, 4 ready to auto-apply, 4 need review
• Est. ROI: $880K/yr vs current tool stack + manual triage

Next: Let's talk commercial terms. Meeting Thursday?

[Calendar link for readout call]

—[Your name]
```

---

## Common Objections + Responses

### "We already use Snyk. Why add another tool?"

**Answer**:
"Snyk is great for *code* dependencies. ALdeci ingests Snyk findings AND adds 27 other sources—cloud posture, container scanning, data loss prevention, threat intelligence. One pane. AI re-scores everything for business impact, not just CVSS.

You get 10x more context, not 10 more tools."

**Proof**: During Day 2–3 setup, show Snyk + AWS + GitHub in same dashboard, mapped to same compliance controls.

---

### "Self-hosted is more operational burden."

**Answer**:
"One Docker Compose file. One server. 8GB RAM, 20GB disk. That's it.

We do the first deploy with you (1 hour). Upgrades are automated—one command every quarter. If something breaks, you get Slack support + 24-hr response (Pro+).

Compare to cloud: You still need to integrate, configure, tune policies. Here, it's pre-tuned for your use case."

**Proof**: Show clean `/admin/system-health` page with no alerts. Uptime chart.

---

### "Multi-LLM consensus sounds expensive."

**Answer**:
"It's not. By default, ALdeci uses 3 free models (Mistral, Llama, DeepSeek). Opus is escalation-only for edge cases—maybe 2% of findings.

Average cost: $0.003 per finding. At 1000 findings/month = $3. Snyk alone is $100+/month."

**Proof**: Show `Settings > LLM Config` — toggle "Consensus Mode" to see free vs Opus trade-off.

---

### "We can't trust AI for security decisions."

**Answer**:
"You don't have to. Every finding shows full reasoning:
- Why this matters (threat context)
- Consensus vote (2/3 models agree → action-ready)
- Confidence score (80%+ = safe to auto-fix; <60% = needs human review)

You set the policy: Auto-fix HIGH 80%+? Approve MEDIUM manually? Defer LOW?"

**Proof**: Pick a finding, click `→ Details`. Show reasoning, vote breakdown, confidence.

---

### "How is my data handled?"

**Answer**:
"Your data never leaves your network. Everything runs on your server, in your VPC.

No cloud sync. No telemetry (unless you opt-in for anonymous usage stats).

We're SOC2-ready (audit Q3 2026). DPA available on request. SCIF-ready for FedRAMP if needed."

**Proof**: Show `/admin/system` — Data Storage section. Confirm SQLite/DuckDB paths on local disk.

---

## Win/Loss Tracker

| Date | Prospect | POC Outcome | Reason | Deal Size | Next |
|------|----------|-------------|--------|-----------|------|
| 2026-05-13 | Acme Corp | WIN | AI consensus resonated; saved $600K/yr | $50K/yr | Contract signed |
| 2026-05-20 | TechStart Inc | LOSS | "Snyk is enough for us" | $30K/yr | Follow-up Q3 |
| 2026-05-27 | FinServ Ltd | IN_PROGRESS | Day 4 compliance demo TBD | $150K/yr | Readout scheduled |

**Learnings**:
- Prospects with 5+ tools → higher urgency (POC Win rate: 80%)
- Prospects with just Snyk → need "multi-source" value prop (Win rate: 30%)
- Compliance framework mapping → strongest closer (72% of wins mention this)

---

## Success Criteria (Day 7 Readout)

POC is a WIN if ≥4 of 5 are true:

1. **Multi-source ingestion works** (≥3 sources, ≥20 findings)
2. **Compliance mapping aligns** (customer sees controls mapped, agrees on gaps)
3. **Remediation demo succeeds** (≥1 auto-fix created & reviewed)
4. **Persona alignment** (CISO / SOC / DevSecOps all see value)
5. **Commercial conversation scheduled** (customer commits to pricing discussion)

**If POC Win**: Move to 14-day contract negotiation (legal review, budget approval, procurement).

**If POC Loss**: Ask 3 questions:
- What ONE thing would've changed your mind?
- When can we revisit (Q3? After renewal?)
- Can we stay in touch via quarterly briefings?

---

## Appendix: Key ALDECI Differentiators

| Feature | ALdeci | Snyk | Wiz | Prisma |
|---------|--------|------|-----|--------|
| **Self-hosted** | ✓ | ✗ | ✗ | ✓ (enterprise) |
| **Air-gapped** | ✓ | ✗ | ✗ | ✗ |
| **Multi-LLM consensus** | ✓ (3 models) | ✗ | ✗ (single AI) | ✗ |
| **Compliance frameworks** | 7 (SOC2, ISO, PCI, HIPAA, FedRAMP, NIST, CIS) | 2 | 4 | 5 |
| **Scanner parsers** | 28+ | 1 (code only) | 8 | 12 |
| **Auto-fix** | ✓ (10 types, confidence-based) | ✓ (deps only) | ✗ | ✗ |
| **Native SAST** | ✓ (8 engines) | ✗ (ingests 3rd-party) | ✗ | ✓ |
| **Pricing** | $199–$1.5K/mo | $100K+/yr | $150K+/yr | $200K+/yr |

**Your pitch**: "You get Snyk's code + Wiz's cloud coverage + ALdeci's AI consensus + self-hosted simplicity. One price. One dashboard."

---

**POC Playbook v1.0 — Approved for use 2026-05-06**  
**Questions?** sales-engineering@aldeci.com or [Slack channel]
