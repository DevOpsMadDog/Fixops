# ALdeci Customer Onboarding Playbook

> **Trigger:** Purchase Order signed.
> **Owner:** Sales Engineer + Customer Success.
> **Goal:** First-week milestone met by D7. 30/60/90-day expansion path agreed by D30.
> **Reference:** `scripts/onboard_real_apps.sh` is the canonical real-API onboarding flow.

---

## First 7 days post-PO checklist

### D0 — PO signed (same day)
- [ ] Sales engineer drafts welcome email with: tenant slug, sandbox URL, day-by-day calendar, kickoff invite
- [ ] Account Executive sends invoice (Net-30)
- [ ] Slack/Teams shared channel created (`#aldeci-{customer-slug}`)
- [ ] Customer Success engineer assigned and CC'd on all comms
- [ ] PagerDuty rotation updated to include this tenant

### D1 — Tenant provisioning
- [ ] Run `scripts/onboard_real_apps.sh` adapted for customer slug — REAL API path, no DB shortcuts:
  ```bash
  # Manual steps mirror the script:
  curl -X POST $API/api/v1/orgs                       # create org
  curl -X POST $API/api/v1/onboarding/start           # begin wizard
  curl -X POST $API/api/v1/connectors/register        # register SCM
  ```
- [ ] Verify tenant isolation: query `GET /api/v1/orgs/{org_id}/summary` — must scope ONLY their data
- [ ] Send named users their invite emails (max 5 in Starter, 25 in Pro, unlimited in Enterprise)
- [ ] SSO/SCIM provisioned if Pro/Enterprise (Okta, Entra, Google Workspace)
- [ ] MFA enforced for all users (TOTP minimum; WebAuthn/FIDO2 for Enterprise)

### D2 — SCM + scanner connectors
- [ ] Wire primary SCM (see matrix below)
- [ ] Wire one existing scanner (see matrix below)
- [ ] Trigger first sync — confirm findings land in `/issues`
- [ ] Verify Brain Pipeline runs: `GET /api/v1/brain/pipeline/status?tenant=...` shows pipeline_status=COMPLETE on each finding

### D3 — First persona walkthrough
- [ ] CISO kickoff (30 min) — see template below
- [ ] Hand off recording to their broader leadership team

### D4 — Cloud + ticketing
- [ ] Wire cloud connector (AWS/GCP/Azure)
- [ ] Wire ticketing bidirectional (Jira or ServiceNow)
- [ ] Verify a finding can round-trip: ALdeci → ticket → status update → ALdeci

### D5 — DevSecOps walkthrough
- [ ] DevSecOps kickoff (30 min) — see template below
- [ ] Walk through Brain Pipeline live; show last DPO pair captured

### D6 — SOC analyst walkthrough + first override
- [ ] SOC analyst kickoff (60 min — longer because operational)
- [ ] Their analyst performs their first real override; we confirm DPO pair captured
- [ ] Schedule D14 review

### D7 — First-week milestone review
- [ ] All five named users have logged in at least once
- [ ] At least one finding from each connected source flowing through Brain Pipeline
- [ ] At least one DPO pair captured
- [ ] At least one AutoFix PR opened (regardless of merge state)
- [ ] At least one ticket round-trip completed
- [ ] CISO + DevSecOps lead + SOC analyst comfortable navigating their hero screens
- [ ] Welcome packet acknowledged by customer commercial sponsor

If any line item is unchecked at end-of-D7 → escalate to Customer Success lead, schedule a recovery sync within 24h.

---

## Connector wiring matrix per stack

| Customer stack | SCM | Cloud | Scanner ingest | Ticketing | SIEM (Pro+) |
|----------------|-----|-------|----------------|-----------|-------------|
| **GitHub + AWS + Snyk + Jira** | GitHub App + HMAC webhook (`github_app` connector) | AWS via IAM Role + boto3 (`agentless_snapshot_scan_engine`) | Snyk PULL connector (`snyk_integration.py`) | Jira bidirectional | Splunk HEC (`siem_connector.py`) |
| **GitHub + GCP + Semgrep + Jira** | GitHub App + HMAC | GCP Service Account JSON | Semgrep SARIF upload via `POST /api/v1/scanner-ingest/upload` | Jira bidirectional | Splunk HEC |
| **GitLab + Azure + Wiz + ServiceNow** | GitLab token + webhook | Azure Service Principal | Wiz API-LIVE pull (`wiz_integration`) | ServiceNow bidirectional | Sentinel KQL (`siem_connector.py`) |
| **GitHub + AWS + Trivy + Jira** | GitHub App + HMAC | AWS IAM Role | Trivy JSON upload | Jira bidirectional | Splunk HEC |
| **Bitbucket + GCP + SARIF batch + Jira** | Bitbucket token | GCP SA JSON | SARIF batch via `POST /api/v1/scanner-ingest/upload` | Jira bidirectional | — |
| **Azure DevOps + Azure + Defender + ServiceNow** | Azure DevOps PAT | Azure SP | Defender CSPM via Wiz adapter pattern | ServiceNow bidirectional | Sentinel KQL |
| **Air-gap (any stack)** | Filesystem connector | Offline cloud snapshot import | SARIF/CycloneDX/SPDX file drop | Jira on-prem OR none | Local Splunk OR none |

For each combination, the SE has a pre-built ansible/terraform snippet in `scripts/onboarding/{stack}-bootstrap.sh` (TODO if missing).

---

## Persona kickoff sessions

### CISO kickoff (30 minutes)

**Goal:** CISO understands the executive view, can verbalize the moat in their own words, and knows where to look during a board prep.

**Agenda:**
1. (5 min) Their security goals + how they currently report to the board
2. (10 min) Walk `/command` — KPI strip, trend lines, top exposures, dollarized FAIR risk
3. (10 min) Walk `/compliance` — frameworks they care about, evidence vault, signed audit chain
4. (5 min) Discussion prompts (below)

**Discussion prompts:**
- "When you go to the board next month, what 3 numbers do you want to be able to defend?"
- "What's the question your auditor asks that you currently can't answer in <5 minutes?"
- "Which framework do you care about most: NIST 800-53, SOC 2, PCI, HIPAA, ISO, or all?"
- "If we cut your noise by 40%, where do you redirect the analyst hours?"

### DevSecOps kickoff (30 minutes)

**Goal:** DevSecOps lead understands the Brain Pipeline, can explain Multi-LLM consensus + MPTE to their team, and knows the AutoFix flow.

**Agenda:**
1. (5 min) Their existing tool chain + biggest pain point
2. (10 min) Walk `/brain` — 12-step pipeline, drill into Multi-LLM consensus + MPTE + AutoFix queue
3. (10 min) Walk `/issues` — drawer drill-down, score breakdown, reachability proof
4. (5 min) Discussion prompts (below)

**Discussion prompts:**
- "How many findings does your team triage per week today? Per finding, how long?"
- "What's your AutoFix acceptance rate today? (Be honest — most are <20%.)"
- "Which scanner produces the most false positives in your environment?"
- "If we ship a HIGH-confidence AutoFix PR to your repo, who reviews it — and how fast?"

### SOC Analyst kickoff (60 minutes — longest because operational)

**Goal:** SOC analyst can run their daily triage in `/issues` solo within 1 week. They understand that their overrides train the model.

**Agenda:**
1. (10 min) Walk their existing daily triage workflow + what tool they use today
2. (15 min) Walk `/issues` queue: filters, saved views, drawer drill-down, override flow
3. (10 min) Walk `/asset-graph` choke-point + blast-radius for context-enrichment
4. (10 min) Live exercise: pick 3 real findings, walk through triage, capture first DPO pair together
5. (10 min) Self-learning telemetry — show the DPO pair captured during the exercise; explain "your override trained your model"
6. (5 min) Discussion prompts (below)

**Discussion prompts:**
- "What would you do with the 60% time saved if your queue was 40% smaller?"
- "When you override a tool's recommendation today, where does that knowledge go? (Usually: nowhere.)"
- "What's the one report you wish your CISO would ask for, but doesn't?"

---

## First-week milestone checklist (signed by customer commercial sponsor)

By end-of-D7:

- [ ] Tenant live, all named users active
- [ ] SCM connected (≥1 repo enrolled)
- [ ] Scanner connected (≥1 source ingested)
- [ ] Cloud connected (≥10 assets enrolled)
- [ ] Ticketing connected (≥1 round-trip)
- [ ] Brain Pipeline runs to completion on all ingested findings (no stuck pipelines)
- [ ] At least one Multi-LLM consensus vote logged
- [ ] At least one MPTE verification (any phase ≥10) completed
- [ ] At least one AutoFix PR opened
- [ ] At least one DPO pair captured
- [ ] CISO walkthrough complete + recording shared
- [ ] DevSecOps walkthrough complete + recording shared
- [ ] SOC analyst walkthrough complete + recording shared
- [ ] First-week status email sent to commercial sponsor

---

## 30 / 60 / 90-day expansion paths

### 30-day milestone — "Established"
- All in-scope sources connected
- Daily SOC triage runs in ALdeci (not legacy tool)
- First compliance evidence export shared with customer's auditor
- First monthly board KPI snapshot generated
- First quarterly ROI calculation: hours saved × loaded analyst rate

**Expansion conversation:** add second cloud, add second SCM, add EDR/XDR ingest

### 60-day milestone — "Scaling"
- Second cloud / second SCM live
- Custom policies authored by their team (not us)
- Self-learning loop: ≥100 DPO pairs/week — model fine-tunes nightly
- AutoFix acceptance rate measured and shared
- Their CISO references ALdeci unprompted in a board update

**Expansion conversation:** Pro→Enterprise tier, air-gap deployment plan, SCIF roadmap (if federal-adjacent), MCP gateway for their internal tooling

### 90-day milestone — "Strategic"
- ALdeci is THE security workbench (legacy tool retired or relegated)
- They co-author a customer reference / case study with us
- Their team owns the platform — we move from active onboarding to quarterly business review cadence
- Renewal conversation kicks off if Annual contract; usage upsell if monthly

**Expansion conversation:** multi-year contract, paid PoC for adjacent business unit, OEM/embed conversation if they have a security product of their own

---

## Escalation matrix

| Issue | Escalate to | SLA |
|-------|-------------|-----|
| API outage (P0) | On-call eng + CTO | 1h response, 4h restore |
| Tenant data isolation breach (P0) | CTO + General Counsel | Immediate, hourly comms |
| Connector broken (P1) | Customer Success eng | 4h ack, 24h fix |
| AutoFix PR introduced regression in customer code (P1) | SE + AutoFix engineering owner | 4h ack, 24h rollback |
| Compliance evidence chain integrity question (P1) | Compliance lead + CTO | Same day |
| Persona walkthrough request | Sales Engineer | 48h schedule |
| Feature request | Product Manager | Logged within 24h, prioritized within 1 sprint cycle |
