# ALdeci 14-Day POC Template

> **Customer:** _________________   **Tenant slug:** _________________
> **Start date:** _________________   **POC commercial sponsor (their):** _________________
> **POC technical lead (theirs):** _________________   **Sales Engineer (ours):** _________________
> **Slack/Teams channel:** _________________

---

## 0. Why 14 days (not 30, not 90)

The 20-day SCIF/federal path is documented separately in `docs/ORG_WIDE_PERSONA_TRIAL_RUNBOOK.md`. This 14-day track is for **commercial customers** with no ATO / IL5 procurement constraints. Time-to-value beats thoroughness; we'd rather prove the moat in 14 days and renew than over-engineer a 90-day proof.

---

## 1. Scope (in / out)

### In scope
- 1 GitHub OR GitLab org (up to 50 repos)
- 1 cloud environment (AWS, GCP, OR Azure — pick one)
- 1 existing scanner ingest (Snyk OR Wiz OR Semgrep OR Trivy OR SARIF batch)
- 1 ticketing system bidirectional (Jira OR ServiceNow)
- Up to 5 named users from customer (1 CISO, 2 DevSecOps, 1 SOC analyst, 1 developer)
- Brain Pipeline runs on every ingested finding
- Self-learning loop captures DPO pairs from real analyst overrides

### Out of scope (for the POC; available on conversion)
- Air-gap deployment — we'll demo on shared SaaS unless customer mandates on-prem (then go to 20-day)
- IDE plugins (GAP-014, not yet shipped)
- DSPM / data classification (defer)
- Custom compliance framework authoring
- More than 50 repos / more than 1 cloud
- More than 5 named users

---

## 2. Day-by-day plan

| Day | Owner | Activity | Exit signal |
|-----|-------|----------|-------------|
| **D0 (kickoff, 60 min)** | SE + their tech lead | Tenant provisioned via `scripts/onboard_real_apps.sh`, named users created, SSO/SCIM tested, channel opened | Their lead can log in to `/command` and sees their tenant |
| **D1** | SE | Wire SCM connector (`POST /api/v1/connectors/register` with their GitHub App / GitLab token), trigger first sync | First repo enrolled, file tree visible at `/asset-graph` |
| **D2** | SE | Wire scanner ingest (their Snyk/Wiz token OR SARIF upload to `POST /api/v1/scanner-ingest/upload`), validate Brain Pipeline runs end-to-end | First 100+ findings visible at `/issues`, all show pipeline_status=COMPLETE |
| **D3** | SE + their DevSecOps | First Multi-LLM Consensus decision walked through together; show vote breakdown | Their DevSecOps lead understands and verbalizes the consensus rule |
| **D4** | SE | Wire cloud connector (AWS via boto3, GCP via SA key, Azure via SP) — agentless snapshot scan kicks in | At least 50 cloud assets in `/asset-graph`, choke-point computation runs |
| **D5** | SE + their SOC analyst | First analyst override captured; surface the DPO pair in self-learning telemetry | Their analyst sees their own override in the telemetry tab; understands "their data trains their model" |
| **D6** | SE | Wire Jira/ServiceNow bidirectional; verify ticket round-trip (Brain → ticket → status update → Brain) | One closed-loop ticket cycle confirmed |
| **D7 (mid-POC review, 60 min)** | SE + their tech lead + their CISO | Review week-1 metrics: ingested findings, MPTE-verified exploitables, AutoFix queue depth, DPO pairs captured | Mid-POC scorecard signed |
| **D8** | SE | Trigger first AutoFix on a HIGH-confidence finding; PR opens to their GitHub | PR visible in their repo, assigned to their developer |
| **D9** | Their developer | Review the AutoFix PR; merge OR reject (both outcomes are signal) | PR closed (merged or rejected) — either way captured as DPO signal |
| **D10** | SE + their CISO | Compliance walkthrough — frameworks, evidence, audit log, SBOM | CISO sees evidence for at least 1 framework they care about |
| **D11** | Their SOC analyst | First persona walkthrough (`/issues` queue, drawer drill-down, override flow) — recorded for replay | Recording exists; analyst comfortable solo |
| **D12** | Their CISO | Second persona walkthrough (`/command` + `/compliance` executive views) | CISO comfortable solo |
| **D13** | SE | Generate POC scorecard against the 5 success criteria below; circulate 24h before exit meeting | Scorecard delivered to all stakeholders |
| **D14 (exit decision, 60 min)** | All | Review scorecard. Decide: convert / extend / terminate. Data export option exercised if terminate. | Decision logged; commercial paperwork or termination kicked off |

---

## 3. Success criteria (5 categories)

The POC is **successful** if **at least 4 of 5** thresholds are met. Customer sees this scorecard before signing — no surprises.

| # | Category | Threshold | How measured |
|---|----------|-----------|--------------|
| 1 | **Noise reduction** | ≥40% of ingested critical/high findings de-prioritized via reachability or compensating-control evidence | `(findings_ingested_critical_high - findings_remaining_actionable) / findings_ingested_critical_high` |
| 2 | **Real exploitables surfaced** | ≥3 MPTE-verified exploitable findings that customer's prior tools either missed OR misclassified | Count of MPTE phase-19 PASS reports vs. customer's existing scanner output |
| 3 | **Analyst loop closed** | ≥3 false-positive suppressions confirmed by their analyst, captured as DPO pairs | Count from `/api/v1/llm/dpo-pairs?tenant=...&since=D0` |
| 4 | **Remediation auto-applied OR PR-accepted** | ≥1 AutoFix PR merged by customer's developer | Git commit ID in their repo signed off by their dev |
| 5 | **Persona adoption** | ≥2 of 3 personas (CISO, DevSecOps, SOC) complete a self-driven walkthrough without SE assistance | Recording exists OR live demo to SE on D11/D12 |

### Stretch goals (nice-to-have, not required for conversion)
- 1 toxic-combo correlation surfaced
- 1 chokepoint identified that customer agrees changes their patch priority
- 1 compliance evidence bundle exported and shared with their auditor

---

## 4. Pricing (transparent, no surprises)

| Tier | Per-month | What's included |
|------|-----------|-----------------|
| Starter | $199 | Up to 50 repos, 1 cloud, 5 users, SaaS only |
| Pro | $499 | 250 repos, 3 clouds, 25 users, SaaS or single-tenant |
| Enterprise | $1,499 | Unlimited, on-prem option, air-gap option, SCIF roadmap |

POC pricing: **$0**. No card on file. This is intentional — we earn the contract on D14, not on signature.

---

## 5. Exit options (defined up front, not at D14)

### Option A — Convert to paid
- Choose tier (Starter / Pro / Enterprise) on D14.
- 30-day net invoice.
- Tenant continues with no data loss.
- Named users keep their saved views, queries, DPO history.

### Option B — Mutual termination + data export
- Customer requests termination on or before D14.
- We export within 24 hours: all findings (JSON), all evidence bundles (signed), audit log (JSONL), DPO pairs (JSONL), graph snapshot (GraphML).
- Tenant tombstoned; data deleted from production within 7 days; deletion certificate signed and emailed.
- We request a 20-minute exit interview (see `docs/sales/win_loss_analysis_template.md`).
- No invoice, no recurring charge, no clawback.

### Option C — Extend POC by 14 days (one-time)
- Triggered ONLY if a blocker outside customer's control delayed measurement (e.g., their scanner integration was stalled by their vendor).
- Same scope. Same success criteria. Same SE.
- Documented decision: who blocked, what unblocked it, why this extension is the right call.

---

## 6. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Customer's scanner API is slow/flaky | Day 2 we ALSO upload one SARIF batch as a backstop so Brain Pipeline has data even if their live ingest stalls |
| Customer doesn't have analyst time for D5/D9 | We pre-write 5 likely override scenarios; their analyst spends 20 min, not 2 hours |
| AutoFix PR has merge conflict in their repo | We rebase before opening PR; their developer reviews, doesn't fix |
| Their CISO can't make D14 | Recorded scorecard walkthrough sent 48h ahead; D14 is decision call only |
| They request air-gap mid-POC | Honest answer: SaaS for 14 days; if conversion is air-gap, separate 20-day runbook (`ORG_WIDE_PERSONA_TRIAL_RUNBOOK.md`) starts at signature |

---

## 7. POC scorecard template (D14 deliverable)

```
ALDECI POC SCORECARD — {customer} — {start} → {end}

1. Noise reduction:        ___% (target ≥40%)         PASS / FAIL
2. MPTE exploitables:      ___ (target ≥3)             PASS / FAIL
3. DPO pairs captured:     ___ (target ≥3)             PASS / FAIL
4. AutoFix PRs merged:     ___ (target ≥1)             PASS / FAIL
5. Personas adopted:       ___/3 (target ≥2)           PASS / FAIL

Overall: ___/5 (need ≥4 to convert)

Recommendation: CONVERT / EXTEND / TERMINATE
```

---

## 8. Sign-off

| Party | Name | Date | Signature |
|-------|------|------|-----------|
| Customer technical lead | | | |
| Customer commercial sponsor | | | |
| ALdeci Sales Engineer | | | |
| ALdeci Account Executive | | | |
