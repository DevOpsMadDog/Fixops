# ALdeci Organization-Wide Persona Trial Runbook

## Purpose
Simulate a real enterprise where:
- All key security and engineering personas exist and actively collaborate.
- All vulnerable apps from the master validation runbook are treated as internal organizational assets.
- ALdeci is already implemented and being evaluated as a production CTEM+ operating platform.

This document is a companion to the master runbook and focuses on people, ownership, handoffs, and operational behavior under realistic organizational conditions.

Reference baseline process:
- docs/REAL_PRODUCT_VALIDATION_MASTER_RUNBOOK.md

## Scenario Assumptions
1. ALdeci is deployed and integrated with API key auth, core scanners, MPTE, AutoFix, and evidence pipeline.
2. The organization has AppSec, SecOps, DevOps, engineering, compliance, and executive stakeholders.
3. The organization maintains intentional internal "training systems" (vulnerable labs) for continuous validation.
4. All validation targets are in scope by policy and recorded in target manifest.

## Internal Validation Asset Catalog (Treated as Organization-Owned)
These are intentionally vulnerable internal training assets used for tool calibration and process proof.

1. Internal-Juice-Shop (OWASP Juice Shop)
2. Internal-crAPI (OWASP crAPI)
3. Internal-WebGoat (OWASP WebGoat)
4. Internal-DVWA (DVWA)
5. Internal-Shepherd (OWASP Security Shepherd) or Internal-bWAPP

These systems are not customer production workloads. They are controlled proving grounds for detection quality, exploitability validation, and remediation workflow stress tests.

## Persona Model (All Active)

### Executive and Leadership Personas
1. CISO
2. VP Engineering
3. CTO
4. CFO

### Security Operations Personas
5. SOC Analyst T1
6. SOC Analyst T2
7. Incident Responder
8. Threat Hunter
9. Vulnerability Manager
10. AppSec Engineer
11. Security Architect
12. GRC Analyst
13. Compliance Manager

### Engineering and Platform Personas
14. Engineering Manager
15. Tech Lead
16. Backend Engineer
17. Frontend Engineer
18. DevOps Engineer
19. SRE
20. Platform Engineer
21. QA Engineer

### Data and AI Personas
22. Data Scientist
23. ML Engineer
24. Security Analyst (AI-assisted triage)
25. Prompt/Automation Engineer

## Responsibility Matrix

### CISO
- Owns risk acceptance policy and severity thresholds.
- Approves scope policy for live permissioned testing.
- Reviews weekly CTEM outcome report and evidence integrity.

### VP Engineering and CTO
- Own engineering execution on remediation SLAs.
- Ensure ALdeci outputs map to team ownership (App -> Component -> Feature).
- Track fix throughput and regression trends.

### SOC T1/T2 + Vulnerability Manager
- Operate finding queues and de-duplicate triage.
- Escalate only actionable and reproducible findings.
- Validate finding quality against noise targets.

### AppSec Engineer + Security Architect
- Tune policies, risk scoring, and route critical findings.
- Trigger MPTE validation on high-impact candidates.
- Verify exploitability narratives before escalation.

### Incident Responder + Threat Hunter
- Cross-check ALdeci findings against active threat signals.
- Build hunt hypotheses from attack path and enrichment metadata.

### DevOps/SRE/Platform
- Maintain scanning runtime reliability and connector uptime.
- Ensure telemetry, logs, and evidence storage durability.

### Engineering Teams
- Consume prioritized remediation backlog.
- Review AutoFix proposals and merge with ownership approvals.
- Report fix effectiveness and reopen rates.

### GRC/Compliance
- Map findings and remediations to control frameworks.
- Generate signed evidence packs for audits and customer proof.

### Data/AI Roles
- Monitor false positive rates and scoring drift.
- Improve prioritization quality and recommendation confidence.

## Trial Governance

### Steering Cadence
- Daily: Tactical standup (SecOps + AppSec + Eng leads)
- Weekly: Risk review (CISO, CTO, VP Eng, GRC)
- Biweekly: Executive trust review (CISO + CFO + Product)

### Decision Rights
1. Risk acceptance: CISO
2. Remediation SLA exceptions: VP Engineering
3. Production release risk exception: CTO
4. Budget and program continuation: CFO + CISO

## Execution Style - Real-Time Rolling E2E
This trial is executed as continuous micro-cycles, not as one giant end-to-end run.

Micro-cycle pattern:
1. Pick one asset + one objective + one persona lead.
2. Run discovery/triage/validation/remediation slice for that objective.
3. Record KPI deltas and handoff to next persona.
4. Repeat throughout the day.

Benefits:
- Faster feedback loops across personas.
- Early blocker detection.
- Better operational realism for enterprise teams.
- Continuous trust signal instead of one-time demo signal.

## End-to-End Trial Flow (Persona-Driven)

### Phase 1 - Intake and Scope Lock
Owner: Security Architect + GRC
- Register all internal validation assets in target manifest.
- Bind each asset to business owner and technical owner.
- Validate scope policy and testing guardrails.

Deliverables:
- Signed scope registry
- Manifest with owner mapping

### Phase 2 - Discover
Owner: SOC T1/T2 + AppSec
- Run multi-engine scans on all internal validation assets.
- Ingest findings, normalize records, and dedupe duplicates.
- Track scanner stability and ingestion completeness.

Deliverables:
- Raw findings export
- Deduplicated finding set

### Phase 3 - Prioritize and Decide
Owner: Vulnerability Manager + Security Architect
- Rank by severity, reachability, business criticality, and exploitability signals.
- Assign ownership by App -> Component -> Feature.
- Generate decision queue for validation.

Deliverables:
- Prioritized queue
- Ownership-assigned backlog

### Phase 4 - Validate (MPTE)
Owner: AppSec Engineer + Threat Hunter
- Run MPTE on selected High/Critical findings.
- Confirm exploitability paths and remove non-actionable alerts.

Deliverables:
- MPTE-confirmed findings
- Validation narrative per finding

### Phase 5 - Remediate
Owner: Tech Leads + Engineering Teams
- Evaluate AutoFix recommendations by confidence class.
- Apply high-confidence changes in controlled branches.
- Route medium/low confidence to manual review.

Deliverables:
- Applied fixes
- Re-test results
- Reopen analysis (if any)

### Phase 6 - Comply and Evidence
Owner: GRC + Compliance Manager
- Generate signed evidence bundles containing findings, decisions, validation, and remediation trail.
- Maintain immutable timeline for auditability.

Deliverables:
- Evidence bundles
- Control mapping report

### Phase 7 - Executive Trust Review
Owner: CISO + CFO + CTO
- Review KPI outcomes against agreed success gates.
- Decide production expansion, pilot extension, or remediation of pilot process gaps.

Deliverables:
- Go/No-Go memo
- Investment continuation recommendation

## KPI Framework (Organization Trial)

### Operational KPIs
1. Ingestion completeness
2. Dedupe ratio
3. Time to first meaningful signal
4. Queue aging by severity

### Quality KPIs
5. Actionability score
6. Noise ratio (sampled false positives)
7. MPTE confirmation rate
8. Reopen rate after remediation

### Business KPIs
9. SLA compliance rate by org unit
10. Mean time to remediation (MTTR)
11. Audit evidence completeness
12. Executive confidence index (surveyed)

## Minimum Acceptance Criteria for Full Organizational Confidence
1. Dedupe ratio >= 35%.
2. Actionability score >= 60%.
3. MPTE confirmation rate >= 20% on High/Critical in controlled assets.
4. Noise ratio < 30%.
5. Evidence completeness >= 90%.
6. Scope compliance = 100%.
7. Critical remediation SLA adherence >= 85%.

## Example Role-to-Workflow Mapping (Internal Validation Assets)

### Internal-Juice-Shop
- SOC T1 triages and tags severity.
- AppSec triggers MPTE on auth/session and injection findings.
- Backend Tech Lead reviews AutoFix recommendations.
- GRC maps accepted fixes to SOC2/ISO control references.

### Internal-crAPI
- API Security specialist validates object-level authorization findings.
- Threat Hunter reviews chainability and abuse paths.
- Platform team validates gateway and runtime controls.

### Internal-WebGoat / Internal-DVWA
- Used for repeatability testing and analyst training.
- QA validates no pipeline regressions across versions.

### Internal-Shepherd / Internal-bWAPP
- Used for edge-case correlation and multi-step attack path logic.
- Security Architect validates policy outcomes and escalation quality.

## Artifacts Required Per Trial Cycle
1. Target manifest with owner mapping
2. Raw scan exports
3. Normalized and deduped findings
4. Prioritized decision queue
5. MPTE validation logs
6. AutoFix recommendation and acceptance table
7. Re-test and closure report
8. Signed evidence bundles
9. Executive summary and Go/No-Go memo

## Anti-Hardcoding and Authenticity Controls
1. Reject findings that only contain static CVE references without source context.
2. Require reproducible trace: endpoint/path/file + request/response or code location.
3. Randomly sample at least 20 findings and manually verify reproducibility.
4. Track repeated CVE patterns across assets and flag template-only detections.
5. Require at least one contextual anchor: exploit path, reachability, owner mapping, or policy tie-in.

## Communication Templates

### Daily Trial Update
- Scope status: in-scope only / violations
- Findings status: raw, unique, critical count
- Validation status: MPTE queued vs confirmed
- Remediation status: accepted, in progress, blocked
- Evidence status: generated, pending, failed
- Top blockers and owner actions

### Weekly Executive Snapshot
- Security outcome trend (week over week)
- Top 5 risk decisions made
- SLA adherence by team
- Evidence completeness and audit readiness
- Recommendation: expand, optimize, or pause

## Ready-to-Use Reporting Templates
Use these immediately for continuous reporting:
- docs/templates/DAILY_REALTIME_E2E_REPORT_TEMPLATE.md
- docs/templates/WEEKLY_REALTIME_E2E_EXECUTIVE_TEMPLATE.md

Reporting rule:
- Daily report captures micro-cycle deltas and persona handoffs.
- Weekly report captures trend, leadership decisions, and go/no-go.

## Exit Outcomes

### Outcome A - Production Ready Confidence
All acceptance criteria met, stable operational rhythm, low noise, high actionability, strong evidence chain.

### Outcome B - Conditional Confidence
Core KPIs met but one or two areas require tuning (for example, noise ratio or MTTR).

### Outcome C - Not Yet Trusted
Critical gates missed. Run focused improvement cycle before external customer pilots.

## Implementation Note
Use this runbook together with:
- docs/REAL_PRODUCT_VALIDATION_MASTER_RUNBOOK.md

The master runbook defines command-level execution. This persona runbook defines organizational behavior, accountability, and trust criteria.

---
Owner: CISO Office + Security Engineering + VP Engineering
Usage: Internal enterprise pilot simulation, customer readiness proof, governance alignment
