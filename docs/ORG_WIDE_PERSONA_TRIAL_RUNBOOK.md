# ALdeci CTEM+ — Enterprise Pilot Deployment Guide

> **Classification**: Company Confidential — Customer-Ready
> **Version**: 3.0 | **Effective**: Q1 2026
> **Audience**: CISOs, Security Architecture Teams, Pilot Program Managers, Compliance Officers

---

## Purpose

This guide defines the organizational deployment model for an ALdeci CTEM+ enterprise pilot. It establishes:

- **Persona-to-workflow mapping** for all stakeholders across security, engineering, compliance, and leadership
- **Governance structure** with decision rights, escalation paths, and steering cadence
- **Operational execution model** with rolling micro-cycles for continuous validation
- **Acceptance criteria** tied to measurable KPIs that determine production readiness

Use this guide alongside the [Technical Validation Runbook](REAL_PRODUCT_VALIDATION_MASTER_RUNBOOK.md), which defines command-level execution. This document defines organizational behavior, accountability, and trust criteria.

---

## Pilot Scope and Prerequisites

### Deployment Assumptions

1. ALdeci is deployed in the customer's environment (SaaS, single-tenant, on-premises, or air-gapped).
2. API authentication is configured (API key and/or JWT).
3. Core platform capabilities are operational: native scanners, Brain Pipeline, MPTE, AutoFix, evidence generation.
4. Integration connectors are configured for the customer's existing toolchain (Jira, Slack, GitHub, etc.).

### Application Portfolio Onboarding

The pilot operates against the customer's **actual application portfolio**. During onboarding, applications are categorized by risk tier:

| Tier | Description | Pilot Priority | Example |
|------|-------------|---------------|---------|
| **Tier 1 — Critical** | Revenue-generating, customer-facing, regulated | Primary | Payment processing, API gateway, identity platform |
| **Tier 2 — Important** | Internal tools, developer platforms, CI/CD | Secondary | Internal dashboards, build systems, package registries |
| **Tier 3 — Standard** | Low-risk utilities, documentation, static content | Tertiary | Marketing site, internal wikis |
| **Validation Assets** | Controlled test environments for calibration | Parallel | Security training labs, staging environments |

Each application is registered in ALdeci's Application Registry with:

- **APP_ID**: Unique identifier
- **Business Owner**: Executive accountable for risk decisions
- **Technical Owner**: Engineering lead responsible for remediation
- **Component Map**: Application → Component → Feature hierarchy
- **Compliance Scope**: Applicable regulatory frameworks (PCI-DSS, SOC 2, HIPAA, etc.)

---

## Persona Model

### 25 Enterprise Personas (All Active During Pilot)

#### Executive and Leadership

| # | Persona | Pilot Role |
|---|---------|-----------|
| 1 | **CISO** | Risk acceptance authority, pilot sponsor, steering committee chair |
| 2 | **VP Engineering** | Remediation SLA owner, engineering resource allocation |
| 3 | **CTO** | Production release risk authority, architecture review |
| 4 | **CFO** | Budget authority, ROI measurement, investment continuation |

#### Security Operations

| # | Persona | Pilot Role |
|---|---------|-----------|
| 5 | **SOC Analyst Tier 1** | Initial triage, severity classification, queue management |
| 6 | **SOC Analyst Tier 2** | Deep analysis, escalation, cross-correlation |
| 7 | **Incident Responder** | Finding-to-incident correlation, active threat cross-reference |
| 8 | **Threat Hunter** | Attack path analysis, hypothesis-driven validation |
| 9 | **Vulnerability Manager** | Finding lifecycle ownership, SLA tracking, queue prioritization |
| 10 | **AppSec Engineer** | Policy tuning, MPTE orchestration, exploitability verification |
| 11 | **Security Architect** | Policy design, risk model calibration, integration architecture |
| 12 | **GRC Analyst** | Control mapping, evidence collection, audit preparation |
| 13 | **Compliance Manager** | Framework alignment, certification readiness, regulatory reporting |

#### Engineering and Platform

| # | Persona | Pilot Role |
|---|---------|-----------|
| 14 | **Engineering Manager** | Sprint capacity allocation, remediation backlog management |
| 15 | **Tech Lead** | AutoFix review authority, code change approval |
| 16 | **Backend Engineer** | Remediation execution, fix verification |
| 17 | **Frontend Engineer** | Client-side vulnerability remediation |
| 18 | **DevOps Engineer** | Scanner runtime, connector configuration, CI/CD integration |
| 19 | **SRE** | Infrastructure scanning, configuration drift monitoring |
| 20 | **Platform Engineer** | Runtime environment hardening, container security |
| 21 | **QA Engineer** | Regression testing post-remediation, fix verification |

#### Data and AI

| # | Persona | Pilot Role |
|---|---------|-----------|
| 22 | **Data Scientist** | Risk model validation, scoring drift analysis |
| 23 | **ML Engineer** | Prioritization quality monitoring, model performance |
| 24 | **Security Analyst (AI-Assisted)** | AI-augmented triage, consensus decision review |
| 25 | **Automation Engineer** | MCP integration, workflow automation, agent orchestration |

---

## Responsibility Matrix (RACI)

### Executive Accountability

| Responsibility | CISO | VP Eng | CTO | CFO |
|---------------|------|--------|-----|-----|
| Risk acceptance policy | **A** | C | C | I |
| Remediation SLA exceptions | C | **A** | C | I |
| Production release risk exception | C | C | **A** | I |
| Pilot budget and continuation | C | I | I | **A** |
| Compliance evidence signoff | **A** | I | I | C |

*A = Accountable, R = Responsible, C = Consulted, I = Informed*

### Operational Responsibilities

| Function | Personas | Key Activities |
|----------|----------|---------------|
| **Triage & Queue Management** | SOC T1/T2, Vulnerability Manager | Operate finding queues, deduplicate, escalate actionable findings |
| **Policy & Risk Calibration** | AppSec Engineer, Security Architect | Tune policies, scoring weights, and routing rules |
| **Exploitability Verification** | AppSec Engineer, Threat Hunter | Orchestrate MPTE validation, verify exploitability narratives |
| **Threat Correlation** | Incident Responder, Threat Hunter | Cross-reference findings against active threat intelligence |
| **Platform Operations** | DevOps, SRE, Platform Engineer | Maintain scanner runtime, connector uptime, telemetry |
| **Remediation Execution** | Tech Lead, Engineers, QA | Review AutoFix proposals, execute fixes, verify resolution |
| **Compliance & Evidence** | GRC Analyst, Compliance Manager | Map to control frameworks, generate signed evidence |
| **AI/ML Quality** | Data Scientist, ML Engineer | Monitor false positive rates, scoring drift, model confidence |

---

## Pilot Governance

### Steering Cadence

| Frequency | Meeting | Participants | Purpose |
|-----------|---------|-------------|---------|
| **Daily** | Tactical standup | SecOps + AppSec + Engineering leads | Operational blockers, queue status, SLA tracking |
| **Weekly** | Risk review | CISO, CTO, VP Eng, GRC lead | Risk decisions, KPI review, policy adjustments |
| **Biweekly** | Executive trust review | CISO, CFO, Product | Investment thesis validation, Go/No-Go assessment |

### Decision Rights

| Decision | Authority | Escalation Path |
|----------|-----------|----------------|
| Risk acceptance for specific finding | CISO | Board Risk Committee |
| Remediation SLA exception | VP Engineering | CTO |
| Emergency production release hold | CTO | CISO + VP Eng joint |
| Pilot extension or termination | CFO + CISO | Executive Committee |
| Compliance evidence release to auditor | Compliance Manager | CISO |

---

## Execution Model — Rolling Micro-Cycles

The pilot executes as **continuous micro-cycles**, not a single end-to-end run. This approach mirrors production operational cadence and generates continuous trust signals.

### Micro-Cycle Pattern

1. Select one application tier + one objective + one persona lead
2. Execute discovery, triage, validation, and remediation slice
3. Record KPI deltas and execute handoff to the next persona
4. Repeat continuously throughout the pilot period

### Benefits Over Traditional POC

| Traditional POC | ALdeci Rolling Micro-Cycle |
|----------------|---------------------------|
| Single pass, single demo | Continuous operational validation |
| Scripted scenarios | Real application portfolio |
| Results in 2 weeks | Trust signal in 48 hours, deepening daily |
| One stakeholder validates | All 25 personas engage |
| Go/No-Go at end | Continuous Go/No-Go assessment |

---

## Seven-Phase Pilot Execution

### Phase 1 — Intake and Scope Lock

**Owner**: Security Architect + GRC Analyst

| Activity | Detail |
|----------|--------|
| Register applications in ALdeci Application Registry | APP_ID, business owner, technical owner, component map |
| Define scope policy | In-scope applications, testing guardrails, excluded environments |
| Configure compliance framework mapping | PCI-DSS, SOC 2, NIST, ISO 27001 as applicable |
| Bind integrations | Jira project mapping, Slack channels, GitHub repositories |

**Deliverables**: Signed scope registry, application manifest with ownership mapping

### Phase 2 — Discover

**Owner**: SOC T1/T2 + AppSec Engineer

| Activity | Detail |
|----------|--------|
| Execute multi-engine scans across application portfolio | Native scanners + integrated external tools |
| Ingest and normalize all findings | Unified Finding Format (UFF) standardization |
| Execute cross-scanner deduplication | Eliminate redundant findings from overlapping tools |
| Track scanner coverage and stability | Ingestion completeness by engine and application |

**Deliverables**: Raw findings export, deduplicated finding set, scanner coverage report

### Phase 3 — Prioritize and Decide

**Owner**: Vulnerability Manager + Security Architect

| Activity | Detail |
|----------|--------|
| Score findings with multi-factor risk model | CVSS + EPSS + business context + reachability |
| Assign ownership via APP_ID hierarchy | Application to Component to Feature to Owner |
| Generate decision queue | Ranked by exploitability, blast radius, and SLA urgency |
| Apply organizational security policies | Auto-triage, auto-assign, auto-escalate per policy |

**Deliverables**: Prioritized queue, ownership-assigned backlog, policy evaluation log

### Phase 4 — Validate (MPTE)

**Owner**: AppSec Engineer + Threat Hunter

| Activity | Detail |
|----------|--------|
| Select High/Critical findings for MPTE verification | Prioritize by reachability and business impact |
| Execute 19-phase exploit verification | Bounded, safe, with automatic rollback |
| Confirm or dismiss exploitability | Evidence-grade confirmation with chain-of-custody |
| Generate validation narratives | Per-finding exploitability report |

**Deliverables**: MPTE-confirmed finding set, per-finding validation narrative, false positive reduction metrics

### Phase 5 — Remediate

**Owner**: Tech Leads + Engineering Teams

| Activity | Detail |
|----------|--------|
| Evaluate AutoFix recommendations by confidence tier | HIGH: auto-apply; MEDIUM: PR review; LOW: manual |
| Apply fixes in controlled branches | Feature branches with automated test gates |
| Execute re-verification scan post-fix | Confirm resolution, detect regressions |
| Track fix effectiveness and reopen rates | Feed into self-learning loop |

**Deliverables**: Applied fixes with PR links, re-test results, reopen analysis

### Phase 6 — Comply and Evidence

**Owner**: GRC Analyst + Compliance Manager

| Activity | Detail |
|----------|--------|
| Generate signed evidence bundles | Finding, Decision, Validation, and Remediation trail |
| Map to compliance control frameworks | Auto-map to SOC 2, PCI-DSS, NIST, ISO controls |
| Maintain immutable audit timeline | WORM-retained with cryptographic signatures |
| Prepare audit-ready compliance reports | Per-framework control coverage and gap analysis |

**Deliverables**: Signed evidence bundles, control mapping report, compliance readiness summary

### Phase 7 — Executive Trust Review

**Owner**: CISO + CFO + CTO

| Activity | Detail |
|----------|--------|
| Review KPI outcomes against acceptance criteria | All 12 KPIs measured and reported |
| Assess operational readiness | Team adoption, workflow integration, process maturity |
| Evaluate ROI indicators | MTTR improvement, false positive reduction, labor savings |
| Issue Go/No-Go decision | Production expansion, pilot extension, or optimization cycle |

**Deliverables**: Go/No-Go memo, investment continuation recommendation, production rollout plan

---

## KPI Framework

### Operational KPIs

| # | KPI | Target | Measurement |
|---|-----|--------|-------------|
| 1 | Ingestion completeness | >= 99% | Findings ingested / findings generated |
| 2 | Deduplication ratio | >= 35% | (Raw - Unique) / Raw |
| 3 | Time to first meaningful signal | < 30 minutes | First actionable finding after scan initiation |
| 4 | Queue aging by severity | Critical < 4h, High < 24h | Time finding remains in triage queue |

### Quality KPIs

| # | KPI | Target | Measurement |
|---|-----|--------|-------------|
| 5 | Actionability score | >= 60% | Actionable findings / Total unique findings |
| 6 | Noise ratio | < 30% | False positives in sampled set / Sample size |
| 7 | MPTE confirmation rate | >= 20% | MPTE-confirmed / High+Critical submitted |
| 8 | Reopen rate after remediation | < 10% | Reopened findings / Closed findings |

### Business KPIs

| # | KPI | Target | Measurement |
|---|-----|--------|-------------|
| 9 | SLA compliance rate | >= 85% | Findings remediated within SLA / Total assigned |
| 10 | Mean time to remediation (MTTR) | Improvement >= 40% | Average remediation time vs. baseline |
| 11 | Audit evidence completeness | >= 90% | Workflows with signed evidence / Total workflows |
| 12 | Executive confidence index | >= 4.0 / 5.0 | Surveyed leadership satisfaction |

---

## Acceptance Criteria

**All criteria must be met for production-ready recommendation:**

| # | Criterion | Gate |
|---|-----------|------|
| 1 | Deduplication ratio | >= 35% |
| 2 | Actionability score | >= 60% |
| 3 | MPTE confirmation rate | >= 20% on High/Critical findings |
| 4 | Noise ratio | < 30% |
| 5 | Evidence completeness | >= 90% |
| 6 | Scope compliance | 100% (zero out-of-scope actions) |
| 7 | Critical remediation SLA adherence | >= 85% |

---

## Persona-to-Workflow Mapping by Application Tier

### Tier 1 — Critical Applications (Revenue-Generating)

| Persona | Workflow |
|---------|----------|
| SOC T1 | Initial triage, severity classification, SLA timer start |
| AppSec Engineer | MPTE verification on authentication, authorization, and injection findings |
| Tech Lead | AutoFix review with mandatory senior engineer approval |
| GRC Analyst | Map accepted fixes to SOC 2, PCI-DSS, and ISO 27001 controls |
| Compliance Manager | Generate signed evidence bundle, prepare audit artifact |

### Tier 2 — Important Applications (Internal Platforms)

| Persona | Workflow |
|---------|----------|
| SOC T2 | Triage and prioritize against infrastructure risk model |
| Threat Hunter | Review attack paths and lateral movement potential |
| Platform Engineer | Validate runtime and infrastructure controls |
| DevOps Engineer | CI/CD integration validation, scanner pipeline health |

### Tier 3 — Standard Applications (Low-Risk)

| Persona | Workflow |
|---------|----------|
| QA Engineer | Verify pipeline consistency across application tiers |
| Automation Engineer | Validate MCP integration and workflow automation |
| Security Architect | Review policy outcomes and escalation quality |

### Validation Assets (Calibration)

| Persona | Workflow |
|---------|----------|
| AppSec Engineer | Baseline scanner detection accuracy against known-vulnerable targets |
| QA Engineer | Regression testing across platform versions |
| Data Scientist | False positive rate benchmarking and scoring model validation |

---

## Pilot Artifacts Checklist

Every pilot cycle produces the following deliverables:

| # | Artifact | Owner | Format |
|---|----------|-------|--------|
| 1 | Application manifest with ownership mapping | Security Architect | YAML/JSON |
| 2 | Raw scan exports (all engines) | SOC T1 | JSON/SARIF |
| 3 | Normalized and deduplicated finding set | Vulnerability Manager | ALdeci UFF |
| 4 | Prioritized decision queue | Security Architect | Dashboard + Export |
| 5 | MPTE validation logs | AppSec Engineer | JSON + Narrative |
| 6 | AutoFix recommendation and acceptance table | Tech Lead | CSV + PR links |
| 7 | Re-test and closure report | QA Engineer | Markdown + JSON |
| 8 | Signed evidence bundles | GRC Analyst | Cryptographically signed JSON |
| 9 | Executive summary and Go/No-Go memo | CISO | PDF |

---

## Data Quality Controls

1. **Source verification**: Reject findings that contain only static CVE references without contextual source evidence (file path, endpoint, request/response, code location).
2. **Reproducibility requirement**: Every finding must include a reproducible trace consisting of endpoint, code location, or artifact path with supporting evidence.
3. **Statistical sampling**: Randomly verify at least 20 findings per pilot cycle for manual reproducibility confirmation.
4. **Pattern detection**: Track repeated CVE patterns across applications and flag template-only or generic detections for manual review.
5. **Contextual anchoring**: Every prioritized finding must include at least one of: exploit path, reachable asset evidence, ownership mapping, or policy tie-in.

---

## Communication Cadence

### Daily Pilot Update (Operational)

| Section | Content |
|---------|---------|
| Scope status | In-scope compliance, any scope questions |
| Finding status | Raw count, unique count, critical/high count |
| Validation status | MPTE queue depth, confirmed vs. dismissed |
| Remediation status | Accepted, in progress, blocked, closed |
| Evidence status | Generated, pending, failed |
| Blockers | Top issues with assigned owners and deadlines |

### Weekly Executive Snapshot (Strategic)

| Section | Content |
|---------|---------|
| Security outcome trend | Week-over-week KPI movement |
| Top 5 risk decisions | Decisions made with rationale and owner |
| SLA adherence | By team and application tier |
| Evidence completeness | Audit readiness percentage |
| Recommendation | Expand, optimize, or escalate |

---

## Pilot Outcomes

### Outcome A — Production Ready

All acceptance criteria met. Stable operational rhythm. Low noise, high actionability, complete evidence chain. **Recommendation**: Expand to full application portfolio.

### Outcome B — Conditional Approval

Core KPIs met with one or two areas requiring tuning (e.g., noise ratio calibration or MTTR optimization). **Recommendation**: Approve production deployment with targeted improvement plan.

### Outcome C — Optimization Required

Critical acceptance gates not met. **Recommendation**: Execute focused improvement cycle with identified remediation actions before production expansion.

---

## Related Documentation

| Document | Purpose |
|----------|---------|
| [Technical Validation Runbook](REAL_PRODUCT_VALIDATION_MASTER_RUNBOOK.md) | Command-level execution and API validation procedures |
| [CEO Vision](CEO_VISION.md) | Strategic platform direction and market positioning |
| [CTEM+ Platform Capabilities](CTEM_PLUS_IDENTITY.md) | Technical capability reference for evaluation teams |

---

*This document defines the organizational deployment model for ALdeci CTEM+ enterprise pilots. It is designed for use by customer security teams, pilot program managers, and executive sponsors during evaluation and deployment.*

*Version 3.0 — Q1 2026 — Company Confidential*
