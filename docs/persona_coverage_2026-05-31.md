# Persona × S0x Screen Coverage Audit
**Date:** 2026-05-31
**Branch:** chore/ui-prune-plan-2026-05-24
**Scope:** 30 ALDECI personas × 31 v2 S0x screens
**Prior audit:** `docs/persona_hub_coverage_2026-05-05.md` (18 COVERED / 8 PARTIAL / 4 MISSING)
**Method:** Structural — read every S0x TSX file; checked existence of new pages referenced (DPOPrivacyHub, AuditorEvidenceHub, DeveloperSecurityHub, BoardLandingPage). No runtime verification.

---

## Summary (delta vs 2026-05-05)

| Metric | 2026-05-05 | 2026-05-31 | Delta |
|--------|-----------|-----------|-------|
| COVERED | 18 | 26 | +8 |
| PARTIAL | 8 | 4 | -4 |
| MISSING | 4 | 0 | -4 |
| **Total personas** | **30** | **30** | — |

**3-line summary:**
26 COVERED, 4 PARTIAL, 0 MISSING.
All 4 previously-MISSING personas (P24 Board Member, P25 External Auditor, P28 DPO, P29 Software Architect) are now COVERED by dedicated S0x screens and new hub pages.
4 PARTIAL personas remain (P2 VP Engineering, P10 IT Director, P15 Security Data Scientist, P16 Platform Engineer) — they have functional S0x coverage but still lack a role-filtered command-centre view.

---

## Full Persona × S0x Coverage Matrix

### Previously COVERED — remain COVERED (18 personas, no regression)

| ID | Persona | Status | Primary S0x Screens |
|----|---------|--------|---------------------|
| P1 | CISO (Sarah Chen) | COVERED | S03 MissionControl (CISO Dashboard + Risk Overview + SLA), S16 CtemCycles (Strategic Posture), S17 FindingsExplorer |
| P3 | SOC Analyst T1 (Alex Rivera) | COVERED | S20 Detections (BehaviorAnalytics + DetectAndRespond + Telemetry + Timeline), S21 Incidents |
| P4 | SOC Analyst T2 (Priya Sharma) | COVERED | S20 Detections, S21 Incidents, S19 ThreatIntel (ThreatActors + ExternalFeeds) |
| P5 | Security Engineer (James Wilson) | COVERED | S04 AspmCode, S08 SecretsCrypto, S17 FindingsExplorer, S07 SupplyChain |
| P6 | DevSecOps Engineer (Emma Davis) | COVERED | S04 AspmCode, S05 AspmApi, S06 AspmRuntime, S08 SecretsCrypto, S07 SupplyChain |
| P7 | Compliance Officer (Robert Kim) | COVERED | S25 Compliance (Dashboard + Evidence Export + Auditor Hub + Reports + SLSA), S16 CtemCycles (Maturity + Strategic) |
| P8 | Penetration Tester (Lisa Zhang) | COVERED | S14 AttackSurface (OffensiveValidation), S22 RansomwareMalware (ThreatHunting + Deception), S19 ThreatIntel |
| P9 | Risk Manager (David Park) | COVERED | S18 RiskAcceptance, S16 CtemCycles (Posture + Gap + Resilience), S17 FindingsExplorer |
| P11 | AppSec Lead (Tom Anderson) | COVERED | S04 AspmCode, S05 AspmApi, S06 AspmRuntime, S08 SecretsCrypto, S07 SupplyChain |
| P12 | Cloud Security Architect (Jennifer Wu) | COVERED | S09 CspmPosture, S10 CloudAccounts, S11 CloudWorkloads, S12 NetworkSec, S13 IdentityAccess |
| P14 | Incident Response Lead (Karen Taylor) | COVERED | S21 Incidents (IR Playbooks + Forensics + AutomationOrchestration), S20 Detections |
| P17 | Threat Intel Analyst (Nina Patel) | COVERED | S19 ThreatIntel (Intel Dashboard + ThreatActors + ExternalFeeds + Enrichment + Ops) |
| P18 | GRC Analyst (Olivia Martin) | COVERED | S25 Compliance, S16 CtemCycles, S18 RiskAcceptance |
| P19 | SecOps Manager (Daniel Thompson) | COVERED | S03 MissionControl (SLA + LiveFeed), S20 Detections, S21 Incidents |
| P21 | Security Architect (Richard Adams) | COVERED | S15 TrustGraph (Brain + ArchAwareGraph + Copilot + Correlation), S14 AttackSurface, S16 CtemCycles |
| P22 | Supply Chain Security (Amanda Scott) | COVERED | S07 SupplyChain (SBOM + Provenance + SupplyChainHub), S04 AspmCode |
| P27 | Threat Modeler | COVERED | S15 TrustGraph (ArchAwareGraph), S19 ThreatIntel, S14 AttackSurface |
| P30 | SecOps Tech Lead | COVERED | S20 Detections, S21 Incidents (AutomationOrchestration), S22 RansomwareMalware |

---

### Previously MISSING — now COVERED (4 personas, gap closed)

| ID | Persona | Status | Closing Screen(s) | Closing File(s) | What's Still Missing |
|----|---------|--------|-------------------|-----------------|----------------------|
| P24 | Board Member (Catherine Williams) | **COVERED** | `/board` route + S03 MissionControl | `src/pages/BoardLandingPage.tsx` (P24-labelled, wired at `/board`). Displays Risk Posture, Financial Impact, Compliance Scorecard, Board Metrics via real API calls. | No `?audience=board` read-only mode to strip action buttons — minor gap, not blocking. |
| P25 | External Auditor (Mark Roberts) | **COVERED** | S25 Compliance → "Auditor Hub" tab | `src/pages/comply/AuditorEvidenceHub.tsx` — 4 tabs: Evidence (control-by-control), Frameworks (completion %), Period (date-range selector), Export (bundle download). Wired to `/api/v1/audit/compliance/controls`, `/api/v1/audit/compliance/frameworks`, `/api/v1/evidence/bundles`. | RBAC viewer-only guard not confirmed at component level (not read from TSX — may need audit); audit-period time-box selector present in Period tab. |
| P28 | DPO (Data Protection Officer) | **COVERED** | S24 Privacy → "DPO Hub" tab | `src/pages/DPOPrivacyHub.tsx` — 4 tabs: DSR Queue (access/deletion/portability/objection requests with SLA), DPIA (risk scores + regulatory status), Cross-Border (transfer registry — EmptyState, endpoint pending), Discovery (PII/PHI inventory). | Cross-border transfer tab renders EmptyState — registry endpoint not yet implemented. DSR + DPIA tabs are wired to real APIs. |
| P29 | Software Architect | **COVERED** | S15 TrustGraph + S06 AspmRuntime | S15: `ArchAwareGraphDashboard` + `BrainVisualization` + `CorrelationEngine`. S06: `CodeToRuntimeDashboard` + `RuntimeCodeTrace` + `TracedFlowViewer`. Together form code-to-cloud traceability workspace. | No single unified "Architect Workspace" hub composing all tabs in one place — S15 and S06 are separate screens. Acceptable for v2; no dedicated route like `/discover/architect` recommended in prior audit. |

---

### Previously PARTIAL — now COVERED (4 personas, gap closed)

| ID | Persona | Status | Closing Screen(s) | What Closed the Gap |
|----|---------|--------|-------------------|---------------------|
| P20 | Developer / Security Champion (Emily Chang) | **COVERED** | `DeveloperSecurityHub.tsx` at `/developer` | 4 tabs: PR-Linked Findings (SAST+DAST filtered to author's PRs), Champion (leaderboard rank + badges + courses), My Code (repo security scores), Helpers (auto-fix snippets). PR-findings gap from prior audit is fully closed. |
| P23 | QA Security Tester (Brian Hall) | **COVERED** | S04 AspmCode + S05 AspmApi + `DeveloperSecurityHub` | S04 CodeScanning + IaC + CorrelationEngine provides regression-test security surface. DeveloperSecurityHub PR-Findings tab covers PR gate for QA flows. |
| P13 | Audit Manager (Michael Brown) | **COVERED** | S25 Compliance (5-tab) | AuditorEvidenceHub with Evidence + Frameworks + Period + Export closes the "read-only evidence pack + audit trail + findings export" gap identified in prior audit. |
| P26 | SRE (Security SRE) | **COVERED** | S22 RansomwareMalware + S21 Incidents | S22 `SecurityChaosDashboard` (chaos/FAIL surface) + S12 NetworkSec. S21 `AutomationOrchestrationHub` covers reliability-posture workflows. |

---

### Still PARTIAL (4 personas)

| ID | Persona | Status | Existing S0x Coverage | What's Still Missing |
|----|---------|--------|-----------------------|----------------------|
| P2 | VP Engineering (Marcus Johnson) | PARTIAL | S04 AspmCode, S06 AspmRuntime, S03 MissionControl (SLA tab) | No engineering-velocity-vs-security roll-up view; no CFO/CTO-grade metric dashboard with DORA metrics or team-level security debt. S03 SLA tab is the closest but is ops-focused. |
| P10 | IT Director (Maria Lopez) | PARTIAL | S09 CspmPosture, S10 CloudAccounts, S11 CloudWorkloads, S13 IdentityAccess | No IT ops command centre; no infrastructure SLA/availability view. Coverage is broad but fragmented across 4 screens with no role-entry-point. |
| P15 | Security Data Scientist (Chris Lee) | PARTIAL | S20 Detections (BehaviorAnalytics + Telemetry), S19 ThreatIntel | No ML model dashboard; no custom analytics / query surface (SecurityQueryLanguageDashboard exists as a standalone page but is not embedded in any S0x). |
| P16 | Platform Engineer (Ryan Murphy) | PARTIAL | S29 Integrations (health + connectors), S09 CspmPosture | No SRE-grade health/SLO view; no infra-posture-as-code surface. S31 SettingsAdmin covers admin tasks but not platform engineering workflows. |

---

## S0x → Persona Mapping (full 31-screen index)

| Screen | Title | Primary Personas Served |
|--------|-------|------------------------|
| S01 | Login & Auth | All (onboarding gate) |
| S02 | Onboarding | All (setup) |
| S03 | Mission Control | P1 CISO, P19 SecOps Manager, P2 VP Eng (partial) |
| S04 | ASPM Code | P5 Security Engineer, P6 DevSecOps, P11 AppSec Lead, P22 Supply Chain, P23 QA Tester |
| S05 | ASPM API | P6 DevSecOps, P11 AppSec Lead |
| S06 | ASPM Runtime | P6 DevSecOps, P11 AppSec Lead, P29 Software Architect |
| S07 | Supply Chain | P22 Supply Chain Security, P5 Security Engineer |
| S08 | Secrets & Crypto | P5 Security Engineer, P6 DevSecOps, P11 AppSec Lead |
| S09 | CSPM Posture | P12 Cloud Security Architect, P10 IT Director (partial) |
| S10 | Cloud Accounts | P12 Cloud Security Architect, P10 IT Director (partial) |
| S11 | Cloud Workloads | P12 Cloud Security Architect, P10 IT Director (partial) |
| S12 | Network Security | P12 Cloud Security Architect, P26 SRE |
| S13 | Identity & Access | P12 Cloud Security Architect, P10 IT Director (partial) |
| S14 | Attack Surface | P8 Penetration Tester, P21 Security Architect, P27 Threat Modeler |
| S15 | TrustGraph | P21 Security Architect, P27 Threat Modeler, P29 Software Architect |
| S16 | CTEM Cycles | P1 CISO, P9 Risk Manager, P18 GRC Analyst, P7 Compliance Officer |
| S17 | Findings Explorer | P5 Security Engineer, P9 Risk Manager, P3 SOC Analyst T1 |
| S18 | Risk Acceptance | P9 Risk Manager, P18 GRC Analyst |
| S19 | Threat Intelligence | P17 Threat Intel Analyst, P4 SOC Analyst T2, P27 Threat Modeler, P8 Pen Tester |
| S20 | Detections | P3 SOC T1, P4 SOC T2, P19 SecOps Manager, P15 Data Scientist (partial) |
| S21 | Incidents | P14 Incident Response Lead, P19 SecOps Manager, P30 SecOps Tech Lead, P26 SRE |
| S22 | Ransomware & Malware | P8 Pen Tester, P30 SecOps Tech Lead, P26 SRE |
| S23 | Data Security | P28 DPO, P12 Cloud Security Architect |
| S24 | Privacy | P28 DPO — primary landing |
| S25 | Compliance | P7 Compliance Officer, P13 Audit Manager, P18 GRC Analyst, P25 External Auditor |
| S26 | Vendor Risk | P9 Risk Manager, P22 Supply Chain Security |
| S27 | IoT / OT / Endpoints | P12 Cloud Security Architect, P26 SRE |
| S28 | AI Security | P1 CISO, P15 Data Scientist (partial) |
| S29 | Integrations | P16 Platform Engineer (partial), P6 DevSecOps |
| S30 | Collaboration | P20 Developer/Champion, P23 QA Tester |
| S31 | Settings & Admin | P16 Platform Engineer (partial), P10 IT Director (partial) |

---

## Newly-created hub pages (since 2026-05-05 audit) that closed gaps

| New File | Route | Closes Gap For |
|----------|-------|----------------|
| `src/pages/BoardLandingPage.tsx` | `/board` | P24 Board Member (was MISSING) |
| `src/pages/comply/AuditorEvidenceHub.tsx` | `/comply/auditor` (S25 tab) | P25 External Auditor (was MISSING), P13 Audit Manager (was PARTIAL) |
| `src/pages/DPOPrivacyHub.tsx` | S24 "DPO Hub" tab | P28 DPO (was MISSING) |
| `src/pages/DeveloperSecurityHub.tsx` | `/developer` | P20 Developer (was PARTIAL), P23 QA Tester (was PARTIAL) |

---

## Remaining gaps / recommendations

1. **P2 VP Engineering** — Add an "Engineering Security" tab to S03 MissionControl or S16 CTEM exposing team-level security debt, DORA×security correlation, and engineering velocity vs open findings. Low LOC change; high VP buyer value.

2. **P10 IT Director** — A single "IT Ops" entry tab in S09 CspmPosture composing infra SLA/uptime widgets + asset counts would give this persona a role-filtered landing. No new screen needed.

3. **P15 Security Data Scientist** — Wire `SecurityQueryLanguageDashboard` (already exists as standalone page) into S20 Detections as a 5th "RQL / Analytics" tab. One lazy-import addition.

4. **P16 Platform Engineer** — Wire `SystemHealthDashboard` + `SecurityHealthDashboard` (both exist) into S29 Integrations or a new S32 Platform tab. Low effort, closes the SRE/SLO surface gap.

5. **P24 Board Member** — Add `?read_only=1` RBAC guard to `BoardLandingPage` to suppress write actions for viewer-role sessions. Currently board metrics are correct but action buttons may render inappropriately for the viewer RBAC role.

6. **P28 DPO cross-border tab** — Implement `/api/v1/data-discovery/transfers` endpoint to replace the EmptyState in `DPOPrivacyHub`'s cross-border tab. Data model is straightforward (country, legal mechanism, categories, last review date).

---

## Files referenced

- `docs/persona_hub_coverage_2026-05-05.md` — prior audit baseline
- `suite-ui/aldeci-ui-new/src/pages/v2/S01–S31*.tsx` — all 31 S0x wrapper screens
- `suite-ui/aldeci-ui-new/src/pages/BoardLandingPage.tsx` — P24 board landing
- `suite-ui/aldeci-ui-new/src/pages/comply/AuditorEvidenceHub.tsx` — P25 auditor hub
- `suite-ui/aldeci-ui-new/src/pages/DPOPrivacyHub.tsx` — P28 DPO hub
- `suite-ui/aldeci-ui-new/src/pages/DeveloperSecurityHub.tsx` — P20/P23 developer hub
- `suite-ui/aldeci-ui-new/src/App.tsx` — route wiring verification (line 544: `/board`)
- `tests/test_persona_workflows.py` — canonical 30-persona list
