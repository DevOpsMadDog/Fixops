# ALDECI Product Completion Plan — 2026-05-06

**Prepared for:** Founder / CTO decision-making
**Branch:** `features/intermediate-stage`
**Graph snapshot:** 190,820 nodes / 594,642 edges (refreshed this session)

---

## Header Summary

- **Today's E2E status:** 18 of 30 personas are FULLY COVERED by wired UI hubs. 34 of 48 hubs have all tabs wired to real API calls. The import-to-finding-to-UI pipeline is end-to-end functional for core security workflows (vuln scan, compliance, SOC, cloud posture, supply chain, secrets, identity). The TrustGraph second-brain receives 425 real calls per session across 548 emit-site files, with 87 distinct event topics. Two live WebSocket endpoints exist and the UI hook is production-ready.
- **Biggest gap:** 8 of 48 hubs (17%) are completely unwired — every tab is a static shell with no API call. These 8 hubs cover 4 PARTIAL personas (DevSecOps, VP Eng, AppSec Lead, IT Director) and block the most visually prominent customer-facing workflows: AppSec, compliance coverage, automation/SOAR, and AI-copilot. Additionally, 52 of 253 pages (21%) have zero API calls whatsoever — they render but show nothing real.
- **Next 1 thing to ship:** Wire the 8 NOT_STARTED hubs (24 shell tabs total). Each needs 3 real API calls wired. This single action moves ALDECI from "engine-rich, display-poor" to a product a customer can demo without seeing empty screens. Estimated effort: 1 focused engineering day.

---

## Section 1 — TrustGraph Emit Sites

### What is TrustGraph and why does it matter?

TrustGraph is ALDECI's "second brain" — a knowledge graph that learns from every scan, finding, and engine event. Every time an engine runs (vuln scan, CTEM assessment, threat intel pull, etc.), it fires an event into TrustGraph. TrustGraph then cross-correlates across domains: a finding in a container engine can be linked to a policy engine event, enriched with threat intel, and surfaced to the UI in real time. This is ALDECI's core differentiator vs Snyk/Apiiro — it's not just a scanner, it's a live security knowledge graph.

### Current Inventory

| Metric | Count |
|--------|-------|
| Files with TrustGraph emit calls | 548 |
| Total individual emit calls | 425 |
| Distinct event topic names | 87 |
| "engine.loaded" events (startup heartbeats) | 97 of 425 — these are NOT meaningful events |
| Meaningful operational events | ~328 |

### Key Event Topics (the ones that matter to customers)

| Topic | Count | What It Means |
|-------|-------|---------------|
| `engine.loaded` | 97 | Engine startup heartbeat — informational only, no customer value |
| `finding.created` | 6 | A security finding was discovered — highest customer value |
| `finding.updated` | 4 | Finding status changed (e.g. remediated, accepted) |
| `asset.discovered` | 3 | New asset found in inventory |
| `rasp.attack_detected` | 1 | Runtime attack blocked |
| `vuln_lifecycle.transitioned` | 1 | Vuln moved through workflow stages |
| `self_scan.completed` | 1 | ALDECI finished scanning itself |
| `waf.rules_generated` | 1 | WAF virtual patch created from a finding |
| `purple_team.exercise_completed` | 1 | Offensive simulation finished |
| `sla_manager.finding_tracked` | 1 | SLA timer started on a finding |
| `pentest_manager.engagement_created` | 1 | Pentest engagement opened |
| (+ 76 more unique topics) | various | Coverage spans compliance, identity, network, cloud, secrets |

### The "engine.loaded" Problem

97 of 425 emit calls (23%) are `engine.loaded` heartbeats that fire on every engine import. These flood the event bus with noise, making it harder for the UI's live feed to surface meaningful events. When a customer looks at the live event stream, they see mostly "engine loaded" messages rather than actual security findings.

**Fix needed:** Filter `engine.loaded` out of the UI's `LiveEventFeed` component, or exclude it at the WebSocket router level (`ws_events_router.py`).

---

## Section 2 — TrustGraph to UI Consumer Mapping

### How Events Reach the UI

There are two WebSocket endpoints:

1. `/api/v1/ws/events` — unified security event stream (`ws_events_router.py`). The UI's `useWebSocket` hook connects here. Supports event-type filtering, org scoping, ping/pong keepalive, and exponential backoff reconnect. **This is production-ready.**

2. `/ws/events` — TrustGraph-specific stream (`ws_trustgraph_events_router.py`). Streams raw TrustGraph bus events. The UI's `api.ts` references this endpoint but no page component actually subscribes to it yet.

### UI Components That Use Live Events

| Component | Where Used | Topics Consumed | Status |
|-----------|------------|-----------------|--------|
| `useWebSocket` hook | `LiveEventStream`, `LiveEventFeed` | all types, filterable | WIRED — hook exists, auth via query param |
| `LiveEventFeed` widget | Shared component | `alert`, `finding`, `incident` | WIRED — connects to `/api/v1/ws/events` |
| `LiveEventStream` component | Shared component | configurable `eventTypes` prop | WIRED |
| `Tour.tsx` | Demo/onboarding tour page | SSE stream from `/api/v1/stream/events` | WIRED — SSE consumer for animated pipeline demo |
| `FindingsExplorer.tsx` | Findings hub | TrustGraph cross-domain correlation (`/api/v1/trustgraph/query`) | WIRED — REST polling, not live stream |
| `/ws/events` TrustGraph stream | Referenced in `api.ts` | Raw TrustGraph events | ORPHAN — defined but no page subscribes |

### Orphan Events (emitted but never displayed)

The following event topics are emitted by engines but have no dedicated UI consumer — they flow into TrustGraph but never surface on any page:

- `waf.virtual_patch_generated` / `waf.rules_generated` — WAF virtual patches created, never shown in UI
- `purple_team.exercise_completed` / `purple_team.report_generated` — Red team results, not surfaced
- `rasp.attack_detected` — Runtime attacks blocked, no live UI indicator
- `vuln_lifecycle.transitioned` — Vuln workflow state changes, no pipeline view consuming this
- `vendor_risk.assessed` — Vendor risk scores, no dedicated consumer
- `sla_manager.finding_tracked` — SLA timers, not shown on findings detail
- `pentest_manager.engagement_created/updated` — Pentest status, not in UI
- All `cache.*`, `queue_manager.*`, `session_manager.*` events — Internal plumbing, appropriately invisible

**Bottom line:** The 6 finding/asset/vuln events that matter most to customers ARE being emitted. The WebSocket infrastructure IS wired. The gap is not the plumbing — it is that only 2 shared components consume live events, and the `/ws/events` TrustGraph stream has zero page-level subscribers. Customers see real data only when they navigate to a page with a REST poll; they do not get pushed notifications on findings as they arrive.

---

## Section 3 — Persona x Hub Status

### Summary Numbers

| Category | Count | Notes |
|----------|-------|-------|
| Total personas | 30 | Verified against `tests/test_persona_workflows.py` |
| COVERED (3+ wired hubs serve the role) | 18 | Working end-to-end for their core tasks |
| PARTIAL (1-2 hubs, functional gaps) | 8 | Can do some tasks but missing key views |
| MISSING (no dedicated surface) | 4 | Persona has no hub at all |
| Total hubs | 48 | All `*Hub.tsx` files |
| Hubs DONE (all tabs wired to real APIs) | 34 | 71% complete |
| Hubs PARTIAL (some tabs wired) | 6 | Need 1-2 more tabs wired each |
| Hubs NOT_STARTED (all tabs shell) | 8 | Zero API calls — pure static display |
| Total hub tabs | 168 | Across all 48 hubs |
| Wired tabs | 135 | 80% |
| Shell tabs | 33 | 20% — look real but return no data |
| Non-hub pages with no API calls | 52 | Out of 253 total pages |
| Pages with mock data patterns remaining | 6 | Down from higher count after session cleanup |

### The 18 WORKING Personas (end-to-end functional)

These personas can log in, navigate to their hubs, and see real data from real API calls:

P1 CISO, P3 SOC Analyst T1, P4 SOC Analyst T2, P5 Security Engineer, P6 DevSecOps Engineer, P7 Compliance Officer, P8 Penetration Tester, P11 AppSec Lead, P12 Cloud Security Architect, P14 Incident Response Lead, P17 Threat Intel Analyst, P18 GRC Analyst, P19 SecOps Manager, P21 Security Architect, P22 Supply Chain Security, P27 Threat Modeler, P30 SecOps Tech Lead.

Smoke-tested this session: P5 Compliance Officer (PASS — 4 pages, real API calls confirmed), P28 DPO (PASS — all tabs functional, API contracts verified).

### The 8 PARTIAL Personas (can do some tasks, blocked on others)

| Persona | What Works | What Is Broken / Missing |
|---------|------------|--------------------------|
| P2 VP Engineering | Dev view, AppLayerSecurityHub | No engineering-velocity-vs-security metric; AppLayerSecurityHub is NOT_STARTED (all tabs shell) |
| P10 IT Director | AssetInventoryHub, CloudPostureUnifiedHub | No IT ops command center; infrastructure SLA view missing |
| P13 Audit Manager | ComplianceCoverageHub, MaturityHub | ComplianceCoverageHub is NOT_STARTED; no evidence export workflow |
| P15 Security Data Scientist | BehaviorAnalyticsHub | No ML model dashboard; no custom analytics surface |
| P16 Platform Engineer | AirGapHub | AutomationOrchestrationHub is NOT_STARTED; no SRE health view |
| P20 Developer / Champion | Dev view, DeveloperPortal | No PR-linked findings; no IDE gateway entry point |
| P23 QA Security Tester | VulnLifecyclePipelineHub | AppLayerSecurityHub shell tabs block mobile/browser testing view |
| P26 SRE | NetworkMonitoringHub | AutomationOrchestrationHub is NOT_STARTED |

### The 4 MISSING Personas (no dedicated surface)

| Persona | Gap | Quick Fix |
|---------|-----|-----------|
| P24 Board Member | No board-briefing view. BRSExecutiveDashboard is partial but not a 1-page board brief. | Wire FinanceHub's executive summary tab as a board-specific entry; or add a `/board` route that filters existing data to top-3 risks + compliance % + dollar exposure |
| P25 External Auditor | No read-only evidence bundle. ComplianceCoverageHub is internal-staff-facing, not locked to auditor view. | Add auditor RBAC scope to ComplianceCoverageHub + SOC2/ISO export tab |
| P28 DPO | Previously MISSING — smoke test this session confirmed it is now FUNCTIONAL via PrivacyComplianceHub. Update status: COVERED. | Already done |
| P29 Software Architect | ThreatModelingHub exists but all 3 tabs are shell (NOT_STARTED). No code-to-cloud traceability. | Wire ThreatModelingHub's 3 tabs — this is the entire fix |

**Note:** P28 DPO should be reclassified from MISSING to COVERED based on smoke test results from this session (p28_verdict.md confirms all tabs functional).

### The 8 NOT_STARTED Hubs (highest priority to wire)

These hubs render a UI but make zero real API calls — they are the most visible "broken windows" a customer would encounter:

| Hub | Tabs to Wire | Personas Blocked | Why It Matters |
|-----|-------------|------------------|----------------|
| AppLayerSecurityHub | web, mobile, browser | P2, P6, P11, P23 | SAST/DAST/AppSec is core product differentiator |
| ComplianceCoverageHub | gaps, cloud, endpoint | P7, P13, P18 | Compliance is the #1 buyer use case for SMB |
| ThreatModelingHub | (3 tabs) | P21, P27, P29 | Blocks Software Architect persona entirely |
| AutomationOrchestrationHub | patch, prioritize, soar | P16, P26 | SOAR/automation is P1 requirement for SecOps managers |
| ExceptionsHub | exceptions, workflow, auto-rules | P5, P11 | Vuln exception management is daily-use workflow |
| IncidentExtensionsHub | (3 tabs) | P14, P19 | Incident response extensions for IR lead persona |
| EmailThreatProtectionHub | email, phishing, ransomware | P3, P4 | Email threats are the #1 attack vector SOC sees |
| AICopilotAgentsHub | console, tasks, shadow | All personas | AI copilot is a demo centerpiece — currently empty |

---

## Section 4 — Priority Roadmap

### P0 — Ships Customer Value Next (do this week, in this order)

**P0.1 — Wire the 8 NOT_STARTED hubs (24 shell tabs)**

This is the single highest-ROI action available. Each hub needs ~3 API endpoint bindings. The backend endpoints already exist (we have 798 routers). The UI framework (DashboardLayout, tab components, useQuery pattern) is already proven in 34 working hubs. This is pure wiring work, not new feature development.

- AppLayerSecurityHub: wire `/api/v1/sast/findings`, `/api/v1/dast/scans`, `/api/v1/mobile-security/findings`
- ComplianceCoverageHub: wire `/api/v1/compliance-gaps`, `/api/v1/cloud-compliance/posture`, `/api/v1/endpoint-compliance/summary`
- ThreatModelingHub: wire `/api/v1/threat-modeling/diagrams`, `/api/v1/mitre-attack/coverage`, `/api/v1/attack-surface/summary`
- AutomationOrchestrationHub: wire `/api/v1/patch-management/queue`, `/api/v1/vuln-prioritization/recommendations`, `/api/v1/soar/playbooks`
- ExceptionsHub: wire `/api/v1/exceptions`, `/api/v1/exceptions/workflows`, `/api/v1/exception-rules`
- IncidentExtensionsHub: wire `/api/v1/incidents/extensions`, `/api/v1/playbooks`, `/api/v1/runbooks`
- EmailThreatProtectionHub: wire `/api/v1/email-filtering/events`, `/api/v1/phishing/detections`, `/api/v1/ransomware/alerts`
- AICopilotAgentsHub: wire `/api/v1/ai-agents/status`, `/api/v1/ai-agents/tasks`, `/api/v1/ai-agents/shadow`

**P0.2 — Filter `engine.loaded` from live event stream**

In `ws_events_router.py` or `ws_trustgraph_events_router.py`, add a one-line filter to drop `engine.loaded` events before they reach the WebSocket subscriber. Currently 23% of all TrustGraph traffic is startup noise. This makes the live feed actually useful as a security signal rather than a log file.

**P0.3 — Board Member persona entry point**

P24 Board Member has zero dedicated surface and is the persona most likely to be in a sales demo room. The data already exists: FinanceHub, RiskQuantHub, StrategicPostureHub all have wired tabs. The fix is a new `/board` route (or `/?view=board`) that pulls a filtered view: top-3 risks, compliance %, MTTR, dollar exposure from RiskQuantHub. One component, no new APIs.

### P1 — Polish (1 week, after P0 ships)

**P1.1 — Partially wired hubs: close remaining shell tabs**

Six hubs are PARTIAL — most tabs work but 1-2 tabs are shell. Fix in priority order:
- DataDiscoveryHub (2 shell tabs — blocks DPO/P28 data lineage view)
- IdentityGovernanceHub (2 shell tabs — blocks P9 Risk Manager identity risk view)
- VulnIntelHub (2 shell tabs — blocks P5 / P11 vuln intelligence)
- DeceptionHub, ForensicsHub, WebhookIngestionHub (1 shell tab each — lower traffic)

**P1.2 — Push findings to UI in real time via WebSocket**

The `useWebSocket` hook and `LiveEventFeed` component are production-ready. TrustGraph emits `finding.created` events. The gap is that no hub page subscribes to the live stream — every page polls REST endpoints on a timer instead. Wire `useWebSocket({ eventTypes: ["finding"] })` into FindingsExplorer so new findings appear without a page refresh. This makes ALDECI feel live rather than static.

**P1.3 — Wire `/ws/events` TrustGraph stream to at least one hub**

The TrustGraph WebSocket endpoint (`ws_trustgraph_events_router.py`) exists and is mounted, but no UI page subscribes to it. Wire it into the BrainVisualization page or a new "TrustGraph Live" tab in StrategicPostureHub to give customers visibility into the second-brain receiving events in real time. This demonstrates the multi-LLM consensus / Brain Pipeline visually — a key differentiator in demos.

**P1.4 — External Auditor scoped view**

Add RBAC-scoped rendering to ComplianceCoverageHub: when the logged-in user has `viewer` role and `external_auditor` tag, show only the evidence bundle, export buttons, and finding history — hide internal admin controls. No new pages, just conditional rendering based on role.

### P2 — Defer (not this sprint)

The following are real work but do not move the needle on customer value in the next two weeks:

- More TrustGraph wiring (emit-sites are at 548 — 38% coverage per CLAUDE.md; pushing to 60-70% is valuable but does not affect what customers see today)
- Additional OWASP hardening sweeps on suite-core (important for security, not for demo readiness)
- More DPO pairs / LLM distillation (Phase 2 at 52% threshold — let it accumulate naturally)
- Performance optimizations on endpoints already under 200ms
- Expanding the Beast Mode test suite beyond 1078 passing tests
- Competitive gap analysis updates (Phase 2 is done at 83% WIN/MATCH — do not re-run)
- Any new pages or new hubs (the founder directive: NO MORE SCREENS — consolidate)

---

## Appendix: Quick-Reference Counts

| Item | Count |
|------|-------|
| TrustGraph emit-site files | 548 |
| Distinct event topics emitted | 87 |
| Orphan topics (emitted, no UI consumer) | ~70 of 87 (only `finding.*`, `alert`, `incident` consumed by LiveEventFeed) |
| Working E2E personas | 18 of 30 (60%), updated to 19 after P28 DPO reclassification |
| Shell-only hubs | 8 NOT_STARTED + 6 PARTIAL = 14 hubs with gaps |
| Remaining mock-data pages | 6 |
| Backend engines | 463 |
| API routers | 798 |
| Beast Mode tests passing | 1,078+ |
| P0 items to ship | 3 (wire 8 hubs + filter engine.loaded + board persona view) |
