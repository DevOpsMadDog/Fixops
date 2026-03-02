# Vision Pre-Flight: 2026-03-03

> **Agent**: vision-agent v37
> **Sprint**: Sprint 2 — Enterprise Demo (Day 3 of 5)
> **Days to Demo**: 3

## Sprint Status
- **Items**: 12 total, 11 done (91.7%), 1 in-progress (DEMO-003)
- **Pillars covered**: V3 (4 items), V5 (1 item), V7 (1 item), V8 (1 item demo-only), V9 (1 item), V10 (3 items), V3-UI (1 item in-progress)
- **Vision alignment score**: 0.83 (down from 0.85 — UI architecture drift)
- **Trend**: SLIGHT_DECLINE

## Today's Focus

### Priority 1: Sidebar Restructure (V3 — Demo-Blocking)
- **What**: Rewrite MainLayout.tsx NavSection[] from 8 Technical Suites to 5 Workflow Spaces
- **Why**: CEO Vision Section V mandates 5 spaces: Mission Control, Discover, Validate, Remediate, Comply. Current sidebar shows CODE SUITE, CLOUD SUITE, etc. — this is the #1 demo visual issue.
- **Owner**: frontend-craftsman
- **Directive**: UX Directive #1 in .claude/team-state/ux-directives.md
- **File**: suite-ui/aldeci/src/layouts/MainLayout.tsx lines 80-182

### Priority 2: DEMO-003 UI Wiring (V3 — Last Sprint Item)
- **What**: Wire 6 remaining pages to real APIs: AttackLab, Copilot, DataFabric, IntelligenceHub, RemediationCenter, Settings
- **Why**: "No UI = no revenue" (debate verdict). These are the last mock pages.
- **Owner**: frontend-craftsman

### Priority 3: Math.random() Cleanup (V5 — Data Integrity)
- **What**: Remove Math.random() from MPTEConsole.tsx (15+ instances), KnowledgeGraphExplorer.tsx (2), CloudPosture.tsx (2)
- **Why**: Enterprise demo cannot show randomly generated confidence scores, risk values, and durations. Must use real API data.
- **Owner**: frontend-craftsman

## Flags

### CRITICAL: UI Architecture Score 0.0
Sidebar still uses 8 Technical Suite grouping (CODE SUITE, CLOUD SUITE, ATTACK SUITE, PROTECT SUITE, AI ENGINE, EVIDENCE, FEEDS SUITE). The CEO's "Steve Jobs UI Redesign" vision (Section V) requires 5 Workflow Spaces. UX Directive #1 created and assigned but NOT yet executed. **Demo in 3 days.**

### HIGH: SEC-ADV-001 Key Rotation (2 days old)
OpenAI API key, JWT secret, and API token need rotation. Infrastructure mitigated but keys still exposed. CEO action required.

### MEDIUM: sales-engineer Failed
3/3 retry attempts exhausted (34s total). DEMO-005 already complete so non-blocking. Agent-doctor should investigate root cause.

### LOW: technical-writer Stale Status
Still showing "Running" from 2026-03-02 15:22 (>12h). Likely completed but status file not updated.

## Customer Feedback New
- No new customer feedback items in .claude/team-state/customer-feedback/

## Verified Metrics (2026-03-03)
| Metric | Value | Delta |
|--------|-------|-------|
| Core Pillar LOC (V3+V5+V7) | 10,740 | brain_pipeline +130, autofix +87 |
| Tests collected | 13,674 | +453 |
| Coverage | 19.23% | -0.02pp (gate: 25%) |
| Newman | 475/475 (10th green) | Stable |
| Moat | 95.60% | +6.65pp |
| UI LOC | 41,423 | +4,335 |
| API 200s | 31/32 | self-learning/stats 404 |

## Day 3 Critical Path
```
frontend-craftsman → Sidebar Restructure (P0) → DEMO-003 Wire 6 Pages (P0) → Math.random() Cleanup (P1)
                                                                                ↓
backend-hardener → Fix self-learning/stats 404 (P1)
                                                                                ↓
qa-engineer → Coverage config push toward 25% gate (P1)
```

---
*Produced by vision-agent v37 | Pillar table verified against CEO_VISION.md lines 133-145*
