# PRD — Community 439: Remediation Center Page (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Finding remediation workflow — assign, track, apply fixes for security findings from all scanners
- **Persona**: Security Engineer, DevOps, Vulnerability Manager
- **ALDECI Pillar**: Remediation / CTEM Stage 5 (Legacy)
- **Backend**: `vulnerability_remediation_engine.py` (8-state lifecycle, SLA)

## Architecture Diagram
```mermaid
graph TD
    A[Route: /protect/remediation or /remediation] --> B[Remediation.tsx]
    B --> C[useSearchParams: finding_id filter from URL]
    B --> D[useQuery: findings + remediation status]
    B --> E[useMutation: apply/assign/close]
    B --> F[useQueryClient: invalidate]
    B --> G[Finding cards: severity + status + assignee]
    B --> H[SLA countdown: days remaining]
    C --> I[GET /api/v1/remediations]
    E --> J[POST /api/v1/remediations/{id}/apply]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/pages/protect/Remediation.tsx:1-70+`
- **Hooks**: useState, useMemo, useCallback, useEffect, useQuery, useMutation, useQueryClient, useSearchParams
- **Icons**: Wrench, RefreshCw, Search, Filter, CheckCircle2, Clock, AlertTriangle, XCircle, User, Shield, Bug, Loader2, GitPullRequest, ExternalLink
- **useSearchParams**: supports deep-link from finding `?finding_id=X`

## Inter-Dependencies
- **Backend**: `vulnerability_remediation_engine.py` — 8-state lifecycle, SLA tracking
- **Router**: `/api/v1/remediations`
- **Deep-link**: Findings pages link directly to remediation with query param

## Data Flow
```
useSearchParams → pre-filter by finding_id if present →
useQuery findings → useMemo sort by severity + SLA →
Apply fix → useMutation → 8-state FSM advances →
GitPullRequest link to fix PR if available
```

## Acceptance Criteria
- [ ] Pre-filtered view when `?finding_id` in URL
- [ ] 8 status states displayed (open/assigned/in_progress/in_review/testing/resolved/verified/closed)
- [ ] SLA countdown per finding
- [ ] Assignee display and reassign action
- [ ] GitPullRequest link for code fixes
- [ ] Bulk status update

## Effort Estimate
**L** — 3 days (complete, frozen)

## Status
**DONE** — Frozen legacy remediation page
