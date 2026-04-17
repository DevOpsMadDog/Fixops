# PRD — Community 438: Security Playbooks Page (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: IR playbook library — create, execute, and track incident response playbooks with MTTD/MTTR metrics
- **Persona**: Incident Commander, SOC Analyst, Security Engineer
- **ALDECI Pillar**: Incident Response / Playbooks (Legacy)
- **Backend**: `ir_playbook_engine.py` (30 tests), `security_playbook_router.py`

## Architecture Diagram
```mermaid
graph TD
    A[Route: /protect/playbooks] --> B[Playbooks.tsx]
    B --> C[useQuery: playbook list]
    B --> D[useMutation: create/run/pause]
    B --> E[useQueryClient: invalidate]
    B --> F[Playbook card: type/status/steps/MTTD]
    B --> G[Run playbook modal + confirm]
    B --> H[Execution history panel]
    C --> I[GET /api/v1/security-playbooks]
    D --> J[POST /api/v1/security-playbooks/{id}/run]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/pages/protect/Playbooks.tsx:1-70+`
- **Hooks**: useState, useQuery, useMutation, useQueryClient, motion
- **Icons**: ClipboardList, Play, Pause, Plus, RefreshCw, CheckCircle2, Clock, Loader2

## Inter-Dependencies
- **Backend**: `ir_playbook_engine.py` — MTTD/MTTR metrics, execution history
- **Router**: `/api/v1/security-playbooks`
- **Related**: Workflows, Remediation, IncidentTriage

## Data Flow
```
GET /api/v1/security-playbooks → playbook cards →
Run → confirm modal → POST /run →
Execution starts → status: running → complete →
MTTD/MTTR updated in execution history
```

## Acceptance Criteria
- [ ] Playbook list with type/trigger/step count
- [ ] Run button with confirm modal
- [ ] Execution history per playbook
- [ ] MTTD/MTTR displayed post-execution
- [ ] Pause active playbook
- [ ] Create new playbook form

## Effort Estimate
**M** — 2 days (complete, frozen)

## Status
**DONE** — Frozen legacy playbook page
