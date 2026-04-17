# PRD — Community 385: Cloud Incident Response Dashboard

## Master Goal Mapping
- **Platform Goal**: Cloud-native incident response across AWS/Azure/GCP — detection, containment, automated playbook execution
- **Persona**: Cloud Security Engineer, Incident Commander, SOC Lead
- **ALDECI Pillar**: Cloud Security / Incident Response
- **Backend Engine**: `suite-core/core/cloud_incident_response_engine.py`

## Architecture Diagram
```mermaid
graph TD
    A[Route: /cloud-ir] --> B[CloudIRDashboard.tsx]
    B --> C[Incident List: provider + type + blast_radius badges]
    B --> D[Response Actions Panel: automated vs manual actions]
    B --> E[Playbook Selector: provider+type matched playbooks]
    B --> F[Timeline: containment_time_mins + resolution_time_mins]
    C --> G[GET /api/v1/cloud-ir]
    G --> H[cloud_incident_response_engine.py]
    H --> I[containment/resolution mins via julianday()]
    H --> J[blast_radius tracking]
    H --> K[playbook execution_count++]
```

## Code Proof
- **File**: `suite-ui/aldeci-ui-new/src/pages/CloudIRDashboard.tsx:1-80+`
- **Providers**: aws (orange), azure (blue), gcp (green) badge map
- **Incident types**: data_exposure, compute_abuse, identity_compromise, misconfiguration
- **Action types**: isolate, revoke_credentials, terminate_instance, revoke_tokens
- **Blast radius**: unknown/low/medium/high/critical color scale
- **Mock data**: 5 incidents, 4 actions, 4 playbooks across AWS/Azure/GCP

## Inter-Dependencies
- **Backend**: `cloud_incident_response_engine.py` — 50 tests, julianday duration calc, blast_radius tracking
- **Router**: `/api/v1/cloud-ir`
- **Related**: SOAR engine, incident_orchestration_engine, playbook system

## Data Flow
```
Incidents list → select incident → filter actions by incident_id →
match playbooks by cloud_provider + incident_type →
execute playbook → execution_count++ → timeline updates
```

## Acceptance Criteria
- [ ] Provider badge color-coded (AWS=orange, Azure=blue, GCP=green)
- [ ] Blast radius badge with severity coloring
- [ ] Actions panel shows automated (SOAR) vs manual (analyst) execution
- [ ] Playbook match by provider + incident_type
- [ ] containment_time_mins shown as "X min" or "Pending"
- [ ] Live API with mock fallback

## Effort Estimate
**M** — 2.5 days (complete)

## Status
**DONE** — Production dashboard
