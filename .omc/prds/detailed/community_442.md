# PRD — Community 442: Cloud Posture Page (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: CSPM dashboard — cloud misconfiguration detection, posture score, compliance findings across AWS/Azure/GCP
- **Persona**: Cloud Security Engineer, CISO
- **ALDECI Pillar**: CSPM / Cloud Security (Legacy)
- **Backend**: `cloud_posture_engine.py` (35 tests), `cloud_security_findings_engine.py`

## Architecture Diagram
```mermaid
graph TD
    A[Route: /cloud/cloud-posture] --> B[CloudPosture.tsx]
    B --> C[useQuery: cloud accounts + findings]
    B --> D[useMutation: remediate finding]
    B --> E[useQueryClient: optimistic update]
    B --> F[Provider tabs: AWS / Azure / GCP]
    B --> G[Posture score gauge per provider]
    B --> H[Findings table: resource/rule/severity/status]
    C --> I[GET /api/v1/cloud-posture]
    D --> J[POST /api/v1/cloud-posture/findings/{id}/remediate]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/pages/cloud/CloudPosture.tsx:1-70+`
- **Hooks**: useState, useQuery, useMutation, useQueryClient, motion
- **Icons**: Cloud, RefreshCw, AlertTriangle, CheckCircle2, Shield, Server, Loader2, Download

## Inter-Dependencies
- **Backend**: `cloud_posture_engine.py` — 35 tests, 6 providers, posture_score ±delta
- **Router**: `/api/v1/cloud-posture`
- **Related**: CloudDrift, CloudGovernance, CloudComplianceDashboard

## Data Flow
```
GET /api/v1/cloud-posture → provider tabs →
Per-provider posture score gauge →
Findings table filtered by provider →
Remediate → POST → optimistic status update →
Score recalculates
```

## Acceptance Criteria
- [ ] Provider tabs: AWS/Azure/GCP/OCI/Alibaba/DigitalOcean
- [ ] Posture score 0-100 per provider
- [ ] Findings by rule/resource/severity
- [ ] Remediate action per finding
- [ ] Download findings as CSV
- [ ] Optimistic UI on remediate

## Effort Estimate
**M** — 2.5 days (complete, frozen)

## Status
**DONE** — Frozen legacy cloud posture page
