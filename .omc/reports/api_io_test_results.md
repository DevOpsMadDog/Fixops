# ALDECI API Input/Output Test Results

> Generated: 2026-04-21 13:44:59 UTC
> Server: http://localhost:8000
> Org ID: `default`

---

## Summary

| Metric | Value |
|--------|-------|
| **Total tests** | 124 |
| **Total passing** | 84 / 124 (68%) |
| **GET passing** | 73 / 94 |
| **GET failing** | 21 / 94 |
| **POST passing** | 11 / 30 |
| **POST failing** | 19 / 30 |
| **Avg response time** | 30.1 ms |
| **Min response time** | 3.2 ms |
| **Max response time** | 315.0 ms |

---

## GET Endpoints (Top 100)

| # | Result | Status | Time (ms) | Fields | Has Data | Endpoint | Description |
|---|--------|--------|-----------|--------|----------|----------|-------------|
| 1 | **PASS** | 200 | 3.2 | 6 | Y | `/api/v1/version` | API version |
| 2 | **PASS** | 200 | 11.2 | 4 | Y | `/api/v1/health` | Health check |
| 3 | **PASS** | 200 | 66.6 | 7 | Y | `/api/v1/access-anomaly/anomalies?org_id=default` | Access anomaly list |
| 4 | **FAIL** | 200 | 14.0 | 0 | Y | `/api/v1/access-anomaly/high-risk-users?org_id=default` | High risk users |
| 5 | **PASS** | 200 | 18.0 | 7 | Y | `/api/v1/access-anomaly/summary?org_id=default` | Access anomaly summary |
| 6 | **PASS** | 200 | 76.0 | 577 | Y | `/api/v1/alert-triage/alerts?org_id=default` | Alert triage list |
| 7 | **PASS** | 200 | 17.2 | 50 | Y | `/api/v1/alert-triage/queue?org_id=default` | Alert triage queue |
| 8 | **PASS** | 200 | 17.8 | 7 | Y | `/api/v1/alert-triage/stats?org_id=default` | Alert triage stats |
| 9 | **PASS** | 200 | 19.9 | 6 | Y | `/api/v1/alert-enrichment/?org_id=default` | Alert enrichment list |
| 10 | **FAIL** | 200 | 14.3 | 0 | Y | `/api/v1/alert-enrichment/queue?org_id=default` | Alert enrichment queue |
| 11 | **PASS** | 200 | 15.6 | 6 | Y | `/api/v1/alert-enrichment/summary?org_id=default` | Alert enrichment summary |
| 12 | **FAIL** | 200 | 22.3 | 0 | Y | `/api/v1/alert-enrichment/high-risk?org_id=default` | Alert enrichment high risk |
| 13 | **PASS** | 200 | 114.7 | 33 | Y | `/api/v1/ransomware-protection/detections?org_id=default` | Ransomware detections |
| 14 | **PASS** | 200 | 47.8 | 16 | Y | `/api/v1/ransomware-protection/unvalidated-backups?org_id=default` | Unvalidated backups |
| 15 | **PASS** | 200 | 71.6 | 7 | Y | `/api/v1/ransomware-protection/status?org_id=default` | Ransomware protection status |
| 16 | **PASS** | 200 | 34.8 | 5 | Y | `/api/v1/ransomware-protection/summary?org_id=default` | Ransomware summary |
| 17 | **PASS** | 200 | 38.5 | 7 | Y | `/api/v1/threat-indicators/?org_id=default` | Threat indicators summary |
| 18 | **PASS** | 200 | 29.2 | 32 | Y | `/api/v1/threat-indicators/indicators?org_id=default` | Threat indicators list |
| 19 | **FAIL** | 200 | 44.0 | 0 | Y | `/api/v1/threat-indicators/expired?org_id=default` | Expired indicators |
| 20 | **PASS** | 200 | 32.7 | 7 | Y | `/api/v1/threat-indicators/summary?org_id=default` | Threat indicators summary detail |
| 21 | **PASS** | 200 | 18.4 | 19 | Y | `/api/v1/privacy-impact/assessments?org_id=default` | PIA assessments list |
| 22 | **PASS** | 200 | 14.6 | 6 | Y | `/api/v1/privacy-impact/summary?org_id=default` | PIA summary |
| 23 | **PASS** | 200 | 19.7 | 25 | Y | `/api/v1/training-effectiveness/programs?org_id=default` | Training programs list |
| 24 | **PASS** | 200 | 19.4 | 6 | Y | `/api/v1/training-effectiveness/summary?org_id=default` | Training effectiveness summary |
| 25 | **PASS** | 200 | 315.0 | 8 | Y | `/api/v1/cost-optimization/?org_id=default` | Cost optimization summary |
| 26 | **PASS** | 200 | 18.6 | 16 | Y | `/api/v1/cost-optimization/tools?org_id=default` | Cost optimization tools |
| 27 | **PASS** | 200 | 19.4 | 16 | Y | `/api/v1/cost-optimization/underutilized?org_id=default` | Underutilized tools |
| 28 | **PASS** | 200 | 15.8 | 8 | Y | `/api/v1/cost-optimization/portfolio?org_id=default` | Cost optimization portfolio |
| 29 | **PASS** | 200 | 21.2 | 16 | Y | `/api/v1/cost-optimization/cost-per-risk?org_id=default` | Cost per risk |
| 30 | **PASS** | 200 | 19.5 | 3 | Y | `/api/v1/patch-management/?org_id=default` | Patch management summary |
| 31 | **PASS** | 200 | 20.7 | 9 | Y | `/api/v1/patch-management/patches?org_id=default` | Patches list |
| 32 | **PASS** | 200 | 13.8 | 18 | Y | `/api/v1/patch-management/deployments?org_id=default` | Patch deployments |
| 33 | **PASS** | 200 | 22.8 | 7 | Y | `/api/v1/patch-management/stats?org_id=default` | Patch management stats |
| 34 | **PASS** | 200 | 18.4 | 3 | Y | `/api/v1/vuln-scoring?org_id=default` | Vuln scoring summary |
| 35 | **PASS** | 200 | 18.2 | 3 | Y | `/api/v1/vuln-scoring/scores?org_id=default` | Vuln scores list |
| 36 | **PASS** | 200 | 12.8 | 3 | Y | `/api/v1/vuln-scoring/top?org_id=default` | Top vulnerabilities |
| 37 | **PASS** | 200 | 19.7 | 5 | Y | `/api/v1/vuln-scoring/distribution?org_id=default` | Vuln distribution |
| 38 | **PASS** | 200 | 16.6 | 8 | Y | `/api/v1/security-benchmarks/?org_id=default` | Security benchmarks summary |
| 39 | **PASS** | 200 | 18.5 | 8 | Y | `/api/v1/security-benchmarks/benchmarks?org_id=default` | Benchmarks list |
| 40 | **PASS** | 200 | 37.7 | 6 | Y | `/api/v1/security-benchmarks/summary?org_id=default` | Benchmarks summary |
| 41 | **PASS** | 200 | 28.1 | 5 | Y | `/api/v1/incident-costs/analytics?org_id=default` | Incident cost analytics |
| 42 | **FAIL** | 200 | 13.2 | 0 | Y | `/api/v1/incident-costs/summaries?org_id=default` | Incident cost summaries |
| 43 | **PASS** | 200 | 20.4 | 20 | Y | `/api/v1/digital-twin/twins?org_id=default` | Digital twins list |
| 44 | **PASS** | 200 | 19.0 | 1 | Y | `/api/v1/digital-twin/simulations?org_id=default` | Twin simulations |
| 45 | **PASS** | 200 | 16.8 | 18 | Y | `/api/v1/digital-twin/findings?org_id=default` | Twin findings |
| 46 | **PASS** | 200 | 14.7 | 6 | Y | `/api/v1/digital-twin/stats?org_id=default` | Twin stats |
| 47 | **PASS** | 200 | 20.6 | 26 | Y | `/api/v1/cyber-threat-intel/reports?org_id=default` | CTI reports |
| 48 | **PASS** | 200 | 16.1 | 24 | Y | `/api/v1/cyber-threat-intel/iocs?org_id=default` | CTI IOCs |
| 49 | **PASS** | 200 | 19.3 | 7 | Y | `/api/v1/cyber-threat-intel/stats?org_id=default` | CTI stats |
| 50 | **PASS** | 200 | 21.3 | 3 | Y | `/api/v1/sbom-export/?org_id=default` | SBOM export summary |
| 51 | **PASS** | 200 | 16.6 | 2 | Y | `/api/v1/sbom-export/projects?org_id=default` | SBOM projects |
| 52 | **PASS** | 200 | 17.7 | 2 | Y | `/api/v1/sbom-export/formats?org_id=default` | SBOM formats |
| 53 | **PASS** | 200 | 20.7 | 7 | Y | `/api/v1/identity-lifecycle/?org_id=default` | Identity lifecycle summary |
| 54 | **PASS** | 200 | 17.6 | 4 | Y | `/api/v1/identity-lifecycle/accounts?org_id=default` | Identity accounts |
| 55 | **PASS** | 200 | 15.6 | 6 | Y | `/api/v1/cloud-ir/incidents?org_id=default` | Cloud IR incidents |
| 56 | **PASS** | 200 | 16.7 | 4 | Y | `/api/v1/arch-review/reviews?org_id=default` | Arch reviews list |
| 57 | **PASS** | 200 | 26.0 | 5 | Y | `/api/v1/arch-review/summary?org_id=default` | Arch review summary |
| 58 | **PASS** | 200 | 17.9 | 10 | Y | `/api/v1/hunting-playbooks/playbooks?org_id=default` | Hunting playbooks list |
| 59 | **PASS** | 200 | 21.4 | 6 | Y | `/api/v1/hunting-playbooks/stats?org_id=default` | Hunting playbooks stats |
| 60 | **PASS** | 200 | 25.2 | 2 | Y | `/api/v1/program-maturity/assessments?org_id=default` | Program maturity assessments |
| 61 | **PASS** | 200 | 16.1 | 6 | Y | `/api/v1/program-maturity/summary?org_id=default` | Program maturity summary |
| 62 | **FAIL** | 404 | 21.2 | 2 | Y | `/api/v1/dependency-mapping/components?org_id=default` | Dependency components |
| 63 | **PASS** | 200 | 16.0 | 5 | Y | `/api/v1/dependency-mapping/summary?org_id=default` | Dependency mapping summary |
| 64 | **PASS** | 200 | 14.6 | 23 | Y | `/api/v1/risk-register-engine/risks?org_id=default` | Risk register risks |
| 65 | **FAIL** | 200 | 17.2 | 0 | Y | `/api/v1/risk-register-engine/treatments?org_id=default` | Risk treatments |
| 66 | **PASS** | 200 | 27.3 | 7 | Y | `/api/v1/security-okrs/objectives?org_id=default` | Security OKR objectives |
| 67 | **PASS** | 200 | 19.0 | 36 | Y | `/api/v1/compliance-mapping/controls?org_id=default` | Compliance mapping controls |
| 68 | **PASS** | 200 | 26.5 | 16 | Y | `/api/v1/compliance-mapping/mappings?org_id=default` | Compliance mappings |
| 69 | **PASS** | 200 | 35.5 | 6 | Y | `/api/v1/vuln-scans/scans?org_id=default` | Vuln scans list |
| 70 | **PASS** | 200 | 13.3 | 6 | Y | `/api/v1/vuln-scans/findings?org_id=default` | Vuln scan findings |
| 71 | **PASS** | 200 | 34.3 | 19 | Y | `/api/v1/container-posture/clusters?org_id=default` | Container posture clusters |
| 72 | **PASS** | 200 | 15.9 | 7 | Y | `/api/v1/container-posture/stats?org_id=default` | Container posture stats |
| 73 | **FAIL** | 404 | 30.4 | 2 | Y | `/api/v1/awareness-metrics/trends?org_id=default` | Awareness metrics trends |
| 74 | **FAIL** | 404 | 32.9 | 2 | Y | `/api/v1/awareness-metrics/summary?org_id=default` | Awareness metrics summary |
| 75 | **FAIL** | 200 | 26.6 | 0 | Y | `/api/v1/cloud-cost/anomalies?org_id=default` | Cloud cost anomalies |
| 76 | **FAIL** | 404 | 28.1 | 2 | Y | `/api/v1/cloud-cost/summary?org_id=default` | Cloud cost summary |
| 77 | **FAIL** | 404 | 23.3 | 2 | Y | `/api/v1/health-scorecard/snapshots?org_id=default` | Health scorecard snapshots |
| 78 | **FAIL** | 404 | 13.5 | 2 | Y | `/api/v1/health-scorecard/summary?org_id=default` | Health scorecard summary |
| 79 | **FAIL** | 404 | 22.4 | 2 | Y | `/api/v1/compliance-calendar/events?org_id=default` | Compliance calendar events |
| 80 | **FAIL** | 200 | 27.7 | 0 | Y | `/api/v1/compliance-calendar/overdue?org_id=default` | Overdue compliance events |
| 81 | **PASS** | 200 | 17.3 | 3 | Y | `/api/v1/cyber-resilience/assessments?org_id=default` | Cyber resilience assessments |
| 82 | **FAIL** | 404 | 21.2 | 2 | Y | `/api/v1/cyber-resilience/summary?org_id=default` | Cyber resilience summary |
| 83 | **PASS** | 200 | 26.4 | 20 | Y | `/api/v1/asset-criticality/assets?org_id=default` | Asset criticality list |
| 84 | **PASS** | 200 | 45.2 | 4 | Y | `/api/v1/asset-criticality/summary?org_id=default` | Asset criticality summary |
| 85 | **FAIL** | 404 | 33.7 | 2 | Y | `/api/v1/posture-maturity/assessments?org_id=default` | Posture maturity assessments |
| 86 | **PASS** | 200 | 35.1 | 2 | Y | `/api/v1/posture-maturity/roadmap?org_id=default` | Posture maturity roadmap |
| 87 | **FAIL** | 404 | 35.9 | 2 | Y | `/api/v1/gap-analysis/analyses?org_id=default` | Gap analysis list |
| 88 | **PASS** | 200 | 26.8 | 6 | Y | `/api/v1/gap-analysis/summary?org_id=default` | Gap analysis summary |
| 89 | **PASS** | 200 | 13.7 | 13 | Y | `/api/v1/cloud-findings/findings?org_id=default` | Cloud security findings |
| 90 | **PASS** | 200 | 16.5 | 6 | Y | `/api/v1/cloud-findings/summary?org_id=default` | Cloud findings summary |
| 91 | **FAIL** | 404 | 25.9 | 2 | Y | `/api/v1/vuln-age/vulnerabilities?org_id=default` | Vuln age list |
| 92 | **FAIL** | 404 | 92.0 | 2 | Y | `/api/v1/vuln-age/summary?org_id=default` | Vuln age summary |
| 93 | **FAIL** | 404 | 35.6 | 2 | Y | `/api/v1/threat-response/responses?org_id=default` | Threat response list |
| 94 | **PASS** | 200 | 38.6 | 6 | Y | `/api/v1/threat-response/summary?org_id=default` | Threat response summary |

---

## POST Endpoints (Top 30)

| # | Result | Status | Time (ms) | Fields | Has Data | Endpoint | Description |
|---|--------|--------|-----------|--------|----------|----------|-------------|
| 1 | **PASS** | 200 | 83.7 | 13 | Y | `/api/v1/access-anomaly/events` | Record access event |
| 2 | **PASS** | 200 | 32.5 | 13 | Y | `/api/v1/ransomware-protection/detections` | Register ransomware detection |
| 3 | **PASS** | 200 | 35.9 | 12 | Y | `/api/v1/ransomware-protection/backups` | Register backup |
| 4 | **FAIL** | 422 | 37.1 | 6 | Y | `/api/v1/threat-indicators/indicators?org_id=default` | Add threat indicator |
| 5 | **PASS** | 201 | 33.4 | 13 | Y | `/api/v1/cost-optimization/tools?org_id=default` | Register cost optimization tool |
| 6 | **FAIL** | 422 | 34.1 | 6 | Y | `/api/v1/patch-management/patches?org_id=default` | Register patch |
| 7 | **FAIL** | 422 | 26.2 | 6 | Y | `/api/v1/alert-triage/alerts` | Ingest alert for triage |
| 8 | **FAIL** | 405 | 28.8 | 2 | Y | `/api/v1/alert-enrichment/enrich?org_id=default` | Enrich alert |
| 9 | **PASS** | 201 | 32.9 | 13 | Y | `/api/v1/cyber-threat-intel/reports?org_id=default` | Create CTI report |
| 10 | **FAIL** | 422 | 30.6 | 6 | Y | `/api/v1/digital-twin/twins?org_id=default` | Create digital twin |
| 11 | **FAIL** | 422 | 25.8 | 6 | Y | `/api/v1/security-benchmarks/metrics?org_id=default` | Submit security benchmark metric |
| 12 | **FAIL** | 422 | 26.4 | 6 | Y | `/api/v1/risk-register-engine/risks?org_id=default` | Create risk register entry |
| 13 | **PASS** | 201 | 37.7 | 10 | Y | `/api/v1/security-okrs/objectives?org_id=default` | Create security OKR objective |
| 14 | **PASS** | 200 | 31.8 | 12 | Y | `/api/v1/compliance-mapping/controls?org_id=default` | Add compliance control |
| 15 | **PASS** | 200 | 34.6 | 15 | Y | `/api/v1/identity-lifecycle/accounts?org_id=default` | Provision identity account |
| 16 | **FAIL** | 422 | 27.2 | 6 | Y | `/api/v1/cloud-ir/incidents` | Create cloud IR incident |
| 17 | **FAIL** | 422 | 34.1 | 6 | Y | `/api/v1/arch-review/reviews?org_id=default` | Create architecture review |
| 18 | **FAIL** | 422 | 64.4 | 6 | Y | `/api/v1/hunting-playbooks/playbooks?org_id=default` | Create hunting playbook |
| 19 | **FAIL** | 422 | 17.0 | 6 | Y | `/api/v1/posture-maturity/assessments?org_id=default` | Create posture maturity assessment |
| 20 | **FAIL** | 405 | 27.1 | 2 | Y | `/api/v1/gap-analysis/analyses?org_id=default` | Create gap analysis |
| 21 | **FAIL** | 422 | 49.4 | 6 | Y | `/api/v1/container-posture/clusters?org_id=default` | Register container cluster |
| 22 | **FAIL** | 422 | 41.8 | 6 | Y | `/api/v1/cyber-resilience/assessments?org_id=default` | Create cyber resilience assessment |
| 23 | **PASS** | 201 | 16.3 | 14 | Y | `/api/v1/asset-criticality/assets?org_id=default` | Register asset criticality |
| 24 | **PASS** | 200 | 33.8 | 8 | Y | `/api/v1/health-scorecard/snapshots?org_id=default` | Create health scorecard snapshot |
| 25 | **FAIL** | 422 | 30.5 | 2 | Y | `/api/v1/compliance-calendar/events?org_id=default` | Create compliance calendar event |
| 26 | **FAIL** | 405 | 37.5 | 2 | Y | `/api/v1/cloud-cost/accounts?org_id=default` | Register cloud cost account |
| 27 | **FAIL** | 422 | 30.3 | 6 | Y | `/api/v1/vuln-scans/scans?org_id=default` | Create vulnerability scan |
| 28 | **FAIL** | 422 | 20.7 | 6 | Y | `/api/v1/cloud-findings/findings?org_id=default` | Ingest cloud security finding |
| 29 | **FAIL** | 405 | 34.6 | 2 | Y | `/api/v1/threat-response/responses?org_id=default` | Create threat response |
| 30 | **PASS** | 200 | 33.8 | 8 | Y | `/api/v1/awareness-metrics/metrics?org_id=default` | Record awareness metric |

---

## Failed Endpoints Detail

### `GET /api/v1/access-anomaly/high-risk-users?org_id=default`
- Description: High risk users
- HTTP Status: `200`
- JSON: `True`
- Field count: `0`

### `GET /api/v1/alert-enrichment/queue?org_id=default`
- Description: Alert enrichment queue
- HTTP Status: `200`
- JSON: `True`
- Field count: `0`

### `GET /api/v1/alert-enrichment/high-risk?org_id=default`
- Description: Alert enrichment high risk
- HTTP Status: `200`
- JSON: `True`
- Field count: `0`

### `GET /api/v1/threat-indicators/expired?org_id=default`
- Description: Expired indicators
- HTTP Status: `200`
- JSON: `True`
- Field count: `0`

### `GET /api/v1/incident-costs/summaries?org_id=default`
- Description: Incident cost summaries
- HTTP Status: `200`
- JSON: `True`
- Field count: `0`

### `GET /api/v1/dependency-mapping/components?org_id=default`
- Description: Dependency components
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/risk-register-engine/treatments?org_id=default`
- Description: Risk treatments
- HTTP Status: `200`
- JSON: `True`
- Field count: `0`

### `GET /api/v1/awareness-metrics/trends?org_id=default`
- Description: Awareness metrics trends
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/awareness-metrics/summary?org_id=default`
- Description: Awareness metrics summary
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/cloud-cost/anomalies?org_id=default`
- Description: Cloud cost anomalies
- HTTP Status: `200`
- JSON: `True`
- Field count: `0`

### `GET /api/v1/cloud-cost/summary?org_id=default`
- Description: Cloud cost summary
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/health-scorecard/snapshots?org_id=default`
- Description: Health scorecard snapshots
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/health-scorecard/summary?org_id=default`
- Description: Health scorecard summary
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/compliance-calendar/events?org_id=default`
- Description: Compliance calendar events
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/compliance-calendar/overdue?org_id=default`
- Description: Overdue compliance events
- HTTP Status: `200`
- JSON: `True`
- Field count: `0`

### `GET /api/v1/cyber-resilience/summary?org_id=default`
- Description: Cyber resilience summary
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/posture-maturity/assessments?org_id=default`
- Description: Posture maturity assessments
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/gap-analysis/analyses?org_id=default`
- Description: Gap analysis list
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/vuln-age/vulnerabilities?org_id=default`
- Description: Vuln age list
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/vuln-age/summary?org_id=default`
- Description: Vuln age summary
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `GET /api/v1/threat-response/responses?org_id=default`
- Description: Threat response list
- HTTP Status: `404`
- JSON: `True`
- Field count: `2`

### `POST /api/v1/threat-indicators/indicators?org_id=default`
- Description: Add threat indicator
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/patch-management/patches?org_id=default`
- Description: Register patch
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/alert-triage/alerts`
- Description: Ingest alert for triage
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/alert-enrichment/enrich?org_id=default`
- Description: Enrich alert
- HTTP Status: `405`
- JSON: `True`
- Field count: `2`

### `POST /api/v1/digital-twin/twins?org_id=default`
- Description: Create digital twin
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/security-benchmarks/metrics?org_id=default`
- Description: Submit security benchmark metric
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/risk-register-engine/risks?org_id=default`
- Description: Create risk register entry
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/cloud-ir/incidents`
- Description: Create cloud IR incident
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/arch-review/reviews?org_id=default`
- Description: Create architecture review
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/hunting-playbooks/playbooks?org_id=default`
- Description: Create hunting playbook
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/posture-maturity/assessments?org_id=default`
- Description: Create posture maturity assessment
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/gap-analysis/analyses?org_id=default`
- Description: Create gap analysis
- HTTP Status: `405`
- JSON: `True`
- Field count: `2`

### `POST /api/v1/container-posture/clusters?org_id=default`
- Description: Register container cluster
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/cyber-resilience/assessments?org_id=default`
- Description: Create cyber resilience assessment
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/compliance-calendar/events?org_id=default`
- Description: Create compliance calendar event
- HTTP Status: `422`
- JSON: `True`
- Field count: `2`

### `POST /api/v1/cloud-cost/accounts?org_id=default`
- Description: Register cloud cost account
- HTTP Status: `405`
- JSON: `True`
- Field count: `2`

### `POST /api/v1/vuln-scans/scans?org_id=default`
- Description: Create vulnerability scan
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/cloud-findings/findings?org_id=default`
- Description: Ingest cloud security finding
- HTTP Status: `422`
- JSON: `True`
- Field count: `6`

### `POST /api/v1/threat-response/responses?org_id=default`
- Description: Create threat response
- HTTP Status: `405`
- JSON: `True`
- Field count: `2`

