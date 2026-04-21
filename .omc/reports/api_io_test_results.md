# ALDECI API Input/Output Test Results

> Generated: 2026-04-21 13:56:43 UTC
> Server: http://localhost:8000
> Org ID: `default`

---

## Summary

| Metric | Value |
|--------|-------|
| **Total tests** | 137 |
| **Total passing** | 137 / 137 (100%) |
| **GET passing** | 107 / 107 |
| **GET failing** | 0 / 107 |
| **POST passing** | 30 / 30 |
| **POST failing** | 0 / 30 |
| **Avg response time** | 33.1 ms |
| **Min response time** | 3.9 ms |
| **Max response time** | 102.8 ms |

---

## GET Endpoints (107 tested)

| # | Result | Status | Time (ms) | Fields | Endpoint | Description |
|---|--------|--------|-----------|--------|----------|-------------|
| 1 | **PASS** | 200 | 3.9 | 6 | `/api/v1/version` | API version |
| 2 | **PASS** | 200 | 7.4 | 4 | `/api/v1/health` | Health check |
| 3 | **PASS** | 200 | 76.1 | 7 | `/api/v1/access-anomaly/anomalies?org_id=default` | Access anomaly list |
| 4 | **PASS** | 200 | 36.0 | 0 | `/api/v1/access-anomaly/high-risk-users?org_id=default` | High risk users |
| 5 | **PASS** | 200 | 36.3 | 7 | `/api/v1/access-anomaly/summary?org_id=default` | Access anomaly summary |
| 6 | **PASS** | 200 | 46.1 | 628 | `/api/v1/alert-triage/alerts?org_id=default` | Alert triage list |
| 7 | **PASS** | 200 | 48.7 | 50 | `/api/v1/alert-triage/queue?org_id=default` | Alert triage queue |
| 8 | **PASS** | 200 | 25.1 | 7 | `/api/v1/alert-triage/stats?org_id=default` | Alert triage stats |
| 9 | **PASS** | 200 | 34.4 | 6 | `/api/v1/alert-enrichment/?org_id=default` | Alert enrichment list |
| 10 | **PASS** | 200 | 41.4 | 0 | `/api/v1/alert-enrichment/queue?org_id=default` | Alert enrichment queue |
| 11 | **PASS** | 200 | 23.1 | 6 | `/api/v1/alert-enrichment/summary?org_id=default` | Alert enrichment summary |
| 12 | **PASS** | 200 | 29.4 | 0 | `/api/v1/alert-enrichment/high-risk?org_id=default` | Alert enrichment high risk |
| 13 | **PASS** | 200 | 37.6 | 37 | `/api/v1/ransomware-protection/detections?org_id=default` | Ransomware detections |
| 14 | **PASS** | 200 | 34.3 | 20 | `/api/v1/ransomware-protection/unvalidated-backups?org_id=default` | Unvalidated backups |
| 15 | **PASS** | 200 | 31.4 | 7 | `/api/v1/ransomware-protection/status?org_id=default` | Ransomware protection status |
| 16 | **PASS** | 200 | 31.2 | 5 | `/api/v1/ransomware-protection/summary?org_id=default` | Ransomware summary |
| 17 | **PASS** | 200 | 36.4 | 7 | `/api/v1/threat-indicators/?org_id=default` | Threat indicators root |
| 18 | **PASS** | 200 | 22.3 | 33 | `/api/v1/threat-indicators/indicators?org_id=default` | Threat indicators list |
| 19 | **PASS** | 200 | 14.1 | 0 | `/api/v1/threat-indicators/expired?org_id=default` | Expired indicators |
| 20 | **PASS** | 200 | 31.0 | 7 | `/api/v1/threat-indicators/summary?org_id=default` | Threat indicators summary |
| 21 | **PASS** | 200 | 20.0 | 19 | `/api/v1/privacy-impact/assessments?org_id=default` | PIA assessments list |
| 22 | **PASS** | 200 | 78.3 | 6 | `/api/v1/privacy-impact/summary?org_id=default` | PIA summary |
| 23 | **PASS** | 200 | 35.9 | 25 | `/api/v1/training-effectiveness/programs?org_id=default` | Training programs list |
| 24 | **PASS** | 200 | 19.2 | 6 | `/api/v1/training-effectiveness/summary?org_id=default` | Training effectiveness summary |
| 25 | **PASS** | 200 | 27.6 | 8 | `/api/v1/cost-optimization/?org_id=default` | Cost optimization summary |
| 26 | **PASS** | 200 | 31.0 | 20 | `/api/v1/cost-optimization/tools?org_id=default` | Cost optimization tools |
| 27 | **PASS** | 200 | 34.0 | 20 | `/api/v1/cost-optimization/underutilized?org_id=default` | Underutilized tools |
| 28 | **PASS** | 200 | 37.9 | 8 | `/api/v1/cost-optimization/portfolio?org_id=default` | Cost optimization portfolio |
| 29 | **PASS** | 200 | 30.4 | 20 | `/api/v1/cost-optimization/cost-per-risk?org_id=default` | Cost per risk |
| 30 | **PASS** | 200 | 33.2 | 3 | `/api/v1/patch-management/?org_id=default` | Patch management summary |
| 31 | **PASS** | 200 | 28.2 | 10 | `/api/v1/patch-management/patches?org_id=default` | Patches list |
| 32 | **PASS** | 200 | 31.1 | 18 | `/api/v1/patch-management/deployments?org_id=default` | Patch deployments |
| 33 | **PASS** | 200 | 35.6 | 7 | `/api/v1/patch-management/stats?org_id=default` | Patch management stats |
| 34 | **PASS** | 200 | 21.6 | 3 | `/api/v1/vuln-scoring?org_id=default` | Vuln scoring summary |
| 35 | **PASS** | 200 | 70.3 | 3 | `/api/v1/vuln-scoring/scores?org_id=default` | Vuln scores list |
| 36 | **PASS** | 200 | 37.2 | 3 | `/api/v1/vuln-scoring/top?org_id=default` | Top vulnerabilities |
| 37 | **PASS** | 200 | 25.3 | 5 | `/api/v1/vuln-scoring/distribution?org_id=default` | Vuln distribution |
| 38 | **PASS** | 200 | 83.2 | 8 | `/api/v1/security-benchmarks/?org_id=default` | Security benchmarks root |
| 39 | **PASS** | 200 | 51.8 | 8 | `/api/v1/security-benchmarks/benchmarks?org_id=default` | Benchmarks list |
| 40 | **PASS** | 200 | 29.8 | 6 | `/api/v1/security-benchmarks/summary?org_id=default` | Benchmarks summary |
| 41 | **PASS** | 200 | 27.8 | 5 | `/api/v1/incident-costs/analytics?org_id=default` | Incident cost analytics |
| 42 | **PASS** | 200 | 36.4 | 0 | `/api/v1/incident-costs/summaries?org_id=default` | Incident cost summaries |
| 43 | **PASS** | 200 | 32.6 | 20 | `/api/v1/digital-twin/twins?org_id=default` | Digital twins list |
| 44 | **PASS** | 200 | 31.8 | 1 | `/api/v1/digital-twin/simulations?org_id=default` | Twin simulations |
| 45 | **PASS** | 200 | 33.3 | 18 | `/api/v1/digital-twin/findings?org_id=default` | Twin findings |
| 46 | **PASS** | 200 | 30.9 | 6 | `/api/v1/digital-twin/stats?org_id=default` | Twin stats |
| 47 | **PASS** | 200 | 25.1 | 30 | `/api/v1/cyber-threat-intel/reports?org_id=default` | CTI reports |
| 48 | **PASS** | 200 | 36.0 | 24 | `/api/v1/cyber-threat-intel/iocs?org_id=default` | CTI IOCs |
| 49 | **PASS** | 200 | 13.4 | 7 | `/api/v1/cyber-threat-intel/stats?org_id=default` | CTI stats |
| 50 | **PASS** | 200 | 18.3 | 3 | `/api/v1/sbom-export/?org_id=default` | SBOM export summary |
| 51 | **PASS** | 200 | 33.4 | 2 | `/api/v1/sbom-export/projects?org_id=default` | SBOM projects |
| 52 | **PASS** | 200 | 21.2 | 2 | `/api/v1/sbom-export/formats?org_id=default` | SBOM formats |
| 53 | **PASS** | 200 | 35.0 | 7 | `/api/v1/identity-lifecycle/?org_id=default` | Identity lifecycle summary |
| 54 | **PASS** | 200 | 26.4 | 9 | `/api/v1/identity-lifecycle/accounts?org_id=default` | Identity accounts |
| 55 | **PASS** | 200 | 38.1 | 7 | `/api/v1/cloud-ir/incidents?org_id=default` | Cloud IR incidents |
| 56 | **PASS** | 200 | 54.7 | 0 | `/api/v1/cloud-ir/playbooks?org_id=default` | Cloud IR playbooks |
| 57 | **PASS** | 200 | 49.2 | 6 | `/api/v1/cloud-ir/metrics?org_id=default` | Cloud IR metrics |
| 58 | **PASS** | 200 | 32.7 | 5 | `/api/v1/arch-review/reviews?org_id=default` | Arch reviews list |
| 59 | **PASS** | 200 | 41.6 | 5 | `/api/v1/arch-review/summary?org_id=default` | Arch review summary |
| 60 | **PASS** | 200 | 32.9 | 11 | `/api/v1/hunting-playbooks/playbooks?org_id=default` | Hunting playbooks list |
| 61 | **PASS** | 200 | 37.2 | 6 | `/api/v1/hunting-playbooks/stats?org_id=default` | Hunting playbooks stats |
| 62 | **PASS** | 200 | 25.9 | 4 | `/api/v1/program-maturity/assessments?org_id=default` | Program maturity assessments |
| 63 | **PASS** | 200 | 26.9 | 6 | `/api/v1/program-maturity/summary?org_id=default` | Program maturity summary |
| 64 | **PASS** | 200 | 29.6 | 0 | `/api/v1/program-maturity/roadmap?org_id=default` | Program maturity roadmap |
| 65 | **PASS** | 200 | 23.5 | 5 | `/api/v1/dependency-mapping/summary?org_id=default` | Dependency mapping summary |
| 66 | **PASS** | 200 | 33.9 | 23 | `/api/v1/risk-register-engine/risks?org_id=default` | Risk register risks |
| 67 | **PASS** | 200 | 17.9 | 0 | `/api/v1/risk-register-engine/treatments?org_id=default` | Risk treatments |
| 68 | **PASS** | 200 | 31.0 | 13 | `/api/v1/security-okrs/objectives?org_id=default` | Security OKR objectives |
| 69 | **PASS** | 200 | 29.7 | 41 | `/api/v1/compliance-mapping/controls?org_id=default` | Compliance mapping controls |
| 70 | **PASS** | 200 | 31.5 | 16 | `/api/v1/compliance-mapping/mappings?org_id=default` | Compliance mappings |
| 71 | **PASS** | 200 | 34.7 | 8 | `/api/v1/vuln-scans/scans?org_id=default` | Vuln scans list |
| 72 | **PASS** | 200 | 35.5 | 6 | `/api/v1/vuln-scans/findings?org_id=default` | Vuln scan findings |
| 73 | **PASS** | 200 | 32.7 | 7 | `/api/v1/vuln-scans/stats?org_id=default` | Vuln scan stats |
| 74 | **PASS** | 200 | 32.3 | 21 | `/api/v1/container-posture/clusters?org_id=default` | Container posture clusters |
| 75 | **PASS** | 200 | 33.5 | 7 | `/api/v1/container-posture/stats?org_id=default` | Container posture stats |
| 76 | **PASS** | 200 | 37.1 | 85 | `/api/v1/awareness-metrics/metrics?org_id=default` | Awareness metrics list |
| 77 | **PASS** | 200 | 18.0 | 8 | `/api/v1/awareness-metrics/metrics/latest?org_id=default&metric_type=phis` | Awareness metrics latest |
| 78 | **PASS** | 200 | 36.7 | 5 | `/api/v1/awareness-metrics/metrics/trend?org_id=default&metric_type=phish` | Awareness metrics trend |
| 79 | **PASS** | 200 | 27.6 | 6 | `/api/v1/awareness-metrics/stats?org_id=default` | Awareness metrics stats |
| 80 | **PASS** | 200 | 22.7 | 0 | `/api/v1/awareness-metrics/benchmarks?org_id=default` | Awareness benchmarks |
| 81 | **PASS** | 200 | 30.3 | 12 | `/api/v1/cloud-cost/snapshots?org_id=default` | Cloud cost snapshots |
| 82 | **PASS** | 200 | 26.5 | 0 | `/api/v1/cloud-cost/anomalies?org_id=default` | Cloud cost anomalies |
| 83 | **PASS** | 200 | 24.7 | 7 | `/api/v1/cloud-cost/stats?org_id=default` | Cloud cost security stats |
| 84 | **PASS** | 200 | 20.6 | 0 | `/api/v1/cloud-cost/budgets?org_id=default` | Cloud cost budgets |
| 85 | **PASS** | 200 | 36.1 | 3 | `/api/v1/health-scorecard?org_id=default` | Health scorecard overview |
| 86 | **PASS** | 200 | 38.6 | 3 | `/api/v1/health-scorecard/current?org_id=default` | Health scorecard current |
| 87 | **PASS** | 200 | 35.4 | 5 | `/api/v1/health-scorecard/history?org_id=default` | Health scorecard history |
| 88 | **PASS** | 200 | 36.6 | 5 | `/api/v1/health-scorecard/grade-trend?org_id=default` | Health scorecard grade trend |
| 89 | **PASS** | 200 | 32.0 | 5 | `/api/v1/compliance-calendar/?org_id=default` | Compliance calendar summary |
| 90 | **PASS** | 200 | 32.3 | 0 | `/api/v1/compliance-calendar/upcoming?org_id=default` | Upcoming compliance events |
| 91 | **PASS** | 200 | 29.7 | 0 | `/api/v1/compliance-calendar/overdue?org_id=default` | Overdue compliance events |
| 92 | **PASS** | 200 | 39.0 | 3 | `/api/v1/cyber-resilience/assessments?org_id=default` | Cyber resilience assessments |
| 93 | **PASS** | 200 | 19.0 | 3 | `/api/v1/cyber-resilience/score?org_id=default` | Cyber resilience score |
| 94 | **PASS** | 200 | 14.1 | 25 | `/api/v1/asset-criticality/assets?org_id=default` | Asset criticality list |
| 95 | **PASS** | 200 | 27.5 | 4 | `/api/v1/asset-criticality/summary?org_id=default` | Asset criticality summary |
| 96 | **PASS** | 200 | 30.5 | 3 | `/api/v1/posture-maturity/overview?org_id=default` | Posture maturity overview |
| 97 | **PASS** | 200 | 24.4 | 10 | `/api/v1/posture-maturity/domains?org_id=default` | Posture maturity domains |
| 98 | **PASS** | 200 | 37.4 | 2 | `/api/v1/posture-maturity/roadmap?org_id=default` | Posture maturity roadmap |
| 99 | **PASS** | 200 | 38.8 | 2 | `/api/v1/gap-analysis/assessments?org_id=default` | Gap analysis list |
| 100 | **PASS** | 200 | 28.0 | 6 | `/api/v1/gap-analysis/summary?org_id=default` | Gap analysis summary |
| 101 | **PASS** | 200 | 24.0 | 14 | `/api/v1/cloud-findings/findings?org_id=default` | Cloud security findings |
| 102 | **PASS** | 200 | 18.0 | 6 | `/api/v1/cloud-findings/summary?org_id=default` | Cloud findings summary |
| 103 | **PASS** | 200 | 41.4 | 5 | `/api/v1/vuln-age/distribution?org_id=default` | Vuln age distribution |
| 104 | **PASS** | 200 | 24.1 | 3 | `/api/v1/vuln-age/sla-compliance?org_id=default` | Vuln SLA compliance |
| 105 | **PASS** | 200 | 36.9 | 6 | `/api/v1/threat-response/?org_id=default` | Threat response summary |
| 106 | **PASS** | 200 | 34.4 | 3 | `/api/v1/threat-response/playbooks/performance?org_id=default` | Playbook performance |
| 107 | **PASS** | 200 | 28.2 | 0 | `/api/v1/threat-response/incidents/active?org_id=default` | Active threat incidents |

---

## POST Endpoints (30 tested)

| # | Result | Status | Time (ms) | Fields | Endpoint | Description |
|---|--------|--------|-----------|--------|----------|-------------|
| 1 | **PASS** | 200 | 24.0 | 13 | `/api/v1/access-anomaly/events` | Record access event |
| 2 | **PASS** | 200 | 31.7 | 13 | `/api/v1/ransomware-protection/detections` | Register ransomware detection |
| 3 | **PASS** | 200 | 30.2 | 12 | `/api/v1/ransomware-protection/backups` | Register backup |
| 4 | **PASS** | 201 | 25.1 | 16 | `/api/v1/threat-indicators/indicators?org_id=default` | Add threat indicator |
| 5 | **PASS** | 201 | 42.1 | 13 | `/api/v1/cost-optimization/tools?org_id=default` | Register cost optimization tool |
| 6 | **PASS** | 201 | 19.2 | 16 | `/api/v1/patch-management/patches?org_id=default` | Register patch |
| 7 | **PASS** | 200 | 34.6 | 14 | `/api/v1/alert-triage/alerts?org_id=default` | Ingest alert for triage |
| 8 | **PASS** | 201 | 40.3 | 15 | `/api/v1/alert-enrichment/alerts?org_id=default` | Submit alert for enrichment |
| 9 | **PASS** | 201 | 30.7 | 13 | `/api/v1/cyber-threat-intel/reports?org_id=default` | Create CTI report |
| 10 | **PASS** | 201 | 39.4 | 10 | `/api/v1/digital-twin/twins?org_id=default` | Create digital twin |
| 11 | **PASS** | 201 | 34.0 | 14 | `/api/v1/risk-register-engine/risks?org_id=default` | Create risk register entry |
| 12 | **PASS** | 201 | 29.3 | 10 | `/api/v1/security-okrs/objectives?org_id=default` | Create security OKR objective |
| 13 | **PASS** | 200 | 28.1 | 12 | `/api/v1/compliance-mapping/controls?org_id=default` | Add compliance control |
| 14 | **PASS** | 200 | 37.8 | 15 | `/api/v1/identity-lifecycle/accounts?org_id=default` | Provision identity account |
| 15 | **PASS** | 200 | 33.8 | 17 | `/api/v1/cloud-ir/incidents` | Create cloud IR incident |
| 16 | **PASS** | 200 | 64.7 | 15 | `/api/v1/arch-review/reviews?org_id=default` | Create architecture review |
| 17 | **PASS** | 200 | 28.7 | 16 | `/api/v1/hunting-playbooks/playbooks?org_id=default` | Create hunting playbook |
| 18 | **PASS** | 200 | 39.9 | 10 | `/api/v1/program-maturity/assessments` | Create program maturity assessment |
| 19 | **PASS** | 201 | 33.7 | 14 | `/api/v1/gap-analysis/assessments` | Create gap analysis assessment |
| 20 | **PASS** | 201 | 27.6 | 11 | `/api/v1/container-posture/clusters?org_id=default` | Register container cluster |
| 21 | **PASS** | 201 | 26.9 | 12 | `/api/v1/cyber-resilience/assessments?org_id=default` | Create cyber resilience assessment |
| 22 | **PASS** | 201 | 26.0 | 14 | `/api/v1/asset-criticality/assets?org_id=default` | Register asset criticality |
| 23 | **PASS** | 200 | 102.8 | 8 | `/api/v1/health-scorecard/snapshots?org_id=default` | Create health scorecard snapshot |
| 24 | **PASS** | 200 | 33.4 | 14 | `/api/v1/compliance-calendar/events?org_id=default` | Create compliance calendar event |
| 25 | **PASS** | 200 | 35.1 | 13 | `/api/v1/cloud-cost/snapshots` | Record cloud cost snapshot |
| 26 | **PASS** | 200 | 27.3 | 13 | `/api/v1/vuln-scans/scans?org_id=default` | Create vulnerability scan |
| 27 | **PASS** | 200 | 35.5 | 16 | `/api/v1/cloud-findings/findings` | Ingest cloud security finding |
| 28 | **PASS** | 201 | 39.9 | 12 | `/api/v1/threat-response/playbooks?org_id=default` | Create threat response playbook |
| 29 | **PASS** | 200 | 34.9 | 8 | `/api/v1/awareness-metrics/metrics?org_id=default` | Record awareness metric |
| 30 | **PASS** | 201 | 33.2 | 10 | `/api/v1/security-okrs/objectives?org_id=default` | Create second security OKR |

---

## All endpoints passed!

