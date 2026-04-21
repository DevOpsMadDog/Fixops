# QA Test Report: Dashboard API Coverage — Top 50 Pages

**Date:** 2026-04-17  
**Server:** http://localhost:8000  
**Tester:** QA Lead (automated tmux-less curl sweep)  
**Method:** Read each .tsx, extract API calls, curl with auth header, rate result

---

## Environment

- **Server:** FastAPI on http://localhost:8000 (confirmed up, port 8000 open)
- **Auth:** `X-API-Key: fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_`
- **Pages tested:** 50 dashboard pages (309 pages exist total)
- **Endpoints exercised:** 127 unique API calls

---

## Critical Finding: org_id Missing from Frontend Calls

**Affects:** ~30 endpoints across 15+ dashboards  
**Root cause:** Many GET endpoints require `?org_id=` as a required query parameter. The frontend TSX files call these endpoints without the param — they all return 422 Unprocessable Entity.  
**Example:** `GET /api/v1/alert-triage/stats` → 422 `{"field": "query -> org_id", "message": "Field required"}`  
**With param:** `GET /api/v1/alert-triage/stats?org_id=default` → 200 with full data  
This is a **systemic frontend bug** — the pages will show broken/empty states for all affected endpoints.

---

## Critical Finding: Wave 41 Routers Silently Not Mounted

**Affects:** privacy-impact, ransomware-protection, access-anomaly, training-effectiveness, cost-optimization, sbom-export, alert-enrichment, patch-management (root GET)  
**Root cause:** These routers define `GET "/"` as their list endpoint (requires trailing slash). The frontend calls the bare path (no trailing slash), FastAPI returns 404 because it does not redirect trailing slashes by default.  
**With trailing slash:** `GET /api/v1/privacy-impact/?org_id=default` → 200  
**Without trailing slash:** `GET /api/v1/privacy-impact?org_id=default` → 404  
The routers import cleanly — the issue is the trailing-slash mismatch.

---

## Test Cases

### TC1: MainOverviewDashboard
**File:** `MainOverviewDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/compliance/status` | 200 + data | 200 | `overall_score: 98.5` | PASS |
| `api/v1/feeds/config` | 200 + data | 200 | feed config returned | PASS |
| `api/v1/posture-score/current` | 200 + data | 200 | `overall_score: 76.95, grade: C` | PASS |
| `api/v1/alert-triage/stats` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/incident-orchestration/incidents` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/vuln-intel/stats` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL** — 3/6 endpoints broken due to missing org_id

---

### TC2: AlertTriageDashboard
**File:** `AlertTriageDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/alert-triage/alerts` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/alert-triage/stats` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL** — 0/2 endpoints work (full page broken)  
**With fix:** Both return 200 with real data (570 alerts, stats populated)

---

### TC3: ComplianceDashboard
**File:** `ComplianceDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/compliance/status` | 200 + data | 200 | operational, score 98.5 | PASS |
| `api/v1/compliance/gaps` | 200 + data | 200 | gap list returned | PASS |
| `api/v1/evidence/list` | 200 + data | 200 (empty) | `total: 0` | WARN |
| `api/v1/compliance-scanner/findings` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/compliance-scanner/scans` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/compliance-scanner/stats` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL** — 2/6 pass, 2 are 404 (route doesn't exist), 1 is 422, 1 is empty

---

### TC4: SecurityPostureDashboard
**File:** `SecurityPostureDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/posture-advisor/score` | 200 + data | 200 | `overall_score: 76.95` | PASS |
| `api/v1/posture-advisor/stats` | 200 + data | 200 | `total_analyses: 8` | PASS |
| `api/v1/posture/score` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/posture-advisor/components` | 200 + data | 200 | components returned | PASS |

**Page verdict: WARN** — 3/4 pass, 1 route (`/api/v1/posture/score`) is 404 (correct route is `/api/v1/posture-advisor/score`)

---

### TC5: ThreatIntelDashboard
**File:** `ThreatIntelDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/feeds/status` | 200 + data | 200 | 8 feeds healthy, 327K EPSS records | PASS |
| `api/v1/threat-feeds/stats` | 200 + data | 200 | `total_sources: 8, active: 8` | PASS |
| `api/v1/threat-intel/iocs` | 200 + data | 200 (empty) | `total: 0, iocs: []` | WARN |

**Page verdict: WARN** — 2/3 pass, IOC list is empty (no data seeded)

---

### TC6: RiskRegisterDashboard
**File:** `RiskRegisterDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/risk-register-engine/risks` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/risk-register-engine/stats` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL** — 0/2 work  
**With fix:** `total_risks: 20, open_risks: 20` — data exists

---

### TC7: VulnIntelligenceDashboard
**File:** `VulnIntelligenceDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/vuln-intel/stats` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/vuln-intel/cves` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/vuln-intel/advisories` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/vuln-intel/subscriptions` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL** — 0/4 work  
**With fix:** `total_cves: 240, critical: 81, high: 29` — rich data exists

---

### TC8: SupplyChainDashboard
**File:** `SupplyChainDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/supply-chain/stats` | 200 + data | 200 | `total_suppliers: 5, components: 164` | PASS |
| `api/v1/supply-chain/suppliers` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/sbom/summary` | 200 + data | 404 | Not Found | **FAIL** |

**Page verdict: WARN** — 1/3 pass with data, 1 empty, 1 is 404

---

### TC9: IncidentResponseDashboard
**File:** `IncidentResponseDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/incidents` | 200 + data | 200 | incidents list, 32 total | PASS |
| `api/v1/incidents/stats` | 200 + data | 200 | `total: 32, by_type: {...}` | PASS |
| `api/v1/soar/playbooks` | 200 + data | 200 | playbooks returned | PASS |

**Page verdict: PASS** — 3/3 pass with data

---

### TC10: CloudComplianceDashboard
**File:** `CloudComplianceDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/cloud-compliance/stats` | 200 + data | 200 | `assessments_run: 3, avg CIS score: 75%` | PASS |
| `api/v1/cloud-compliance/controls` | 200 + data | 200 | controls list | PASS |
| `api/v1/cloud-compliance/assessments` | 200 + data | 200 | assessments returned | PASS |
| `api/v1/cloud-compliance/remediation-plans` | 200 + data | 200 | plans returned | PASS |

**Page verdict: PASS** — 4/4 pass with data

---

### TC11: NDRDashboard
**File:** `NDRDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/ndr/alerts` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/ndr/flows` | 200 + data | 200 | flows list returned | PASS |
| `api/v1/ndr/segments` | 200 + data | 200 (empty) | `[]` | WARN |

**Page verdict: WARN** — 1/3 has data, 2 empty

---

### TC12: EDRDashboard
**File:** `EDRDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/edr/endpoints` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/edr/detections` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/edr/processes` | 200 + data | 404 | Not Found | **FAIL** |

**Page verdict: FAIL** — 0/3 work  
**With fix (org_id):** endpoints, detections return data; processes route simply doesn't exist

---

### TC13: XDRDashboard
**File:** `XDRDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/xdr/signals` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/xdr/incidents` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/xdr/rules` | 200 + data | 200 (empty) | `[]` | WARN |

**Page verdict: WARN** — 3/3 endpoints exist but no data seeded

---

### TC14: AttackSurfaceDashboard
**File:** `AttackSurfaceDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/attack-surface/score` | 200 + data | 200 | score returned (0.0 — no assets) | PASS |
| `api/v1/attack-surface/assets` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/attack-surface/changes` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/attack-surface/summary` | 200 + data | 404 | Not Found | **FAIL** |

**Page verdict: WARN** — 1/4 has real data, 2 empty, 1 missing route

---

### TC15: VendorManagement (VendorRiskDashboard)
**File:** `VendorRiskDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/vendor-risk/vendors` | 200 + data | 500 | Internal Server Error | **FAIL** |
| `api/v1/vendor-risk/risk-register` | 200 + data | 500 | Internal Server Error | **FAIL** |
| `api/v1/vendors` | 200 + data | 200 | vendor list returned | PASS (wrong path) |

**Page verdict: FAIL** — Frontend uses `/api/v1/vendor-risk/vendors` but router is mounted at `/api/v1/vendors`. Two 500 errors from non-existent sub-paths.

---

### TC16: SBOMManagement (SBOMDashboard)
**File:** `SBOMDashboard.tsx`

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/sbom` | 200 + data | 200 | components list | PASS |
| `api/v1/sbom/stats` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/sbom/assets` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/sbom/summary` | 200 + data | 404 | Not Found | **FAIL** |

**Page verdict: FAIL** — 1/4 pass

---

### TC17: DarkWebMonitoringDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/dark-web/stats` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/dark-web/mentions` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/dark-web/credential-exposures` | 200 + data | 404 | Not Found | **FAIL** |

**Page verdict: FAIL** — 0/3 work  
**With fix (org_id):** stats and mentions return data (`total_mentions: 5`); credential-exposures route missing

---

### TC18: ITDRDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/itdr/stats` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/itdr/threats` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/itdr/response-actions` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL** — 0/3 work  
**With fix:** `total_threats: 15`, threats and actions populated

---

### TC19: ZeroTrustDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/zero-trust/policies` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/zero-trust/score` | 200 + data | 404 | Not Found | **FAIL** |

**Page verdict: WARN/FAIL** — 1/2 endpoints exist but no data; score route missing

---

### TC20: MITREAttackDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/mitre-attack/coverage` | 200 + data | 200 | coverage object (0% — no techniques) | PASS |
| `api/v1/mitre-attack/gaps` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/mitre-attack/stats` | 200 + data | 404 | Not Found | **FAIL** |

**Page verdict: WARN** — 1/3 has data, 1 empty, 1 missing

---

### TC21: CISOReportDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/ciso-report/executive-summary` | 200 + data | 200 | full report generated | PASS |
| `api/v1/ciso-report/weekly-brief` | 200 + data | 200 | brief generated | PASS |
| `api/v1/ciso-report/top-risks` | 200 + data | 200 | top risks ranked | PASS |
| `api/v1/ciso-report/export/markdown` | 200 + data | 200 | export available | PASS |

**Page verdict: PASS** — 4/4 pass with data

---

### TC22: SecurityHealthScorecardDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/health-scorecard` | 200 + data | 200 (empty) | `snapshot: null, domains: []` | WARN |

**Page verdict: WARN** — endpoint exists but no snapshot data

---

### TC23: CloudSecurityFindingsDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/cloud-findings/findings` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL**  
**With fix:** findings list returned (azure, account data present)

---

### TC24: VulnerabilityAgeDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/vuln-age` | 200 + data | 404 | Not Found | **FAIL** |

**Page verdict: FAIL** — route doesn't exist even with org_id. Router may not be mounted.

---

### TC25: PatchManagementDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/patch-management` | 200 + data | 404 | Not Found (no trailing slash) | **FAIL** |
| `api/v1/patch-management/` | 200 + data | 200 | patch list, `7 patches` | PASS (with slash) |
| `api/v1/patch-management/patches` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/patch-management/stats` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL** — trailing slash + org_id both missing

---

### TC26: ContainerPostureDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/container-posture` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/container-posture/findings` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/container-posture/stats` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL**  
**With fix:** `total_clusters: 18, avg_posture_score: 90.67`

---

### TC27: InsiderThreatMonitor

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/insider-threat/stats` | 200 + data | 200 | `total_activities: 10` | PASS |
| `api/v1/insider-threat/high-risk` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/insider-threat/distribution` | 200 + data | 200 | `low: 6, medium: 1` | PASS |
| `api/v1/insider-threat/timeline` | 200 + data | 200 | timeline returned | PASS |

**Page verdict: PASS** — 3/4 have data, 1 empty (no high-risk users flagged)

---

### TC28: AssetInventory

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/assets` | 200 + data | 200 | asset list returned | PASS |

**Page verdict: PASS**

---

### TC29: PostureAdvisor

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/posture-advisor/score` | 200 + data | 200 | score 76.95 | PASS |
| `api/v1/posture-advisor/roadmap` | 200 + data | 200 | roadmap phases returned | PASS |
| `api/v1/posture-advisor/analyze` | 200 + data | 404 | Not Found | **FAIL** |

**Page verdict: WARN** — 2/3 pass, /analyze route missing

---

### TC30: GRCDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/grc/stats` | 200 + data | 200 (empty) | `frameworks_count: 0` | WARN |
| `api/v1/grc/frameworks` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/grc/risks` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/grc/controls` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/grc/assessments` | 200 + data | 200 (empty) | `[]` | WARN |

**Page verdict: WARN** — all endpoints respond 200 but no GRC data seeded

---

### TC31: CloudWorkloadProtectionDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/cwp/stats` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/cwp/workloads` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/cwp/threats` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL**  
**With fix:** stats return `total_workloads: 0` (empty but live), workloads/threats empty lists

---

### TC32: IoTSecurityDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/iot-security/devices` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/iot-security/stats` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/iot-security/anomalies` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL**  
**With fix:** `total_devices: 30, total_anomalies: 30` — rich data available

---

### TC33: FirmwareSecurityDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/firmware-security/devices` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/firmware-security/stats` | 200 + data | 422 | org_id required | **FAIL** |
| `api/v1/firmware-security/vulnerabilities` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL**  
**With fix:** `total_devices: 12, total_vulns: 12, unpatched: 12`

---

### TC34: QuantumCryptoDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/quantum-crypto/stats` | 200 + data | 200 | `total_assets: 1, quantum_vulnerable: 1` | PASS |
| `api/v1/quantum-crypto/assets` | 200 + data | 200 | asset listed | PASS |
| `api/v1/quantum-crypto/migrations` | 200 + data | 200 (empty) | `[]` | WARN |

**Page verdict: PASS** — 2/3 have data

---

### TC35: SBOMExportDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/sbom-export` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/sbom-export/` | 200 + data | 200 | `projects: [], total: 0` | WARN (with slash) |

**Page verdict: FAIL** — trailing slash mismatch; no projects seeded

---

### TC36: ThreatGeolocationDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/threat-geolocation/stats` | 200 + data | 200 | `total_events: 0` (empty) | WARN |
| `api/v1/threat-geolocation/heatmap` | 200 + data | 200 (empty) | `[]` | WARN |

**Page verdict: WARN** — endpoints live, no data seeded

---

### TC37: IPReputationDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/ip-reputation/stats` | 200 + data | 200 | `total_ips: 8, blocked: 6, avg_score: 54.75` | PASS |
| `api/v1/ip-reputation/blocklist` | 200 + data | 200 | blocklist entries returned | PASS |

**Page verdict: PASS** — 2/2 pass with data

---

### TC38: NetworkMonitoringDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/network-monitoring/stats` | 200 + data | 200 | `interface_count: 3, sample_count: 3` | PASS |
| `api/v1/network-monitoring/alerts` | 200 + data | 200 (empty) | `[]` | WARN |

**Page verdict: PASS** — 1/2 has data, 1 empty (no alerts triggered)

---

### TC39: FirewallPolicyDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/firewall-policy/stats` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL**  
**With fix:** `firewalls: 14, total_rules: 12, deny_rules: 4`

---

### TC40: NetworkSegmentationDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/network-segmentation/stats` | 200 + data | 422 | org_id required | **FAIL** |

**Page verdict: FAIL**  
**With fix:** `segments: 0, flow_policies: 0` (empty but live)

---

### TC41: SecurityBudgetDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/security-budget/stats` | 200 + data | 200 | stats returned (zeroes — no allocations) | WARN |
| `api/v1/security-budget/allocations` | 200 + data | 200 (empty) | `[]` | WARN |
| `api/v1/security-budget/transactions` | 200 + data | 200 (empty) | `[]` | WARN |

**Page verdict: WARN** — all endpoints live, no budget data seeded

---

### TC42: ComplianceAutomationDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/compliance-automation` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/compliance/gaps` | 200 + data | 200 | gaps returned | PASS |
| `api/v1/compliance/status` | 200 + data | 200 | status returned | PASS |

**Page verdict: WARN/FAIL** — compliance-automation root 404; note router uses `/api/v1/compliance` prefix (shared with main compliance router — collision suspected)

---

### TC43: ThreatAttributionDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/threat-attribution/stats` | 200 + data | 200 | `total_actors: 9, active: 9` | PASS |
| `api/v1/threat-attribution/attributions` | 200 + data | 200 | attribution records | PASS |

**Page verdict: PASS** — 2/2 pass with data

---

### TC44: BehavioralAnalyticsDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/behavioral-analytics/stats` | 200 + data | 200 | `monitored: 5, anomalies: 15, critical: 6` | PASS |
| `api/v1/behavioral-analytics/anomalies` | 200 + data | 200 | anomaly records returned | PASS |

**Page verdict: PASS** — 2/2 pass with data

---

### TC45: AlertEnrichmentDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/alert-enrichment` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/alert-enrichment/` | 200 + data | 200 | `total: 0` (empty) | WARN (with slash) |

**Page verdict: FAIL** — trailing slash mismatch; no enriched alerts

---

### TC46: PrivacyImpactDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/privacy-impact` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/privacy-impact/` | 200 + data | 200 | `total: 15, by_type: {dpia: 6, pia: 9}` | PASS (with slash) |

**Page verdict: FAIL** — trailing slash mismatch; data exists when slash added

---

### TC47: RansomwareProtectionDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/ransomware-protection` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/ransomware-protection/` | 200 + data | 200 | `total_detections: 29, critical: 17` | PASS (with slash) |

**Page verdict: FAIL** — trailing slash mismatch; rich data available

---

### TC48: AccessAnomalyDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/access-anomaly` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/access-anomaly/` | 200 + data | 200 | `total_anomalies: 7, open: 7` | PASS (with slash) |

**Page verdict: FAIL** — trailing slash mismatch

---

### TC49: TrainingEffectivenessDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/training-effectiveness` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/training-effectiveness/` | 200 + data | 200 | `total_programs: 25` | PASS (with slash) |

**Page verdict: FAIL** — trailing slash mismatch

---

### TC50: CloudCostOptimizationDashboard

| Endpoint | Expected | Actual Code | Data | Status |
|----------|----------|-------------|------|--------|
| `api/v1/cost-optimization` | 200 + data | 404 | Not Found | **FAIL** |
| `api/v1/cost-optimization/` | 200 + data | 200 | `total_tools: 16, monthly_cost: $15,600` | PASS (with slash) |

**Page verdict: FAIL** — trailing slash mismatch

---

## Bug Summary

### BUG-001 (CRITICAL): Missing org_id in Frontend API Calls
- **Severity:** Critical
- **Affects:** 20+ endpoints across 15 dashboards
- **Symptom:** `422 Unprocessable Entity` with `"field": "query -> org_id", "message": "Field required"`
- **Root Cause:** Frontend TSX pages call GET endpoints without appending `?org_id=default`. The backend requires org_id as a mandatory query param but has no default.
- **Affected pages:** AlertTriage, RiskRegister, VulnIntelligence, MainOverview (partial), EDR, CloudFindings, Patch, ContainerPosture, SBOM (partial), DarkWeb, ITDR, CWP, IoT, Firmware, Firewall, NetworkSegmentation
- **Fix:** Either (a) add `?org_id=default` in all frontend fetch calls, or (b) make org_id optional with a default in the router (e.g. `org_id: str = Query(default="default")`)

### BUG-002 (CRITICAL): Trailing Slash Mismatch — Wave 41 Routers
- **Severity:** Critical
- **Affects:** 8 routers — privacy-impact, ransomware-protection, access-anomaly, training-effectiveness, cost-optimization, sbom-export, alert-enrichment, patch-management root path
- **Symptom:** `GET /api/v1/privacy-impact` → 404; `GET /api/v1/privacy-impact/` → 200
- **Root Cause:** Routers define `GET "/"` as the list endpoint. FastAPI does not auto-redirect trailing slashes. Frontend calls bare path without slash.
- **Fix:** Add `redirect_slashes=True` to the APIRouter or FastAPI app, OR add an explicit `GET ""` route alias in each router, OR update frontend to always append trailing slash for these routers.

### BUG-003 (HIGH): Vendor Risk — Wrong URL in Frontend
- **Severity:** High
- **Affects:** VendorRiskDashboard
- **Symptom:** `GET /api/v1/vendor-risk/vendors` → 500; `GET /api/v1/vendors` → 200
- **Root Cause:** Router is mounted at prefix `/api/v1/vendors` but the frontend calls `/api/v1/vendor-risk/vendors`
- **Fix:** Either update frontend to use `/api/v1/vendors`, or update router prefix to `/api/v1/vendor-risk`

### BUG-004 (HIGH): Missing Route Implementations
- **Severity:** High
- **Endpoints that return 404 regardless of params:**
  - `GET /api/v1/vuln-age` — VulnerabilityAgeDashboard (router may not be loaded)
  - `GET /api/v1/posture/score` — SecurityPostureDashboard (correct path is `/posture-advisor/score`)
  - `GET /api/v1/zero-trust/score` — ZeroTrustDashboard (only `/zero-trust/policies` exists)
  - `GET /api/v1/mitre-attack/stats` — MITREAttackDashboard (only `/coverage` and `/gaps` exist)
  - `GET /api/v1/attack-surface/summary` — AttackSurfaceDashboard
  - `GET /api/v1/sbom/summary` — SBOMDashboard
  - `GET /api/v1/dark-web/credential-exposures` — DarkWebMonitoringDashboard
  - `GET /api/v1/edr/processes` — EDRDashboard
  - `GET /api/v1/posture-advisor/analyze` — PostureAdvisor page
  - `GET /api/v1/compliance-scanner/findings` and `/scans` — ComplianceDashboard
  - `GET /api/v1/api-keys` — AuditLog page
  - `GET /api/v1/webhooks` — AuditLog page
  - `GET /api/v1/rbac/permissions` — AuditLog page
  - `GET /api/v1/audit/events` — AuditLog page
  - `GET /api/v1/compliance-automation` (root) — ComplianceAutomationDashboard

### BUG-005 (MEDIUM): Empty Data — Engines Have No Seed Data
- **Severity:** Medium
- **Affects:** XDR, NDR (alerts), ZeroTrust, GRC, SecurityBudget, ThreatGeolocation, AttackSurface assets, SupplyChain suppliers, SecurityHealthScorecard
- **Symptom:** 200 OK but returns `[]` or zeroes
- **Root Cause:** Engines are live but no data has been ingested/seeded
- **Impact:** Pages render empty dashboards with no meaningful content

### BUG-006 (MEDIUM): Compliance Automation Router Prefix Collision
- **Severity:** Medium
- **Details:** `compliance_automation_router` uses prefix `/api/v1/compliance` — same as the main compliance router. The root `GET /` resolves to 404 when called as `/api/v1/compliance-automation`. Any sub-path defined in this router may shadow or collide with the main compliance router.

---

## Summary

| Rating | Count | Pages |
|--------|-------|-------|
| PASS | 9 | IncidentResponse, CloudCompliance, CISOReport, InsiderThreat, AssetInventory, IPReputation, ThreatAttribution, BehavioralAnalytics, QuantumCrypto |
| WARN | 13 | ThreatIntel, SupplyChain, SecurityPosture, NDR, XDR, AttackSurface, MITREAttack, SecurityHealthScorecard, GRC, SecurityBudget, ThreatGeolocation, NetworkMonitoring, QuantumCrypto |
| FAIL | 28 | AlertTriage, MainOverview (partial), Compliance, RiskRegister, VulnIntelligence, VendorManagement, SBOM, DarkWeb, ITDR, ZeroTrust, CloudFindings, VulnAge, PatchManagement, ContainerPosture, CWP, IoT, Firmware, SBOMExport, FirewallPolicy, NetworkSegmentation, ComplianceAutomation, AlertEnrichment, PrivacyImpact, Ransomware, AccessAnomaly, TrainingEffectiveness, CloudCostOptimization, EDR |

**Total tests run:** 127 endpoint calls  
**Total unique pages:** 50  
**Pages PASS:** 9 (18%)  
**Pages WARN:** 13 (26%)  
**Pages FAIL:** 28 (56%)

---

## Priority Fix List

1. **[P0 — 30 min fix]** Add `org_id: str = Query(default="default")` to all 20+ endpoints that require it — instantly unblocks 15 dashboards
2. **[P0 — 30 min fix]** Add `redirect_slashes=True` to FastAPI app or to each Wave 41 router — fixes 8 dashboards
3. **[P1 — 1 hr]** Fix vendor-risk URL mismatch (frontend or router)
4. **[P1 — 2 hrs]** Add missing sub-routes: `/zero-trust/score`, `/mitre-attack/stats`, `/attack-surface/summary`, `/sbom/summary`, `/dark-web/credential-exposures`, `/edr/processes`, `/posture-advisor/analyze`, `/posture/score`
5. **[P2 — 4 hrs]** Seed demo data for XDR, GRC, SecurityBudget, ThreatGeolocation, AttackSurface
6. **[P2 — 2 hrs]** Fix compliance-automation router prefix collision

---

## Cleanup

- No tmux sessions were created (direct curl approach used — no orphaned processes)
- Temp files cleaned up per call (`rm -f /tmp/qa_$$_*.json`)
- Artifacts removed: YES
