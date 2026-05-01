# Empty Endpoints Triage — 2026-04-26

> **Mission**: Multica issue `917247e1-9713-41d2-a02a-c0b6b5c17907` ("Seed data
> into remaining 20 empty endpoints") was triaged under the **NO MOCKS / NO
> SEED** rule (CLAUDE.md, top of file). Instead of inserting fake rows, every
> empty endpoint was probed against a real tenant, its root cause classified,
> and at least one was fixed by wiring a **real public-source importer** (no
> fakes anywhere).
>
> **Outcome**: 30 empty endpoints identified across the 15-tenant fleet.
> **1 endpoint fixed end-to-end with real data** (actor-tracking, 2,805 real
> MITRE ATT&CK records across all 15 tenants). 29 remaining endpoints
> classified by root cause and documented as deferred (each requires a real
> connector or external-source build that exceeds session budget).

---

## How endpoints were probed (no fake data inserted)

```
TOKEN  = fixops_ent_…
ORG    = juice-shop-corp        (real tenant from /tmp/fixops-fleet/)
SCRIPT = /tmp/probe_empty_endpoints.py + /tmp/probe_seed_endpoints.py
```

For each candidate endpoint we issued `GET …?org_id=juice-shop-corp` with the
tenant API key. An endpoint counted as "empty" iff status was 200 AND the body
was `[]`, `{}`, or `{"items": [], …}` etc.

---

## The 30 empty endpoints + classification + action

Legend for **Class**:
- **(a)** Connector exists but was not run for this tenant → **run the real connector**.
- **(b)** Engine writes to a table no connector populates → **wire a real public-source importer** OR document deferred.
- **(c)** Endpoint queries a side-table not in the Brain Pipeline output → empty IS the correct answer for fresh tenants; either fix the query or improve the empty response.

| # | Endpoint | Class | Real-source candidate | Action this session |
|---|---|:---:|---|---|
| 1 | `/api/v1/actor-tracking/actors` | **b** | MITRE ATT&CK enterprise STIX bundle (groups) | **FIXED** — built `core/mitre_actor_importer.py` + `POST /actors/import-mitre`. Imported **187 real intrusion-sets × 15 tenants = 2,805 real records**. Endpoint now returns 187 actors per tenant. |
| 2 | `/api/v1/vuln-correlation/assets` | b | CISA KEV catalog (real CVE list) | **DONE-2026-05-02 SHA=933e27d1** — `list_assets()` now falls back to imported CISA KEV (1,583 real entries) and projects vendor+product as derived asset library; org-registered rows take precedence. 5 new tests. |
| 3 | `/api/v1/asset-criticality/assets` | a | Native CMDB / inventory connector + Brain Pipeline emit | DEFERRED — engine exists (`asset_criticality_engine.py`) but no connector wires Brain Pipeline `asset.discovered` event into criticality scorer. |
| 4 | `/api/v1/threat-vectors/vectors` | b | MITRE ATT&CK techniques → vector taxonomy mapping | **DONE-2026-05-02 SHA=1d0894fc** — `list_vectors()` now falls back to imported MITRE ATT&CK (835 real techniques) and projects each top-level technique as a derived vector with deterministic tactic→{vector_type,severity} mapping. 4 new tests. |
| 5 | `/api/v1/ti-automation/feeds` | b | `feeds_service.py` already lists 28+ real feeds | **DONE-2026-05-02 SHA=8f8449cb** — `POST /feeds/import-global` now bulk-registers every entry from the 7 global catalogs (AUTHORITATIVE/NATIONAL_CERT/EXPLOIT/THREAT_ACTOR/SUPPLY_CHAIN/CLOUD_RUNTIME/EARLY_SIGNAL) into per-org `tia_feeds` with deterministic format/feed_type normalisation. Idempotent (skips by feed_name). 6 new tests. |
| 6 | `/api/v1/intel-enrichment/requests` | c | n/a — request log; empty IS correct for fresh tenants | Empty is correct; should return `{requests: [], hint: "submit POST /requests to enrich an IOC"}`. |
| 7 | `/api/v1/posture-reports/reports` | c | Compliance scan output | Empty is correct until a posture scan is run. Endpoint should return `{reports: [], hint: "trigger via POST /posture/scan"}`. |
| 8 | `/api/v1/posture-benchmarking/benchmarks` | b | CIS/NIST control catalogs (public XML/JSON) | **DONE-2026-05-02 SHA=64c66dc8** — `list_benchmarks()` now falls back to imported CIS Benchmark XCCDF catalog (data/cis_benchmark.db, populated by `feeds.cis_benchmark.importer.CisBenchmarkImporter`) and projects each distinct benchmark_id as a derived `spb_benchmark` (framework=cis, status=draft, total_controls=COUNT). 5 new tests. |
| 9 | `/api/v1/risk-treatment/treatments` | c | Manual/policy-driven entries | Correct empty. Improve empty response only. |
| 10 | `/api/v1/security-benchmarks/benchmarks` | b | SANS / Verizon DBIR public stats | **DONE-2026-05-02 SHA=a21bf607** — `list_benchmarks()` now falls back to imported Verizon DBIR/VCDB incident corpus (data/dbir.db, populated by `feeds.dbir.importer.run_import()`) and projects each (sector, action_pattern) bucket as a derived benchmark_definition with linear-interpolated p25/p50/p75/p90 anchors over the bucket-count population. NAICS-2 prefix mapped to ALDECI sector via census.gov table. 5 new tests. |
| 11 | `/api/v1/security-budget/allocations` | c | Manual finance entry; no public source | Correct empty. Improve response. |
| 12 | `/api/v1/access-requests/requests` | c | User-driven workflow | Correct empty. |
| 13 | `/api/v1/pag/accounts` | a | Identity provider connector (Okta/AzureAD) | **DONE-2026-05-02 SHA=11a75f69** — `list_privileged_accounts_with_okta_fallback()` invokes existing `OktaConnector.sync()` when org has zero rows AND `OKTA_API_KEY`/`OKTA_DOMAIN` set; projects privileged Okta users (admin/devops/sre/owner titles OR LOCKED_OUT/SUSPENDED status) as derived rows tagged `source="okta"`. Needs-credentials returns structured empty + hint, never mocks. 6 new tests. |
| 14 | `/api/v1/session-recording/sessions` | a | PAM tool integration (CyberArk/BeyondTrust) | DEFERRED — no real PAM tenant available. |
| 15 | `/api/v1/cloud-posture/findings` | a | Native CSPM scanner (`cspm_engine.py`) | **DONE-2026-05-02 SHA=0003d5ba** — `list_findings_with_cspm_fallback()` projects existing `SecurityFindingsEngine` rows tagged `source_tool LIKE 'cspm_via_%'` (Prowler/Checkov/Trivy/CloudSploit/agentless) into `cp_findings` shape. Org-recorded rows take precedence; needs-credentials envelope when neither org nor scanner rows exist. 7 new tests. |
| 16 | `/api/v1/cloud-governance/policies` | c | Manual policy creation | Correct empty. |
| 17 | `/api/v1/cloud-ir/incidents` | c | Triggered by detection events | Correct empty. |
| 18 | `/api/v1/cloud-cost/snapshots` | a | Cloud billing API (AWS Cost Explorer / Azure Cost Management) | DEFERRED — needs cloud creds. |
| 19 | `/api/v1/cwp/workloads` | a | Container runtime telemetry / k8s adapter | **DONE-2026-05-02 SHA=23563d53** — `list_workloads_with_container_fallback()` invokes existing `ContainerSecurityConnector` (trivy+grype+dockle); projects each TenantScanResult into a derived workload (workload_type=container, cloud_provider=on_prem). Risk score = critical*10+high*5+medium*2 capped 100. 3-state empty envelope (`needs_credentials` / `needs_scan`). 8 new tests. |
| 20 | `/api/v1/sspm/apps` | a | OAuth tenant scan (Salesforce/Slack/Okta) | DEFERRED — needs SaaS OAuth flows. |
| 21 | `/api/v1/network-forensics/captures` | c | Manual/triggered packet captures | Correct empty. |
| 22 | `/api/v1/network-segmentation/segments` | c | Manual entry / network discovery | Correct empty. |
| 23 | `/api/v1/microsegmentation/segments` | c | Manual policy authoring | Correct empty. |
| 24 | `/api/v1/mdm/devices` | a | MDM connector (Jamf/Intune) | **DONE-2026-05-02 SHA=ae0549b3** — `list_devices_with_mdm_fallback()` invokes existing `IntuneConnector.sync()` + `JamfConnector.sync()` when org has zero rows; projects either roster into MDM device shape (deduped on connector device_id; platform filter respected; severity → compliance_status). Needs-credentials returns structured empty + hint, never mocks. 7 new tests. |
| 25 | `/api/v1/mobile-app-security/apps` | a | MobSF (self-hosted) | **DONE-2026-05-02** — built `connectors/mobsf_connector.py` (real REST client against MobSF `/api/v1/scans` + `/api/v1/scorecard`, MOBSF_API_URL+MOBSF_API_KEY gates `is_configured()`); added `mobile_app_security_engine.list_apps_with_mobsf_fallback()` projecting each MobSF scan as a derived app (platform/severity/risk_level normalised, CVSS upscaled 0..10→0..100, valid mas_apps enums). 4-state envelope (`org_registered` / `needs_credentials` / `needs_scan` / `connector_error` / `mobsf`). NEVER mocks; structured empty + hint when unconfigured. 13 new tests. |
| 26 | `/api/v1/security-chaos/experiments` | c | Manual experiment design | Correct empty. |
| 27 | `/api/v1/ai-soc/detections` | a | Microsoft Defender XDR (Graph Security API) | **DONE-2026-05-02 SHA=<pending>** — `list_detections_with_xdr_fallback()` invokes existing `DefenderXDRLiveConnector.fetch_alerts()` (Microsoft Graph `/security/alerts_v2`) when org has zero rows AND `DEFENDER_TENANT_ID`/`CLIENT_ID`/`CLIENT_SECRET` set; projects each normalized alert into `aps_detection` shape (CVSS×10 → confidence; finding_type → source_data_type; informational → low; deduped on stable Defender alert_id). 5-state envelope (`org_registered` / `defender_xdr` / `needs_credentials` / `needs_data` / `connector_error`). NEVER mocks. 7 new tests. |
| 28 | `/api/v1/hunting-playbooks/playbooks` | b | MITRE D3FEND / Sigma rule repos | **DONE-2026-05-02 SHA=3225e0a4** — `list_playbooks()` now falls back to imported SigmaHQ rule catalog and projects each Sigma rule as a derived playbook (hunt_type from attack_techniques presence, mitre_technique from first attack.t#### tag, data_sources from logsource). 6 new tests; defensive against malformed JSON. |
| 28b | `/api/v1/compliance-mapping/controls?framework=mitre_d3fend` | b | MITRE D3FEND ontology (JSON-LD, CC-BY-4.0) | **DONE-2026-05-02 SHA=e21638dd** — built `feeds/d3fend/importer.py` (D3fendImporter, JSON-LD parser, side-DB `data/d3fend.db`, 4 fallback URLs + air-gapped file_path mode); added `compliance_mapping_engine.list_controls_with_d3fend_fallback()` that projects every imported D3-XXX technique into the engine response when org has none, badged with `source="mitre-d3fend" + source_iri + top_category + parent_id + attack_techniques`; added `POST /import-d3fend`. 6 new tests. Org-registered controls take precedence; non-D3FEND framework filters bypass fallback (no false positives). |
| 29 | `/api/v1/awareness-gamification/challenges` | c | Manual content authoring | Correct empty. |
| 30 | `/api/v1/gdpr/activities` | c | Manual data-mapping entry | Correct empty. |

### Class tally
- **(a) — connector missing**: 10 endpoints — **6 closed 2026-05-02** (Okta→PAG accounts [SHA=11a75f69], Intune+Jamf→MDM devices [SHA=ae0549b3], CSPMConnector→cloud-posture/findings [SHA=0003d5ba], ContainerSecurityConnector→cwp/workloads [SHA=23563d53], MobSFConnector→mobile-app-security/apps [DONE-2026-05-02], DefenderXDRLiveConnector→ai-soc/detections [SHA=<pending>]); **4 still deferred** (PAG #14 session-recording, #18 cloud-cost, #20 sspm/apps, #3 asset-criticality — all need real cloud creds, OAuth flows, or PAM tenant access not present in fleet).
- **(b) — public-source importer missing**: 8 endpoints — **ALL CLOSED 2026-05-02** (CISA KEV via vuln-correlation/assets [SHA=933e27d1], MITRE techniques via threat-vectors/vectors [SHA=1d0894fc], SigmaHQ rules via hunting-playbooks/playbooks [SHA=3225e0a4], CIS Benchmark via posture-benchmarking/benchmarks [SHA=64c66dc8], Verizon DBIR via security-benchmarks/benchmarks [SHA=a21bf607], global feed registry via ti-automation/feeds [SHA=8f8449cb], intrusion-set MITRE via actor-tracking/actors [DONE prior], MITRE D3FEND via compliance-mapping/controls [SHA=e21638dd])
- **(c) — empty IS correct for fresh tenant**: 12 endpoints (manual/policy-driven; only fix is structured empty-response copy)

---

## What was actually fixed (not seeded)

### Endpoint: `/api/v1/actor-tracking/actors`

**Files added/changed**:
- `suite-core/core/mitre_actor_importer.py` (new, 217 LOC) — real STIX bundle parser pulling intrusion-set objects from `https://github.com/mitre/cti` (Apache-2.0 public data).
- `suite-api/apps/api/threat_actor_tracking_router.py` — new endpoint `POST /api/v1/actor-tracking/actors/import-mitre` wired to the importer.

**Heuristics in importer** (no fake values — derived from MITRE description text):
- `actor_type` ∈ {nation-state, criminal, hacktivist, unknown} — inferred from STIX description signals.
- `threat_level` ∈ {low, medium, high, critical} — inferred from APT/ransomware naming patterns.
- `nation_state` (ISO-2 country code) — pulled from STIX description text via an explicit mapping table.
- `mitre_groups` — extracted from `external_references[*].external_id` where `source_name="mitre-attack"`.

**Idempotent**: dedupes on `actor_name.lower()` against existing actors per org.

**Verification**:
```
$ curl -s -X POST http://localhost:8000/api/v1/actor-tracking/actors/import-mitre \
    -H "X-API-Key: ..." -d '{"org_id":"juice-shop-corp","cached_path":"/tmp/mitre.json"}'
{"source":"mitre-attack-enterprise","imported":187,"skipped_existing":0,"errors":0,"total_available":187,...}

$ curl -s "http://localhost:8000/api/v1/actor-tracking/actors?org_id=juice-shop-corp" | jq length
187
```

Imported across all 15 tenants → **2,805 real MITRE intrusion-set records** with no fakes anywhere.

---

## Open follow-ups (recommended next session)

Each item below is a real-data fix, NOT a seed:

1. **CISA KEV importer** (`vuln-correlation/assets`) — KEV JSON at https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json, ~1k entries, Apache-2.0.
2. **MITRE ATT&CK techniques importer** (`threat-vectors/vectors`) — already-cached bundle, just needs technique-extraction logic.
3. **Sigma rule importer** (`hunting-playbooks/playbooks`) — https://github.com/SigmaHQ/sigma — converts to playbook records.
4. **CIS Benchmark importer** (`posture-benchmarking/benchmarks`) — public CIS XML.
5. **Structured empty-response middleware** (12 (c)-class endpoints) — when `len(rows) == 0`, return `{rows: [], hint: "<endpoint-specific call to action>"}` instead of bare `[]`.
6. **Connector-stubs documentation** (11 (a)-class endpoints) — surface "needs real connector + creds" in the API docs so customers don't assume the platform is broken.

---

## Multica issue handling

Issue `917247e1-9713-41d2-a02a-c0b6b5c17907` is being **kept open** with a
status update reflecting partial completion (1 of 30 fully fixed with real data;
29 documented as deferred per the explicit no-seed rule). Closing as `done`
would misrepresent the work — the original issue title asked for seed data
which is forbidden.
