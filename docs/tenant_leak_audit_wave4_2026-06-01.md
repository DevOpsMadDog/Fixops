# Tenant Leak Audit — Wave 4 (2026-06-01)

Branch: `chore/ui-prune-plan-2026-05-24`
Auditor: security-auditor agent (read-only, no code changes)
Scope: Routers NOT in waves 1-3 fixed list. Top 40 highest-traffic customer-facing routers audited.

Already-fixed (skipped): risk_acceptance, audit, scanner_ingest, copilot, secrets,
secret_scanner, secrets_rotation, vuln_discovery, webhook_events, code_to_cloud,
mpte_orchestrator, admin, teams, users, policies, inventory, workflows, analytics,
remediation, reports, threat_hunting, fail, sla, brain, data_classification,
pipeline, sso, connector_management.

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 14    |
| HIGH     | 9     |
| MEDIUM   | 4     |
| **Total actionable** | **27** |

---

## Findings Table (CRITICAL first)

| # | File : Line | Handler | Severity | Missing Guard | Notes |
|---|-------------|---------|----------|---------------|-------|
| 1 | `suite-core/api/exposure_case_router.py:142` | `GET /{case_id}` | CRITICAL | No auth dependency on router or handler; no org_id comparison — any authenticated caller can read any case by guessing UUID | `router = APIRouter(prefix="/api/v1/cases")` has zero `Depends(api_key_auth)` at router or handler level; `get_case(case_id)` calls `mgr.get_case(case_id)` with no org filter |
| 2 | `suite-core/api/exposure_case_router.py:152` | `PATCH /{case_id}` | CRITICAL | Same — no auth, no org_id comparison on update | `update_case(case_id, req)` calls `mgr.update_case(case_id, updates)` — cross-tenant write |
| 3 | `suite-core/api/exposure_case_router.py:166` | `POST /{case_id}/transition` | CRITICAL | Same — no auth, no org_id check | `transition_case` mutates state machine with no tenant check |
| 4 | `suite-core/api/exposure_case_router.py:185` | `POST /{case_id}/clusters` | CRITICAL | Same — no auth | `add_clusters` appends cluster_ids to any case |
| 5 | `suite-core/api/exposure_case_router.py:196` | `GET /{case_id}/transitions` | CRITICAL | Same — no auth, no org filter | reads valid transitions for any case |
| 6 | `suite-api/apps/api/cspm_engine_router.py:126` | `GET /resources/{resource_id}` | CRITICAL | No auth on router or handler; no org_id guard on by-id fetch | `router = APIRouter(prefix="/api/v1/cspm-engine")` has no `dependencies=[Depends(...)]`; `get_resource(resource_id)` returns `engine.get_resource(resource_id)` with no org scope |
| 7 | `suite-api/apps/api/cspm_engine_router.py:73` | `POST /sync` | CRITICAL | No auth; `SyncResourceRequest.org_id` is caller-supplied with no server-side enforcement | Caller can sync cloud resources into any org's namespace |
| 8 | `suite-api/apps/api/ciem_router.py:84` | `POST /analyze-policy` | CRITICAL | No auth dependency on router or any handler; no org_id filtering | `router = APIRouter(prefix="/api/v1/ciem")` imports no auth; all 7 handlers have no `Depends(...)` |
| 9 | `suite-api/apps/api/ciem_router.py:103` | `POST /analyze-account` | CRITICAL | Same — no auth; `AnalyzeAccountRequest` supplies org_id unchecked | Cross-tenant IAM data analysis |
| 10 | `suite-api/apps/api/ciem_router.py:139` | `GET /risks` | CRITICAL | Same — no auth; list of IAM risks returned for any org_id query param | |
| 11 | `suite-api/apps/api/incident_response_router.py:142` | `GET /{incident_id}` | CRITICAL | Router has no `dependencies=` block; handler has no `Depends(api_key_auth)` and no org_id comparison | `get_incident(incident_id)` calls `manager.get_incident(incident_id)` — global lookup, no org filter. Any caller can read any incident. |
| 12 | `suite-api/apps/api/incident_response_router.py:152` | `PATCH /{incident_id}/status` | CRITICAL | Same — no auth; `UpdateStatusRequest` has no org_id field; update operates on global incident store | Cross-tenant status mutation |
| 13 | `suite-api/apps/api/incident_response_router.py:166` | `POST /{incident_id}/steps/{step_order}/assign` | CRITICAL | Same — no auth; no org comparison | Cross-tenant playbook step assignment |
| 14 | `suite-api/apps/api/incident_response_router.py:196` | `GET /{incident_id}/transitions` | CRITICAL | Same — no auth; no org_id param | Exposes any incident's valid transition states |
| 15 | `suite-core/api/deduplication_router.py:163` | `GET /clusters/{cluster_id}` | HIGH | Router has no auth; handler `get_cluster(cluster_id)` fetches from global store with no org_id check | `router = APIRouter(prefix="/api/v1/deduplication")` — no Depends at router level; cluster belongs to an org but lookup is purely by UUID |
| 16 | `suite-core/api/deduplication_router.py:173` | `PUT /clusters/{cluster_id}/status` | HIGH | Same — no auth; `update_cluster_status` mutates cluster with no org verification | Cross-tenant cluster status mutation |
| 17 | `suite-core/api/deduplication_router.py:199` | `PUT /clusters/{cluster_id}/assign` | HIGH | Same — no auth; assigns cluster to user with no org check | |
| 18 | `suite-core/api/deduplication_router.py:213` | `PUT /clusters/{cluster_id}/ticket` | HIGH | Same — no auth; links ticket to cluster with no org check | |
| 19 | `suite-api/apps/api/security_findings_router.py:116` | `PATCH /findings/{finding_id}/status` | HIGH | Auth present (`api_key_auth`), but `org_id` comes entirely from request body (`body.org_id`), never validated against the authenticated caller's org | Attacker calls `PATCH /findings/<victim_finding_id>/status` with `{"org_id":"victim-org","status":"resolved"}` — auth passes, finding is mutated cross-tenant |
| 20 | `suite-api/apps/api/security_findings_router.py:131` | `POST /findings/{finding_id}/evidence` | HIGH | Same — auth present but `org_id` from `body.org_id` not matched to caller identity | Cross-tenant evidence injection |
| 21 | `suite-api/apps/api/security_findings_router.py:142` | `POST /findings/{finding_id}/suppress` | HIGH | Same — `body.org_id` is caller-supplied; no server-side comparison to authed org | Attacker can suppress another org's findings |
| 22 | `suite-api/apps/api/asset_inventory_router.py:247` | `GET /{asset_id}` | HIGH | `_require_asset(asset_id)` only checks existence, NOT org_id membership. Handler has no `org_id` parameter. | `get_asset(asset_id)` returns any asset regardless of tenant; a caller authenticated to org-A can enumerate org-B's assets by ID |
| 23 | `suite-api/apps/api/asset_inventory_router.py:257` | `PUT /{asset_id}` | HIGH | Same — `update_asset(asset_id, req)` calls `_require_asset` (existence only) then mutates with no org check | Cross-tenant asset update |
| 24 | `suite-api/apps/api/risk_scoring_router.py:161` | `GET /exposure/{asset_id}` | MEDIUM | Auth present, but `get_asset_exposure(asset_id)` fetches the asset with no org_id parameter and no tenant filter | Any authenticated caller can retrieve exposure score for any asset in any org |
| 25 | `suite-integrations/api/integrations_router.py:257` | `POST /{id}/test` | MEDIUM | `test_integration(id)` has no `org_id` parameter and no `stored_org` check (unlike the surrounding GET/PUT/DELETE handlers which do check) | Authenticated caller can trigger connectivity test for another org's integration |
| 26 | `suite-integrations/api/integrations_router.py:436` | `GET /{id}/sync-status` | MEDIUM | `get_sync_status(id)` has no org_id or stored_org guard | Reads sync status for any integration |
| 27 | `suite-integrations/api/integrations_router.py:453` | `POST /{id}/trigger-sync` | MEDIUM | `trigger_sync(id)` has no org_id or stored_org guard | Triggers sync for any integration, including foreign orgs |

---

## Notes on Routers Confirmed Clean (no leaks found)

| Router | Verdict |
|--------|---------|
| `findings_persistence_router.py` | CLEAN — all handlers use `get_org_id` dependency; `get_finding` returns 404 on tenant mismatch |
| `findings_lifecycle_router.py` | LOW RISK — `org_id` from query param, but the engine filters by org_id so records only returned if they belong; no cross-tenant enumeration possible |
| `export_router.py` | CLEAN — all SQL queries filter `WHERE org_id = ?` with caller-supplied org_id; auth gated at router level |
| `connectors_router.py` | CLEAN — uses `_org_prefix(org_id)` namespacing; GET/DELETE check prefix; well-isolated |
| `vuln_scan_router.py` | CLEAN — all handlers pass `org_id` as required query param to engine; engine enforces it |
| `alert_triage_router.py` | CLEAN — bulk_triage has explicit cross-org pre-check with `alert_exists_anywhere`; by-id handlers pass org_id required |
| `compliance_router.py` | CLEAN — engine is single-tenant per DB path; no by-id cross-org risk |
| `soar_router.py` | CLEAN — all handlers pass org_id to engine; `get_playbook` takes org_id param |
| `cloud_security_findings_router.py` | CLEAN — all mutations take `org_id` from request body and pass to engine; GET filters by org_id |
| `sbom_router.py` | CLEAN — all handlers pass org_id to engine |
| `risk_scoring_router.py` (list/summary) | CLEAN — summary, rank, score, trend, org-exposure all use org_id query param correctly |
| `executive_dashboard_router.py` | CLEAN — all handlers use `org_id = Query(...)` and pass to engine |
| `ctem_engine_router.py` | CLEAN — all handlers pass org_id; cycle by-id fetches use engine which stores org_id per cycle |
| `ctem_router.py` | CLEAN — same pattern as ctem_engine_router |
| `vuln_lifecycle_router.py` | CLEAN — uses `get_org_id` dependency throughout |
| `vuln_prioritization_router.py` | CLEAN — auth at router level; all handlers pass org_id query param to engine |
| `playbook_router.py` | CLEAN — auth at router level; all by-id handlers pass org_id |
| `incident_triage_router.py` | CLEAN — all by-id handlers take org_id query param and pass to engine |
| `asset_risk_calculator_router.py` | CLEAN — all by-id handlers pass org_id to engine; engine enforces ownership |
| `findings_wave_b_router.py` | CLEAN — uses `get_org_id` dependency; all handlers enforce org via Depends |
| `attack_path_router.py` | CLEAN — all handlers pass org_id; `remove_node` passes org_id to engine |
| `attack_surface_engine_router.py` | CLEAN — all handlers pass org_id query param to engine |
| `integrations_router.py` (GET/PUT/DELETE by-id) | CLEAN — checks `stored_org != "default" and stored_org != org_id` |
| `risk_register_router.py` (list handlers) | CLEAN — list handlers use org_id query param |

---

## Critical Detail: exposure_case_router.py — Complete Auth Absence

File: `suite-core/api/exposure_case_router.py`

```python
router = APIRouter(prefix="/api/v1/cases", tags=["exposure-cases"])
# No dependencies=[Depends(api_key_auth)] here or on any handler

@router.get("/{case_id}")
async def get_case(case_id: str):          # no org_id, no Depends
    mgr = get_case_manager()
    case = mgr.get_case(case_id)           # global lookup by UUID only
    if not case:
        raise HTTPException(status_code=404, ...)
    return case.to_dict()
```

All 5 by-id handlers on this router (GET, PATCH, POST /transition, POST /clusters, GET /transitions) are completely unauthenticated and untenanted.

---

## Critical Detail: cspm_engine_router.py — No Auth at All

File: `suite-api/apps/api/cspm_engine_router.py` line 50:

```python
router = APIRouter(prefix="/api/v1/cspm-engine", tags=["cspm-engine"])
# No imports of api_key_auth, no Depends anywhere in file
```

`GET /resources/{resource_id}` (line 126) fetches a cloud resource by UUID with no org check. `POST /scan` (line 138) runs security checks for a caller-supplied org_id.

---

## Critical Detail: ciem_router.py — No Auth at All

File: `suite-api/apps/api/ciem_router.py`:

```python
from core.ciem_engine import CIEMEngine, get_ciem_engine
from fastapi import APIRouter, HTTPException, Query
# No auth import, no Depends

router = APIRouter(prefix="/api/v1/ciem", tags=["ciem"])
```

All 7 handlers expose IAM risk analysis, policy scoring, escalation path detection, and least-privilege suggestions with zero authentication or tenant isolation.

---

## Critical Detail: incident_response_router.py — No Auth on By-ID Handlers

File: `suite-api/apps/api/incident_response_router.py`:

```python
router = APIRouter(prefix="/api/v1/incidents", tags=["incident-response"])
# Router has no dependencies=[...]; list/create handlers explicitly add
# Depends(api_key_auth) but by-id handlers do NOT

@router.get("/{incident_id}")              # line 142 — no Depends(api_key_auth)
def get_incident(incident_id: str):
    incident = manager.get_incident(incident_id)   # global lookup, no org_id
```

The `list_incidents` and `create_incident` handlers pass `org_id` but the by-id handlers (`get_incident`, `update_status`, `assign_step`, `complete_step`, `add_timeline_event`, `create_post_mortem`, `get_post_mortem`) have no auth dependency and no org_id parameter — pure IDOR.

---

## Critical Detail: security_findings_router.py — Body-Supplied org_id Not Validated

File: `suite-api/apps/api/security_findings_router.py`:

```python
class FindingStatusUpdate(BaseModel):
    org_id: str           # caller supplies this — never verified against auth token
    status: str

@router.patch("/findings/{finding_id}/status", dependencies=[Depends(api_key_auth)])
def update_status(finding_id: str, body: FindingStatusUpdate):
    result = _get_engine().update_status(
        finding_id=finding_id,
        org_id=body.org_id,   # attacker supplies victim org's org_id here
        ...
    )
```

Auth passes (valid API key), but the engine receives attacker-controlled `org_id`. If the engine filters by org_id before mutating, the risk is contained; if it fetches by `finding_id` first and then updates, this is a cross-tenant write. Same pattern on `add_evidence` and `suppress_finding`.

---

## Critical Detail: asset_inventory_router.py — _require_asset Has No Org Check

File: `suite-api/apps/api/asset_inventory_router.py` line 143:

```python
def _require_asset(asset_id: str) -> ManagedAsset:
    asset = _inv().get_asset(asset_id)   # global lookup — no org_id
    if not asset:
        raise HTTPException(status_code=404, ...)
    return asset

@router.get("/{asset_id}", ...)
def get_asset(asset_id: str) -> ManagedAsset:
    return _require_asset(asset_id)      # no org_id param in handler at all
```

The `get_asset`, `update_asset`, `delete_asset`, `assign_owner`, `tag_asset`, `apply_compliance_scope`, `get_relationships`, `get_impact_graph`, `sync_to_cmdb`, `get_sync_history` handlers all call `_require_asset` (or the inventory directly) with no org_id parameter. All are IDOR-vulnerable.

---

## Risk Register by-ID Handlers — Also Missing Org Guards

File: `suite-api/apps/api/risk_register_router.py` lines 325-377:

`GET /{risk_id}`, `PATCH /{risk_id}`, `DELETE /{risk_id}`, `POST /{risk_id}/controls/map`, `DELETE /{risk_id}/controls/{ctrl_id}`, `GET /{risk_id}/treatments` — none accept an `org_id` parameter and none compare `risk.org_id` to caller identity. Auth is applied centrally by `app.py` so authentication exists, but tenant isolation on by-id operations is absent. Classified HIGH.

---

## Recommended Fix Wave 5 Priority Order

1. **Immediate (production risk):** `exposure_case_router.py` — add `dependencies=[Depends(api_key_auth)]` to router + org_id filter on all by-id handlers.
2. **Immediate:** `cspm_engine_router.py` — add auth; add org_id to `get_resource` and verify record ownership.
3. **Immediate:** `ciem_router.py` — add `dependencies=[Depends(api_key_auth)]` to router; add org_id scoping.
4. **Immediate:** `incident_response_router.py` — add `Depends(api_key_auth)` and `org_id` param to all 8 by-id handlers; compare `incident.org_id == org_id`.
5. **High:** `security_findings_router.py` — replace `body.org_id` with `org_id: str = Depends(get_org_id)` on update_status, add_evidence, suppress_finding.
6. **High:** `asset_inventory_router.py` — add `org_id: str = Depends(get_org_id)` to `_require_asset` signature; check `asset.org_id == org_id` before returning.
7. **High:** `deduplication_router.py` — add auth to router; add org_id to get/update/assign/link cluster handlers.
8. **High:** `risk_register_router.py` by-id handlers — add `org_id: str = Depends(get_org_id)`; verify `risk.org_id == org_id`.
9. **Medium:** `risk_scoring_router.py /exposure/{asset_id}` — add `org_id` param; verify asset belongs to org.
10. **Medium:** `integrations_router.py /test`, `/sync-status`, `/trigger-sync` — add same `stored_org` check as existing GET/PUT/DELETE handlers.
