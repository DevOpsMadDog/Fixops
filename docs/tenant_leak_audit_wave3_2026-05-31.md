# Tenant Leak Audit — Wave 3 (2026-05-31)

**Auditor:** security-auditor agent (chief-architect C1 sweep)
**Scope:** Full router surface across `suite-api/apps/api/`, `suite-core/api/`, `suite-attack/api/`
**Already fixed (wave 1+2, excluded):** risk_acceptance, audit, scanner_ingest, copilot, secrets, secret_scanner, secrets_rotation, vuln_discovery, webhook_events, code_to_cloud, mpte_orchestrator, admin, teams, users, policies, inventory, workflows, analytics
**Method:** grep `Depends(get_org_id)` across all routers; for each, verify id-parameterised handlers compare `record.org_id != org_id`; identify list endpoints that omit `org_id` in their DB call; identify tenant-scoped routers with zero org isolation.

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL (id-param read/write with no org check) | 18 |
| HIGH (list endpoint leaks all-tenant data, or cross-tenant write) | 13 |
| MEDIUM (no org isolation on lower-sensitivity tenant data) | 9 |
| **Total** | **40** |

---

## Findings Table (sorted by severity)

| # | Severity | File (path relative to repo root) | Line(s) | Handler | Missing guard |
|---|----------|-----------------------------------|---------|---------|---------------|
| 1 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 165–172 | `get_task(task_id)` | `service.get_task(task_id)` returns any tenant's task — no `org_id` param passed, no `task.org_id != org_id` check after fetch |
| 2 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 175–213 | `update_task_status(task_id, ...)` | `service.update_status(task_id=...)` — no org_id forwarded; any authenticated tenant can flip another tenant's task status |
| 3 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 216–229 | `assign_task(task_id, ...)` | `service.assign_task(task_id=...)` — no org_id forwarded; cross-tenant task assignment |
| 4 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 232–247 | `submit_verification(task_id, ...)` | `service.submit_verification(task_id=...)` — no org_id forwarded |
| 5 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 250–265 | `link_ticket(task_id, ...)` | `service.link_to_ticket(task_id=...)` — no org_id forwarded |
| 6 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 321–375 | `autofix_task(task_id, ...)` | `service.get_task(task_id)` with no org check before building autofix payload from task data |
| 7 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 376–392 | `get_task_autofix_suggestions(task_id)` | `engine.list_fixes(finding_id=task_id)` — no org_id parameter, returns fixes for any tenant's task |
| 8 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 394–410 | `transition_task_status(task_id, ...)` | Alias for update_task_status; same missing org check |
| 9 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 412–426 | `verify_task(task_id, ...)` | Alias for submit_verification; same missing org check |
| 10 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 716–731 | `get_task_timeline(task_id)` | No `org_id` parameter; returns timeline for any tenant's task |
| 11 | CRITICAL | `suite-api/apps/api/remediation_router.py` | 935–950 | `update_plan_state(plan_id, ...)` | `engine.update_plan_state(plan_id=...)` — no org_id forwarded; cross-tenant plan mutation |
| 12 | CRITICAL | `suite-api/apps/api/reports_router.py` | 591–597 | `get_report(id)` | `db.get_report(id)` — no org_id filter; returns any tenant's report |
| 13 | CRITICAL | `suite-api/apps/api/reports_router.py` | 600–622 | `download_report(id)` | `db.get_report(id)` — no org_id filter; allows downloading any tenant's report file |
| 14 | CRITICAL | `suite-api/apps/api/reports_router.py` | 624–667 | `get_report_file(id)` | `db.get_report(id)` — no org_id filter; serves raw report file bytes without tenant check |
| 15 | CRITICAL | `suite-api/apps/api/threat_hunting_router.py` | 187–194 | `get_session(session_id)` | `engine.get_session(session_id)` — no org_id parameter; returns any tenant's hunt session |
| 16 | CRITICAL | `suite-api/apps/api/threat_hunting_router.py` | 238–249 | `end_session(session_id, ...)` | `engine.end_session(session_id, ...)` — no org_id parameter; allows ending another tenant's active session |
| 17 | CRITICAL | `suite-api/apps/api/threat_hunting_router.py` | 353–361 | `get_hunt(hunt_id)` | `engine.get_hunt(hunt_id)` — no org_id parameter; returns any tenant's saved hunt definition |
| 18 | CRITICAL | `suite-api/apps/api/threat_hunting_router.py` | 396–405 | `delete_hunt(hunt_id)` | `engine.delete_hunt(hunt_id)` — no org_id parameter; allows deleting another tenant's saved hunt |
| 19 | HIGH | `suite-api/apps/api/reports_router.py` | 468–488 | `list_reports(org_id=...)` | `db.list_reports(report_type=..., limit=..., offset=...)` — `org_id` is fetched but **never passed** to the DB call; returns all tenants' reports |
| 20 | HIGH | `suite-api/apps/api/reports_router.py` | 490–516 | `create_report(report_data)` | No `org_id` parameter at all; report created with no tenant stamp; visible to all tenants via list_reports leak |
| 21 | HIGH | `suite-api/apps/api/reports_router.py` | 518–525 | `generate_report(report_data)` | Delegates to `create_report`; same missing org stamp |
| 22 | HIGH | `suite-api/apps/api/reports_router.py` | 527–589 | `get_report_stats(...)` | No `org_id` filter; stats aggregated across all tenants' reports |
| 23 | HIGH | `suite-api/apps/api/remediation_router.py` | 613–648 | `remediation_stats(request)` | Reads `org_id` from query param with fallback to `"default"`; not validated via `Depends(get_org_id)`; any tenant can specify another tenant's org_id |
| 24 | HIGH | `suite-api/apps/api/remediation_router.py` | 650–679 | `remediation_queue(request)` | Same pattern — `org_id = request.query_params.get("org_id", "default")`; no auth validation of org_id value |
| 25 | HIGH | `suite-api/apps/api/remediation_router.py` | 681–714 | `remediation_summary(request)` | Hardcodes `org_id="default"` — returns remediation summary for the `default` org to every authenticated tenant |
| 26 | HIGH | `suite-api/apps/api/fail_router.py` | 338–352 | `get_drill(drill_id)` | `engine.get_drill(drill_id)` — no org_id parameter; returns any tenant's FAIL drill record |
| 27 | HIGH | `suite-api/apps/api/fail_router.py` | 484–511 | `cancel_drill(drill_id, ...)` | `engine.cancel_drill(drill_id=...)` — no org_id parameter; allows cancelling another tenant's active security drill |
| 28 | HIGH | `suite-core/api/pipeline_router.py` | 106–120 | `list_pipeline_runs(...)` | `pipeline.list_runs()` — no org_id filter; returns all tenants' pipeline run history |
| 29 | HIGH | `suite-core/api/pipeline_router.py` | 123–133 | `get_pipeline_run(run_id)` | `pipeline.get_run(run_id)` — no org_id filter; returns any tenant's pipeline run detail (includes ingested findings, scan results) |
| 30 | HIGH | `suite-core/api/pipeline_router.py` | 158–166 | `list_evidence_packs(...)` | `generator.list_packs()` — no org_id filter; lists SOC2 evidence packs across all tenants |
| 31 | HIGH | `suite-core/api/pipeline_router.py` | 168–175 | `get_evidence_pack(pack_id)` | `generator.get_pack(pack_id)` — no org_id filter; serves any tenant's SOC2 evidence pack |
| 32 | HIGH | `suite-api/apps/api/threat_hunting_router.py` | 197–235 | `run_hunt(session_id, ...)` | `engine.get_session(session_id)` without org check before executing hunt against caller-supplied findings |
| 33 | HIGH | `suite-api/apps/api/threat_hunting_router.py` | 251–263 | `get_session_results(session_id)` | `engine.get_session(session_id)` — no org_id parameter; returns hunt results from any tenant's session |
| 34 | MEDIUM | `suite-api/apps/api/sla_router.py` | 282–356 | `sla_dashboard_legacy()` | No `org_id` parameter; calls `db.list_tasks(limit=500)` with no tenant filter; exposes SLA metrics across all tenants |
| 35 | MEDIUM | `suite-api/apps/api/sla_router.py` | 358–413 | `sla_metrics()` | No `org_id` parameter; same global `list_tasks` — MTTR and team breakdown leaked cross-tenant |
| 36 | MEDIUM | `suite-api/apps/api/sla_router.py` | 415–463 | `sla_breaches()` | No `org_id` parameter; lists breached tasks across all tenants |
| 37 | MEDIUM | `suite-core/api/brain_router.py` | 197–207 | `get_node(node_id)` | `brain.get_node(node_id)` — no org_id filter; TrustGraph nodes are shared-instance, allows reading another tenant's ingested finding/CVE nodes |
| 38 | MEDIUM | `suite-core/api/brain_router.py` | 207–222 | `delete_node(node_id)` | `brain.delete_node(node_id)` — no org_id filter; allows deleting another tenant's brain node (destructive) |
| 39 | MEDIUM | `suite-api/apps/api/data_classification_router.py` | 116–126 | `get_asset_classification(asset_id)` | `engine.get_asset_classification(asset_id)` — no org_id parameter; engine factory `_engine` is not per-org (no `org_id` in `Depends`); returns any asset classification |
| 40 | MEDIUM | `suite-api/apps/api/reports_router.py` | 670–698 | `schedule_report(...)` / `list_schedules(...)` | `db.create_schedule` / `db.list_schedules` — no org_id column passed; schedules are global; any tenant can trigger or view any other tenant's scheduled report jobs |

---

## Fix Agent Instructions

### Priority 1 — CRITICAL: remediation_router.py (10 handlers, lines 165–726)

All `tasks/{task_id}` handlers must:
1. Add `org_id: str = Depends(get_org_id)` to the function signature.
2. After `task = service.get_task(task_id)`, assert `task.get("org_id") == org_id` (raise 404 on mismatch — not 403, to avoid enumeration).
3. Pass `org_id=org_id` to all downstream `service.*` calls.

`update_plan_state` (line 935): add `org_id: str = Depends(get_org_id)` and assert `plan.org_id == org_id` after fetch.

### Priority 2 — CRITICAL: reports_router.py (lines 468–667)

1. `list_reports` (468): pass `org_id=org_id` to `db.list_reports(...)`.
2. `create_report` / `generate_report` (490, 518): add `org_id: str = Depends(get_org_id)`, stamp `Report(org_id=org_id, ...)`.
3. `get_report_stats` (527): add `org_id: str = Depends(get_org_id)`, filter reports to `r.org_id == org_id`.
4. `get_report` / `download_report` / `get_report_file` (591, 600, 624): after `db.get_report(id)`, assert `report.org_id == org_id` (return 404 on mismatch).
5. `schedule_report` / `list_schedules` (670, 686): stamp schedule with `org_id`; filter list by `org_id`.

### Priority 3 — CRITICAL: threat_hunting_router.py (lines 187–405)

`get_session`, `end_session`, `run_hunt`, `get_session_results`: add `org_id: str = Depends(get_org_id)`, pass to `engine.*` calls and assert ownership.
`get_hunt`, `delete_hunt`, `run_saved_hunt`, `get_hunt_results`, `schedule_hunt`: add `org_id: str = Depends(get_org_id)`, pass to engine and assert `hunt.org_id == org_id`.

### Priority 4 — HIGH: remediation_router.py stats/queue/summary (lines 613–714)

Replace raw `request.query_params.get("org_id", "default")` with `org_id: str = Depends(get_org_id)`. Remove hardcoded `"default"` in `remediation_summary`.

### Priority 5 — HIGH: fail_router.py (lines 338, 484)

`get_drill` (338): add `org_id: str = Depends(get_org_id)`, assert `drill.get("org_id") == org_id`.
`cancel_drill` (484): same pattern.
Also audit `mark_detected` (358), `mark_triaged` (381), `mark_remediated` (407), `grade_drill` (436) — same unguarded drill_id pattern.

### Priority 6 — HIGH: pipeline_router.py (lines 106–175)

`list_pipeline_runs` / `get_pipeline_run`: add `org_id: str = Depends(get_org_id)`, filter `pipeline.list_runs(org_id=org_id)` and assert `run.org_id == org_id` on fetch.
`list_evidence_packs` / `get_evidence_pack`: same pattern.

### Priority 7 — MEDIUM: sla_router.py (lines 282–463)

`sla_dashboard_legacy`, `sla_metrics`, `sla_breaches`: add `org_id: str = Depends(get_org_id)`, filter `db.list_tasks(org_id=org_id, limit=500)`.

### Priority 8 — MEDIUM: brain_router.py (lines 197–222)

`get_node` / `delete_node`: add `org_id: str = Depends(get_org_id)`, assert `node.get("org_id") == org_id` after fetch. For `delete_node`, return 404 on mismatch.

### Priority 9 — MEDIUM: data_classification_router.py (line 116)

`get_asset_classification`: add `org_id: str = Depends(get_org_id)`, pass to engine factory `_engine(org_id)`, assert `asset.org_id == org_id`.
`upgrade_classification` (145) / `downgrade_classification` (163): same — add `org_id: str = Depends(get_org_id)`.

---

## Out-of-scope (confirmed clean in this sweep)

The following org-aware routers were inspected and found to correctly pass `org_id` to all id-parameterised fetches with explicit ownership assertions:
`findings_persistence_router.py`, `findings_routes.py`, `findings_wave_b_router.py`, `evidence_collector_router.py` (primary handlers), `compliance_planner_router.py`, `risk_quantifier_router.py`, `vuln_lifecycle_router.py`, `pentest_router.py`, `auto_pentest_router.py`, `pam_router.py`, `ndr_router.py`, `xdr_router.py`, `outbound_webhooks_router.py`, `webhook_subscriptions_router.py`, `webhook_filter_rules_router.py`, `webhook_dlq_router.py`, `sla_engine_router.py`, `sla_management_router.py`, `composite_risk_router.py`, `exception_policy_router.py`, `regulatory_tracker_router.py`, `cloud_security_router.py`, `fail_router.py` (inject/list/scores/top-risks/stats endpoints only).
