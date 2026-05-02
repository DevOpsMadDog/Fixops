# Dead-Router & Duplicate-Mount Sweep — 2026-05-03

Read-only follow-up to commits `c96dba09` (app.py, 6 deletes), `39e77140`
(ctem_app.py, 6 dup deletes), and `696edbf7` (platform_app.py, 1 ff_router
delete). Same pattern, broader scope.

## Method
AST-walked every `try: from <mod> import router; app.include_router(...) except (ImportError|Exception): pass` block in:

- `suite-api/apps/api/app.py`
- `suite-api/apps/api/sub_apps/{aspm,cspm,ctem,grc,platform}_app.py`

Then resolved `<mod>` against the 6 sitecustomize roots
(`suite-api`, `suite-core`, `suite-attack`, `suite-feeds`, `suite-integrations`,
`suite-evidence-risk`) and the repo root.

## Totals
| Metric | Count |
|--------|-------|
| Router-mounting modules scanned (registrars) | 6 (app.py + 5 sub_apps) |
| Total `include_router`-bearing files in `suite-api/` | 20 |
| Total `try/except` mount blocks in registrars | 923 |
| **DEAD candidates** (`.py` file absent) | **1** |
| **DUP candidates** (same module mounted in 2+ registrars) | **231** |
|   - of which involve `app.py` (Wave-1 leftovers) | **225** |
| Deletable lines in `app.py` (sum of dup try-blocks) | **~1412** |

## DEAD candidates (file missing)
| Module | File:line | Recommended action |
|--------|-----------|---------------------|
| `apps.api.scif_router` | `suite-api/apps/api/sub_apps/grc_app.py:1181` | Delete try-block (file truly absent — `ls` confirmed) |

## DUP candidates — by sub_app (which registrar holds the duplicate)
| Sub_app | Dup count vs app.py | Pattern |
|---------|---------------------|---------|
| `ctem_app.py` | 114 | Wave-3 extracted these; app.py copies were never deleted |
| `grc_app.py` | 109 | Wave-4 extracted these; app.py copies were never deleted |
| `platform_app.py` | 4 | `unified_dashboard`, `metrics_timeseries`, `security_telemetry`, `security_registry` |
| 3-way (app.py + ctem + grc) | 2 | `incident_cost_router`, `incident_metrics_router` (mounted 3x) |
| sub_app↔sub_app only | 6 | `bulk_operations` (aspm/platform), `log_management` (grc/platform), `playbook_marketplace` (grc/platform), `report_scheduler` (grc/platform), `security_automation` (grc/platform), `security_health` (grc/platform) |

## TOP-15 by deletable-line impact (app.py blocks to remove)
| Lines | app.py block(s) | Module | Dup with |
|-------|-----------------|--------|----------|
| 15 | 5833-5841, 6996-7001 | `compliance_automation_router` | grc_app.py |
| 15 | 5866-5874, 6760-6765 | `compliance_gap_router` | grc_app.py |
| 12 | 5501-5513 (×2) | `vendor_risk_router` | grc_app.py |
| 12 | 5529-5534, 6859-6864 | `iot_security_router` | ctem_app.py |
| 11 | 5935-5940, 6367-6371 | `threat_correlation_router` | ctem_app.py |
| 10 | 5041-5050 | `unified_dashboard_router` | platform_app.py |
| 10 | 5055-5064 | `auto_evidence_router` | grc_app.py |
| 9  | 5563-5571 | `audit_analytics_router` | grc_app.py |
| 9  | 5667-5675 | `composite_alert_router` | ctem_app.py |
| 9  | 5678-5686 | `drp_router` | ctem_app.py |
| 9  | 5689-5697 | `deception_router` | ctem_app.py |
| 9  | 5733-5741 | `attack_path_router` | ctem_app.py |
| 9  | 5755-5763 | `insider_threat_router` | ctem_app.py |
| 9  | 5777-5785 | `playbook_router` | grc_app.py |
| 9  | 5844-5852 | `data_classification_router` | grc_app.py |

## Recommended cleanup waves
1. **Wave A — DEAD (safe, immediate):** delete the 1 dead `scif_router` try-block in `grc_app.py` (~7 lines).
2. **Wave B — app.py↔grc_app.py dups (109 blocks, ~650 lines):** delete the app.py copy; sub_app already mounts.
3. **Wave C — app.py↔ctem_app.py dups (114 blocks, ~700 lines):** same as B.
4. **Wave D — sub_app↔sub_app dups (6 blocks):** decide canonical owner per router (recommend keeping the domain-aligned one, e.g. `bulk_operations` → aspm).
5. **Wave E — 3-way triplicates (2 blocks):** `incident_cost_router` and `incident_metrics_router` mounted in app.py + ctem + grc; keep grc, drop the other two.

## Verification before each delete
- Confirm sub_app mount executes at request time (no order-dependent side effect lost)
- Run Beast Mode tests + 42-hub smoke test
- Re-count `len(app.routes)` — should not change (sub_app already provides the route)
