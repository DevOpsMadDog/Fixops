# ALdeci / FixOps — Stubs to Clean Up

> **Audit date**: 2026-02-20  
> **Scope**: All 6 suites (suite-api, suite-core, suite-attack, suite-feeds, suite-evidence-risk, suite-integrations) + suite-ui  
> **Total stubs found**: 29 UI pages + 21 backend TODOs + 29 NotImplementedError + 17,912 LOC legacy duplication + 5 redundant files

---

## Table of Contents

1. [Summary Dashboard](#1-summary-dashboard)
2. [UI Page Stubs (29 pages)](#2-ui-page-stubs)
3. [Backend TODO Stubs (21 TODOs)](#3-backend-todo-stubs)
4. [Backend NotImplementedError Stubs (29 raises)](#4-backend-notimplementederror-stubs)
5. [Backend Placeholder / Fallback Endpoints](#5-backend-placeholder--fallback-endpoints)
6. [Legacy / Enterprise Code Duplication](#6-legacy--enterprise-code-duplication)
7. [Dead / Redundant Files](#7-dead--redundant-files)
8. [Empty __init__.py Placeholders](#8-empty-__init__py-placeholders)
9. [Dead UI Buttons](#9-dead-ui-buttons)
10. [Cleanup Priority Matrix](#10-cleanup-priority-matrix)

---

## 1. Summary Dashboard

| Category | Count | Impact | Cleanup Effort |
|----------|-------|--------|---------------|
| **UI Minimal Stubs** (< 80 LOC, read-only) | 6 pages | Investors see empty screens | 3-5 days |
| **UI Basic Stubs** (actions exist but broken/alert-only) | 10 pages | Features appear broken | 5-7 days |
| **UI Functional Stubs** (works but shallow) | 11 pages | Missing depth, no charts/search/pagination | 7-10 days |
| **UI Near-Complete** (minor gaps) | 2 pages | Polish only | 1-2 days |
| **Backend TODOs** (endpoints returning placeholder data) | 21 | APIs lie — return fake data | 5-8 days |
| **Backend NotImplementedError** (abstract + real stubs) | 29 | Crashes if called | 2-3 days |
| **Backend Placeholders/Fallbacks** | ~9 | Silent failures | 2 days |
| **Legacy Code Duplication** | 17,912 LOC in `*/legacy/` dirs | Confusing, inflates LOC | 3-5 days (delete) |
| **Redundant Frontend Files** | 3 files (2,994 LOC) | Dead code shipped to browser | 30 min |
| **Dead UI Buttons** | ~8 buttons across 5 pages | Users click, nothing happens | 2 days |
| **Empty `__init__.py`** | 18 files | No impact (normal Python) | — |

---

## 2. UI Page Stubs

### Category: Minimal Stub (< 80 LOC, read-only flat list, no interactivity)

| # | File | LOC | What It Renders | Why It's a Stub | What's Missing |
|---|------|-----|-----------------|-----------------|----------------|
| 1 | `pages/evidence/AuditLogs.tsx` | 52 | Single card listing log entries (action, user, timestamp) | Read-only flat list, no filtering or export | Date/user/action filters, search, pagination, log level badges, export, real-time streaming, detail drill-down |
| 2 | `pages/code/Inventory.tsx` | 53 | Single card listing apps (name, type) | Flat list with no interaction | Search/filter, asset detail view, risk scoring per asset, dependency graph, grouping, CRUD, tagging |
| 3 | `pages/settings/Teams.tsx` | 55 | Card listing teams + "Create Team" / "Manage" buttons | **Buttons have no onClick handlers** — they render but do nothing | Create/edit/delete team forms, member management, role assignment, permission matrix, invite flow |
| 4 | `pages/settings/Users.tsx` | 55 | Card listing users + "Add User" / "Edit" buttons | **Buttons have no onClick handlers** — decorative only | Create/edit/delete user forms, role assignment, password reset, MFA, activity history, bulk ops |
| 5 | `pages/protect/Collaboration.tsx` | 72 | Two-column: Recent Comments + Pending Notifications | Purely read-only, no post/reply/dismiss | Post comments, reply threads, @mentions, mark notifications read, notification preferences, entity linking |
| 6 | `pages/cloud/ThreatFeeds.tsx` | 80 | Tabbed: EPSS scores (CVE + %) and KEV catalog (CVE + name) | Tab switching only — no search, refresh, or detail | Search by CVE, feed refresh controls, NVD tab, ExploitDB tab, feed health, enrichment, pagination, sorting |

### Category: Basic Stub (has 1 API action, but major features missing)

| # | File | LOC | What It Renders | Why It's a Stub | What's Missing |
|---|------|-----|-----------------|-----------------|----------------|
| 7 | `pages/settings/Marketplace.tsx` | 66 | 3-column grid of items + "Install" button | Install uses `alert()` for feedback instead of toast/UI update | Search/filter, categories sidebar, installed vs available, uninstall, version management, detail modal |
| 8 | `pages/code/IaCScanning.tsx` | 67 | Scan list with status badges + "Trigger Scan" button | Scan trigger works but no configuration | File upload, scan config (rules, exclusions), finding details, remediation, scan history with diff, severity breakdown |
| 9 | `pages/protect/Workflows.tsx` | 71 | Workflow list + "Run" button + dead "Create Workflow" button | Execute works; **Create is non-functional** | Workflow editor/builder, create/edit/delete, condition config, execution history, step visualization, enable/disable toggle |
| 10 | `pages/evidence/EvidenceBundles.tsx` | 74 | Bundle list + "Verify" + dead "Download" button | Verify uses `alert()`; **Download has no handler** | Download implementation, bundle creation, content preview, signature details, comparison, compliance mapping, WORM status |
| 11 | `pages/ai-engine/Policies.tsx` | 75 | Policy list + "Validate" + dead "Create Policy" button | Validate calls API; **Create is non-functional** | Policy editor (rule builder), create/edit/delete, OPA/Rego integration, policy testing, violation history, import/export |
| 12 | `pages/evidence/Reports.tsx` | 76 | Report list + "Generate" + dead "Download" button | Generate calls API; **Download has no handler** | Download implementation, report templates, scheduled reports, preview, custom date ranges, compliance-specific reports |
| 13 | `pages/cloud/CorrelationEngine.tsx` | 78 | Stats (Total Clusters, Reduction Rate) + cluster list | **"~40%" reduction rate is hardcoded** — not calculated from data | Real reduction rate, cluster detail/drill-down, merge/split, similarity visualization, rule config |
| 14 | `pages/settings/SystemHealth.tsx` | 89 | Status/Version/Uptime cards + service list + raw JSON dump | Read-only, no refresh, shows raw JSON to users | Auto-refresh interval, historical uptime graphs, alerting thresholds, service restart controls, resource usage |
| 15 | `pages/protect/Remediation.tsx` | 103 | 4 stat cards + task list with status badges | **Refresh button only** — no task CRUD | Create/edit tasks, status transitions (drag & drop), assignee management, SLA tracking, Jira sync, priority ordering, bulk actions |
| 16 | `pages/cloud/RuntimeProtection.tsx` | 127 | Stats + runtime agent grid (status/CPU/mem) + security events | **Refresh button only** — well-designed but read-only | Agent deployment/management, policy config, real-time event streaming, incident response actions, alert rules |

### Category: Functional Stub (real actions work, but shallow depth)

| # | File | LOC | What It Renders | Why It's a Stub | What's Missing |
|---|------|-----|-----------------|-----------------|----------------|
| 17 | `pages/ai-engine/Predictions.tsx` | 76 | CVE input form + results (risk, 30-day forecast, trend, raw JSON) | Works end-to-end but displays raw JSON | Visualization charts (risk over time), historical predictions, batch analysis, comparison view, confidence intervals, export |
| 18 | `pages/attack/Reachability.tsx` | 103 | Input form (CVE + repo URL) + results panel | Pre-filled with `https://github.com/example/repo` placeholder | Batch analysis, network topology visualization, path graph rendering, asset mapping, history |
| 19 | `pages/ai-engine/AlgorithmicLab.tsx` | 118 | Input form + Monte Carlo + Causal Analysis results | **Uses raw `<button>` instead of `<Button>` component**; shows raw JSON | Distribution histograms, causal DAGs, parameter tuning, history, comparison mode, export |
| 20 | `pages/attack/AttackSimulation.tsx` | 123 | Header + 4 stat cards + embedded `<MPTEChat />` | **Thin wrapper** — page is just stat cards; all real logic in MPTEChat | Page is a shell; attack config, target selection, campaign history, report generation all external |
| 21 | `pages/cloud/ContainerSecurity.tsx` | 134 | Stats + tabs: Images (risk bars) + Vulns (severity badges) | Works but only bulk scan — no per-image control | Individual image scan, registry integration, CIS benchmarks, Dockerfile analysis, layer-by-layer view |
| 22 | `pages/code/SBOMGeneration.tsx` | 136 | Stats + 3 tabs: SBOMs, Dependencies, Licenses | Generate CycloneDX/SPDX works; **Download button non-functional** | Download implementation, SBOM diff, dependency tree visualization, license policy enforcement, VEX support |
| 23 | `pages/evidence/SLSAProvenance.tsx` | 142 | 5 stats + 3 tabs: Attestations, Evidence Bundles, SLSA Levels | Good layout but **refresh only** — no create/verify/sign | Create attestation, verify signature, builder config, in-toto layout editor, provenance graph |
| 24 | `pages/evidence/EvidenceAnalytics.tsx` | 151 | 5 stats + 3 tabs: Severity Trends (progress bars), Anomaly, Audit Chain | Export CSV/JSON works; all charts are progress bars | Real line/bar charts (recharts), date range picker, drill-down, anomaly alert config, custom metrics |
| 25 | `pages/Copilot.tsx` | 153 | Chat interface with message bubbles + quick action buttons | Full chat works but responses display as plain text | Markdown rendering, message history persistence, streaming responses, file attachment, code syntax highlighting |
| 26 | `pages/ai-engine/MLDashboard.tsx` | 238 | 5 stats + 3 tabs: ML Models (accuracy bars), Anomalies, API Traffic | Retrain button works; every section is list-only | Model config/hyperparameters, training history charts, prediction accuracy over time, A/B testing, feature importance |
| 27 | `pages/code/CodeScanning.tsx` | 260 | Scan input + 4 stat cards + findings list | **Scan mutation injects fake vulnerability string** (`eval(data.text)` as simulated code) | Real repo cloning, scan configuration, finding detail view, fix suggestions, scan history, branch selection |

### Category: Near-Complete (minor polish needed)

| # | File | LOC | What It Renders | Why It's Here | What's Missing |
|---|------|-----|-----------------|---------------|----------------|
| 28 | `pages/feeds/LiveFeedDashboard.tsx` | 206 | 5 stats + 6-feed health grid + EPSS/KEV tabs + per-feed refresh | Well-structured, multiple API calls, per-feed actions | Auto-refresh interval, feed configuration, historical latency charts, alert on degradation |
| 29 | `pages/protect/AutoFixDashboard.tsx` | 248 | 5 stats + 3 tabs + confidence chart + extracted FixCard component | Most feature-rich: generate/apply/rollback/PR link all functional | Patch preview/diff viewer, test validation, approval workflow, batch ops |

---

## 3. Backend TODO Stubs

All 21 TODO comments mark endpoints that **return placeholder/synthetic data** instead of real integrations.

### agents_router.py (16 TODOs — largest stub concentration)

| Line | Function | TODO Text | Impact |
|------|----------|-----------|--------|
| L625 | `analyze_attack_path()` | Integrate with real asset inventory and network topology service | Returns synthetic attack paths, not real network data |
| L705 | `get_asset_risk_score()` | Integrate with asset inventory service to get real vulnerability counts | Returns fabricated risk scores |
| L1100 | `map_findings_to_compliance()` | Integrate with compliance mapping service | Returns placeholder compliance mappings |
| L1122 | `run_gap_analysis()` | Integrate with compliance engine | Returns template gap analysis, not real assessment |
| L1148 | `collect_audit_evidence()` | Integrate with evidence store | Returns placeholder evidence collection |
| L1172 | `check_regulatory_alerts()` | Integrate with regulatory update feeds | Returns empty/static alerts |
| L1199 | `get_framework_controls()` | Integrate with full compliance control library | Returns partial control list |
| L1272 | `get_compliance_dashboard()` | Integrate with compliance assessment database | Returns synthetic dashboard stats |
| L1301 | `generate_compliance_report()` | Integrate with compliance report generator | Returns template report, not real |
| L1329 | `generate_fix()` | Integrate with LLM for code fix generation | Returns placeholder fix code |
| L1353 | `create_pull_request()` | Integrate with Git provider APIs | Returns fake PR URL |
| L1375 | `update_dependencies()` | Integrate with package managers | Returns placeholder update results |
| L1397 | `generate_playbook()` | Integrate with remediation knowledge base | Returns template playbook |
| L1422 | `get_recommendations()` | Integrate with finding details and remediation database | Returns generic recommendations |
| L1446 | `verify_remediation()` | Integrate with scanning tools for verification | Returns placeholder verification |
| L1472 | `get_remediation_queue()` | Integrate with remediation tracking database | Returns synthetic queue |

### vuln_discovery_router.py (3 TODOs)

| Line | Function | TODO Text | Impact |
|------|----------|-----------|--------|
| L320 | CVSS calculation | Integrate with cvss library for real calculation | Returns estimated scores, not CVSS v3.1 computed |
| L696 | External CVE count | Query actual CVE database when integrated | `external_count = 0` hardcoded |
| L761 | MindsDB training | Implement actual MindsDB training call | ML training endpoint is a no-op |

### Other files (2 TODOs)

| File | Line | TODO Text | Impact |
|------|------|-----------|--------|
| `advanced_pentest_engine.py` | L1273 | Implement remediation for {category} in {language} | Returns template string instead of real fix code |
| `business_context_enhanced.py` | L47 | Store ssvc_context in database linked to service_name | Business context not persisted — lost on restart |

---

## 4. Backend NotImplementedError Stubs

29 `raise NotImplementedError` calls across 10 files. Some are **intentional abstract base classes** (ABCs), others are **real stubs**.

### Intentional ABCs (expected — define interface contracts)

| File | Lines | Class | Method | Why It Exists |
|------|-------|-------|--------|---------------|
| `core/connectors.py` | L315 | `_BaseConnector` | `health_check()` | ABC — all connectors must override |
| `core/vector_store.py` | L60, L65 | `VectorStore` | `add()`, `search()` | ABC — vector store interface |
| `core/adapters.py` | L97, L101 | `BaseAdapter` | `transform()`, `validate()` | ABC — data adapter interface |
| `ssvc/__init__.py` | L58 | `SSVCPlugin` | `evaluate()` | ABC — SSVC plugin interface |

### Real Stubs (should be implemented)

| File | Lines | What | Why It's There | Impact |
|------|-------|------|----------------|--------|
| `apps/api/ingestion.py` | L424 | `IngestorBase.ingest()` | Ingestion base class never completed — concrete ingestors exist but base is empty | Would crash if base called directly |
| `apps/api/integrations.py` | L49, L135, L139, L301, L305 | `IntegrationProvider` methods: `test_connection()`, `sync()`, `disconnect()`, `get_status()`, `get_config()` | **5 abstract methods** — provider interface exists but some integration types don't implement all methods | Crashes when calling unimplemented integration types |
| `utils/enterprise/crypto.py` | L49-L75 | 6 methods: `encrypt()`, `decrypt()`, `sign()`, `verify()`, `generate_key()`, `rotate_key()` | Enterprise crypto placeholder — **all 6 methods raise NotImplementedError** | Enterprise crypto module is a complete stub (970 LOC file, but core methods are empty) |
| `utils/legacy/crypto.py` | L50-L76 | Same 6 methods as enterprise | Copy-paste of enterprise crypto stub | Same — complete stub |
| `services/enterprise/vector_store.py` | L32, L37, L63 | `add()`, `search()`, `delete()` | Enterprise vector store — interface-only | Embedding search not available in enterprise mode |
| `services/enterprise/real_opa_engine.py` | L25, L29 | `evaluate()`, `load_policy()` | OPA (Open Policy Agent) integration not connected | Policy evaluation doesn't work via OPA |

---

## 5. Backend Placeholder / Fallback Endpoints

These endpoints **don't crash** but return synthetic/demo data silently.

| File | Line | Endpoint/Function | What It Does Instead |
|------|------|--------------------|---------------------|
| `integrations_router.py` | L289 | `test_integration()` | Returns `"Test not implemented for {type}"` for unsupported integration types |
| `integrations_router.py` | L460 | `trigger_sync()` | Returns `"Sync not implemented for {type}"` for unsupported types |
| `marketplace_router.py` | L126-L275 | All marketplace endpoints | Returns **hardcoded demo data** (`_DEMO_MARKETPLACE_ITEMS`, `_DEMO_CONTRIBUTORS`) when enterprise module is unavailable |
| `continuous_validation.py` | L323 | Validation check | Comment: `"For now, this is a placeholder"` |
| `cloud.py` (risk/runtime) | L130 | Cloud runtime check | Comment: `"For now, this is a placeholder"` |
| `intelligent_security_engine.py` | L810 | Simulation result | Returns `{"simulated": True, "findings": [], "evidence": []}` |
| `feeds_router.py` | L510, L568, L645 | `get_all_exploits()`, `get_all_threat_actors()`, misc | `"Fallback if method not implemented"` — returns empty lists |
| `deduplication_router.py` | L251 | Dedup method | `"Fallback if method not implemented"` — uses default |

---

## 6. Legacy / Enterprise Code Duplication

**17,912 LOC** in `suite-core/*/legacy/` directories that duplicate or obsolete the main codebase.

### Legacy Directories (6 locations)

| Path | Files | LOC | Duplicates |
|------|-------|-----|------------|
| `core/services/legacy/` | 20 files | 15,802 | `advanced_pentest_engine.py` (2,605 LOC) duplicates `core/mpte_advanced.py` |
| `core/utils/legacy/` | 3 files | ~730 | `crypto.py` (723 LOC) duplicates `core/crypto.py` (570 LOC) |
| `core/models/legacy/` | 2 files | ~20 | Empty __init__ + old models |
| `core/db/legacy/` | 1 file | 1 | Empty `__init__.py` with docstring `"Database package placeholder."` |
| `core/legacy/` | 1+ files | ~0 | Empty __init__ |
| `config/legacy/` | 2 files | 104 | Old `settings.py` |

### Top Legacy Files by Size

| File | LOC | What It Is | Active Replacement |
|------|-----|-----------|-------------------|
| `services/legacy/playbook_executor.py` | 2,840 | Old playbook engine | `core/playbook_executor.py` exists |
| `services/legacy/advanced_pentest_engine.py` | 2,605 | Old pentest engine | `core/mpte_advanced.py` (production) |
| `services/legacy/feeds_service.py` | 2,299 | Old feeds service | `suite-feeds/` (separate suite) |
| `services/legacy/automated_pentest.py` | 1,430 | Older pentest automation | `core/micro_pentest.py` (production) |
| `services/legacy/micro_pentest_engine.py` | 1,189 | Even older pentest engine | Third version — two newer exist |
| `services/legacy/marketplace_service.py` | 781 | Old marketplace | `services/enterprise/marketplace.py` |
| `services/legacy/mitre_compliance_analyzer.py` | 764 | Old MITRE mapping | `core/mitre_mapper.py` likely |
| `services/legacy/crypto.py` (in utils/) | 723 | Old crypto module | `core/crypto.py` (production, 570 LOC) |
| `services/legacy/vex_ingestion.py` | 653 | Old VEX parser | Ingestion router handles this now |
| `services/legacy/real_opa_engine.py` | 612 | Old OPA engine | `services/enterprise/real_opa_engine.py` |
| `services/legacy/evidence.py` | 606 | Old evidence service | `core/evidence.py` (production, 437 LOC) |

### Enterprise Directories (duplicates but may be needed)

| Path | Key Files | LOC | Relationship |
|------|-----------|-----|-------------|
| `core/utils/enterprise/crypto.py` | Enterprise crypto stubs | 970 | **All 6 core methods raise NotImplementedError** — 970 LOC of scaffolding with no implementation |
| `core/services/enterprise/vector_store.py` | Enterprise vector store | 452 | 3 core methods raise NotImplementedError |
| `core/services/enterprise/real_opa_engine.py` | Enterprise OPA | ~100 | 2 core methods raise NotImplementedError |
| `core/services/enterprise/marketplace.py` | Enterprise marketplace | 652 | Functional but fallback to demo data |

---

## 7. Dead / Redundant Files

| File | LOC | Why It's Dead | Action |
|------|-----|---------------|--------|
| `suite-ui/aldeci/src/lib/api.backup.ts` | 731 | Old API client backup — `api.ts` (1,257 LOC) is the active version | Delete |
| `suite-ui/aldeci/src/lib/api-complete.ts` | 1,032 | Intermediate API client version — never imported | Delete |
| `suite-core/core/db/legacy/__init__.py` | 1 | Contains only `"""Database package placeholder."""` | Delete with parent dir |
| `suite-core/core/services/legacy/compliance_engine.py` | 7 | Essentially empty file | Delete |
| `suite-core/core/services/legacy/runtime.py` | 11 | Near-empty wrapper | Delete |
| `suite-core/core/services/legacy/id_allocator.py` | 43 | Superseded by UUID generation in newer code | Delete |
| `suite-core/core/services/legacy/marketplace.py` | 70 | Tiny duplicate of larger marketplace_service.py | Delete |
| VS Code task `replace-api-file` | — | Task `mv ui/aldeci/src/lib/api.v2.ts ui/aldeci/src/lib/api.ts` — references file that may not exist | Remove task from `.vscode/tasks.json` |

---

## 8. Empty `__init__.py` Placeholders

These are **normal Python** — not real stubs. Listed for completeness (no action needed unless the directory itself is dead).

| File | Content | Keep? |
|------|---------|-------|
| `suite-api/apps/api/routes/__init__.py` | 0 bytes | Keep if routes/ is used |
| `suite-core/config/legacy/__init__.py` | 0 bytes | **Delete** — legacy dir |
| `suite-core/core/legacy/__init__.py` | 0 bytes | **Delete** — legacy dir |
| `suite-core/core/utils/legacy/__init__.py` | 0 bytes | **Delete** — legacy dir |
| `suite-api/apps/fixops_cli/__init__.py` | 1 line | Keep |
| `suite-core/core/db/enterprise/migrations/__init__.py` | 1 line | Keep |
| `suite-core/core/db/legacy/__init__.py` | 1 line (`"""Database package placeholder."""`) | **Delete** — legacy dir |
| `suite-core/core/services/__init__.py` | 1 line | Keep |
| `suite-core/new_apps/__init__.py` | 1 line | Keep |
| `suite-core/new_apps/api/__init__.py` | 1 line | Keep |
| `suite-core/new_backend/__init__.py` | 1 line | Keep |
| `suite-core/services/__init__.py` | 1 line | Keep |
| `suite-core/services/match/__init__.py` | 1 line | Keep |
| `suite-evidence-risk/risk/__init__.py` | 1 line | Keep |
| `suite-integrations/integrations/__init__.py` | 1 line | Keep |
| `suite-integrations/ssvc/plugins/__init__.py` | 1 line | Keep |
| `tests/__init__.py` | 0 bytes | Keep |
| `tests/e2e/__init__.py` | 1 line | Keep |

---

## 9. Dead UI Buttons

Buttons that render visually but have **no click handler** or use `alert()` instead of real UX.

| Page | Button Text | Problem | Fix |
|------|------------|---------|-----|
| `settings/Teams.tsx` | "Create Team" | No `onClick` handler — decorative | Wire to create team modal/form |
| `settings/Teams.tsx` | "Manage" (per team) | No `onClick` handler | Wire to team detail/edit view |
| `settings/Users.tsx` | "Add User" | No `onClick` handler | Wire to user invite/create form |
| `settings/Users.tsx` | "Edit" (per user) | No `onClick` handler | Wire to user edit form |
| `protect/Workflows.tsx` | "Create Workflow" | No `onClick` handler | Wire to workflow builder |
| `ai-engine/Policies.tsx` | "Create Policy" | No `onClick` handler | Wire to policy editor |
| `evidence/EvidenceBundles.tsx` | "Download" (per bundle) | No `onClick` handler — `<Button>` with no action | Implement blob download from API |
| `evidence/Reports.tsx` | "Download" (per report) | No `onClick` handler | Implement blob download from API |
| `code/SBOMGeneration.tsx` | "Download" (per SBOM) | No `onClick` handler | Implement SBOM file download |
| `settings/Marketplace.tsx` | "Install" | Works but uses `alert()` for feedback | Replace with toast notification + list refresh |
| `evidence/EvidenceBundles.tsx` | "Verify" | Works but uses `alert()` for feedback | Replace with inline status badge update |

---

## 10. Cleanup Priority Matrix

### P0 — Fix Before Next Demo (1 week)

| Item | Type | Why | Effort |
|------|------|-----|--------|
| Delete `api.backup.ts` + `api-complete.ts` | Dead files | Ship 1,763 fewer LOC to browser | 5 min |
| Wire dead buttons in Teams/Users/Workflows/Policies | Dead UI | Investors click → nothing happens | 2 days |
| Replace `alert()` with toast in Marketplace/EvidenceBundles | Bad UX | Looks amateur | 1 hour |
| Implement Download buttons (EvidenceBundles, Reports, SBOM) | Dead UI | Core compliance features don't work | 1 day |
| Fix hardcoded "~40%" in CorrelationEngine | Bad data | Misleading dashboard metric | 30 min |
| Fix fake scan payload in CodeScanning.tsx | Simulation | `eval(data.text)` simulated vuln is obvious | 2 hours |

### P1 — Fix Before Seed Round (2 weeks)

| Item | Type | Why | Effort |
|------|------|-----|--------|
| Upgrade 6 Minimal Stubs to 300+ LOC | UI stubs | AuditLogs, Inventory, Teams, Users, Collaboration, ThreatFeeds are embarrassing | 5 days |
| Add search/filter/pagination to ALL pages | Universal gap | Every competitor has this | 3 days |
| Wire agents_router.py TODOs to real services | Backend stubs | 16 endpoints return fake data | 5 days |
| Implement enterprise crypto module (or delete) | Backend stub | 970 LOC of empty methods | 2 days |
| Add real charts (recharts) to Predictions, EvidenceAnalytics, MLDashboard | UI depth | Progress bars instead of charts looks weak | 3 days |

### P2 — Fix Before GA (1 month)

| Item | Type | Why | Effort |
|------|------|-----|--------|
| Delete all `*/legacy/` directories (17,912 LOC) | Code hygiene | Technical debt, confuses contributors | 3 days (verify no imports first) |
| Implement streaming chat in Copilot.tsx | UI feature | Every AI copilot streams | 2 days |
| Wire vuln_discovery_router.py TODOs (CVSS lib, CVE DB, MindsDB) | Backend stubs | Core vuln features are approximate | 3 days |
| Upgrade 10 Basic Stubs to feature-complete | UI depth | Second wave of UI investment | 7 days |
| Implement real OPA engine (or remove) | Backend stub | Policy evaluation doesn't work | 3 days |

### P3 — Technical Debt (ongoing)

| Item | Type | Why | Effort |
|------|------|-----|--------|
| Audit enterprise/ directories for real vs stub | Code clarity | Some enterprise code works, some is empty shell | 2 days |
| Remove VS Code task `replace-api-file` | Config hygiene | References non-existent file | 5 min |
| Consolidate 3 pentest engine versions into 1 | Code hygiene | `micro_pentest_engine.py`, `automated_pentest.py`, `advanced_pentest_engine.py` in legacy + `mpte_advanced.py`, `micro_pentest.py` in main | 3 days |
| Add error toasts (replace `console.error`) across all UI pages | UX | Users see nothing when API fails | 2 days |
| Add loading skeletons to all pages | UX polish | Blank screens during data fetch | 2 days |

---

## Appendix: Common Patterns Across All Stubs

1. **All UI stubs have real API calls** — none render purely hardcoded data (except CorrelationEngine's "~40%")
2. **No "Coming Soon" placeholders** — every page attempts to fetch and display real data
3. **Empty state handling is universal** — all show "No X found" messages
4. **Error handling is `console.error` only** — no toast/snackbar user-facing errors (except CodeScanning which uses `sonner`)
5. **No pagination anywhere** — all truncate with `.slice()` or show everything
6. **No search/filter on any stub page** — universally missing
7. **Download buttons are non-functional** across EvidenceBundles, Reports, SBOMGeneration
8. **Backend TODOs cluster in agents_router.py** — 16 of 21 TODOs are in one file (the AI agent tool endpoints)
9. **Legacy code has 3 generations of pentest engines** — all still importable, causing confusion
10. **Enterprise crypto module is 970 LOC of scaffolding** with zero working methods

---

*Generated: 2026-02-20*  
*Source: Automated codebase scan across 6 suites + suite-ui*
