# FixOps Backend Stub Audit Report

**Date**: 2026-02-20  
**Scope**: Backend only (`suite-api/`, `suite-core/`, `suite-attack/`, `suite-feeds/`, `suite-evidence-risk/`, `suite-integrations/`)  
**UI stubs**: Excluded per request  

---

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| **P0** | 2 | Fabricated data indistinguishable from production |
| **P1** | 6 | Noticeable gaps — missing data, fake metrics, dropped input |
| **P2** | 20 | Self-documenting `"status": "pending"` stubs |
| **P3** | 8 | Acceptable patterns (abstract interfaces, labeled demo fallbacks) |
| **Total** | **36** | 28 actionable (P0–P2), 8 acceptable |

---

## P0 — Breaks User Trust (2)

These return fabricated data that looks like real production output.

### 1. `suite-core/api/decisions.py` — Fake Component Metrics

- **Endpoint**: `GET /api/v1/decisions/core-components`
- **Lines**: ~125–166
- **Issue**: Returns hardcoded fabricated numbers in demo mode:
  ```python
  "model": "gpt-5 (demo)"
  "current_rate": 0.87
  "validation_accuracy": 0.987
  "total_cases": 1247
  "enforcement_rate": 0.98
  ```
- **Risk**: Users/investors see fake accuracy metrics that look like real production telemetry.

### 2. `suite-api/apps/api/marketplace_router.py` — Fake Download Counts & Ratings

- **Lines**: ~126–218 (`_DEMO_MARKETPLACE_ITEMS`, `_DEMO_CONTRIBUTORS`, `_DEMO_STATS`)
- **Issue**: 3 hardcoded demo items with fabricated social proof:
  - Ratings: 4.5, 4.8, 4.2
  - Download counts: 1542, 967, 423
  - Fake IDs: `demo-remediation-pack-1`, etc.
  - Fake contributor names
- **Risk**: Download counts and ratings are indistinguishable from real marketplace activity.

---

## P1 — Noticeable (6)

### 3. `suite-core/api/agents_router.py` — Hardcoded Compliance Framework Counts

- **Endpoint**: `GET /api/v1/copilot/agents/compliance/controls/{framework}`
- **Lines**: ~1193–1268
- **Issue**: Returns static control counts per framework (PCI-DSS: 64, SOC2: 117, ISO27001: 93, HIPAA: 54, NIST: 108) that will drift from actual framework versions.

### 4. `suite-attack/api/vuln_discovery_router.py` — CVSS Always Returns None

- **Lines**: ~313–328 (`_calculate_cvss` helper)
- **Issue**: CVSS library not integrated. Every internally-scored vulnerability gets `cvss_score: null`.

### 5. `suite-api/apps/api/marketplace_router.py` — Fake Stats Endpoint

- **Endpoint**: `GET /api/v1/marketplace/stats`
- **Lines**: ~696–698
- **Issue**: Fallback returns `total_downloads: 2932` which looks like real aggregate data.

### 6. `suite-api/apps/api/reports_router.py` — Synthetic Report Generation

- **Endpoint**: `GET /api/v1/reports/download/{id}`
- **Lines**: ~254–295
- **Issue**: Generates synthetic PDF/JSON/CSV/SARIF reports on-the-fly in demo mode via `demo_data` module. Output could be mistaken for real scan results.

### 7. `suite-attack/api/micro_pentest_router.py` — Generic Hardcoded PoCs

- **Lines**: ~886–893 (`_hardcoded_poc`)
- **Issue**: Returns static PoC strings (`curl -X POST ... "id=1' OR '1'='1"` for SQLi, `<script>alert(1)</script>` for XSS). Not validated against actual target.

### 8. `suite-evidence-risk/api/business_context_enhanced.py` — Data Not Persisted

- **Endpoint**: `POST /api/v1/enhanced/upload`
- **Line**: 47
- **Issue**: Processes uploaded business context / SSVC data but has `# TODO: Store ssvc_context in database linked to service_name`. Data is computed then **discarded** — user believes it's saved.

---

## P2 — Labeled "pending" / Self-documenting (20)

### `suite-core/api/agents_router.py` — 16 Copilot Agent Stubs

All return `"status": "pending"` with empty result sets and list requirements for integration.

| # | Line | Endpoint | TODO Comment |
|---|------|----------|--------------|
| 9 | 625 | `POST /analyst/attack-path` | Integrate with real asset inventory and network topology service |
| 10 | 705 | `GET /analyst/risk-score/{asset_id}` | Integrate with asset inventory service to get real vulnerability counts |
| 11 | 1100 | `POST /compliance/map-findings` | Integrate with compliance mapping service |
| 12 | 1122 | `POST /compliance/gap-analysis` | Integrate with compliance engine |
| 13 | 1148 | `POST /compliance/audit-evidence` | Integrate with evidence store |
| 14 | 1172 | `POST /compliance/regulatory-alerts` | Integrate with regulatory update feeds |
| 15 | 1199 | `GET /compliance/controls/{framework}` | Integrate with full compliance control library |
| 16 | 1272 | `GET /compliance/dashboard` | Integrate with compliance assessment database |
| 17 | 1301 | `POST /compliance/generate-report` | Integrate with compliance report generator |
| 18 | 1329 | `POST /remediation/generate-fix` | Integrate with LLM for code fix generation |
| 19 | 1353 | `POST /remediation/create-pr` | Integrate with Git provider APIs |
| 20 | 1375 | `POST /remediation/update-dependencies` | Integrate with package managers |
| 21 | 1397 | `POST /remediation/playbook` | Integrate with remediation knowledge base |
| 22 | 1422 | `GET /remediation/recommendations/{finding_id}` | Integrate with finding details and remediation database |
| 23 | 1446 | `POST /remediation/verify` | Integrate with scanning tools for verification |
| 24 | 1472 | `GET /remediation/queue` | Integrate with remediation tracking database |

### `suite-attack/api/vuln_discovery_router.py` — 2 Stubs

| # | Line | Issue |
|---|------|-------|
| 25 | 696 | `external_count = 0` hardcoded — external CVE database not queried |
| 26 | 761 | `_run_training` returns `"pending_implementation"` — MindsDB training not wired |

### `suite-evidence-risk/` — 2 Stubs

| # | File | Line | Issue |
|---|------|------|-------|
| 27 | `risk/reachability/monitoring.py` | ~221–232 | `get_metrics_summary` returns `"N/A"` for all metrics |
| 28 | `risk/runtime/cloud.py` | ~126–137 | `_analyze_aws_s3`, `_analyze_aws_rds` return empty findings — no boto3 integration |

---

## P3 — Acceptable Patterns (8) — No Action Required

### Abstract Interface / Protocol Methods (raises `NotImplementedError`)

These are proper OOP patterns — concrete subclasses implement them.

| File | Methods | Notes |
|------|---------|-------|
| `suite-core/core/utils/enterprise/crypto.py` | `sign()`, `verify()`, `rotate()`, `fingerprint()`, `last_rotated_at`, `attestation()` | `KeyProvider` Protocol — implemented by `EnvKeyProvider` |
| `suite-core/core/services/enterprise/vector_store.py` | `upsert()`, `search()`, `_generate_embedding()` | `VectorStore` base — implemented by `DemoVectorStore`, `ChromaVectorStore` |
| `suite-core/core/services/enterprise/real_opa_engine.py` | `evaluate_policy()`, `health_check()` | `OPAEngine` base — implemented by `DemoOPAEngine`, `ProductionOPAEngine` |
| `suite-core/core/vector_store.py` | `index()`, `search()` | `BaseVectorStore` — implemented by `InMemoryVectorStore` |
| `suite-core/core/adapters.py` | `configured`, `fetch_findings()` | `_BaseAdapter` — implemented by `GitLabAdapter`, etc. |
| `suite-core/core/connectors.py` | `health_check()` | `_BaseConnector` — implemented by all connector subclasses |
| `suite-integrations/ssvc/__init__.py` | `to_vector()` | `Decision` wrapper — raises if plugin doesn't implement |

### Marketplace Demo Fallbacks

| File | Endpoints | Notes |
|------|-----------|-------|
| `suite-api/apps/api/marketplace_router.py` | `browse`, `recommendations`, `items/{id}`, `contributors`, `compliance-content/{stage}` | All clearly tagged `"marketplace_mode": "demo"` ✅ |

---

## Other Non-Actionable Items

| File | Line | Pattern | Notes |
|------|------|---------|-------|
| `suite-api/apps/api/ide_router.py` | 115, 123 | `"Hardcoded password detected"`, `"Hardcoded secret detected"` | These are **detection rule labels**, not hardcoded data — correct behavior |
| `suite-api/apps/api/pipeline.py` | 1451 | `# Placeholder so compliance checks recognise evidence availability` | Intentional pipeline marker, not a stub |
| `suite-core/pydantic_settings/__init__.py` | 1 | `"Minimal shim for pydantic_settings"` | Compatibility shim — working as intended |
| `suite-core/api/mindsdb_router.py` | 10 | `"Replaces the stub MindsDB endpoints"` | Comment referring to what it replaced — the replacement is functional |
| `suite-evidence-risk/risk/runtime/iast.py` | ~367–370 | `instrument_application` — logs but no-ops | Runtime instrumentation placeholder |
| `suite-evidence-risk/api/business_context_enhanced.py` | 47 | `# TODO: Store ssvc_context` | Listed under P1 (#8) |
| `data/archive/sbom/*.raw` | — | `"Architecture N placeholder with Mermaid diagram"` | Demo SBOM data files — expected for demo mode |

---

## Recommended Fix Order

1. **P0 #1** — `decisions.py`: Remove or clearly label fake metrics (`"demo": true` flag, or return `null` values instead of fabricated numbers)
2. **P0 #2** — `marketplace_router.py`: Zero out fake download counts/ratings or add unmistakable `[DEMO]` prefix
3. **P1 #8** — `business_context_enhanced.py`: Persist SSVC context to SQLite (silent data loss)
4. **P1 #4** — `vuln_discovery_router.py`: Integrate `cvss` library for real CVSS calculation
5. **P1 #3** — `agents_router.py` L1193: Replace hardcoded framework control counts with config file or DB lookup
6. **P2 batch** — Wire `agents_router.py` 16 stubs to real services (compliance engine, LLM, Git APIs)

---

*Generated: 2026-02-20 | Audit scope: Backend Python files only | UI stubs excluded*
