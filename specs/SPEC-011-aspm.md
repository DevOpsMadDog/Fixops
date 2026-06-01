# SPEC-011 — Application Security Posture Management (ASPM)

- **Status**: BACKFILL (documents verified code; not a new build)
- **Owner family**: ASPM
- **Routers**:
  - `suite-api/apps/api/scanner_ingest_router.py` (prefix `/api/v1/scanner-ingest`)
  - `suite-api/apps/api/scanner_ingest_router.py` alias router (prefix `/api/v1/scanners`)
  - `suite-api/apps/api/findings_routes.py` (prefix `/api/v1/findings`)
  - `suite-api/apps/api/security_findings_router.py` (prefix `/api/v1/security-findings`)
  - `suite-api/apps/api/findings_lifecycle_router.py` (prefix `/api/v1/findings/lifecycle`)
  - `suite-api/apps/api/findings_persistence_router.py` (prefix `/api/v1/findings/v2`)
  - `suite-api/apps/api/function_reachability_router.py` (prefix `/api/v1/reachability`)
- **Engines**:
  - `suite-core/core/security_findings_engine.py` — `SecurityFindingsEngine`
  - `suite-core/core/smart_dedup.py` — `SmartDedup`
  - `suite-core/core/scanner_parsers.py` — `SCANNER_NORMALIZERS` (35 keys) + `parse_scanner_output`
  - `suite-core/core/function_reachability_engine.py` — `FunctionReachabilityEngine`
- **Stores**:
  - `.fixops_data/security_findings_engine.db` — tables `security_findings`, `finding_evidence`, `finding_suppressions`
  - `suite-core/core/smart_dedup.db` — tables `dedup_groups`, `dedup_runs`
  - `.fixops_data/function_reachability.db` — tables `callgraph_nodes`, `callgraph_edges`, `reachability_queries`
  - `suite-core/data/reachability_cache.db` — repo_sha-keyed verdict cache
  - `data/analytics.db` — `findings` table; read by `/stats` endpoint
- **Depends on**:
  - SPEC-001 (TrustGraph correlation — `SecurityFindingsEngine.record_finding` synchronously indexes into TrustGraph via `UniversalFindingIndexer`)
  - SPEC-004 (reachability multi-language — `FunctionReachabilityEngine`, TypeScript/Java stubs pending NEW-G070)
  - SPEC-005b (graph population — findings produce `FINDING_AFFECTS_ASSET` edges)
  - SPEC-007 (systemic tenancy — `get_org_id` dependency on every mutable endpoint; cross-org returns 404 not 403)
  - `apps/api/dependencies.py` `get_org_id` (re-exports from `org_middleware`)
  - `apps/api/auth_deps.py` `api_key_auth`
  - `core/trustgraph_event_bus.py` (fire-and-forget async TrustGraph events at upload/webhook)
  - `core/unified_issues_engine.py` (findings list UNIONs with engine-DB via `unified_list`)
  - `core/event_bus.py` `EventType.FINDINGS_INDEX_REFRESH` (published after promotion)
- **Last updated**: 2026-06-01

---

## 1. Intent (the why)

ASPM is the ingest-to-insight pipeline for application-layer security findings. It solves the core enterprise pain: security teams receive scanner output from 35+ heterogeneous tools (SAST, SCA, DAST, secret-scanners, IaC checkers, cloud scanners), each with its own format and severity vocabulary, producing duplicate alerts that burn analyst time before any remediation happens.

ALDECI's ASPM surface closes this loop in three steps: (1) accept any scanner output via file upload or CI/CD webhook, normalise it into `UnifiedFinding` records, and store canonicalised findings per-org; (2) run SmartDedup across five complementary strategies so the same CVE reported by Trivy, Grype, and Snyk becomes one open row, not three; (3) expose the surviving findings through paginated, tenant-scoped REST APIs that drive the Issues hero, SLA dashboards, and remediation workflows. Function-level reachability (the Endor Labs moat) further reduces noise by filtering out CVEs on code paths the application never calls, typically cutting CVE volume by 60–80 %.

Today the engine carries 1,236 real findings from self-dogfooding and customer onboarding. The system is the upstream source for `/api/v1/issues` federation, TrustGraph graph population (SPEC-005b), LLM Council enrichment (SPEC-001), and compliance evidence (SPEC-006).

---

## 2. Scope — endpoints

### 2a. Scanner Ingest

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | `/api/v1/scanner-ingest/` | List supported scanners + session stats | `get_org_id` | yes (org_id) |
| POST | `/api/v1/scanner-ingest/upload` | Multipart file upload; auto-detect or explicit scanner type | `get_org_id` | yes |
| POST | `/api/v1/scanner-ingest/webhook/{scanner_type}` | Raw-body webhook receiver for CI/CD push | `get_org_id` | yes |
| POST | `/api/v1/scanner-ingest/detect` | Return scanner type scores without processing | none | no |
| GET | `/api/v1/scanner-ingest/supported` | Return full normaliser list by category | none | no |
| GET | `/api/v1/scanner-ingest/stats` | Ingestion statistics from `data/analytics.db` | `get_org_id` | yes |
| GET | `/api/v1/scanner-ingest/health` | Health check + live counts | `get_org_id` | yes |
| GET | `/api/v1/scanner-ingest/status` | Status + per-source breakdown | none | no |
| POST | `/api/v1/scanners/ingest` | JSON-body alias (demo-path + UI callers) | `get_org_id` | yes |

### 2b. Findings Lifecycle (`findings_routes.py`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | `/api/v1/findings` | List with filters + pagination (UNIONs engine-DB) | `get_org_id` | yes |
| GET | `/api/v1/findings/{finding_id}` | Full finding detail + audit trail | `get_org_id` | yes (404 on miss) |
| PUT | `/api/v1/findings/{finding_id}/status` | Update status with audit record | `get_org_id` | yes |
| PUT | `/api/v1/findings/{finding_id}/assign` | Assign to user or team | `get_org_id` | yes |
| POST | `/api/v1/findings/{finding_id}/comment` | Append analyst comment | `get_org_id` | yes |
| GET | `/api/v1/findings/{finding_id}/timeline` | Ordered audit trail | `get_org_id` | yes |
| GET | `/api/v1/findings/summary` | Executive summary (counts, rates, SLA) | `get_org_id` | yes |
| GET | `/api/v1/findings/sla` | SLA compliance by severity | `get_org_id` | yes |
| POST | `/api/v1/findings/bulk/status` | Bulk status update (max 100) | `get_org_id` | yes |
| POST | `/api/v1/findings/export` | Export findings JSON or CSV | `get_org_id` | yes |

### 2c. Security Findings Engine direct surface (`security_findings_router.py`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | `/api/v1/security-findings/` | List findings for org | `api_key_auth` | yes (query param) |
| POST | `/api/v1/security-findings/findings` | Record finding; dedup-or-create | `api_key_auth` | yes (body) |
| PATCH | `/api/v1/security-findings/findings/{finding_id}/status` | Update status + resolved_at | `api_key_auth` | yes |
| POST | `/api/v1/security-findings/findings/{finding_id}/evidence` | Attach evidence record | `api_key_auth` | yes |
| POST | `/api/v1/security-findings/findings/{finding_id}/suppress` | Suppress with reason/expiry | `api_key_auth` | yes |
| GET | `/api/v1/security-findings/findings/{finding_id}` | Full record + evidence + suppressions | `api_key_auth` | yes |
| GET | `/api/v1/security-findings/findings` | Filtered list | `api_key_auth` | yes |
| GET | `/api/v1/security-findings/assets/{asset_id}/findings` | Findings per asset | `api_key_auth` | yes |
| GET | `/api/v1/security-findings/summary` | Severity/tool breakdown + top assets | `api_key_auth` | yes |
| GET | `/api/v1/security-findings/export` | CSV streaming export | `api_key_auth` | yes |

### 2d. Findings Lifecycle API (`findings_lifecycle_router.py`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | `/api/v1/findings/lifecycle/reconcile` | Diff two scan IDs; mark new/unchanged/resolved | `api_key_auth` | yes |
| GET | `/api/v1/findings/lifecycle/summary` | Rolling N-day new/unchanged/resolved counts | `api_key_auth` | yes |
| GET | `/api/v1/findings/lifecycle/{finding_id}/history` | Walk `previous_violation_id` chain | `api_key_auth` | yes |

### 2e. Findings Persistence v2 (`findings_persistence_router.py`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | `/api/v1/findings/v2` | List from persistence store | `get_org_id` | yes |
| GET | `/api/v1/findings/v2/stats` | Persistence stats | `get_org_id` | yes |
| GET | `/api/v1/findings/v2/{finding_id}` | Single finding from persistence | `get_org_id` | yes |

### 2f. Function Reachability (`function_reachability_router.py`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | `/api/v1/reachability/parse` | Parse repo into call graph (Python; TS/Java stubs) | `api_key_auth` | yes (body) |
| POST | `/api/v1/reachability/query` | BFS: is `start_fqn` → `target_fqn` reachable? | `api_key_auth` | yes (body) |
| POST | `/api/v1/reachability/vulnerable` | Find reachable callers of a CVE-affected dependency | `api_key_auth` | yes (body) |
| GET | `/api/v1/reachability/callgraph/{repo_ref}` | Enumerate nodes/edges for a repo_ref | `api_key_auth` | yes |
| GET | `/api/v1/reachability/stats` | Engine stats (node/edge counts, cache hit ratio) | `api_key_auth` | yes |

**Out of scope for this spec:** `/api/v1/issues` federation (unified_issues_engine — separate surface), `/api/v1/analytics/*` and `/api/v1/duckdb-analytics/*` dashboards, compliance report generation (SPEC-006), SIEM/EDR connectors (connector framework), Brain Pipeline orchestration (SPEC-003).

---

## 3. Data contracts

### 3a. POST /api/v1/scanner-ingest/upload

```
Request (multipart/form-data):
  file           UploadFile  required  — .json | .sarif | .xml | .csv | .txt only; max 50 MB
  scanner_type   str         optional  — ^[a-z0-9][a-z0-9_-]{0,63}$; auto-detected if absent
  app_id         str         optional  — asset context tag (max 255)
  component      str         optional  — component context tag
  pipeline       bool        optional  — default false; if true, pushes to BrainPipeline

Response 200:
{
  "status": "success",
  "org_id": "<org>",
  "scanner": "<detected_or_provided>",
  "file_name": "<sanitised_basename>",
  "findings_count": <int>,         // raw parsed count (pre-dedup)
  "parse_time_ms": <float>,
  "app_id": <str|null>,
  "component": <str|null>,
  "findings": [ ... ],             // capped at first 100 for response size
  "total_findings": <int>,
  "deduped_count": <int>,          // canonical survivors after SmartDedup
  "duplicates_removed": <int>,
  "promoted_to_issues": <int>,     // rows written to SecurityFindingsEngine
  "pipeline_result": <obj|null>
}

Error paths:
  400  — empty file body
  413  — body > 50 MB (checked on Content-Length header AND actual read)
  415  — file extension not in {.json, .sarif, .xml, .csv, .txt}
  422  — scanner type auto-detect failed, or parse error (error type exposed, not message)
  503  — scanner_parsers module unavailable
```

### 3b. POST /api/v1/scanner-ingest/webhook/{scanner_type}

```
Request (raw body, Content-Type: application/json):
  Path param: scanner_type  — validated against SCANNER_NORMALIZERS keys; 404 if unknown
  Query:  app_id, component, pipeline (same as upload)

Response 200: same shape as /upload minus "file_name"

Error paths:
  400  — empty body
  404  — unknown scanner_type
  413  — body > 50 MB
  422  — parse error
  503  — scanner_parsers unavailable
```

### 3c. GET /api/v1/scanner-ingest/stats

```
Response 200 (analytics.db present):
{
  "status": "ok",
  "org_id": "<org>",
  "total_findings_ingested": <int>,   // from analytics.db findings table; org-scoped
  "distinct_scanners": <int>,
  "by_source": { "<scanner>": {"findings": <int>} },
  "last_ingest_at": "<iso8601|null>",
  "in_session": {
    "files_processed": <int>,         // in-process counter (resets on restart)
    "findings_parsed": <int>,
    "errors": <int>,
    "note": "Per-process counters since last server start"
  }
}

Response 200 (analytics.db absent — fallback to in-memory only):
  Same shape but "total_findings_ingested" comes from in-session counter.
  Honest: never fabricated, never 500.
```

### 3d. GET /api/v1/findings (findings_routes.py)

```
Query params:
  severity      str    — low|medium|high|critical
  status        str    — open|in_progress|remediated|suppressed|false_positive|accepted_risk
  connector     str
  cve_id        str
  asset_id      str
  assigned_to   str
  date_from     str    — ISO 8601; 400 on parse failure
  date_to       str    — ISO 8601; 400 on parse failure
  scan_id       str    — substring match
  q             str    — free-text across title/description/asset_id
  sort_by       str    — severity|created_at|risk_score|last_seen (default: severity)
  limit         int    — 1–500 (default 50)
  offset        int    — ≥0

Response 200:
{
  "total": <int>,
  "limit": <int>,
  "offset": <int>,
  "findings": [ FindingDetailResponse, ... ]  // UNIONs in-memory store + engine-DB rows
}

Notes:
  - in-memory rows win on id collision (authoritative for post-ingest state transitions)
  - engine-DB rows carry "_source": "engine_db" field
  - cross-org isolation: only rows where org_id == caller's org_id are returned
```

### 3e. POST /api/v1/security-findings/findings (SecurityFindingsEngine)

```
Request body (JSON):
{
  "org_id": "<str>",
  "title": "<str>",
  "finding_type": "vulnerability",  // vulnerability|misconfiguration|policy-violation|anomaly|
                                    //  secret-exposure|compliance-gap|malware|data-leak
  "source_tool": "custom",          // SAST|DAST|SIEM|EDR|CSPM|CNAPP|Nessus|Qualys|Burp|
                                    //  Semgrep|Trivy|custom
  "severity": "medium",             // critical|high|medium|low|informational
  "cvss_score": 0.0,                // clamped to [0.0, 10.0]
  "asset_id": "",
  "asset_type": "",
  "description": "",
  "remediation": ""
}

Response 200:
  Full security_findings row dict including:
    id, org_id, correlation_key, scan_id, first_seen_at, previous_violation_id,
    resolved_at, unchanged_scan_count, occurrence_count

Dedup behaviour:
  If an open row with same (org_id, correlation_key) and no scan_id exists →
    occurrence_count +1, last_seen updated, returns existing row.
  Legacy fallback (no correlation_key, no scan_id provided) →
    dedup on (org_id, title, source_tool, asset_id, status != 'resolved').
  New row: first_seen_at = NOW(), TrustGraph indexed synchronously.
  Critical severity: triggers NotificationEngine.send_slack_alert (best-effort).
```

### 3f. POST /api/v1/findings/lifecycle/reconcile

```
Request body:
{
  "org_id": "<str>",
  "prior_scan_id": "<str>",
  "current_scan_id": "<str>"   // must differ from prior_scan_id; 400 if equal
}

Response 200:
{
  "org_id": "<str>",
  "prior_scan_id": "<str>",
  "current_scan_id": "<str>",
  "new_count": <int>,
  "unchanged_count": <int>,
  "resolved_count": <int>,
  "new_violation_ids": [...],
  "unchanged_violation_ids": [...],
  "resolved_violation_ids": [...],
  "reconciled_at": "<iso8601>"
}

Side effects:
  - unchanged rows get previous_violation_id + unchanged_scan_count +1
  - unchanged rows inherit earliest first_seen_at from prior chain
  - resolved rows get status='resolved' + resolved_at=NOW()
```

### 3g. POST /api/v1/reachability/vulnerable

```
Request body:
{
  "org_id": "default",
  "cve_id": "<CVE-YYYY-NNNNN>",
  "dependency_fqn_pattern": "<SQL LIKE pattern, e.g. 'requests.%'>"
}

Response 200:
{
  "cve_id": "<str>",
  "dependency_fqn_pattern": "<str>",
  "results": [ FunctionReachabilityResult.to_dict(), ... ]
}
  where FunctionReachabilityResult fields:
    is_reachable     bool
    call_path        list[str]     // BFS path from entry-point to vuln symbol
    confidence       float 0–1
    entry_point      str|null
    analysis_method  "call_graph"|"ast_static"|"fallback_conservative"
    vuln_function_fqn str
    repo_sha         str
    cached           bool

Notes:
  - fallback_conservative = dynamic dispatch or unknown symbol → conservatively reachable=True
    (customers never silently miss a real risk)
  - Python: full AST call-graph. TypeScript/Java: raises NotImplementedError (stubs)
```

---

## 4. Functional requirements

- **REQ-011-01**: The upload endpoint MUST reject files with extensions outside `{.json, .sarif, .xml, .csv, .txt}` with HTTP 415, checked on filename extension before reading the body.

- **REQ-011-02**: The upload and webhook endpoints MUST reject bodies exceeding 50 MB with HTTP 413. For upload, Content-Length header is checked before body read; actual read size is re-validated after.

- **REQ-011-03**: The `scanner_type` path parameter on the webhook endpoint MUST be validated against `^[a-z0-9][a-z0-9_-]{0,63}$` before use; invalid values return HTTP 422. Unknown scanner types (not in SCANNER_NORMALIZERS) return HTTP 404.

- **REQ-011-04**: Filenames in upload MUST be sanitised to strip directory components (`..`, `/`, `\`) before use in any response or log. Path traversal attempts are logged at WARNING level.

- **REQ-011-05**: Parse errors MUST expose the exception type name only (e.g. `"Parse error (ValueError)"`) and MUST NOT leak internal paths, module names, or stack traces in the HTTP response body.

- **REQ-011-06**: After a successful upload or webhook call, SmartDedup MUST be run over the serialised findings before promotion. If the SmartDedup engine raises any exception, the endpoint MUST fall back to no-op dedup (all findings treated as canonical) and continue — never 500.

- **REQ-011-07**: SmartDedup MUST apply all five strategies in a single `deduplicate()` call: EXACT_CVE (confidence 0.98), FUZZY_TITLE (Levenshtein ≥ 0.82, location-aware — distinct file:line pairs MUST NOT merge on title alone), SAME_FILE_LINE (5-line tolerance; (0,0) line-range findings MUST be excluded to prevent dependency CVE collapse), CROSS_SCANNER (multi-scanner agreement), COMPONENT_VERSION (key includes CVE to prevent collapsing distinct advisories on same package).

- **REQ-011-08**: After SmartDedup, canonical findings MUST be promoted to `SecurityFindingsEngine` via `_promote_findings_to_issues`. The correlation_key for each finding MUST be location-granular: `scanner|rule_or_cve|file_path:line_number` when file and line are available, falling back to `package@version` then `asset_id`.

- **REQ-011-09**: After promotion, the router MUST publish `EventType.FINDINGS_INDEX_REFRESH` to the event bus. This is best-effort: failure MUST NOT cause a 500 or alter the response.

- **REQ-011-10**: The `GET /api/v1/findings` endpoint MUST union in-memory findings with `SecurityFindingsEngine` rows via `unified_issues_engine.unified_list`. In-memory rows MUST win on `id` collision (authoritative for lifecycle state).

- **REQ-011-11**: `SecurityFindingsEngine.record_finding` MUST synchronously index the finding into TrustGraph via `UniversalFindingIndexer` (`_emit_finding_to_trustgraph`). Failures in TrustGraph indexing MUST be swallowed at DEBUG level — they MUST NOT propagate to the caller or cause a transaction rollback.

- **REQ-011-12**: `SecurityFindingsEngine.record_finding` dedup MUST prefer `correlation_key` match (GAP-063) over legacy `(title, source_tool, asset_id)` match. Legacy fallback applies ONLY when both `scan_id` and `correlation_key` are absent. When `correlation_key` is provided, coarse legacy dedup MUST NOT run.

- **REQ-011-13**: `SecurityFindingsEngine.update_status` MUST stamp `resolved_at = NOW()` on transition to `"resolved"` and MUST clear `resolved_at` (set to NULL) on transition back to `"open"` or `"in-progress"`.

- **REQ-011-14**: `lifecycle/reconcile` MUST NOT accept `prior_scan_id == current_scan_id`; it MUST raise `ValueError` (400 at the router) if they are equal.

- **REQ-011-15**: Unchanged findings (present in both prior and current scan by `correlation_key`) MUST inherit the earliest `first_seen_at` from the prior chain so age is preserved across scan cycles.

- **REQ-011-16**: Findings absent from the current scan (keys in prior but not current) MUST be auto-resolved: `status='resolved'`, `resolved_at=NOW()`.

- **REQ-011-17**: `FunctionReachabilityEngine.analyse_vulnerable_symbol` MUST return `is_reachable=True` (conservative) when the vulnerable symbol is unknown or dynamic dispatch is encountered (`analysis_method="fallback_conservative"`). False negatives are preferable to false assurance.

- **REQ-011-18**: Reachability analysis for TypeScript and Java MUST raise `NotImplementedError` (stubs) until the Tree-sitter DCA engine (NEW-G070) is shipped. The router MUST surface this as HTTP 501 with a clear message.

- **REQ-011-19**: `GET /api/v1/findings/{finding_id}` MUST return HTTP 404 (not 403) when the finding exists but belongs to a different org, preventing tenant enumeration (AUTHZ-VULN-06).

- **REQ-011-20**: All endpoints that accept `org_id` from the caller MUST derive it from `Depends(get_org_id)` (header-sourced, validated by `org_middleware`) — never from a query parameter alone for mutable or sensitive operations.

- **REQ-011-21**: Rate limiting MUST be enforced on ingest paths: `ingest:upload` and `ingest:webhook` — 30 requests per minute per calling identity, enforced by `endpoint_rate_limit.enforce`.

- **REQ-011-22**: `GET /api/v1/scanner-ingest/stats` MUST read from `data/analytics.db` when the file exists, scoped to the caller's `org_id`. When the DB lacks an `org_id` column (schema migration lag), the query MUST degrade gracefully to unfiltered counts rather than returning 500.

- **REQ-011-23**: The `SCANNER_NORMALIZERS` registry MUST contain at minimum the 35 keys verified at code-read time: `zap`, `burp`, `nessus`, `openvas`, `bandit`, `checkmarx`, `sonarqube`, `fortify`, `veracode`, `nikto`, `nuclei`, `nmap`, `snyk`, `prowler`, `checkov`, `gitleaks`, `trivy`, `grype`, `osv-scanner`, `osv`, `semgrep`, `dependabot`, `qualys`, `tenable`, `rapid7`, `acunetix`, `aws_inspector`, `gitlab_sast`, `sarif`, `cyclonedx`, `spdx`, `claude_code_security`, `combobulator`, `pip-audit`, `pip_audit`.

- **REQ-011-24**: `POST /api/v1/scanner-ingest/detect` MUST run all normaliser `can_handle()` scorers and return `detected` (highest scorer key) plus `all_scores` dict. Scorer exceptions MUST be swallowed per-normaliser (no partial failures propagate).

- **REQ-011-25**: `SecurityFindingsEngine` MUST be thread-safe via `threading.RLock` for all write operations. SQLite WAL mode MUST be enabled on init.

---

## 5. Non-functional requirements

- **Latency**: `POST /upload` and `POST /webhook` MUST complete parse + dedup + promotion within 5 s for files up to 5 MB. Files between 5–50 MB may take up to 30 s. No synchronous BrainPipeline execution on the hot ingest path unless `pipeline=true` is explicitly set.
- **Throughput**: Rate limit of 30 ingest calls/minute per org is the primary guard. No additional concurrency guarantees at the application layer beyond SQLite WAL.
- **Tenancy**: `org_id` sourced from `get_org_id` dependency (header). Cross-org access returns 404, not 403 (enumeration prevention). All `security_findings` queries are parameterised with `org_id`. Findings in `/api/v1/findings` list are filtered to `org_id` before any other processing.
- **Failure modes**:
  - `scanner_parsers` module unavailable → 503 `{"detail": "Scanner parser module not available"}` — honest, never fabricated findings.
  - SmartDedup engine error → no-op fallback, 200 with `"duplicates_removed": 0`.
  - `SecurityFindingsEngine` promotion error → per-finding skip, `promoted_to_issues` count reflects actual successes.
  - TrustGraph indexing error → swallowed at DEBUG, no effect on response.
  - `data/analytics.db` absent → `/stats` falls back to in-process counters; never 500.
- **Storage**: Each `security_findings` row is ~1 KB. At 10,000 findings per org, DB is ~10 MB. SmartDedup DB grows by one `dedup_groups` row per duplicate group per run.
- **Security**: File extension validation, Content-Length pre-check, path traversal sanitisation, scanner_type regex validation, and rate limiting are all enforced before body read. Internal error detail is never leaked in responses (exception type name only).

---

## 6. Acceptance criteria (executable)

- **AC-011-01**: `pytest tests/test_smart_dedup.py -q` — all tests pass including `test_exact_cve_matches_two_scanners`, `test_different_file_path_no_merge`, `test_different_line_no_merge`.

- **AC-011-02**: `pytest tests/test_dedup_cross_scanner.py -q` — all tests pass including `test_two_scanner_merge`, `test_different_file_path_no_merge`, `test_severity_hoisting_critical_beats_high`.

- **AC-011-03**: `pytest tests/test_scanner_parsers_coverage.py -q` — all tests pass including `test_extracts_single_cve`, `test_4_maps_to_critical`, `test_valid_json_returns_parsed_object`.

- **AC-011-04**: `pytest tests/test_findings_lifecycle.py -q` — all tests pass including `test_schema_has_new_columns`, `test_ensure_schema_idempotent`, `test_uses_first_seen_at_when_available`.

- **AC-011-05**: `pytest tests/test_function_reachability_engine.py -q` — all tests pass including `test_parse_python_repo_inserts_nodes`, `test_is_reachable_true_simple_repo`, `test_parse_typescript_raises_parser_unavailable_when_dep_blocked`.

- **AC-011-06**: Upload 415 enforcement:
  ```
  curl -s -X POST http://localhost:8000/api/v1/scanner-ingest/upload \
    -H "X-API-Key: $KEY" -F "file=@evil.sh;type=application/x-sh" \
    | jq .detail
  # expect: contains "Unsupported file extension"
  ```

- **AC-011-07**: Upload 413 enforcement (requires a >50 MB file):
  ```
  dd if=/dev/urandom bs=1M count=51 > /tmp/big.json
  curl -s -o /dev/null -w "%{http_code}" -X POST \
    http://localhost:8000/api/v1/scanner-ingest/upload \
    -H "X-API-Key: $KEY" -F "file=@/tmp/big.json"
  # expect: 413
  ```

- **AC-011-08**: Semgrep upload round-trip:
  ```
  curl -s -X POST http://localhost:8000/api/v1/scanner-ingest/upload \
    -H "X-API-Key: $KEY" \
    -F "file=@tests/fixtures/semgrep_sample.json" \
    -F "scanner_type=semgrep" \
    | jq '{scanner,findings_count,promoted_to_issues}'
  # expect: scanner="semgrep", findings_count>=1, promoted_to_issues>=1
  ```

- **AC-011-09**: Trivy webhook ingest:
  ```
  curl -s -X POST http://localhost:8000/api/v1/scanner-ingest/webhook/trivy \
    -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
    --data-binary @tests/fixtures/trivy_sample.json \
    | jq '.findings_count'
  # expect: integer >= 1
  ```

- **AC-011-10**: Unknown webhook scanner returns 404:
  ```
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:8000/api/v1/scanner-ingest/webhook/notascanner \
    -H "X-API-Key: $KEY" -d '{}'
  # expect: 404
  ```

- **AC-011-11**: Cross-tenant isolation — GET finding with wrong org returns 404:
  ```
  # Create finding for org-A, attempt retrieval with org-B header
  curl -s -o /dev/null -w "%{http_code}" \
    http://localhost:8000/api/v1/findings/<org_a_finding_id> \
    -H "X-API-Key: $KEY_ORG_B"
  # expect: 404 (not 403, not 200)
  ```

- **AC-011-12**: SmartDedup location-awareness — same rule at different files does NOT collapse:
  ```python
  # pytest tests/test_smart_dedup.py::test_different_file_path_no_merge
  ```

- **AC-011-13**: Lifecycle reconcile — resolved findings get resolved_at:
  ```
  POST /api/v1/findings/lifecycle/reconcile
  Body: {"org_id":"test","prior_scan_id":"scan-1","current_scan_id":"scan-2"}
  # findings present in scan-1 but absent from scan-2 → response.resolved_count >= 1
  # verify: GET /api/v1/security-findings/findings/<id> → resolved_at is not null
  ```

- **AC-011-14**: Python reachability parse + query:
  ```
  POST /api/v1/reachability/parse
  Body: {"org_id":"test","repo_ref":"myapp@main","language":"python","root_path":"/path/to/repo"}
  # expect: {"nodes_added": >= 1}

  POST /api/v1/reachability/query
  Body: {"org_id":"test","start_fqn":"myapp.main","target_fqn":"requests.Session.mount"}
  # expect: {"is_reachable": bool, "confidence": float}
  ```

- **AC-011-15**: `pytest tests/test_security_real_scanner_integration.py tests/test_real_scanner_unit.py -q` — passes without mocks.

---

## 7. Debate log (Mysti)

| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-01 | Backfill | Initial spec authored from code-read. No debates yet. |
| | Debate | Pending Mysti review |
| | Red-Team | Pending |

---

## 8. Implementation notes

### Files mapped

| File | Role |
|------|------|
| `suite-api/apps/api/scanner_ingest_router.py` | Ingest endpoints + alias router; SmartDedup + promotion orchestration; rate limiting; TrustGraph fire-and-forget |
| `suite-core/core/scanner_parsers.py` (2,986 lines) | 35-key `SCANNER_NORMALIZERS` dict; `parse_scanner_output`; `auto_detect_scanner`; `get_supported_scanners`; defusedxml XXE hardening; `_emit_event` for TrustGraph bus |
| `suite-core/core/smart_dedup.py` | `SmartDedup` engine; 5 strategies; union-find grouping; SQLite-backed `dedup_groups` + `dedup_runs` |
| `suite-api/apps/api/findings_routes.py` | `/api/v1/findings` lifecycle CRUD; in-memory + engine-DB UNION read path |
| `suite-core/core/security_findings_engine.py` | `SecurityFindingsEngine`; WAL SQLite; `record_finding` with GAP-063 correlation_key dedup; `reconcile_scans`; `lifecycle_summary`; `lifecycle_history`; TrustGraph synchronous indexing |
| `suite-api/apps/api/security_findings_router.py` | Direct engine surface at `/api/v1/security-findings/*` |
| `suite-api/apps/api/findings_lifecycle_router.py` | `/api/v1/findings/lifecycle/*` — reconcile, summary, history |
| `suite-api/apps/api/findings_persistence_router.py` | `/api/v1/findings/v2` — persistence-backed list |
| `suite-core/core/function_reachability_engine.py` | `FunctionReachabilityEngine`; Python AST call-graph; BFS with cycle safety; `analyse_vulnerable_symbol`; conservative fallback |
| `suite-api/apps/api/function_reachability_router.py` | `/api/v1/reachability/*` router |

### Key design decisions preserved from code

1. **Location-granular correlation_key** (dogfooding fix 2026-05-27): the original dedup collapsed 1,636 findings to 8 by keying on `asset_id` alone. The fix keys on `scanner|rule_or_cve|file_path:line_number`. Both `SmartDedup.find_fuzzy_title_matches` (union-find skips distinct file:line pairs) and `SmartDedup.find_same_location` ((0,0) line-range excluded to prevent dependency CVE collapse) and `SecurityFindingsEngine.record_finding` (legacy fallback gated behind absence of both `correlation_key` and `scan_id`) all carry this fix.

2. **COMPONENT_VERSION strategy keys include CVE** (fix #9050): a single `package@version` carries multiple distinct CVEs. Keying on `package@version|CVE` (empty suffix for no-CVE) preserves distinct advisories.

3. **`/api/v1/findings` UNION read path** (onboarding bug fix 2026-04-27, Bug A — playbook divergence): prior to this fix, `/findings` returned zero for orgs that had rows in `security_findings_engine.db` inserted before the pipeline bridge. The fix UNIONs in-memory store with `unified_issues_engine.unified_list` at read time. In-memory rows win on `id` collision.

4. **Conservative reachability fallback**: `FunctionReachabilityEngine` returns `is_reachable=True` with `analysis_method="fallback_conservative"` when dynamic dispatch or unknown symbols are encountered. False negatives are unacceptable in a security tool.

5. **TrustGraph indexing is synchronous in `record_finding`**: this makes tests deterministic (no async flake). The graph update happens before the function returns. Errors are swallowed at DEBUG to never break the findings write path.

6. **`api_key_auth` vs `get_org_id`**: the `/api/v1/security-findings/*` and `/api/v1/reachability/*` surfaces use `api_key_auth` (full key validation). The `/api/v1/scanner-ingest/*` and `/api/v1/findings/*` surfaces use `get_org_id` (header-sourced org scoping). Both ultimately enforce tenant isolation.

### Test coverage

| Test file | What it covers |
|-----------|----------------|
| `tests/test_smart_dedup.py` | All 5 SmartDedup strategies, union-find, pick_canonical, fatigue score |
| `tests/test_dedup_cross_scanner.py` | Cross-scanner merge, location-aware no-merge, severity hoisting |
| `tests/test_scanner_parsers_coverage.py` | CVE/CWE extraction helpers, severity normalisation, JSON parse |
| `tests/test_findings_lifecycle.py` | GAP-063 schema columns, idempotent migration, first_seen_at backfill |
| `tests/test_function_reachability_engine.py` | Python AST parse, BFS reachability, TS/Java stubs, schema idempotency |
| `tests/test_reachability_multilang.py` | Multi-language reachability (SPEC-004 companion) |
| `tests/test_reachability_router_deep.py` | Router-level reachability integration |
| `tests/test_security_real_scanner_integration.py` | Real scanner file integration (no mocks) |
| `tests/test_real_scanner_unit.py` | Unit normaliser tests per scanner type |
| `tests/test_findings_wave_b_router.py` | Wave-B findings router coverage |

### Cross-references

- SPEC-001 (`trustgraph-correlation`): `SecurityFindingsEngine.record_finding` and `scanner_ingest_router` both emit into TrustGraph. SPEC-001 REQ-001-02 requires enrichment returns related_findings for linked findings; this spec is the upstream producer.
- SPEC-004 (`reachability-multilang`): `FunctionReachabilityEngine` implements the Python path; SPEC-004 owns the TS/Java DCA layer (NEW-G070). This spec defers to SPEC-004 for non-Python languages.
- SPEC-005b (`graph-populate`): `_emit_finding_to_trustgraph` creates `FINDING_AFFECTS_ASSET` edges consumed by SPEC-005b graph population queries.
- SPEC-006 (`honest-compliance-reporting`): findings counts and severity breakdowns from `get_findings_summary` feed compliance report generation.
- SPEC-007 (`systemic-tenancy`): all mutable endpoints enforce `get_org_id`; cross-tenant returns 404 per tenancy spec; `security_findings` table is indexed on `(org_id, ...)` composite keys.
