# Suite-API Deep Analysis Report

**Generated:** 2025-01-XX  
**Scope:** All 32+ files in `/suite-api/`  
**Analyst:** Automated code audit

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Critical Security Findings](#critical-security-findings)
4. [File-by-File Analysis](#file-by-file-analysis)
5. [Cross-Cutting Concerns](#cross-cutting-concerns)
6. [Recommendations](#recommendations)

---

## Executive Summary

The `suite-api` directory contains the FastAPI gateway for FixOps — approximately **15,000+ lines** across 32+ Python files. The codebase demonstrates strong domain modeling (normalizers, pipeline, ingestion) but has several systemic security and reliability issues:

| Category | Count | Severity |
|----------|-------|----------|
| Missing Authentication | 0 (mitigated in app.py) | — |
| In-Memory State (data loss on restart) | 8 stores | HIGH |
| SSRF Vectors | 1 confirmed | CRITICAL |
| Stub/Fake Data Endpoints | 3-4 endpoints | MEDIUM |
| Input Validation Gaps | 5+ endpoints | MEDIUM |
| Inconsistent Error Handling | Throughout | LOW |

**Key positive finding:** All routers ARE protected by `_verify_api_key` dependency when mounted in `app.py` — the per-router analysis notes "no auth" but the `create_app()` factory applies auth globally via `dependencies=[Depends(_verify_api_key)]`. The exception is `webhooks_receiver_router` which correctly uses signature verification instead.

---

## Architecture Overview

```
suite-api/
├── apps/api/
│   ├── app.py              (2457 lines) — Application factory, ingestion endpoints, pipeline
│   ├── normalizers.py       (1839 lines) — SARIF/SBOM/CVE/VEX/CNAPP normalizers
│   ├── ingestion.py         (2100 lines) — Scanner-agnostic ingestion system
│   ├── pipeline.py          (1735 lines) — Risk scoring, guardrail evaluation
│   ├── webhooks_router.py   (1803 lines) — Bidirectional ALM sync
│   ├── ide_router.py        (981 lines)  — IDE extension support
│   ├── bulk_router.py       (957 lines)  — Enterprise bulk operations
│   ├── analytics_router.py  (796 lines)  — Dashboard, findings, metrics
│   ├── marketplace_router.py(706 lines)  — Remediation packs marketplace
│   ├── reports_router.py    (685 lines)  — Report generation/export
│   ├── collaboration_router.py (587 lines) — Comments, watchers, notifications
│   ├── inventory_router.py  (585 lines)  — Asset/service/API inventory
│   ├── remediation_router.py(~350 lines) — Remediation lifecycle
│   ├── validation_router.py (~350 lines) — Dry-run compatibility checking
│   ├── workflows_router.py  (~470 lines) — Workflow orchestration
│   ├── policies_router.py   (~370 lines) — Policy-as-code engine
│   ├── audit_router.py      (~420 lines) — Tamper-proof audit chain
│   ├── knowledge_graph.py   (~260 lines) — CTINexus-compatible graph builder
│   ├── demo_data.py         (~340 lines) — Demo data seeding
│   ├── upload_manager.py    (~220 lines) — Chunked upload support
│   ├── users_router.py      (~250 lines) — User management + JWT login
│   ├── iac_router.py        (~220 lines) — IaC security scanning
│   ├── teams_router.py      (~150 lines) — Team CRUD
│   ├── integrations_router.py(~370 lines) — Integration management
│   ├── auth_router.py       (~130 lines) — SSO/SAML configuration
│   ├── rate_limiter.py      (~170 lines) — Token bucket rate limiter
│   ├── health.py            (~160 lines) — Health/readiness probes
│   ├── middleware.py         (~100 lines) — Correlation ID + logging
│   ├── dependencies.py      (~80 lines)  — Shared FastAPI dependencies
│   └── routes/enhanced.py   (~100 lines) — Multi-LLM consensus API
├── backend/
│   ├── app.py               (shim → apps.api.app.create_app)
│   └── normalizers.py       (shim → apps.api.normalizers)
└── data/                    (runtime data directory)
```

---

## Critical Security Findings

### 1. SSRF Vector in Workflows (CRITICAL)

**File:** `workflows_router.py`, `_execute_action()` function  
**Issue:** The `http_call` action type makes HTTP requests to URLs specified in workflow step config with **zero URL validation**.

```python
# An attacker who can create/modify workflows can hit internal services:
action_config = {"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"}
```

**Impact:** Access to cloud metadata endpoints, internal services, localhost ports.  
**Fix:** Implement URL allowlist; block RFC 1918, link-local, and loopback addresses.

### 2. JWT Secret Inconsistency (HIGH)

**Files:** `app.py` (L1-30), `users_router.py` (L1-50)  

- `app.py`: Falls back to ephemeral `secrets.token_hex(32)` if `FIXOPS_JWT_SECRET` is unset — tokens invalidated on every restart.
- `users_router.py`: **Requires** `FIXOPS_JWT_SECRET` with ≥32 chars or raises 500.

These two modules may use **different secrets** if the env var is set after app.py initializes its module-level constant but before a login request hits users_router.py. In production, this creates a split-brain auth scenario.

### 3. ServiceNow Webhook — No Signature Verification (HIGH)

**File:** `webhooks_router.py`, `receive_servicenow_webhook()`  
**Issue:** Jira webhook verifies HMAC-SHA256 signatures. GitLab verifies `X-Gitlab-Token`. Azure DevOps has no verification. **ServiceNow has no signature verification at all.**

Any network actor who knows the endpoint URL can forge ServiceNow webhook events to manipulate finding statuses, trigger drift detection, and modify integration mappings.

### 4. Azure DevOps Webhook — No Authentication (HIGH)

**File:** `webhooks_router.py`, `receive_azure_devops_webhook()`  
**Issue:** No token, signature, or any form of authentication. Open to the internet.

### 5. In-Memory State — Data Loss on Restart (HIGH)

| Store | File | Impact |
|-------|------|--------|
| `_violation_store` | `policies_router.py` | All policy violations lost |
| `_dependency_store` | `inventory_router.py` | All dependency graph data lost |
| `_service_store` | `inventory_router.py` | All service inventory lost |
| `_api_store` | `inventory_router.py` | All API inventory lost |
| `_jobs` | `bulk_router.py` | All bulk operation job states lost |
| `_sla_store` | `workflows_router.py` | All SLA configurations lost |
| `_execution_steps` | `workflows_router.py` | All execution timeline data lost |
| `_paused_executions` | `workflows_router.py` | All paused workflow states lost |
| `_chain_hashes`/`_chain_index` | `audit_router.py` | Tamper-proof chain broken |
| `_login_attempts` | `users_router.py` | Rate limiting reset |
| `app.state.artifacts` | `app.py` | All ingested artifacts lost |
| `app.state.last_pipeline_result` | `app.py` | Triage/graph data lost |

### 6. Jira Webhook Signature Verification Uses Reconstructed Body (MEDIUM)

**File:** `webhooks_router.py`, `receive_jira_webhook()`  
**Issue:** Signature is verified against `json.dumps(payload.model_dump())` (Pydantic-reconstructed), not the raw HTTP body. If Pydantic normalizes field ordering, types, or defaults, the HMAC will fail or pass incorrectly.

---

## File-by-File Analysis

### `app.py` (2457 lines)

**Purpose:** Main FastAPI application factory — wires all middleware, sets up CORS, mounts 40+ routers, defines file-upload ingestion endpoints, pipeline execution, triage view, and graph visualization.

**Key Endpoints:**
- `POST /inputs/{design|sbom|sarif|cve|vex|cnapp|context}` — File upload ingestion
- `POST /inputs/{stage}/chunks/{start|upload|complete}` — Chunked upload
- `POST /api/v1/ingest/multipart` — Scanner-agnostic batch ingestion
- `GET/POST /pipeline/run` — Execute analysis pipeline
- `GET /api/v1/triage` — Triage inbox (events + clusters view)
- `GET /api/v1/graph` — Interactive knowledge graph
- `GET /api/v1/search` — Global search
- `GET /analytics/dashboard` — Analytics dashboard
- `POST /feedback` — Analyst feedback capture

**Dependencies:** Massive — imports from all 7 suites. 40+ optional router imports via try/except.

**Problems Found:**
1. **CORS defaults to localhost origins** when `FIXOPS_ALLOWED_ORIGINS` is unset, including `https://*.devinapps.com` wildcard (line ~618).
2. **Global search** (`/api/v1/search`) loads up to 500 findings into memory and does string matching (line ~800). No pagination, O(n) scan.
3. **`/pipeline/run` accepts both GET and POST** — GET with side effects is unconventional.
4. **Triage export** generates all rows in-memory before streaming.
5. **Module-level `app = create_app()`** at the very end means the app is created at import time.
6. **JWT secret** generated at module level before `create_app()` runs — initialization order matters.
7. `_get_triage_clusters()` hardcodes `org_id="default"` — multi-tenant gap.

**Lines of Interest:**
- L1-30: JWT_SECRET initialization with ephemeral fallback
- L501-530: `create_app()` factory entry point
- L615-640: CORS configuration with localhost defaults
- L800-830: Global search implementation
- L870-900: Router mounting with `_verify_api_key`
- L1475-1500: Multipart ingestion with asyncio.Semaphore
- L1750-1900: Triage endpoint with crosswalk transformation
- L2440-2457: Module-level app instantiation

---

### `normalizers.py` (1839 lines)

**Purpose:** Core normalization engine — transforms SARIF, SBOM (CycloneDX/SPDX/Syft/GitHub), CVE feeds, VEX, CNAPP, business context, and Snyk JSON into unified internal models.

**Key Classes:**
- `InputNormalizer` — Main normalizer with `load_sarif()`, `load_sbom()`, `load_cve_feed()`, `load_vex()`, `load_cnapp()`, `load_business_context()`
- `NormalizedSARIF`, `NormalizedSBOM`, `NormalizedCVEFeed`, `NormalizedVEX`, `NormalizedCNAPP`, `NormalizedBusinessContext` — Output dataclasses
- `SBOMComponent`, `CVERecordSummary`, `VEXAssertion`, `CNAPPFinding`, `CNAPPAsset` — Internal models
- `SarifFindingSchema`, `NormalizedSarifSchema` — Pydantic strict validators

**Dependencies:** sarif-om (required), lib4sbom (optional), cvelib (optional), snyk-to-sarif (optional), PyYAML (optional)

**Problems Found:**
1. **`_safe_json_loads` recursive depth check** is O(n*d) where n=items, d=depth — could be slow on deeply nested docs near the limit.
2. **Snyk-to-SARIF fallback** (`_convert_snyk_payload_to_sarif`) duplicates logic from the snyk-to-sarif package — maintenance burden.
3. **`_maybe_decompress` zip handling** extracts by extension priority but only reads the first matching file — multi-file archives silently lose data.
4. **`MAX_JSON_ITEMS = 1,000,000`** — very high limit could allow memory exhaustion with crafted input.
5. **SBOM parser fallback chain** tries lib4sbom → CycloneDX JSON → GitHub snapshot → Syft. If lib4sbom partially parses and throws, the error is swallowed and fallbacks tried, but the `last_error` from lib4sbom may shadow the real issue.

**Lines of Interest:**
- L88-125: `_safe_json_loads` with depth/item limits
- L186-253: Snyk issue collection with multi-format support
- L254-350: Snyk-to-SARIF manual conversion
- L570-600: `InputNormalizer._ensure_bytes` — handles 7+ input types
- L640-680: Gzip decompression with size limit
- L750-900: lib4sbom SBOM parsing with vulnerability deduplication
- L900-1000: CycloneDX JSON fallback parser

---

### `ingestion.py` (2100 lines)

**Purpose:** Scanner-agnostic ingestion system with `UnifiedFinding` model, asset inventory, normalizer plugin architecture supporting 16+ source formats.

**Key Classes:**
- `UnifiedFinding` — Pydantic model with ~50 fields for normalized findings
- `Asset` — Discovered asset model
- `NormalizerPlugin` (Protocol) — Plugin interface for format-specific normalizers
- `NormalizerConfig` — YAML-configurable normalizer settings
- `BaseNormalizer` — Pattern-based format detection
- `SARIFNormalizer`, `CycloneDXNormalizer`, `SPDXNormalizer`, etc.
- `NormalizerRegistry` — Plugin registry with priority-based dispatch
- `IngestionService` — Main service orchestrating detection → normalization → deduplication

**Problems Found:**
1. **`_parse_json` has regex-based JSON "repair"** — removes trailing commas via regex, which could corrupt string values containing commas.
2. **Asset inventory is in-memory** `Dict[str, Asset]` — lost on restart, unbounded growth.
3. **No rate limiting** on the ingestion service itself.
4. **Format detection** relies on string matching (`"sarif" in str(data).lower()`) which is O(n) on document size.
5. **`UnifiedFinding` has 50+ fields** — serialization overhead for bulk operations.

---

### `pipeline.py` (1735 lines)

**Purpose:** `PipelineOrchestrator` — derives insights from uploaded artifacts, computes risk profiles, evaluates guardrails, builds crosswalks between design/SBOM/SARIF/CVE data.

**Key Features:**
- Risk profile computation combining EPSS, KEV, Bayesian, and Markov chain models
- BN-LR hybrid model support via feature flags
- Guardrail evaluation against configurable severity thresholds
- Context engine integration for business-criticality scoring
- Evidence bundle generation with RSA-SHA256 signatures
- Knowledge graph construction

**Problems Found:**
1. **Magic numbers** in `_compute_risk_profile_heuristic`: `baseline_prior = 0.02`, `posterior * 10`, `markov_state * 0.15` — undocumented constants that affect risk scores.
2. **`overlay` accessed via `getattr(self, "overlay", None)`** — suggests it's injected externally, not a constructor parameter.
3. **Heavy import chain** — imports from 15+ core modules; failure of any one cascades.
4. **No timeout** on pipeline execution — a large dataset could block the event loop.

---

### `webhooks_router.py` (1803 lines)

**Purpose:** Bidirectional webhook sync with Jira, ServiceNow, GitLab, Azure DevOps. Two routers: `router` (management, API key auth) and `receiver_router` (inbound webhooks, signature verification).

**Key Features:**
- SQLite-backed mapping/event/drift/outbox tables
- HMAC-SHA256 Jira signature verification
- GitLab token verification
- Outbox pattern with exponential backoff retries
- Drift detection between FixOps ↔ external statuses
- ALM work item creation/update queuing
- Full outbox lifecycle (queue → process → retry → cancel)

**Key Endpoints:**
- `POST /webhooks/jira` — Receive Jira webhooks (signature verified)
- `POST /webhooks/servicenow` — Receive ServiceNow webhooks (**NO auth**)
- `POST /webhooks/gitlab` — Receive GitLab webhooks (token verified)
- `POST /webhooks/azure-devops` — Receive Azure DevOps webhooks (**NO auth**)
- `GET/POST/PUT/DELETE /api/v1/webhooks/mappings` — CRUD integration mappings
- `GET/PUT /api/v1/webhooks/drift` — Drift detection and resolution
- `POST/GET/PUT/DELETE /api/v1/webhooks/outbox` — Outbox management
- `POST /api/v1/webhooks/alm/work-items` — ALM work item creation

**Problems Found:**
1. **ServiceNow webhook has NO signature verification** — open to forgery.
2. **Azure DevOps webhook has NO authentication** — completely open.
3. **Jira signature uses reconstructed body** (`json.dumps(payload.model_dump())`), not raw bytes.
4. **`_init_db()` at module load** — global side effect, creates SQLite tables on import.
5. **Direct `sqlite3.connect()` calls** — no connection pooling, each endpoint opens/closes.
6. **SQL injection is NOT present** — parameterized queries used consistently (good).
7. **`process_pending_outbox_items`** processes items sequentially — could be parallelized.
8. **Error handling in receiver endpoints** does `conn.commit()` after setting error, but the INSERT may not have committed — potential data loss.

---

### `analytics_router.py` (796 lines)

**Purpose:** Analytics dashboard with findings CRUD, decisions, MTTR calculation, coverage, ROI estimation, noise reduction metrics, custom queries, and CSV export.

**Key Endpoints:**
- `GET /api/v1/analytics/dashboard/{overview|trends|top-risks|compliance-status}`
- `GET/POST /api/v1/analytics/findings` + `/{id}`
- `GET/POST /api/v1/analytics/decisions` + `/{id}`
- `GET /api/v1/analytics/{mttr|coverage|roi|noise-reduction}`
- `POST /api/v1/analytics/custom-query`
- `GET /api/v1/analytics/export`

**Problems Found:**
1. **ROI calculation uses hardcoded constants:** `avg_breach_cost = 4_240_000` and `critical_breach_probability = 0.15` — misleading for customers.
2. **`create_finding` doesn't validate org_id ownership** — any org_id can create findings for any org.
3. **Export endpoint loads up to 10,000 records** into memory before CSV serialization.
4. **`custom-query` endpoint** accepts arbitrary filter dicts — needs sanitization.

---

### `reports_router.py` (685 lines)

**Purpose:** Report generation, scheduling, templates, export in SARIF/CSV/PDF/JSON formats.

**Key Endpoints:**
- `GET/POST /api/v1/reports` — List/create reports
- `POST /api/v1/reports/generate` — Trigger report generation
- `GET /api/v1/reports/{id}/download` — Download report file
- `POST /api/v1/reports/schedule` — Schedule recurring reports
- `GET /api/v1/reports/export/{sarif|csv}` — Export findings

**Problems Found:**
1. **`create_report` immediately marks status as "COMPLETED"** with hardcoded `file_size = 1024` and fake `file_path = /tmp/reports/{id}.{format}` — stub behavior masquerading as real functionality.
2. **Report download** generates demo data on-the-fly if file doesn't exist (when `FIXOPS_MODE=demo`).
3. **Uses `/tmp/fixops_reports`** as default directory — not persistent across container restarts.
4. **HTML report format raises 501** — unimplemented.

---

### `bulk_router.py` (957 lines)

**Purpose:** Enterprise bulk operations with async job management — status updates, assignments, ticket creation, risk acceptance, export.

**Key Endpoints:**
- `POST /api/v1/bulk/{status|assign|tickets|risk-accept|export}`
- `GET /api/v1/bulk/jobs` — List jobs
- `GET /api/v1/bulk/jobs/{id}` — Get job details
- `DELETE /api/v1/bulk/jobs/{id}` — Cancel job

**Problems Found:**
1. **`_jobs` is an in-memory dict** — all job state lost on restart, unbounded memory growth.
2. **No pagination** on job listing or results.
3. **Ticket creation** supports Jira/ServiceNow/GitLab/GitHub/Azure DevOps via real connectors — functional, not stub.

---

### `collaboration_router.py` (587 lines)

**Purpose:** Team collaboration — comments, watchers, activity feeds, mentions, notifications with Slack/email delivery.

**Key Endpoints:**
- `POST/GET /api/v1/collaboration/comments` — Comment CRUD
- `POST/GET/DELETE /api/v1/collaboration/watchers` — Watcher management
- `POST/GET /api/v1/collaboration/activities` — Activity feed
- `GET/PUT /api/v1/collaboration/mentions/{user_id}` — Mention tracking
- `POST /api/v1/collaboration/notifications/{queue|notify-watchers|process|deliver}`
- `GET/PUT /api/v1/collaboration/notifications/preferences/{user_id}`

**Problems Found:**
1. **SSRF protection is good** — Slack webhook URL read from env var `FIXOPS_SLACK_WEBHOOK_URL`, not user input.
2. **SMTP password from env var** (`FIXOPS_SMTP_PASSWORD`) — credentials never in request body (good security practice).
3. **No auth on individual endpoints** — but mounted with `_verify_api_key` in app.py.
4. **`_collab_service` is a lazy singleton** — thread-safe via SQLite but no connection pooling.

---

### `remediation_router.py` (~350 lines)

**Purpose:** Remediation lifecycle management with state machine transitions, SLA tracking, verification evidence, AutoFix AI integration.

**Key Endpoints:**
- `POST/GET /api/v1/remediation/tasks` — Task CRUD
- `PUT /api/v1/remediation/tasks/{id}/status` — State machine transitions
- `PUT /api/v1/remediation/tasks/{id}/assign` — Task assignment
- `POST /api/v1/remediation/tasks/{id}/verification` — Submit evidence
- `PUT /api/v1/remediation/tasks/{id}/ticket` — Link to external ticket
- `POST /api/v1/remediation/tasks/{id}/autofix` — AI-powered autofix
- `GET /api/v1/remediation/metrics/{org_id}` — MTTR metrics
- `POST /api/v1/remediation/sla/check` — SLA breach detection

**Problems Found:**
1. **Knowledge Brain integration** is optional (`_HAS_BRAIN`) — graceful degradation is good.
2. **Status change event** reuses `EventType.REMEDIATION_CREATED` for non-terminal status changes — misleading event type.
3. **AutoFix engine** is optional (`_HAS_AUTOFIX`) — returns 501 when unavailable (correct).
4. **Duplicate endpoints**: `/tasks/{id}/status` and `/tasks/{id}/transition` do the same thing; `/tasks/{id}/verification` and `/tasks/{id}/verify` do the same thing.
5. **`get_global_metrics`** hardcodes `org_id="default"` — multi-tenant gap.

---

### `validation_router.py` (~350 lines)

**Purpose:** Dry-run validation for security tool output compatibility testing. Tests parsing without persisting.

**Key Endpoints:**
- `POST /api/v1/validate/input` — Validate single file
- `POST /api/v1/validate/batch` — Validate multiple files
- `GET /api/v1/validate/supported-formats` — List supported formats

**Problems Found:**
1. **File size limit is enforced properly** (8MB, chunked reads) — good.
2. **`_detect_input_type`** uses cascading string checks — fragile but functional.
3. **`SpooledTemporaryFile` cleanup** in `finally` block — good resource management.
4. **No issues found** — this is a well-implemented validation endpoint.

---

### `marketplace_router.py` (706 lines)

**Purpose:** Remediation packs marketplace with browse, search, contribute, rate, purchase, and download functionality. Falls back to built-in catalog when enterprise module unavailable.

**Key Endpoints:**
- `GET /api/v1/marketplace/browse` — Browse/search items
- `GET /api/v1/marketplace/recommendations` — Org-specific recommendations
- `GET /api/v1/marketplace/items/{id}` — Item details
- `POST /api/v1/marketplace/contribute` — Submit content
- `POST /api/v1/marketplace/items/{id}/rate` — Rate content
- `POST /api/v1/marketplace/purchase/{id}` — Purchase item
- `GET /api/v1/marketplace/download/{token}` — Download purchased content

**Problems Found:**
1. **Enterprise module loaded via `importlib.util.spec_from_file_location`** from hardcoded path `fixops-enterprise/src/services/marketplace_service.py` — fragile path coupling.
2. **Built-in catalog has hardcoded metrics** (`rating: 4.8`, `downloads: 3842`) — fake engagement data.
3. **Legacy endpoint** `GET /packs/{framework}/{control}` returns hardcoded remediation data.
4. **Own `authenticate` function** defined but NOT used on any endpoint — dead code. Auth is handled by app.py's `_verify_api_key`.
5. **`_MARKETPLACE_STATS` are hardcoded** — don't reflect actual usage.

---

### `workflows_router.py` (~470 lines)

**Purpose:** Workflow orchestration with step execution, conditional branching, parallel steps, SLA tracking, pause/resume.

**Key Endpoints:**
- CRUD `/api/v1/workflows`
- `POST /api/v1/workflows/{id}/execute` — Execute workflow
- `GET /api/v1/workflows/{id}/history` — Execution history
- `GET/PUT /api/v1/workflows/{id}/sla` — SLA configuration
- `POST /api/v1/workflows/executions/{id}/pause|resume`

**Problems Found:**
1. **SSRF in `http_call` action** — makes requests to arbitrary URLs in step config (CRITICAL).
2. **All state in-memory** (`_sla_store`, `_execution_steps`, `_paused_executions`).
3. **Pause/resume is fake** — sets flags but doesn't actually stop/restart execution.
4. **Step execution with retry** uses `httpx` with no timeout configuration.

---

### `policies_router.py` (~370 lines)

**Purpose:** Policy-as-code engine with OPA-style condition evaluation, enforcement, simulation, conflict detection.

**Key Features:**
- Operators: eq, ne, gt, gte, lt, lte, in, not_in, matches, contains
- Policy simulation against test data
- Conflict detection between policies
- Violation tracking per policy

**Problems Found:**
1. **`_violation_store` is in-memory** — violations lost on restart.
2. **`matches` operator uses `re.search`** on user input — ReDoS risk if patterns aren't sanitized.
3. **Policy CRUD** uses `PolicyDB` (SQLite) but violations use in-memory dict — inconsistent persistence.

---

### `audit_router.py` (~420 lines)

**Purpose:** Tamper-proof audit chain with SHA-256 hash linking, compliance framework assessment, SIEM export (CEF format).

**Key Features:**
- Blockchain-style audit chain (each entry's hash includes previous hash)
- CEF export for SIEM integration
- Compliance framework assessment with control-level checks
- Decision trail tracking

**Problems Found:**
1. **Chain hashes in-memory** (`_chain_hashes`, `_chain_index`) — tamper-proof guarantee breaks on restart.
2. **`get_audit_log` iterates all logs** to find by ID — O(n).
3. **Retention policy endpoint returns hardcoded static values** — stub.
4. **CEF export** properly escapes special characters (good).

---

### `users_router.py` (~250 lines)

**Purpose:** User management with JWT auth, bcrypt password hashing, rate-limited login.

**Key Features:**
- `_get_jwt_secret()` requires `FIXOPS_JWT_SECRET` ≥32 chars
- Rate limiting: 5 attempts, 5-minute lockout
- JWT with `jti` claim for revocation support
- bcrypt password hashing

**Problems Found:**
1. **User CRUD has no authorization** — any authenticated user can create/list/update/delete any user.
2. **`_login_attempts` is in-memory** — rate limiting reset on restart.
3. **No password complexity** validation beyond `min_length=8`.
4. **JWT secret requirement** contradicts app.py's ephemeral fallback.

---

### `teams_router.py` (~150 lines)

**Purpose:** Team CRUD and member management.

**Problems Found:**
1. Minimal — clean implementation.
2. `sqlite3.IntegrityError` handling for duplicate names (good).

---

### `integrations_router.py` (~370 lines)

**Purpose:** CRUD for integration management (Jira, Slack, GitHub, GitLab, ServiceNow, etc.) with test and sync capabilities.

**Problems Found:**
1. **`create_integration` doesn't use `org_id`** — the parameter is accepted but unused.
2. **`db = IntegrationDB()` global singleton** — created at module level.
3. **Sync endpoint sends real Slack test message** ("FixOps sync test") — could surprise users.

---

### `auth_router.py` (~130 lines)

**Purpose:** SSO/SAML configuration management.

**Problems Found:**
1. **Anyone can create/modify SSO configurations** — no RBAC beyond API key.
2. **SSO certificate stored in plain text** in database.
3. **No DELETE endpoint** — SSO configs cannot be removed.

---

### `inventory_router.py` (585 lines)

**Purpose:** Application/service/API inventory, dependency graphs, license compliance.

**Problems Found:**
1. **Four in-memory dicts** (`_dependency_store`, `_service_store`, `_api_store`, inventory metadata).
2. **`create_service` and `create_api`** accept `Dict[str, Any]` with no schema validation.
3. **Security score defaults to 85.0** — misleading hardcoded value.

---

### `iac_router.py` (~220 lines)

**Purpose:** IaC security scanning with checkov/tfsec.

**Problems Found:**
1. **`resolve` and `remediate`** endpoints do identical things.
2. **Real scanner integration** via `get_iac_scanner()` — not stub.

---

### `ide_router.py` (981 lines)

**Purpose:** IDE extension support with AST-based code analysis, security pattern matching, complexity metrics.

**Key Features:**
- Security patterns for Python, JavaScript, TypeScript, Java, Go, Rust
- Cyclomatic and cognitive complexity calculation
- Maintainability index computation

**Problems Found:**
1. **TypeScript patterns inherit from JavaScript** but the TypeScript list is empty — falls back to nothing, not JS patterns.
2. **`count_nesting_depth` counts `{(` characters** — won't work for Python (indentation-based).
3. **`calculate_cognitive_complexity` uses naive nesting detection** — unreliable for real code.

---

### `knowledge_graph.py` (~260 lines)

**Purpose:** Assembles CTINexus-compatible knowledge graph from pipeline artifacts (design rows, crosswalk, compliance, guardrails, marketplace recommendations).

**Problems Found:**
1. **Imports from `new_apps.api.processing`** — unusual import path, suggesting a migration in progress.
2. **No validation** on input data — defensive `isinstance` checks throughout (good pattern).

---

### `demo_data.py` (~340 lines)

**Purpose:** Demo data seeding for all FixOps features. Generates realistic PDF/JSON/CSV/SARIF demo reports.

**Problems Found:**
1. **`is_demo_mode()`** defaults to `True` when `FIXOPS_MODE` unset — production deployments could accidentally run in demo mode.
2. **PDF generation** constructs raw PDF bytes with calculated xref offsets — clever but fragile.
3. **Demo MPTE data** includes realistic exploit steps (SQL injection, JWT bypass) — could be educational/concerning depending on context.

---

### `upload_manager.py` (~220 lines)

**Purpose:** Chunked upload manager with session lifecycle, SHA-256 checksum verification, resumable transfers.

**Problems Found:**
1. **Good security:**  `_sanitize_filename()` prevents path traversal.
2. **Thread-safe** via `threading.RLock`.
3. **Sessions are in-memory** (dict) + on-disk (metadata.json) — sessions survive restart via `_load_existing_sessions()`. Well designed.

---

### `rate_limiter.py` (~170 lines)

**Purpose:** Token bucket rate limiter middleware.

**Key Features:**
- Configurable requests per minute and burst size
- Per-client tracking (user ID or IP)
- Exempt paths for health checks
- `X-RateLimit-Limit` and `Retry-After` headers

**Problems Found:**
1. **In-memory buckets** — no distributed rate limiting (expected for single-instance).
2. **No issue** — clean implementation.

---

### `health.py` (~160 lines)

**Purpose:** Kubernetes health/readiness/version/metrics probes.

**Problems Found:**
1. **`/metrics` endpoint** has broad `try/except` that silently swallows errors — could hide monitoring failures.

---

### `middleware.py` (~100 lines)

**Purpose:** `CorrelationIdMiddleware` (UUID tracking) and `RequestLoggingMiddleware` (timing).

**No significant issues.**

---

### `dependencies.py` (~80 lines)

**Purpose:** Shared FastAPI dependencies for `org_id` and `correlation_id` extraction.

**Problems Found:**
1. **`get_org_id` defaults to "default"** — masks multi-tenancy issues in queries.

---

### `routes/enhanced.py` (~100 lines)

**Purpose:** Exposes multi-LLM consensus engine (GPT-4 + Claude + Gemini).

**Key Endpoints:**
- `POST /api/v1/enhanced/analysis` — Full enhanced analysis
- `POST /api/v1/enhanced/compare-llms` — Compare individual model verdicts
- `GET /api/v1/enhanced/capabilities` — Engine telemetry
- `GET /api/v1/enhanced/signals` — Feed badges and SSVC labels

**No significant issues.**

---

### `backend/app.py` (15 lines) & `backend/normalizers.py` (3 lines)

**Purpose:** Compatibility shims — `backend.app.create_app` → `apps.api.app.create_app`, `backend.normalizers` → `apps.api.normalizers`.

**No issues** — thin wrappers as expected.

---

## Cross-Cutting Concerns

### 1. Authentication Architecture

**Good news:** `create_app()` in `app.py` applies `_verify_api_key` dependency to ALL router mounts. Only `webhooks_receiver_router` bypasses API key auth (correctly using signature verification for inbound webhooks).

**Bad news:** Within the API key perimeter, there is **no RBAC**. Any valid API key can:
- Create/delete users
- Modify SSO/SAML configuration
- Execute bulk operations
- Access all organizations' data
- Run the pipeline
- Modify integrations

### 2. SQL Injection Protection

**All files using SQLite use parameterized queries** — no SQL injection vulnerabilities found. This is a consistent, good practice across the codebase.

### 3. Error Handling Patterns

| Pattern | Files | Issue |
|---------|-------|-------|
| Broad `try/except Exception` | health.py, app.py, several routers | Swallows unexpected errors |
| `HTTPException` with dict detail | app.py upload endpoints | Good structured errors |
| Bare `raise HTTPException(400, str(e))` | Multiple routers | May leak internal error details |
| Missing error response on empty result | analytics, inventory | Returns empty list instead of 404 |

### 4. Rate Limiting Coverage

`RateLimitMiddleware` exists but is **not applied** in `create_app()`. The `login` endpoint in `users_router.py` has its own in-memory rate limiter. All other endpoints have **no rate limiting**.

### 5. Duplicate Routes

No duplicate route paths found — route prefixes are unique per router.

### 6. Data Persistence Summary

| Data Type | Storage | Survives Restart? |
|-----------|---------|-------------------|
| Findings, decisions | AnalyticsStore (SQLite) | Yes |
| Integrations | IntegrationDB (SQLite) | Yes |
| Webhooks, mappings, drift | SQLite (webhooks DB) | Yes |
| Teams, users | SQLite | Yes |
| Policies | PolicyDB (SQLite) | Yes |
| Remediation tasks | SQLite | Yes |
| Collaboration | SQLite | Yes |
| Audit logs | AuditChainDB (SQLite) | Partial (chain hashes lost) |
| Upload sessions | Disk + memory | Yes (loads from disk) |
| Reports | `/tmp` | No (ephemeral) |
| Violations, inventory, jobs, SLA, artifacts | In-memory | **No** |

---

## Recommendations

### Priority 1 — Security (Do Immediately)

1. **Fix SSRF in workflows:** Add URL allowlist to `_execute_action()` http_call. Block private/internal IPs.
2. **Add auth to ServiceNow/Azure DevOps webhooks:** Implement HMAC or token verification.
3. **Fix Jira webhook signature:** Verify against raw request body, not Pydantic-reconstructed JSON.
4. **Unify JWT secret handling:** Remove ephemeral fallback from `app.py`; require `FIXOPS_JWT_SECRET` everywhere.
5. **Apply `RateLimitMiddleware`** in `create_app()` — it exists but isn't wired.
6. **Add RBAC** — at minimum, separate admin vs. user API keys.

### Priority 2 — Reliability (Do Soon)

7. **Persist in-memory stores to SQLite:** violations, inventory (services/APIs/dependencies), bulk jobs, SLA configs, execution steps, paused workflows.
8. **Fix audit chain persistence:** Store chain hashes in SQLite alongside audit logs.
9. **Fix demo mode default:** Change `is_demo_mode()` to default to `False` when `FIXOPS_MODE` is unset.
10. **Add connection pooling** for SQLite connections used in webhooks router.

### Priority 3 — Code Quality (Do When Possible)

11. **Remove duplicate endpoints** in remediation_router (`/status` vs `/transition`, `/verification` vs `/verify`).
12. **Remove dead `authenticate` function** from marketplace_router.
13. **Add pagination** to global search, bulk job listing, and analytics export.
14. **Add proper TypeScript security patterns** in ide_router (currently empty).
15. **Replace hardcoded ROI constants** in analytics_router with configurable values.
16. **Add report generation** to reports_router — current `create_report` is a stub.
