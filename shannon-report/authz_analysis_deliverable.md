# Authorization Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Target:** Aldeci CTEM+ Platform — http://host.docker.internal:8000
- **Analysis Date:** 2026-04-16
- **Key Outcome:** 15 high-confidence authorization vulnerabilities were identified and confirmed via source-code tracing. Vulnerabilities span all three categories: vertical privilege escalation (including a systemic authentication bypass that grants admin access by default), horizontal privilege escalation (multiple missing tenant-isolation guards), and context/workflow flaws (SAML replay, scanner pipeline poisoning, DNS rebinding). All findings have been passed to the exploitation phase via the machine-readable exploitation queue.
- **Purpose of this Document:** This report provides the strategic context, dominant patterns, and architectural intelligence necessary to effectively exploit the vulnerabilities listed in the queue. It is intended to be read alongside the JSON deliverable.

| Category | Count | Highest Confidence |
|---|---|---|
| Vertical Privilege Escalation | 4 | High |
| Horizontal / IDOR | 8 | High |
| Context / Workflow | 3 | Medium |
| **Total** | **15** | — |

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Systemic Authentication Bypass via Dev-Mode Default (Vertical)
- **Description:** The application's authentication middleware defaults to `FIXOPS_AUTH_MODE="dev"`, which unconditionally returns a full administrator context (`role="admin"`, all scopes) for every unauthenticated request. A second independent bypass in `app.py` triggers when `auth_strategy` is empty (the default), also granting full admin privileges. Together, these mean the default installation requires **zero credentials** to reach any endpoint as an admin.
- **Implication:** All role-based guards protecting admin, user management, and privileged operations are irrelevant — an external attacker can bypass them entirely.
- **Representative:** AUTHZ-VULN-01, AUTHZ-VULN-02

### Pattern 2: Missing Tenant Isolation in Multi-Tenant Data Stores (Horizontal)
- **Description:** Multiple subsystems (findings, audit logs, analytics) store shared data in SQLite databases whose schemas have **no `org_id` column**. Consequently, all database queries return cross-tenant data. In other subsystems (SSO configs, API keys, workflows, evidence bundles), an `org_id` is stored but the read/delete paths never include it in the `WHERE` clause or guard condition.
- **Implication:** Any authenticated user (or unauthenticated user under Pattern 1) can read, modify, or delete data belonging to any other tenant.
- **Representative:** AUTHZ-VULN-05, AUTHZ-VULN-06, AUTHZ-VULN-07, AUTHZ-VULN-08, AUTHZ-VULN-09, AUTHZ-VULN-10, AUTHZ-VULN-11, AUTHZ-VULN-12

### Pattern 3: org_id Extracted But Never Used (Horizontal)
- **Description:** Several routes correctly inject `org_id` via `Depends(get_org_id)` in the function signature, establishing the illusion of tenant isolation, but then never pass that value to the underlying database query. The `org_id` variable is declared but silently ignored.
- **Implication:** The guard is present in form but absent in effect; a code reviewer would miss this without tracing to the DB layer.
- **Representative:** AUTHZ-VULN-09 (audit logs), AUTHZ-VULN-10 (analytics)

### Pattern 4: Privilege Escalation via Unrestricted Role Assignment (Vertical)
- **Description:** The user creation endpoint and the API key creation endpoint both accept a `role` field from the caller without validating it against the caller's own role. An admin (or anyone under Pattern 1) can create admin-level users or admin-scoped API keys for arbitrary `user_id` values.
- **Implication:** Persistent privilege escalation — an attacker can plant a backdoor admin account or API key.
- **Representative:** AUTHZ-VULN-03, AUTHZ-VULN-04

### Pattern 5: State Validation Missing in Multi-Step Workflows (Context)
- **Description:** The SAML authentication flow validates assertion signatures but never checks `InResponseTo` or tracks used assertion IDs, enabling replay attacks. The scanner ingest pipeline accepts arbitrary findings data with `pipeline=True`, poisoning the ML pipeline without content validation. Webhook delivery re-resolves hostnames without re-running the IP-block check registered at subscription time.
- **Implication:** Attackers can forge authentication sessions, inject poisoned ML training data, and leverage webhooks for SSRF.
- **Representative:** AUTHZ-VULN-13, AUTHZ-VULN-14, AUTHZ-VULN-15

---

## 3. Strategic Intelligence for Exploitation

### Session Management Architecture
- **Auth Methods:** JWT HS256 (24h TTL), scoped API keys (`fixops_` / `aldeci_` prefixed), SSO/OIDC (RS256), SAML 2.0
- **Auth Enforcement:** Controlled by `FIXOPS_AUTH_MODE` env var (default: `"dev"`) in `/repos/Fixops/suite-core/core/auth_middleware.py:42`
- **Second Bypass:** `auth_strategy` read from overlay config at `/repos/Fixops/suite-api/apps/api/app.py:2063`; empty default causes fallback to admin at line 2186–2188
- **Critical Finding:** In the default deployment, **no credentials are required for any endpoint**. An HTTP request with no headers returns an `AuthContext` with `role="admin"` and `scopes=ROLE_SCOPES[UserRole.ADMIN]` (all 13 scopes including `admin:all`).

### Role/Permission Model
- **Two Parallel Role Systems:**
  - `auth_models.UserRole`: viewer / analyst / admin / service
  - `rbac.RBACRole`: viewer / developer / security_analyst / compliance_officer / admin / super_admin
- **28 defined RBAC permissions** including `admin:all` (catch-all), `system:config` (super_admin only)
- **Critical Finding:** Because the dev-mode bypass grants `admin:all`, the entire RBAC model is bypassed in the default configuration. There is no separate `super_admin`-only gate that the bypass cannot cross.

### Resource Access Patterns
- **Primary IDs:** Path parameters (e.g., `/findings/{finding_id}`, `/workflows/{workflow_id}`)
- **Tenant Field:** `org_id`, injected via `Depends(get_org_id)` middleware. The middleware correctly extracts org_id from the authenticated context, but many handlers never pass it to the DB layer.
- **Critical Finding:** The auth bypass hardcodes `org_id="default"`. In a real deployment, all bypass-mode requests appear to belong to the `"default"` org — exploitation should test whether non-default org data is also reachable by enumerating IDs directly.

### Database Architecture
- **40+ SQLite files** with world-readable permissions (0644 on host filesystem)
- **Affected databases:** `findings.db`, `audit.db`, `analytics.db` lack `org_id` columns entirely
- **Findings store:** `_findings_store` is an in-memory global dict (`Dict[str, Dict[str, Any]]`) — no per-tenant scoping possible
- **Critical Finding:** Because findings are stored in a global dict, *all* findings are accessible to any authenticated caller regardless of org.

### Workflow for Exploitation Under Auth Bypass
1. Send any HTTP request to the API — no `Authorization` header needed
2. The middleware returns admin context (`dev-user` / `default` org / all scopes)
3. All role guards (`_require_scope("admin:all")`) are satisfied automatically
4. Proceed to access/modify cross-tenant resources directly by ID

---

## 4. Vectors Analyzed and Confirmed Secure

These authorization checks were traced to the DB layer and confirmed to have robust, properly-placed guards. They are **low-priority** for further testing.

| **Endpoint** | **Guard Location** | **Defense Mechanism** | **Verdict** |
|---|---|---|---|
| `GET /api/v1/backups/{backup_id}` | backup_router.py:87-93 | `record.org_id != org_id` check + SQL `WHERE id=? AND org_id=?` | SAFE |
| `DELETE /api/v1/backups/{backup_id}` | backup_router.py:96-105 | Same org_id ownership check before delete | SAFE |
| `POST /api/v1/backups/{backup_id}/restore` | backup_router.py:118-134 | Same org_id ownership check before restore | SAFE |
| `GET /api/v1/tenants/{org_id}/stats` | tenant_router.py:181-193 (`_require_admin_or_self`) | Validates `current_org == resource_org_id` or `admin:all` scope | SAFE |
| `GET/POST/PUT/DELETE /api/v1/admin/users/*` | app.py:2549-2552 | Router-level `_require_scope("admin:all")` before all handlers | SAFE (still bypassed by VULN-01) |
| `GET/POST/PUT/DELETE /api/v1/admin/teams/*` | app.py:2549-2552 | Same admin scope middleware | SAFE (still bypassed by VULN-01) |
| `GET /api/v1/attack-sim/simulations*` | attack_simulation_engine.py:1330-1344 | `WHERE sim_id=? AND org_id=?` in all queries | SAFE |
| `GET /api/v1/auth/sso` callback (SSO login) | sso_router.py:296 | `_STATE_STORE.pop(state)` — one-time use state | SAFE (replay prevented) |
| `GET /api/v1/autofix/suggestions/{finding_id}` | autofix_router.py:308 | Post-query filter `getattr(f, "org_id", org_id) == org_id` (correct logic) | SAFE |
| `POST /api/v1/triage/enrich` | triage_router.py:540-602 | Pydantic validators + 200-item cap; no pipeline write | SAFE (DoS risk only) |
| `GET /api/v1/graphql` | graphql_router.py | Router is **not registered** in app.py — endpoint unreachable | N/A |

---

## 5. Detailed Vulnerability Findings

### AUTHZ-VULN-01 — Dev-Mode Authentication Bypass (Vertical)
- **File:** `suite-core/core/auth_middleware.py:42, 192–201`
- **Code:**
  ```python
  _AUTH_MODE = os.getenv("FIXOPS_AUTH_MODE", "dev")  # default = "dev"
  ...
  if _AUTH_MODE != "enforced":
      return AuthContext(user_id="dev-user", email="dev@fixops.local",
                         role="admin", org_id="default",
                         scopes=ROLE_SCOPES[UserRole.ADMIN], auth_method="dev-bypass")
  ```
- **Side Effect:** Every unauthenticated HTTP request receives full admin privileges
- **Confidence:** HIGH

### AUTHZ-VULN-02 — Empty auth_strategy Fallback to Admin (Vertical)
- **File:** `suite-api/apps/api/app.py:2063, 2186–2188`
- **Code:**
  ```python
  auth_strategy = overlay.auth.get("strategy", "").lower()  # default = ""
  ...
  # Fallback — no auth strategy → admin (dev mode)
  request.state.user_role = "admin"
  request.state.user_scopes = _ALL_SCOPES
  ```
- **Side Effect:** When overlay config has no `strategy` key, all requests are granted admin scope including `admin:all`
- **Confidence:** HIGH

### AUTHZ-VULN-03 — Unrestricted Role on API Key Creation (Vertical)
- **File:** `suite-api/apps/api/auth_router.py:175–188`
- **Code:**
  ```python
  async def create_api_key(req: CreateKeyRequest):
      km.create_key(user_id=req.user_id, role=req.role, ...)
      # No check that req.role <= caller's role
      # No check that req.user_id == caller's user_id
  ```
- **Side Effect:** Under auth bypass, caller creates admin-scoped keys for arbitrary `user_id` values — persistent backdoor
- **Confidence:** HIGH

### AUTHZ-VULN-04 — Create Admin User Without Role Restriction (Vertical)
- **File:** `suite-api/apps/api/users_router.py:262–279`
- **Code:**
  ```python
  async def create_user(user_data: UserCreate):
      user = User(..., role=user_data.role, ...)  # caller-supplied role, no restriction
      db.create_user(user)
  ```
- **Side Effect:** Under auth bypass, attacker creates a permanent admin account in the database
- **Confidence:** HIGH

### AUTHZ-VULN-05 — Findings List: No Tenant Isolation (Horizontal)
- **File:** `suite-api/apps/api/findings_routes.py:251`
- **Code:**
  ```python
  findings = list(_findings_store.values())  # global in-memory dict, no org filter
  ```
- **Side Effect:** Authenticated caller reads security findings from every tenant in the system
- **Confidence:** HIGH

### AUTHZ-VULN-06 — Finding by ID: No Tenant Check (Horizontal)
- **File:** `suite-api/apps/api/findings_routes.py:322–325`
- **Code:**
  ```python
  finding = _findings_store.get(finding_id)  # no org_id verification
  ```
- **Side Effect:** Attacker enumerates finding IDs to read/update findings owned by other tenants
- **Confidence:** HIGH

### AUTHZ-VULN-07 — SSO Config CRUD: No Tenant Scoping (Horizontal)
- **File:** `suite-api/apps/api/auth_router.py:62–123`
- **Code:**
  ```python
  async def list_sso_configs():
      return db.list_sso_configs()  # returns ALL orgs' SSO providers
  async def get_sso_config(id: str):
      return db.get_sso_config(id)  # no org_id WHERE clause
  async def update_sso_config(id: str, ...):
      db.update_sso_config(id, ...)  # no org_id WHERE clause
  ```
- **Side Effect:** Admin from org A reads/overwrites SSO provider configs of org B — can redirect org B's logins to attacker-controlled IdP
- **Confidence:** HIGH

### AUTHZ-VULN-08 — API Key Management: No Ownership Verification (Horizontal)
- **File:** `suite-api/apps/api/auth_router.py:191–243`; `suite-core/core/key_manager.py`
- **Code:**
  ```python
  async def rotate_api_key(key_id: str):
      km.rotate_key(key_id)  # no user_id check — rotates any key
  async def revoke_api_key(key_id: str):
      km.revoke_key(key_id)  # no user_id check — revokes any key
  async def list_api_keys(user_id: Optional[str] = None):
      km.list_keys(user_id=user_id)  # optional filter; omitting returns all keys
  ```
- **Side Effect:** Cross-org key rotation/revocation and global key enumeration
- **Confidence:** HIGH

### AUTHZ-VULN-09 — Audit Logs: No Tenant Isolation (Horizontal)
- **File:** `suite-api/apps/api/audit_router.py:105–199`; `audit_db.py:41–52`
- **Root Cause:** `audit_logs` table has **no `org_id` column**. Even though `org_id = Depends(get_org_id)` is declared at line 107, it is never passed to `db.list_audit_logs()`. The export endpoint (line 125) has no auth parameter at all.
- **Side Effect:** Any authenticated user reads the full audit trail of all orgs — exposes user activities, resource IDs, IP addresses, and actions system-wide
- **Confidence:** HIGH

### AUTHZ-VULN-10 — Analytics Findings: No Tenant Isolation (Horizontal)
- **File:** `suite-api/apps/api/analytics_router.py:163–450`; `analytics_db.py:42–60`
- **Root Cause:** `findings` table in analytics DB has **no `org_id` column**. All calls to `db.list_findings(limit=5000)` return all findings regardless of tenant. `GET /analytics/findings/{id}` has no org_id parameter.
- **Side Effect:** Authenticated caller reads analytics metrics, finding details, and severity distributions for all other tenants
- **Confidence:** HIGH

### AUTHZ-VULN-11 — Workflow IDOR: GET/PATCH/DELETE by ID (Horizontal)
- **File:** `suite-api/apps/api/workflow_router.py:138–177`; `suite-core/core/workflow_engine.py:409–432`
- **Code:**
  ```python
  @router.get("/{workflow_id}")
  async def get_workflow_handler(workflow_id: str):  # no org_id param
      return engine.get_workflow(workflow_id)         # WHERE id=? only

  @router.delete("/{workflow_id}")
  async def delete_workflow_handler(workflow_id: str):
      engine.delete_workflow(workflow_id)            # DELETE WHERE id=? only
  ```
- **Side Effect:** Attacker reads, modifies, and deletes workflows belonging to other tenants
- **Confidence:** HIGH

### AUTHZ-VULN-12 — Evidence Bundles: No Tenant Isolation on Read (Horizontal)
- **File:** `suite-evidence-risk/api/evidence_router.py:530–576, 823–918`
- **Code:**
  ```python
  @router.get("/bundles")
  async def list_compliance_bundles(request: Request):  # no org_id dependency
      # iterates filesystem bundle directory without filtering by org

  @router.get("/bundles/{bundle_id}/download")
  async def download_evidence_bundle(bundle_id: str, ...):  # no org_id
      # serves any bundle file by ID without tenant check
  ```
- **Side Effect:** Attacker downloads compliance evidence bundles (audit findings, remediation evidence) from any tenant
- **Confidence:** HIGH

### AUTHZ-VULN-13 — SAML Assertion Replay: No InResponseTo / No Assertion ID Tracking (Context)
- **File:** `suite-core/core/sso_provider.py:587–638`
- **Root Cause:** `process_response()` validates status code but never checks `InResponseTo` against the stored AuthnRequest ID, and never tracks seen assertion IDs to prevent replay.
- **Side Effect:** Attacker replays a captured valid SAML assertion to authenticate as any SAML-authenticated user without performing the actual IdP login
- **Confidence:** MEDIUM (SAML must be configured for the target org)

### AUTHZ-VULN-14 — Scanner Ingest: Unauthenticated Pipeline Poisoning (Context)
- **File:** `suite-api/apps/api/scanner_ingest_router.py:224–242`
- **Code:**
  ```python
  if pipeline and findings:
      bp = BrainPipeline()
      pipe_input = PipelineInput(findings=findings_dicts, ...)  # raw caller-supplied data
      pipeline_result = bp.run(pipe_input)  # injected directly into ML pipeline
  ```
- **Side Effect:** Authenticated caller submits up to 200 crafted "findings" per request with `pipeline=True`, poisoning the ML-based risk-scoring pipeline with false data
- **Confidence:** MEDIUM (requires authenticated API key, but any scope suffices)

### AUTHZ-VULN-15 — Webhook SSRF via DNS Rebinding (Context)
- **File:** `suite-api/apps/api/webhook_subscriptions_router.py:204`
- **Root Cause:** The private-IP check (`_is_private_ip()`) runs once at registration time (line 129) but the delivery function (`_deliver_webhook()`) at line 204 calls `requests.post(sub["url"], ...)` without re-resolving and re-checking the IP. DNS TTL expiry between registration and delivery allows the hostname to be rebound to an internal IP (e.g., `169.254.169.254`).
- **Side Effect:** Attacker registers a webhook pointing to a controlled domain, waits for DNS rebind, then triggers a delivery to reach internal metadata services or internal HTTP endpoints
- **Confidence:** MEDIUM (requires webhook registration + DNS control)

---

## 6. Analysis Constraints and Blind Spots

- **GraphQL Router Not Mounted:** The GraphQL router (`graphql_router.py`) defines endpoints without authentication and resolvers without authorization, but no `include_router` call was found in `app.py`. The endpoint `/api/v1/graphql` appears unreachable. If it is mounted in a non-standard path or enabled conditionally, the resolver authorization flaws would become critical.
- **Express.js Bridge (Port 3000):** The Express.js bridge provides direct SQLite read-only access. Its authorization model was not analyzed in this phase; cross-service data leakage may exist.
- **n8n Workflow Automation (Port 5678):** External workflow automation on port 5678 was not analyzed for authorization controls.
- **Dependency-Track (Ports 8080/8081):** The SBOM analysis service was out of scope for this authorization analysis.
- **SQLite File-Level Access:** 40+ SQLite databases have world-readable file permissions (0644). An attacker with code-execution capability can read any database directly. This is an infrastructure-level finding outside the HTTP authorization scope.
- **Dynamic Permission Loading:** Some endpoints may load permissions dynamically from the database at runtime. Static analysis cannot fully capture runtime permission checks; the exploitation phase should confirm with live testing.
- **Autofix Org Filtering:** The post-query filter in `autofix_router.py:308` was analyzed and deemed correct in logic, but should be verified in the exploitation phase given the unusual `getattr`-with-default pattern.
