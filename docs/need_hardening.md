# FixOps — Endpoints That Need Hardening

> **Scope**: ~280 endpoints (44% of API surface) that execute real logic but have known security, reliability, or correctness issues.  
> **Date**: 2025-02 | **Source**: Code-verified audit of all 55 unique router files

---

## Table of Contents

1. [TLS Disabled — 9 occurrences / 6 files](#1-tls-disabled--verifyfylse)
2. [In-Memory State — 14 stores / 13 files](#2-in-memory-state--lost-on-restart)
3. [No RBAC — All endpoints affected](#3-no-rbac--any-api-key--full-admin)
4. [Rate Limiter Not Wired](#4-rate-limiter-exists-but-not-wired)
5. [Webhook Auth Missing — 2 endpoints](#5-webhook-auth-missing)
6. [SSRF in Workflows — 1 endpoint](#6-ssrf-in-workflows)
7. [LLM Silent Fallback to Heuristic](#7-llm-silent-fallback-to-heuristic)
8. [datetime.utcnow() — 61 files](#8-datetimeutcnow-deprecated--61-files)
9. [Priority Fix Order](#9-priority-fix-order)

---

## 1. TLS Disabled — `verify=False`

**Impact**: Man-in-the-middle attacks on all outbound MPTE, pentest, and scanning HTTP calls. Attacker on the network can intercept/modify vulnerability data, exploit payloads, and scan results.

| # | File | Line | Endpoint(s) Affected | Code |
|---|------|------|---------------------|------|
| 1 | `suite-core/api/agents_router.py` | 839 | `POST /agents/tasks` (MPTE call) | `httpx.AsyncClient(verify=False, timeout=30.0)` |
| 2 | `suite-attack/api/mpte_router.py` | 83 | `POST /mpte/verify` | `httpx.AsyncClient(verify=False, timeout=30.0)` |
| 3 | `suite-attack/api/mpte_router.py` | 123 | `POST /mpte/scan` | `httpx.AsyncClient(verify=False, timeout=30.0)` |
| 4 | `suite-attack/api/micro_pentest_router.py` | 73 | `GET /micro-pentest/health` | `httpx.AsyncClient(verify=False, timeout=5.0)` |
| 5 | `suite-attack/api/micro_pentest_router.py` | 110 | `POST /micro-pentest/run` | `httpx.AsyncClient(verify=False, timeout=30.0)` |
| 6 | `suite-core/core/intelligent_security_engine.py` | 321 | Internal ISE calls | `verify=False` |
| 7 | `suite-core/core/api_fuzzer.py` | 220 | API fuzz testing engine | `verify=False` |
| 8 | `suite-core/core/dast_engine.py` | 240 | DAST scanning engine | `verify=False` |
| 9 | `suite-core/core/micro_pentest.py` | 1654 | CVE tester | `CVEVulnerabilityTester(verify_ssl=False)` |

### Fix

```python
# Before (every occurrence)
async with httpx.AsyncClient(verify=False, timeout=30.0) as client:

# After — use env var for CA bundle, default to system certs
import ssl
import certifi

_VERIFY = os.getenv("FIXOPS_TLS_VERIFY", "true").lower() != "false"
_CA_BUNDLE = os.getenv("FIXOPS_CA_BUNDLE", certifi.where())

async with httpx.AsyncClient(
    verify=_CA_BUNDLE if _VERIFY else False,
    timeout=30.0
) as client:
```

**Effort**: Small — mechanical find/replace across 6 files. Add `certifi` to requirements.txt.

---

## 2. In-Memory State — Lost on Restart

**Impact**: 14 module-level Python dicts/lists store critical application state that is completely lost when the process restarts. No persistence layer, no recovery mechanism.

| # | File | Variable(s) | Line(s) | Endpoints Affected | What's Lost |
|---|------|-------------|---------|-------------------|-------------|
| 1 | `suite-core/api/copilot_router.py` | `_sessions`, `_messages`, `_actions` | 217–219 | `POST /copilot/sessions`, `GET /copilot/sessions`, `POST /copilot/sessions/{id}/messages`, `GET /copilot/sessions/{id}/messages`, `DELETE /copilot/sessions/{id}` | **All copilot conversation state** — sessions, chat history, action log |
| 2 | `suite-core/api/agents_router.py` | `_agent_tasks` | 366 | `POST /agents/tasks`, `GET /agents/tasks/{id}` | Agent task state and execution results |
| 3 | `suite-api/apps/api/inventory_router.py` | `_dependency_store` | 25 | `GET/POST /inventory/{id}/dependencies`, `DELETE /inventory/{id}/dependencies/{dep_id}` | Application dependency maps |
| 4 | `suite-api/apps/api/inventory_router.py` | `_service_store`, `_api_store` | 351–352 | `GET/POST /inventory/services`, `GET/POST /inventory/apis` | Service catalog and API inventory |
| 5 | `suite-api/apps/api/policies_router.py` | `_violation_store` | 26 | `GET/POST /policies/{id}/violations` | Policy violation records |
| 6 | `suite-api/apps/api/users_router.py` | `_login_attempts` | 58 | `POST /users/login` | **Brute-force rate limiting resets** — attacker gets fresh attempts after restart |
| 7 | `suite-api/apps/api/workflows_router.py` | `_sla_store`, `_execution_steps`, `_paused_executions` | 26–28 | `PUT/GET /workflows/{id}/sla`, `POST /workflows/{id}/execute`, `POST /workflows/executions/{id}/pause`, `POST /workflows/executions/{id}/resume` | SLA configs, execution step logs, paused workflow state |
| 8 | `suite-core/api/llm_router.py` | `_settings` | 88 | `GET/PUT /llm/settings` | LLM config (provider, timeout, temperature, max_tokens) reverts to defaults |
| 9 | `suite-core/api/intelligent_engine_routes.py` | `_sessions`, `_results` | 126–127 | `POST/GET /intelligent-engine/sessions`, `GET /intelligent-engine/sessions/{id}` | ISE analysis sessions and all results |
| 10 | `suite-attack/api/vuln_discovery_router.py` | `_discovered_vulns`, `_contributions`, `_retrain_jobs` | 282–284 | `GET/POST /vuln-discovery/vulns`, `GET /vuln-discovery/vulns/{id}`, `POST /vuln-discovery/verify`, `POST /vuln-discovery/contribute`, `POST /vuln-discovery/retrain` | **ALL discovered vulnerabilities** (pre-CVE intelligence), community contributions, ML retrain jobs |
| 11 | `suite-attack/api/micro_pentest_router.py` | `self._audit_logs`, `self._active_scans` | 450, 1084 | `POST /micro-pentest/enterprise/scan`, `GET /micro-pentest/enterprise/scans`, `GET /micro-pentest/enterprise/audit-logs` | Audit trail and active scan tracking |
| 12 | `suite-core/api/nerve_center.py` | Overlay config | 837–843 | `PUT /nerve-center/overlay` | Config changes accepted but _never persisted_ — returns success then silently discards |
| 13 | `suite-api/apps/api/bulk_router.py` | `_jobs` | 85 | `POST /bulk/findings/update`, `POST /bulk/findings/export`, `GET /bulk/jobs/{id}`, `POST /bulk/jobs/{id}/cancel` | All bulk operation state, job progress, results |
| 14 | `suite-core/new_backend/api.py` | Decision feedback | 56–62 | `POST /decisions/{id}/feedback` | Feedback accepted (`{"status": "received"}`) but immediately discarded |

### Highest Risk Items

1. **`vuln_discovery_router.py`** — ALL pre-CVE intelligence lost. This is original research data that cannot be recovered.
2. **`copilot_router.py`** — Users lose all conversation context mid-session if server restarts.
3. **`users_router.py`** — Security control (brute-force protection) bypassed by restart.
4. **`inventory_router.py`** — 4 separate stores with no persistence for a core asset management feature.

### Fix Pattern

The project already has 15+ SQLite WAL-backed stores. Follow the existing pattern:

```python
# Before
_sessions: Dict[str, dict] = {}

# After — use the existing DB pattern from analytics_db, audit_db, etc.
from core.copilot_db import CopilotDB  # new file

_db = CopilotDB(db_path="data/copilot.db")

@router.post("/sessions")
async def create_session(...):
    session = _db.create_session(...)
    return session
```

**Effort**: Medium — each store needs a new `*_db.py` file (~100-200 lines each following existing patterns). 14 stores × ~2 hours = ~28 hours.

---

## 3. No RBAC — Any API Key = Full Admin

**Impact**: Any user with a valid API key can access every endpoint including admin operations (user management, policy changes, LLM settings, pentest execution, bulk deletes).

**Location**: `suite-api/apps/api/app.py` lines 633–657

```python
async def _verify_api_key(
    request: Request,
    api_key: Optional[str] = Depends(api_key_header),
) -> None:
    # ...
    if auth_strategy == "token":
        if not api_key or api_key not in expected_tokens:
            raise HTTPException(status_code=401, detail="Invalid or missing API token")
        return  # ← No role check. Valid key = full access.

    if auth_strategy == "jwt":
        # ...
        decode_access_token(token)  # ← Decodes JWT but role is never extracted or checked
```

**Endpoints of concern** (should require admin role):
- `PUT /api/v1/llm/settings` — change LLM provider/config
- `POST /api/v1/micro-pentest/enterprise/scan` — launch pentests
- `DELETE /api/v1/analytics/findings/{id}` — delete findings
- `POST /api/v1/bulk/findings/delete` — bulk delete
- `PUT /api/v1/users/{id}` — modify user accounts
- `PUT /api/v1/workflows/{id}/sla` — change SLA policies
- `PUT /api/v1/nerve-center/overlay` — change system config

### Fix

```python
from core.auth_middleware import AuthContext, require_scope

# Per-endpoint guard
@router.put("/llm/settings")
async def update_settings(
    ...,
    auth: AuthContext = Depends(require_scope("admin"))
):
    ...
```

**Note**: The `AuthContext` class exists but has a bug — `has_scope()` method is missing (uses `__slots__` which doesn't allow dynamic attributes). Fix that first:

```python
class AuthContext:
    __slots__ = ("user_id", "email", "role", "org_id", "scopes", "auth_method")
    
    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes
```

**Effort**: Medium — fix `AuthContext.has_scope()` (5 min), then add `Depends(require_scope(...))` to sensitive endpoints (~50 endpoints, ~2 hours).

---

## 4. Rate Limiter Exists But Not Wired

**Impact**: Zero rate limiting on any endpoint. Enables DoS, credential stuffing on `/users/login`, API abuse.

**The middleware exists**: `suite-api/apps/api/rate_limiter.py` lines 16–160

```python
class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute=60, burst_size=10, exempt_paths=None):
        ...
```

**But it's never added to the app**: Searching `app.py` for `rate_limit`, `RateLimit`, or `rate_limiter` → **zero matches**.

### Fix

In `suite-api/apps/api/app.py`, inside `create_app()`:

```python
from apps.api.rate_limiter import RateLimitMiddleware

app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=120,
    burst_size=20,
    exempt_paths=["/api/v1/health", "/api/v1/feeds/refresh"]
)
```

**Effort**: Trivial — 3 lines, 5 minutes.

---

## 5. Webhook Auth Missing

**Impact**: Anyone on the internet can POST fabricated webhook payloads to inject false status changes, create drift records, and manipulate finding statuses.

### ServiceNow — No Auth

**File**: `suite-api/apps/api/webhooks_router.py` line 357

```python
@receiver_router.post("/servicenow")
def receive_servicenow_webhook(payload: ServiceNowWebhookPayload) -> Dict[str, Any]:
    event_id = str(uuid.uuid4())
    # Immediately processes payload — NO signature verification, NO auth
```

No `_verify_servicenow_signature()` function exists anywhere.

### Azure DevOps — No Auth

**File**: `suite-api/apps/api/webhooks_router.py` line 1485

```python
@receiver_router.post("/azure-devops")  
def receive_azure_devops_webhook(payload: AzureDevOpsWebhookPayload) -> Dict[str, Any]:
    event_id = str(uuid.uuid4())
    # Immediately processes payload — NO auth
```

No Basic Auth, no shared secret, no header verification.

### Contrast: Jira IS Authenticated

Lines 179–181 define `_get_jira_webhook_secret()` and `_verify_jira_signature()`. The Jira endpoint validates HMAC signatures. ServiceNow and Azure DevOps have no equivalent.

### Fix

```python
# ServiceNow — add HMAC signature verification
def _verify_servicenow_signature(request: Request) -> None:
    secret = os.getenv("SERVICENOW_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(401, "Webhook secret not configured")
    signature = request.headers.get("X-ServiceNow-Signature")
    if not signature:
        raise HTTPException(401, "Missing signature header")
    body = await request.body()
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(401, "Invalid signature")

# Azure DevOps — add Basic Auth
def _verify_azure_webhook(request: Request) -> None:
    expected_user = os.getenv("AZURE_WEBHOOK_USER")
    expected_pass = os.getenv("AZURE_WEBHOOK_PASS")
    auth = request.headers.get("Authorization")
    # ... validate Basic Auth header
```

**Effort**: Small — ~30 lines per webhook, ~1 hour for both.

---

## 6. SSRF in Workflows

**Impact**: Any authenticated user who can create/execute a workflow can make the server issue arbitrary HTTP requests — probe internal networks, hit cloud metadata endpoints (AWS IMDS, GCP metadata), access internal APIs bypassing auth.

**File**: `suite-api/apps/api/workflows_router.py` lines 264–271

```python
elif action == "http_call":
    import httpx
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.request(
            params.get("method", "GET"),
            params["url"],           # ← ANY URL, no validation
            json=params.get("body")
        )
        return {"status_code": resp.status_code, "body": resp.text[:500]}
```

**Attack examples**:
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — AWS credentials
- `http://metadata.google.internal/computeMetadata/v1/` — GCP metadata
- `http://localhost:8000/api/v1/users` — internal API without auth
- `http://10.0.0.x:port/` — internal network scanning

### Fix

```python
import ipaddress
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / AWS IMDS
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),         # IPv6 private
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]
ALLOWED_SCHEMES = {"http", "https"}

def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise HTTPException(400, f"Scheme '{parsed.scheme}' not allowed")
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        for network in BLOCKED_NETWORKS:
            if ip in network:
                raise HTTPException(400, "Target URL resolves to blocked network")
    except socket.gaierror:
        raise HTTPException(400, "Cannot resolve hostname")
```

**Effort**: Small — ~40 lines, 1 hour. Consider also adding a domain allowlist via env var.

---

## 7. LLM Silent Fallback to Heuristic

**Impact**: The "multi-LLM consensus" engine (GPT-4 + Claude + Gemini) silently degrades to returning the caller's `default_action` when API keys aren't set or API calls fail. Decisions presented as "AI-powered" may actually be simple heuristics.

**File**: `suite-core/core/llm_providers.py` lines 109–115

```python
# OpenAIChatProvider.analyse()
if not self.api_key:
    return super().analyse(...)  # ← Falls back to BaseLLMProvider
```

The `BaseLLMProvider.analyse()` (lines 43–70) returns a deterministic response echoing the caller's defaults:

```python
def analyse(self, *, prompt, context, default_action, default_confidence, 
            default_reasoning, mitigation_hints=None) -> LLMResponse:
    return LLMResponse(
        recommended_action=default_action,     # ← Just echoes what caller asked for
        confidence=default_confidence,
        reasoning=default_reasoning,
        metadata={"mode": "deterministic", "reason": "provider_disabled"},
    )
```

**Additionally**: The Anthropic provider is broken (system message in `messages` array instead of top-level `system` param) → Claude calls always fail → falls back too.

**Result**: In most deployments without all 3 API keys, "multi-LLM consensus" = single heuristic returning caller defaults. The `metadata.mode` field is set to `"deterministic"` or `"fallback"` but nothing alerts on this.

### Fix

```python
# 1. Log when fallback activates
if not self.api_key:
    logger.warning("LLM provider %s: no API key — using deterministic fallback", self.__class__.__name__)
    return super().analyse(...)

# 2. Surface mode in API responses (copilot, agents, brain)
response["ai_mode"] = llm_response.metadata.get("mode", "unknown")

# 3. Add health endpoint reporting provider availability
@router.get("/llm/providers/status")
async def provider_status():
    return {
        "openai": {"available": bool(os.getenv("OPENAI_API_KEY")), "model": "gpt-4"},
        "anthropic": {"available": bool(os.getenv("ANTHROPIC_API_KEY")), "model": "claude-3", "broken": True},
        "gemini": {"available": bool(os.getenv("GOOGLE_API_KEY")), "model": "gemini-pro"},
        "active_count": sum(1 for k in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"] if os.getenv(k)),
    }

# 4. Fix Anthropic — move system to top-level param
response = client.messages.create(
    model=self.model,
    system=system_message,    # ← Fix: top-level, not in messages[]
    messages=[{"role": "user", "content": prompt}],
    max_tokens=1024,
)
```

**Effort**: Medium — fix Anthropic call (5 min), add logging (15 min), surface in API (30 min), heath endpoint (30 min).

---

## 8. `datetime.utcnow()` Deprecated — 61 Files

**Impact**: `datetime.utcnow()` is deprecated since Python 3.12. Returns naive datetimes (no timezone) causing comparison bugs, ambiguous timestamps in audit logs, and eventual removal in future Python versions.

**Scope**: 61 non-venv files, ~150+ occurrences.

### Top 10 Highest-Impact Files

| # | File | Occurrences | Usage Context |
|---|------|-------------|---------------|
| 1 | `suite-api/apps/api/reports_router.py` | 11 | Report generation timestamps, date range filters |
| 2 | `suite-api/apps/api/analytics_router.py` | 8 | Metric timestamps, finding resolution times |
| 3 | `suite-api/apps/api/app.py` | 5 | JWT token expiry, status timestamps, retention |
| 4 | `suite-api/apps/api/users_router.py` | 3 | Login timestamps, JWT `iat`/`exp` claims |
| 5 | `suite-api/apps/api/demo_data.py` | 6 | Demo data time ranges |
| 6 | `suite-api/apps/api/health.py` | 3 | Health check timestamps |
| 7 | `suite-api/apps/api/mcp_router.py` | 2 | MCP server uptime calculation |
| 8 | `suite-api/apps/api/integrations_router.py` | 1 | Integration sync timestamps |
| 9 | `suite-api/apps/api/workflows_router.py` | 1 | Execution completion time |
| 10 | `suite-core/core/analytics_db.py` | 2+ | Database timestamp columns |

Additional files: `auth_db.py`, `auth_middleware.py`, `automated_remediation.py`, `bn_lr.py`, `continuous_validation.py`, `exploit_generator.py`, `integration_db.py`, `inventory_db.py`, `mpte_db.py`, `policy_db.py`, `workflow_db.py`, `user_db.py`, and ~40 more.

### Fix

```python
# Before (every occurrence)
from datetime import datetime
timestamp = datetime.utcnow()

# After
from datetime import datetime, timezone
timestamp = datetime.now(timezone.utc)
```

**Effort**: Trivial per file — mechanical find/replace. But 61 files × ~150 occurrences = ~2 hours with testing. Can be automated:

```bash
# Automated fix (verify with tests after)
find suite-* -name "*.py" -exec sed -i '' \
  's/datetime\.utcnow()/datetime.now(timezone.utc)/g' {} +
# Then add 'timezone' to imports where missing
```

---

## 9. Priority Fix Order

| Priority | Issue | Effort | Impact | Fix First? |
|----------|-------|--------|--------|------------|
| **P0** | SSRF in workflows | 1 hour | Critical — server-side request forgery | ✅ Yes |
| **P0** | Webhook auth (ServiceNow + Azure) | 1 hour | Critical — unauthenticated payload injection | ✅ Yes |
| **P1** | Wire rate limiter | 5 min | High — DoS protection | ✅ Yes |
| **P1** | TLS `verify=False` | 30 min | High — MITM on all pentest/scan traffic | ✅ Yes |
| **P1** | RBAC (fix `has_scope` + add guards) | 3 hours | High — access control | ✅ Yes |
| **P2** | In-memory → SQLite (vuln_discovery first) | 4 hours | High — data loss on restart | After P0/P1 |
| **P2** | In-memory → SQLite (copilot, inventory) | 8 hours | Medium — UX data loss | After P0/P1 |
| **P2** | Fix Anthropic LLM call | 5 min | Medium — restores 3-model consensus | After P0/P1 |
| **P2** | LLM fallback logging + health | 1 hour | Medium — visibility into degradation | After P0/P1 |
| **P3** | In-memory → SQLite (remaining 9 stores) | 16 hours | Medium — various data loss | This sprint |
| **P3** | `datetime.utcnow()` replacement | 2 hours | Low — deprecation, future breakage | This quarter |

**Total estimated effort**: ~37 hours for all hardening work.

---

*This document covers all ~280 endpoints (44% of the 640 unique) that need hardening. For the full endpoint-by-endpoint inventory, see [ROUTER_ENDPOINT_INVENTORY.md](ROUTER_ENDPOINT_INVENTORY.md). For stub/dead code endpoints, see [fake_make_it_real.md](fake_make_it_real.md).*
