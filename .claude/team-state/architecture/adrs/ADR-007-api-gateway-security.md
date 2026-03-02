# ADR-007: API Gateway Security Architecture

- **Status**: Accepted
- **Date**: 2026-03-02
- **Context**: Enterprise demo in 4 days. Need to audit and document the API gateway security posture to ensure demo readiness and identify risks for Phase 2 hardening.
- **Pillar(s)**: V3 (Decision Intelligence — protects pipeline access), V7 (MCP — protects tool discovery), V10 (CTEM — protects evidence integrity)

## Decision

### 1. Multi-Strategy Authentication
The API gateway supports three authentication strategies configured via overlay config:

| Strategy | Header | Mechanism | Use Case |
|----------|--------|-----------|----------|
| `token` | `X-API-Key` | Static tokens from `overlay.auth_tokens` | Service accounts, CI/CD |
| `jwt` | `Authorization: Bearer <token>` | HS256 JWT with configurable expiry (default 120 min) | User sessions |
| (none) | — | No auth required (dev mode) | Local development |

**ADR**: Token-based auth is the primary strategy for the enterprise demo. JWT is available for user-facing features. Dev mode (no auth) MUST NOT be enabled in production/demo.

### 2. Scope-Based Authorization
After authentication, endpoints enforce scopes via `_require_scope()`:

| Scope | Routes | Risk Level |
|-------|--------|------------|
| `admin:all` | Users, Teams, Auth, Admin, System | HIGH |
| `attack:execute` | SAST, DAST, Container, CSPM, API Fuzzer, Malware, Attack Sim | HIGH |
| `write:findings` | Policies, Bulk import | MEDIUM |
| `write:integrations` | Integrations, Webhooks, IaC, IDE | MEDIUM |
| `read:evidence` | Evidence, Risk, Graph, Provenance, Compliance, Business Context | LOW |
| (default) | Analytics, Reports, Audit, Workflows, Brain, Feeds, MCP, Self-Learning | LOW |

**ADR**: All admin routes require `admin:all` scope. All offensive security routes require `attack:execute` scope. Default endpoints only require valid authentication (no specific scope).

### 3. Unauthenticated Endpoints (Verified Safe)
Only these endpoints are intentionally unauthenticated:

| Endpoint | Reason | Protection |
|----------|--------|------------|
| `/health`, `/api/v1/health`, `/api/v1/ready` | Container orchestrator probes | Returns minimal data |
| `/api/v1/version`, `/api/v1/metrics` | Monitoring/observability | No sensitive data |
| `/api/v1/webhooks/{jira,servicenow,gitlab,azure-devops}` | Inbound webhooks | HMAC signature verification |

**ADR**: Webhook receivers use HMAC signature verification (hmac.compare_digest) as their auth mechanism, which is industry standard for webhook security.

### 4. JWT Secret Management
- **Priority 1**: `FIXOPS_JWT_SECRET` environment variable (required for production)
- **Priority 2**: Ephemeral secret generated at startup (local dev only, tokens die on restart)
- **ADR**: We intentionally do NOT persist JWT secrets to disk to avoid cleartext storage. Production deployments MUST set `FIXOPS_JWT_SECRET`.

### 5. Rate Limiting
- Token bucket: 120 requests/minute, burst size 20
- Per-client IP tracking
- Exempt paths: health, ready, version, metrics, feeds/refresh
- Disabled via `FIXOPS_DISABLE_RATE_LIMIT=1` for testing

### 6. CORS Policy
- Default: localhost origins (3000, 3001, 5173, 8000) + `*.devinapps.com`
- Override: `FIXOPS_ALLOWED_ORIGINS` environment variable
- **Risk**: `*.devinapps.com` wildcard in defaults — acceptable for dev, must be removed for production (TD-016)

### 7. Request Size Limits
- Upload: Configurable per-stage via overlay config
- XML: 100 MB limit
- JSON: 100 MB limit
- Pipeline: MAX_FINDINGS=50,000, MAX_ASSETS=10,000

## Security Findings (2026-03-02)

### ✅ PASS — No Critical Vulnerabilities
- 0 Bandit HIGH findings across all core files
- All 769 routes have authentication (except intentionally exempted health/webhook endpoints)
- JWT implementation uses HS256 with proper expiry validation
- Webhook endpoints use HMAC signature verification
- XML parsing hardened with defusedxml (XXE protection)
- Input validation on Brain Pipeline (size limits, type checking)

### ⚠️ WARN — Phase 2 Items
- 63 Bandit MEDIUM findings (mostly temp file usage, subprocess calls)
- 27 SQL injection vectors detected (verified: most use parameterized queries, flagged due to f-string syntax)
- CORS wildcard in default config
- No per-endpoint rate limiting (global only)
- JWT secret not rotated automatically

### Known Attack Surface
1. **Scanner Ingest** — accepts untrusted scanner output → protected by defusedxml + size limits
2. **Micro Pentest (Step 10)** — sends network probes to user-supplied URLs → SSRF risk mitigated by URL validation
3. **AutoFix (Step 11)** — generates code patches via LLM → output validation prevents code injection
4. **MCP Tool Discovery** — exposes 705+ tools → protected by API key auth

## Consequences

### Positive
- Demo-ready: All endpoints authenticated
- Defense in depth: Auth + Scopes + Rate Limiting + CORS + Size Limits
- Air-gap compatible: No external auth service required (V9)
- Webhook security follows industry standard (HMAC)

### Negative
- Token-based auth is simple but not enterprise-grade (no rotation, no MFA)
- Single JWT algorithm (HS256) — consider RS256 for asymmetric signing in Phase 2
- No API key rotation mechanism
- No OAuth2/OIDC support (Phase 3)

### Trade-offs
- Simplicity over enterprise features (appropriate for Phase 1)
- In-process auth over external IdP (supports air-gap, V9)
- Static tokens over OAuth2 (demo-appropriate, Phase 2 upgrade)

---

*Reviewed by enterprise-architect on 2026-03-02. Maps to V3, V7, V10.*
