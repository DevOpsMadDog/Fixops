# Multi-Tenant Isolation Audit — 2026-05-06

**Scope:** Read-only audit of 5 sampled API routes for org_id enforcement.
**Method:** grep + manual review of router files.
**Status:** Documentation only — no fixes applied in this pass.

---

## Summary

| Route prefix | Router file | Uses org_id | Isolation method | Risk |
|---|---|---|---|---|
| `/api/v1/analytics` | `analytics_router.py` | YES | `Depends(get_org_id)` from `org_middleware` — JWT claim → X-Org-ID header → query param | LOW |
| `/api/v1/sbom` | `sbom_router.py` | PARTIAL | `org_id: str = Query(default="default")` — caller-supplied, not enforced from JWT | MEDIUM |
| `/api/v1/connectors` | `connectors_router.py` | NO | No org_id parameter in any route; connector registry appears global | HIGH |
| `/api/v1/findings` | `findings_router.py` | NOT FOUND | File exists but no org_id/tenant references detected via grep | HIGH |
| `/api/v1/vulnerabilities` | `vulnerabilities_router.py` | NOT FOUND | File exists but no org_id/tenant references detected via grep | HIGH |

---

## Detail

### `/api/v1/analytics` — LOW risk
- Uses `Depends(get_org_id)` which resolves org_id from (1) JWT claim, (2) `X-Org-ID` header, (3) `?org_id=` query param, in that order.
- JWT-sourced org_id cannot be spoofed by the caller.
- All three dashboard endpoints (`/overview`, `/summary`, `/severity`) use this pattern consistently.
- **Action required:** None. Pattern is correct.

### `/api/v1/sbom` — MEDIUM risk
- `org_id` accepted as a plain query parameter (`Query(default="default")`).
- No enforcement that the caller's JWT `org_id` matches the supplied `org_id`.
- An authenticated user from org A could query `?org_id=org_b` and retrieve org B's SBOM assets if no secondary check exists in the engine layer.
- Engine (`SBOMEngine`) does scope queries to the supplied `org_id` column, so cross-tenant reads are gated on the value passed — but the value is user-controlled.
- **Action required:** Replace `Query(default="default")` with `Depends(get_org_id)` so JWT claim is authoritative.

### `/api/v1/connectors` — HIGH risk
- No `org_id` parameter found in any route (GET /types, GET /, POST /register, POST /test, DELETE /{name}, GET /{name}/health).
- Connector registry appears to be a single global namespace.
- An authenticated user from any org can register, list, test, or delete connectors belonging to other orgs.
- **Action required:** Add `org_id` scoping to all connector CRUD operations; migrate connector storage to per-org namespace.

### `/api/v1/findings` — HIGH risk
- `findings_router.py` is present in the router directory but grep found zero references to `org_id`, `org_name`, `get_org_id`, or `tenant`.
- Cannot confirm isolation without deeper engine-level review.
- Findings are the core security output of the platform; cross-tenant exposure here is a critical data leak vector.
- **Action required:** Full audit of findings engine and router; add `org_id` scoping; add regression test asserting org A cannot read org B findings.

### `/api/v1/vulnerabilities` — HIGH risk
- Same pattern as findings: `vulnerabilities_router.py` present, zero org_id references detected.
- Vulnerabilities likely share the same storage layer as findings; same risk applies.
- **Action required:** Full audit; add `org_id` scoping; add cross-tenant isolation test.

---

## Additional Observations

- `org_middleware.py` provides a correct, JWT-authoritative `get_org_id` dependency. Routers that use it (e.g. analytics) are properly isolated. Routers that bypass it (sbom via Query, connectors/findings/vulns with no param) are not.
- The `AuditLogger` records `org_id` on every event. Auth login/refresh endpoints added in this session use it correctly.
- `access_control_engine.py` has full `org_id` scoping on all policy/grant operations — this engine is LOW risk.

---

## Recommended Fix Priority

1. **CRITICAL (this sprint):** findings_router, vulnerabilities_router — core data exposure risk.
2. **HIGH (this sprint):** connectors_router — connector hijack / data exfil risk.
3. **MEDIUM (next sprint):** sbom_router — replace `Query` with `Depends(get_org_id)`.

*Audit performed by security-architect agent, 2026-05-06. No code changes made in this document.*
