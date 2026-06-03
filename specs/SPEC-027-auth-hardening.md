# SPEC-027 — Auth Hardening: every /api/v1 endpoint requires authentication

- **Status**: IMPLEMENTED
- **Owner family**: Platform / Auth / Red-Team
- **Routers**: cross-cutting — all `/api/v1/*` routers (enforced via router-level `dependencies=[Depends(api_key_auth)]`); the global `RateLimitMiddleware` + `OrgTierRateLimitMiddleware` also apply.
- **Engines**: `apps/api/auth_deps.py` (`api_key_auth`, request-based enforcer)
- **Stores**: n/a (token validation)
- **Depends on**: SPEC-014 (auth/tenancy), SPEC-005 (air-gap); env `FIXOPS_API_TOKEN`
- **Last updated**: 2026-06-03
- **Multica**: #9082 (this spec), #9076 (the epic)

## 1. Intent (the why)
For a SCIF/on-prem product, an `/api/v1` endpoint that returns data or performs an action to an
UNAUTHENTICATED caller is an ATO/procurement blocker. This spec governs the invariant: **every
`/api/v1` endpoint requires `X-API-Key` (401/403 without it)** except a small, documented set of
intentionally-public endpoints. It backfills governance over the 2026-06-03 auth-hardening epic
(24 router/surface fixes found by systematic no-key probing — see #9076) and locks the invariant
behind a CI regression gate so it cannot silently regress.

## 2. Scope — the invariant + the allowlist
**Invariant:** for every mounted `/api/v1/<path>` (GET / POST / PUT / DELETE / PATCH), a request
with **no `X-API-Key`** returns **401 or 403** before the handler runs.

**Allowlist (intentionally public, verified 2026-06-03):**
| Endpoint(s) | Why public |
|-------------|-----------|
| `POST /api/v1/oauth2/token` | issues tokens (called to obtain a key) |
| `/api/v1/auth/*`, `/api/v1/users/login` | pre-authentication flow |
| `/api/v1/slack/*`, inbound provider webhooks (`/webhooks/{github,gitlab,jira,azure-devops,servicenow,okta}`, `/billing/(stripe-)?webhook`, `/servicenow-sync/webhooks`) | authenticated by provider **signature**, not API key |
| `/api/v1/trust/{public,compliance,sub-processors,practices,documents,faq,request,nda,dpa}` + `/trust/{org_id}/public` | trust-center public page (by design) |
| `*/health`, `/metrics`, `/version`, `/openapi.json`, `/docs`, `/redoc`, `/api/v1/system/git-sha` | ops/version/schema probes |
| `/api/v1/scif/{boot,audit-chain/verify,hsm/*}` | SCIF ops-posture (metadata only) — **FOUNDER-DECISION pending: gate or keep public** |

Out of scope: authorization/RBAC depth (SPEC-014); rate-limit tuning; the scif-posture
gate decision (recorded, founder-owned).

## 3. Data contracts
```
GET|POST|PUT|DELETE /api/v1/<non-allowlisted> with NO X-API-Key  → 401 (or 403)
                                              with valid X-API-Key → 200/422/... (handler runs)
```

## 4. Functional requirements
- **REQ-027-01**: Routers enforce auth at the **router level** (`dependencies=[Depends(api_key_auth)]`)
  so all methods + path-param endpoints are covered, not per-endpoint-only (which leaves gaps).
- **REQ-027-02**: `api_key_auth` is the real request-based enforcer — never a placeholder that
  returns `True`, and never a no-op fallback (fail **closed** if the import fails).
- **REQ-027-03**: Webhook **receiver** endpoints may be API-key-exempt only when they verify a
  provider signature; webhook **management** endpoints (mappings/outbox/…) require api_key.
- **REQ-027-04**: The invariant is enforced by a CI regression gate, not manual review.

## 5. Non-functional requirements
- Failure mode: missing key → 401 fast (before handler); no data/side-effects on a no-key request.
- No regression: with a valid key, behaviour is unchanged (the real UI sends `X-API-Key`).

## 6. Acceptance criteria (executable, verified 2026-06-03)
- **AC-027-01**: `tests/test_no_unauthenticated_endpoints.py::test_no_unauthenticated_api_v1_endpoints`
  passes — every no-path-param `/api/v1` endpoint (4975) returns 401/403/404/405 no-key, except allowlist.
- **AC-027-02**: `…::test_no_unauthenticated_path_param_endpoints` passes — 1101 path-param routes,
  no 200/422/500 to a no-key caller.
- **AC-027-03**: the gate is wired into `.github/workflows/regression-gates.yml` (owasp-lockdown job,
  "No unauthenticated /api/v1 endpoints" step).
- **AC-027-04**: this spec is registered in `specs/INDEX.md`.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-03 | Backfill-author | Retro-spec of the 24-fix auth epic (#9076) per founder governance rule (every surface spec-governed). The exhaustive no-key probe + CI gate ARE the executable enforcement; this spec records the invariant + allowlist rationale. |

## 8. Implementation notes
The 24 fixes + the guard were shipped 2026-06-03 (commits `0e23ebf0`, `dce3fa88`, `fe2ea077`,
`737e8d8c`, `6aa69b1d`, `1d3b74a8`, `55c1067d`, `a5b64888`). Three root causes were addressed:
missing router-level dep; a placeholder `api_key_auth(): return True`; and a circular-import
NO-OP fallback (made fail-closed). One boot-crash (UnboundLocalError from referencing a
create_app local in a decorator) was caught + fixed mid-flight. No code change in this spec —
governance backfill only.
