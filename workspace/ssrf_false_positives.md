# SSRF False Positives Tracking

## SSRF-VULN-03: ServiceNow Connector instance_url SSRF

**What was attempted:**
- Checked `/api/v1/servicenow-sync/configure` endpoint → HTTP 404 (Not Found)
- Searched app.py for ServiceNow sync router mount → No references found
- Attempted `POST /api/v1/connectors/register` with `type: "servicenow"` → HTTP 422 (enum error: only jira/github/slack accepted)

**Why it's a FALSE POSITIVE (for external testing):**
The `servicenow_sync_router.py` exists in the codebase at `/repos/Fixops/suite-api/apps/api/servicenow_sync_router.py` with the vulnerable `instance_url` parameter, but the router is NOT mounted in the running FastAPI application (`app.py` has no reference to it). The vulnerable code path is unreachable from external network.

**Conclusion:** Vulnerable code exists but is not deployed/accessible. This is a FALSE POSITIVE for external exploitation purposes.

---

## SSRF-VULN-05: OIDC Cascading SSRF via Unvalidated jwks_uri

**What was attempted:**
- Checked `GET /api/v1/auth/sso/providers` → HTTP 404 (SSO configuration not found)
- Verified `FIXOPS_SSO_ENABLED` environment variable → not set in container env
- SSO router is conditionally mounted: `if sso_router: app.include_router(sso_router)` — not included because import fails or SSO_ENABLED=false
- Attempted to find API endpoint to set `issuer_url` → No such endpoint (configured via env vars only)

**Why it's a FALSE POSITIVE:**
1. SSO feature is disabled (FIXOPS_SSO_ENABLED not set → falsy)
2. The `issuer_url` can only be set via environment variables, not via API
3. The SSO callback endpoint `/api/v1/auth/sso/{provider}/callback` returns 404
4. Exploiting this requires: (a) admin:all scope to change env vars, OR (b) ability to set issuer_url via API — neither is possible from external network

**Conclusion:** Vulnerable code path is unreachable because SSO feature is disabled and issuer_url is env-var-only configuration.
