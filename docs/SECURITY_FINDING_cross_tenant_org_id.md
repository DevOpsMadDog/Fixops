# P0 — a customer API key can read and write any other tenant's data

Found 2026-08-19 while working the dead-screen queue (Q1). **Proven exploitable, not yet fixed.**

## What was demonstrated

A key minted by real self-service signup, scoped to its own org, read another
tenant's data by naming that tenant in a query string:

```
POST /api/v1/identity-governance/entitlements?org_id=acme-secret   (write)
GET  /api/v1/identity-governance/entitlements?org_id=acme-secret   (read)
     -H "X-API-Key: fixops_…"        # a DIFFERENT tenant's customer key
  -> [{"org_id":"acme-secret","identity_id":"user-1", …}]
```

The credential's own org is never consulted. This is a cross-tenant read **and**
write, reachable by any authenticated customer. It is disqualifying for a
multi-tenant or SCIF sale.

## Why — four layers, each hiding the one below

1. **`ManagedKey` has no `org_id` field.** `_mint_signup_api_key` documents the
   key as "org-scoped (key name encodes org_id)" — the org is a substring of the
   human-readable display name, not a column. An API key therefore cannot be
   tenant-scoped, no matter what the caller does.

2. **The managed-key auth branch never binds an org.** `auth_deps.api_key_auth`
   sets `request.state.user_role`, `user_scopes` and `user_id`, then returns.
   Only the JWT branch sets `request.state.org_id`.

3. **So org resolution falls through to client input.** `_extract_org_id`'s
   precedence is correct on paper — state, then `X-Org-ID`, then `?org_id=`, then
   "default" — but with step 2 never populating state, every API-key request
   lands on the client-controlled header or query param.

4. **35 handlers across 8 files skip the dependency entirely**, declaring a bare
   `org_id: str`, which FastAPI exposes as a plain query parameter:
   compliance_scanner (13), identity_governance (12), openclaw (3),
   trust_center (3), deduplication (2), collaboration (1), remediation (1).

There is a fifth, separate ordering hazard: `OrgIdMiddleware` resolves the
contextvar during middleware dispatch, which runs *before* route dependencies —
so the contextvar can be seeded from client input even once step 2 is fixed.
`get_org_id` returns that contextvar whenever it is not "default".

## The fix, in order

1. `ManagedKey.org_id` + an `org_id` column on `managed_keys` (idempotent
   migration, matching the `users`/`teams` pattern); `create_key` persists it and
   `validate_key` returns it.
2. `auth_deps` managed-key branch: `request.state.org_id = managed_record.org_id`.
3. `get_org_id`: prefer `request.state.org_id` over the contextvar, because auth
   runs after the middleware that seeds it.
4. Replace all 35 bare `org_id: str` params with `Depends(get_org_id)`.
5. A regression test that mints two real customer keys and asserts neither can
   name the other's org — the same test shape as `test_user_org_isolation.py`.

Static-operator-token behaviour is a deliberate decision to make explicitly:
`FIXOPS_API_TOKEN` is the platform operator credential, and targeting a named org
with it is legitimate administration. That should be stated in code, not left as
an accident of the fall-through.

## Related

Same root cause family as the `users.org_id` defect fixed in `10d9eecc`: an org
is derived, promised to the caller, and then never persisted anywhere the
enforcement path can read it.
