# P0 — a customer API key can read and write any other tenant's data

Found 2026-08-19 while working the dead-screen queue (Q1). **RESOLVED 2026-08-19** — see
"Verification" at the end. The analysis below is kept as written when the breach was live,
because the causal chain is the reusable part.

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


---

## Verification (2026-08-19)

Fixed across `513cdc13` and the commit that follows it. Re-ran the original
reproduction against a rebuilt image, with two accounts created through the real
signup endpoint:

```
A org: org-0996b8f5-…      B org: org-27d29e37-…

A writes, no org in the URL   -> stored under org-0996b8f5-…   (was: "default")
B GETs ?org_id=<A's org>      -> 0 rows, A's data absent       (was: A's row returned)
A reads its own               -> 1 row                          (isolation did not seal the product)
```

All five layers closed:

1. `ManagedKey.org_id` exists, is persisted, and round-trips through
   `create_key` / `validate_key`, with an idempotent migration for existing
   databases.
2. The managed-key branch of `api_key_auth` pins `request.state.org_id` from the
   validated credential. The static operator token is left deliberately
   unpinned, and now says so in a comment — targeting a named tenant with
   `FIXOPS_API_TOKEN` is legitimate administration, and that exception should be
   a decision rather than an accident of fall-through.
3. `get_org_id` reads `request.state` FIRST, ahead of the contextvar — the
   middleware that seeds it runs before route dependencies, so the contextvar
   could carry client input even after auth had identified the caller.
4. 33 handlers across 7 routers converted from a bare `org_id: str` to
   `Depends(get_org_id)`, with the parameter moved last so its new default
   cannot precede a non-default one.
5. Both `create_key` call sites pass a real org: signup passes the org it
   derives, and `POST /auth/keys` passes the *caller's* org, so an admin cannot
   mint a key into someone else's tenant.

Locked by `tests/test_cross_tenant_api_key.py` (6 tests), which exercises the
whole seam with two real signups — read, write, and the `X-Org-ID` header as a
second client-supplied channel — plus a test that a tenant still reads its own
data, because sealing the breach must not seal the product.

Gates: Beast Mode smoke **768/768**; tenancy and authz suites **1511 passed, 16
skipped, exit 0**.

## Two unrelated defects found in the same file

`deduplication_router` was dead at import, and had been for some time:

* its `except ImportError:` fallback referenced `get_org_id`, a name that does
  not exist in that branch — which is the branch taken when the import fails. So
  the fallback raised `NameError` at module load and took the router down with
  it. The fallback now reads the credential-pinned org off the request and never
  client input, so degrading to it cannot widen access.
* three Pydantic request models declared `org_id: str = Depends(get_org_id)`.
  `Depends()` in a model body does not do what it appears to; more importantly a
  client-supplied tenant in a request body is the same defect as one in a query
  string. The field is gone and the handlers take the dependency instead.
