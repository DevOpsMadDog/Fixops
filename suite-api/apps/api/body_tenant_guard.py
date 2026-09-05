"""Catch a request body that names a tenant the credential did not authorise.

206 routers take the credential (``Depends(get_org_id)``) and then read
``body.org_id`` anyway. Each is individually fixable — twenty were fixed by hand
— but a codemod across the rest has broken this build three times, most recently
11 files out of 16. So the remainder gets one guard instead of 206 edits.

**What it does.** On a JSON request whose credential pins a real tenant, if the
body names a *different* tenant, act according to the mode. Nothing else is
touched.

**Why it is ASGI middleware and not BaseHTTPMiddleware.** Reading the body
requires consuming the receive channel, and whatever consumes it must put it
back or the route handler gets an empty body and hangs. Pure ASGI middleware
owns ``receive`` explicitly and can replay it; the BaseHTTPMiddleware route to
the same result is subtle and easy to get wrong.

**What it deliberately never inspects:**

* anything that is not ``application/json`` — in particular ``multipart/form-data``,
  which is how scanner output is uploaded. Buffering a scan file into memory on
  every request to look for a field it cannot contain would be a real cost for
  no benefit.
* bodies larger than ``_MAX_INSPECT_BYTES``. An org_id lives in the first few
  hundred bytes of a request; a megabyte of JSON is something else.
* requests whose credential did not pin a tenant. ``FIXOPS_API_TOKEN`` is the
  operator credential and naming an org with it is legitimate administration.

**Modes** (``FIXOPS_BODY_TENANT_GUARD``):

* ``off`` — installed but returns immediately.
* ``warn`` — log the conflict, allow the request.
* ``enforce`` — **default.** Reject with 403.

The staging was the point, and it has now run its course. ``off`` was the
default until the guard was shown to work end-to-end; ``warn`` came next so its
log could say whether honest clients send a mismatched org before anything was
refused. Both questions are answered:

* The warn log fires on a real attack. Measured against the running app —
  attacker B posting to ``/api/v1/training/completions`` with the victim's
  ``org_id`` in the body — the guard logged the conflict naming both orgs.
* Nothing honest is refused. The full smoke suite plus the tenancy suites,
  793 tests, pass **identically** under ``warn`` and ``enforce``.

The only caller that legitimately names another organisation in a body is an
unpinned operator credential, and that case returns early before any
comparison — so ``enforce`` refuses exactly the traffic that has no honest
explanation.

That warn stage was not ceremony: it is how the guard was found to be a
complete no-op for login JWTs (see ``_org_for_token``), which is the credential
the console and every logged-in user present. Enforcing before fixing that
would have shipped a control that refused managed-key callers and waved
through everyone else.

Rollback is one environment variable: ``FIXOPS_BODY_TENANT_GUARD=warn``.

Measured cost, alternating runs after warm-up, 20 KB JSON body:
**+0.060 ms/request** against a 1.058 ms baseline. Bodies over
``_MAX_INSPECT_BYTES`` and every non-JSON content type are not read at all.
"""

from __future__ import annotations

import json
import logging
import os
from collections import OrderedDict
from typing import Any, Callable

logger = logging.getLogger(__name__)

__all__ = ["BodyTenantGuard", "guard_mode"]

# An org_id sits in the first few hundred bytes. Anything larger is a payload
# we have no business buffering.
_MAX_INSPECT_BYTES = 64 * 1024

_UNPINNED = "default"


def guard_mode() -> str:
    """Resolve the mode. Default is ``enforce``; a typo still falls back to
    ``warn`` rather than ``off``, so a mistake weakens the control without
    disabling it."""
    mode = (os.environ.get("FIXOPS_BODY_TENANT_GUARD") or "enforce").strip().lower()
    return mode if mode in {"off", "warn", "enforce"} else "warn"


def _conflicting_org(body: bytes, credential_org: str) -> str | None:
    """The tenant the body asked for, when it disagrees with the credential.

    Returns None whenever there is nothing to complain about — including every
    parse failure. A malformed body is the route's problem to report, not this
    middleware's; failing the request here would turn a clear 422 into a
    confusing 403.
    """
    try:
        payload = json.loads(body)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None

    requested = payload.get("org_id")
    if not isinstance(requested, str):
        return None
    requested = requested.strip()
    if not requested or requested == credential_org:
        return None

    # A body that says "default" is not asking for another tenant — it is a
    # client that never set the field, which is the overwhelmingly common case
    # and not an attack. Treating it as a conflict would refuse honest traffic.
    if requested == _UNPINNED:
        return None
    return requested


_TOKEN_ORG_CACHE: "OrderedDict[str, str]" = OrderedDict()
_TOKEN_ORG_CACHE_MAX = 512


def _org_for_token(headers: dict) -> str:
    """The tenant a presented API key is bound to, or "" if unknowable.

    Resolved here rather than read from request state because the auth
    dependency that binds it has not run yet — see the call site.

    Returns "" on absolutely every failure. A guard that cannot identify the
    credential must fall through to its existing behaviour, never invent a
    tenant and never reject: a security control that fails closed on its own
    lookup error would take the API down on a database hiccup.
    """
    token = (headers.get("x-api-key") or "").strip()
    if not token:
        authorization = (headers.get("authorization") or "").strip()
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
    if not token:
        return ""

    if not token.startswith("fixops_"):
        # A LOGIN JWT. This branch used to `return ""`, which made the guard a
        # complete no-op for the credential nearly every real caller presents:
        # the console and every logged-in user authenticate with a JWT, and a
        # JWT never starts with "fixops_". The guard was verified with a
        # managed API key and this path was never exercised.
        #
        # Measured with the guard at its default mode ("warn") and no env
        # override — i.e. the production posture:
        #
        #   B POST /api/v1/training/completions
        #        {"user_email": "planted-by-attacker@evil.example.com",
        #         "module_id": ..., "org_id": "<victim org>"}
        #   -> 201, recorded under the VICTIM's org, and it then appeared in
        #      the victim's training stats. Zero guard log lines.
        #
        # So the one control meant to catch a body naming another tenant was
        # silent for the attack it exists to see.
        #
        # The token is VERIFIED, not merely decoded. An unverified read would
        # still be safe in the narrow sense — the guard only ever uses this to
        # REFUSE, never to grant, and a forged token is rejected by real auth
        # moments later — but verifying costs nothing here and keeps this
        # function from becoming a place where unverified claims are trusted.
        if token.count(".") != 2:
            return ""
        try:
            import jwt as _jwt

            from apps.api.auth_deps import _JWT_ALGORITHM, _load_jwt_secret

            secret = _load_jwt_secret()
            if not secret:
                return ""
            claims = _jwt.decode(token, secret, algorithms=[_JWT_ALGORITHM])
        except Exception:  # noqa: BLE001 - see the docstring: never reject here
            logger.debug("body-tenant-guard: JWT org lookup failed", exc_info=True)
            return ""
        return (claims.get("org_id") or "").strip()

    cached = _TOKEN_ORG_CACHE.get(token)
    if cached is not None:
        _TOKEN_ORG_CACHE.move_to_end(token)
        return cached

    org = ""
    try:
        from core.key_manager import KeyManager

        record = KeyManager().validate_key(token)
        if record is not None:
            org = (getattr(record, "org_id", "") or "").strip()
    except Exception:  # noqa: BLE001 - never let a lookup failure reject traffic
        logger.debug("body-tenant-guard: token org lookup failed", exc_info=True)
        return ""

    _TOKEN_ORG_CACHE[token] = org
    _TOKEN_ORG_CACHE.move_to_end(token)
    while len(_TOKEN_ORG_CACHE) > _TOKEN_ORG_CACHE_MAX:
        _TOKEN_ORG_CACHE.popitem(last=False)
    return org


class BodyTenantGuard:
    """ASGI middleware. Install last so the credential is already resolved."""

    def __init__(self, app: Callable) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> Any:
        if scope.get("type") != "http" or guard_mode() == "off":
            return await self.app(scope, receive, send)

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers") or []}
        content_type = headers.get("content-type", "")
        if not content_type.startswith("application/json"):
            return await self.app(scope, receive, send)
        try:
            if int(headers.get("content-length") or 0) > _MAX_INSPECT_BYTES:
                return await self.app(scope, receive, send)
        except ValueError:
            return await self.app(scope, receive, send)

        # Buffer the body, then hand back a receive channel that replays it.
        chunks: list[bytes] = []
        more = True
        while more:
            message = await receive()
            if message.get("type") != "http.request":
                # A disconnect mid-read: pass it straight through untouched.
                async def _passthrough(msg=message) -> dict:
                    return msg
                return await self.app(scope, _passthrough, send)
            chunks.append(message.get("body", b"") or b"")
            more = bool(message.get("more_body"))
            if sum(len(c) for c in chunks) > _MAX_INSPECT_BYTES:
                break
        body = b"".join(chunks)

        replayed = False

        async def replay() -> dict:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        # scope["state"] is a plain DICT — Request.state is only a wrapper over
        # it. getattr() on the dict returns nothing, so reading it that way makes
        # this guard a silent no-op that looks installed. Read the key.
        state = scope.get("state") or {}
        credential_org = ""
        if isinstance(state, dict):
            credential_org = (state.get("org_id") or "").strip()
        else:  # pragma: no cover — a future Starlette may hand back an object
            credential_org = (getattr(state, "org_id", None) or "").strip()

        # ...and when that is unpinned, resolve the TOKEN ourselves.
        #
        # This guard was a no-op for exactly the credential that matters, and
        # only end-to-end testing with a real key showed it. An API key's tenant
        # is bound in _verify_api_key, which is a route DEPENDENCY and therefore
        # runs AFTER all middleware. At guard time the only thing in
        # scope["state"] is whatever OrgIdMiddleware derived — and with no
        # X-Org-ID header that is "default", so the guard returned early.
        #
        # Measured against the real app with a key genuinely pinned to "acme":
        #   no X-Org-ID header   -> guard never reached the comparison
        #   X-Org-ID: acme       -> 403
        #
        # It protected the honest client who volunteers the header and was
        # silent for the attacker who omits it. Precisely backwards. So resolve
        # the credential from the token, which is present in the request and
        # cannot be spoofed into another tenant.
        if not credential_org or credential_org == _UNPINNED:
            token_org = _org_for_token(headers)
            if token_org:
                credential_org = token_org
        if not credential_org or credential_org == _UNPINNED:
            # Unpinned credential — the operator token. Naming an org with it is
            # legitimate administration, which resolve_tenant also allows.
            return await self.app(scope, replay, send)

        requested = _conflicting_org(body, credential_org)
        if requested is None:
            return await self.app(scope, replay, send)

        path = scope.get("path", "?")
        if guard_mode() == "warn":
            logger.warning(
                "body-tenant-guard: %s asked for org %r with a credential pinned to %r "
                "(allowed — mode=warn)", path, requested, credential_org,
            )
            return await self.app(scope, replay, send)

        logger.warning(
            "body-tenant-guard: REFUSED %s — body asked for org %r, credential pins %r",
            path, requested, credential_org,
        )
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({
            "type": "http.response.body",
            "body": json.dumps({
                "detail": "request body names a different organisation than the credential",
                "credential_org": credential_org,
                "requested_org": requested,
            }).encode("utf-8"),
        })
