"""One rule for deciding which tenant a request acts on.

The codebase grew a habit of ``effective_org = body.org_id or org_id``: take the
tenant from the request body, fall back to the credential. Two things go wrong
with it, and both were live.

**The credential becomes dead code.** 222 request models declare
``org_id: str = Field("default")``. A defaulted field is always truthy, so
``body.org_id or org_id`` *always* selects the body — the credential-derived
value can never be reached. Every SOC2 evidence pack was generated into
"default" while the org-scoped listing looked in the caller's real tenant and
found nothing. The feature appeared empty to every customer who used it.

**A client names someone else's tenant.** The body is caller-controlled, so the
same line lets an authenticated customer write into, or read from, any org they
can name — the request-body twin of the query-parameter breach recorded in
docs/SECURITY_FINDING_cross_tenant_org_id.md.

The rule here: the credential decides. A body-supplied tenant is honoured only
when the credential did not pin one, which is the deliberate operator case —
``FIXOPS_API_TOKEN`` is the platform operator credential and targeting a named
org with it is legitimate administration (migrations, support, cross-tenant
reporting). Customer credentials pin their org in ``api_key_auth`` /
``verify_api_key``, so for them the body is simply ignored.
"""

from __future__ import annotations

from typing import Any, Optional

__all__ = ["resolve_tenant"]

# The value org resolution falls back to when nothing pinned a tenant. A
# credential that resolves to this has NOT identified an org.
_UNPINNED = "default"


def resolve_tenant(credential_org: Optional[str], body: Any = None) -> str:
    """Return the org this request may act on.

    Args:
        credential_org: the value from ``Depends(get_org_id)`` — derived from
            the validated API key or JWT.
        body: the request model, which may carry a caller-supplied ``org_id``.

    The credential always wins when it pinned a real tenant. Only an unpinned
    credential (the operator token) may be directed by the body.
    """
    pinned = (credential_org or "").strip()
    if pinned and pinned != _UNPINNED:
        return pinned

    requested = (getattr(body, "org_id", None) or "").strip() if body is not None else ""
    return requested or _UNPINNED
