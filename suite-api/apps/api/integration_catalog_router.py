"""What a customer can connect, and exactly what each needs.

A fresh install answers ``GET /api/v1/integrations`` with ``[]`` — correct, since that
endpoint lists integrations the org has *registered*, and a new tenant has none. But it
means the first thing a buyer sees on the Integrations screen is nothing at all, for a
product whose entire thesis is that it already speaks their tools (ADR-009). The empty
list is honest and useless at the same time.

This catalogue answers the other question: *what could I connect, and what would I need?*

It is **generated from the code that already enforces the requirement**, not from a
hand-maintained list. Each integration router declares its needs once, in the
``NotConfigured`` it raises when credentials are absent; this endpoint harvests those
same declarations. So the catalogue cannot drift from runtime behaviour — if a router
changes which variables it needs, the catalogue changes with it, and an integration that
is never wired up simply never appears.

See docs/architecture/adr/007-credential-gated-integrations.md and
docs/architecture/adr/009-ingest-first-is-the-product-thesis.md.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List

from fastapi import APIRouter, Depends

from apps.api.auth_deps import api_key_auth
from apps.api.not_configured import NotConfigured

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/integrations",
    tags=["integrations"],
    dependencies=[Depends(api_key_auth)],
)


def _discover() -> List[Dict[str, Any]]:
    """Harvest integration requirements from already-imported routers.

    Reads ``sys.modules`` rather than importing: every router is imported during app
    construction, so the information is already in memory and this costs nothing. It
    also means the catalogue reflects exactly what this process mounted.
    """
    catalogue: Dict[str, Dict[str, Any]] = {}

    for name, module in list(sys.modules.items()):
        if not name.startswith("apps.api.") or module is None:
            continue
        raiser = getattr(module, "_raise_unavailable", None)
        if not callable(raiser):
            continue
        try:
            raiser()
        except NotConfigured as exc:
            configured = all(os.getenv(var, "").strip() for var in exc.required_env)
            catalogue[exc.service] = {
                "service": exc.service,
                "configured": configured,
                "required_env": exc.required_env,
                "missing_env": [
                    var for var in exc.required_env if not os.getenv(var, "").strip()
                ],
                "docs_url": exc.docs_url,
                "router": name.rsplit(".", 1)[-1],
            }
        except Exception:  # noqa: BLE001 — a malformed router must not break the list
            logger.debug("integration catalogue: %s did not declare cleanly", name)

    return sorted(catalogue.values(), key=lambda item: item["service"])


@router.get(
    "/catalog",
    summary="Integrations available to connect, and what each requires",
)
def integration_catalog() -> Dict[str, Any]:
    """List every integration this deployment can connect, with its configuration state.

    Unlike ``GET /api/v1/integrations`` — which lists what the org has already registered
    — this describes what is *available*, so a tenant with nothing connected still sees
    the product's reach and the exact next step for each entry.
    """
    entries = _discover()
    connected = [entry for entry in entries if entry["configured"]]
    return {
        "total": len(entries),
        "configured": len(connected),
        "available": len(entries) - len(connected),
        "integrations": entries,
    }


__all__ = ["router"]
