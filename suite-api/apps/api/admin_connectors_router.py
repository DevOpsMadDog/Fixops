"""Admin Connectors Inventory Router — connector capability surface.

Provides:
    GET /api/v1/admin/connectors/inventory — enumerate all connector classes
        found under suite-core/connectors/, reporting name, module, docstring
        summary, and available public methods.

Security:
    - Requires valid API key via api_key_auth dependency.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil

from fastapi import APIRouter, Depends

from apps.api.auth_deps import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/connectors", tags=["admin"])


@router.get(
    "/inventory",
    dependencies=[Depends(api_key_auth)],
    summary="Connector inventory + capabilities",
    response_description="List of all connector classes with capabilities",
)
async def connector_inventory() -> dict:
    """Return all available connector classes and their public method surfaces.

    Walks the ``connectors`` package (suite-core/connectors/) and reflects
    every class whose name contains 'Connector', emitting:

    - **name**: class name
    - **module**: dotted module path
    - **doc**: first line of the class docstring (≤200 chars)
    - **methods**: sorted public method names (first 20)
    - **error**: import error class name if the module failed to load
    """
    out: list[dict] = []
    try:
        import connectors as connectors_pkg  # suite-core/connectors/__init__.py
    except ImportError:
        try:
            import core.connectors as connectors_pkg  # fallback path
        except ImportError:
            return {"connectors": [], "count": 0, "note": "connectors package not importable"}

    for _finder, name, _ispkg in pkgutil.iter_modules(connectors_pkg.__path__):
        try:
            mod = importlib.import_module(f"connectors.{name}")
        except Exception as exc:  # noqa: BLE001
            out.append({"module": f"connectors.{name}", "error": type(exc).__name__})
            continue

        for cname, cls in inspect.getmembers(mod, inspect.isclass):
            if cls.__module__ != mod.__name__:
                continue  # skip re-exported classes from other modules
            if "Connector" not in cname:
                continue
            raw_doc = (cls.__doc__ or "").strip()
            first_line = raw_doc.split("\n")[0][:200]
            public_methods = sorted(
                m for m in dir(cls) if not m.startswith("_") and callable(getattr(cls, m))
            )[:20]
            out.append(
                {
                    "name": cname,
                    "module": mod.__name__,
                    "doc": first_line,
                    "methods": public_methods,
                }
            )

    return {"connectors": out, "count": len(out)}
