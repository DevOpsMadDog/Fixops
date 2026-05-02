"""Hooks Router — install/uninstall .fixops/hooks.yaml policies (Multica 5894d7d7).

Endpoints (api_key_auth on all):
  POST /api/v1/hooks/uninstall   — uninstall (delete) an active hook policy

This router complements the existing ``github_app_router.router_hooks``
(``/api/v1/hooks-yaml/parse``, ``/api/v1/hooks-yaml/apply``) by providing the
delete side of the lifecycle. We mount on ``/api/v1/hooks`` (matching the
Multica spec id 5894d7d7) and delegate the actual delete to the
``DevSecOpsEngine.delete_hook_policy`` API. If the engine is missing that
method we fall back to writing a tombstone via persistent_store so the rest of
the pipeline can still observe the uninstall.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/hooks",
    tags=["Fixops Hooks"],
    dependencies=[Depends(api_key_auth)],
)


class HookUninstallRequest(BaseModel):
    """Body for POST /api/v1/hooks/uninstall.

    At least one of ``hook_id``, ``policy_hash``, or ``org_id`` must be
    supplied. ``org_id`` may also be supplied via the ``X-Org-ID`` header.
    """

    hook_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Specific hook policy record id (returned by /hooks-yaml/apply).",
    )
    policy_hash: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=128,
        description="SHA-256 (or other content) hash of the policy to remove.",
    )
    org_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Org/tenant id. Required if not supplied via X-Org-ID header.",
    )
    reason: Optional[str] = Field(
        default=None,
        max_length=512,
        description="Audit reason recorded with the tombstone.",
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_table_name(name: str) -> str:
    """SQLite-safe identifier (alnum + underscore only, alpha-leading, ≤128 chars)."""
    out = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
    if not out or not (out[0].isalpha() or out[0] == "_"):
        out = "t_" + out
    return out[:128]


def _persistent_store(name: str):
    try:
        from core.persistent_store import get_persistent_store  # type: ignore
        return get_persistent_store(_safe_table_name(name))
    except Exception as exc:  # noqa: BLE001
        _logger.debug("hooks_router: persistent_store(%s) unavailable: %s", name, exc)
        return None


@router.post(
    "/uninstall",
    summary="Uninstall an active hook policy (delete by id, hash, or org)",
)
def uninstall_hook(
    body: HookUninstallRequest,
    x_org_id: Optional[str] = Header(default=None, alias="X-Org-ID"),
) -> Dict[str, Any]:
    """Delete an active hook policy and emit an audit tombstone.

    Resolution order:
      1. ``hook_id`` — exact policy record id
      2. ``policy_hash`` + org — content-addressed delete
      3. ``org_id`` alone — uninstall the *active* (most recent) policy for that org

    Returns: deleted_count, deleted record metadata, tombstone id.
    Raises 404 if nothing matches, 422 if no resolver fields supplied.
    """
    org_id = (body.org_id or x_org_id or "").strip()
    if not (body.hook_id or body.policy_hash or org_id):
        raise HTTPException(
            status_code=422,
            detail="provide at least one of hook_id, policy_hash, or org_id (header or body)",
        )

    deleted_count = 0
    deleted_record: Optional[Dict[str, Any]] = None
    engine_used = False

    try:
        from core.devsecops_engine import get_devsecops_engine  # type: ignore
        engine = get_devsecops_engine()
    except Exception as exc:  # noqa: BLE001
        _logger.warning("hooks_router: devsecops engine unavailable: %s", exc)
        engine = None

    if engine is not None:
        # Prefer engine-native delete when present
        try:
            if hasattr(engine, "delete_hook_policy"):
                engine_used = True
                res = engine.delete_hook_policy(  # type: ignore[attr-defined]
                    org_id=org_id or None,
                    hook_id=body.hook_id,
                    policy_hash=body.policy_hash,
                )
                if isinstance(res, dict):
                    deleted_count = int(res.get("deleted", 0))
                    deleted_record = res.get("record") or res.get("deleted_record")
                elif isinstance(res, int):
                    deleted_count = res
                elif isinstance(res, bool):
                    deleted_count = 1 if res else 0
            else:
                # Fallback — engine has no delete API. Use get_active_hook_policy
                # to surface what the *would-be* deletion targets are, but we
                # can't actually remove without a SQL update. Surface 501.
                if not hasattr(engine, "delete_hook_policy"):
                    raise HTTPException(
                        status_code=501,
                        detail={
                            "error": "delete_hook_policy_unavailable",
                            "hint": "DevSecOpsEngine.delete_hook_policy not present in this build",
                        },
                    )
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            _logger.exception("hooks_router: delete_hook_policy failed")
            raise HTTPException(status_code=500, detail=f"delete failure: {exc}")

    if deleted_count == 0:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "no_matching_hook_policy",
                "filters": {
                    "hook_id": body.hook_id,
                    "policy_hash": body.policy_hash,
                    "org_id": org_id or None,
                },
            },
        )

    # Audit tombstone in persistent_store (best-effort, non-blocking)
    tombstone_id = None
    try:
        store = _persistent_store(f"hook_policy_tombstones_{org_id or 'global'}")
        if store is not None:
            import uuid
            tombstone_id = f"tomb_{uuid.uuid4().hex[:12]}"
            tomb = {
                "id": tombstone_id,
                "hook_id": body.hook_id,
                "policy_hash": body.policy_hash,
                "org_id": org_id or None,
                "reason": body.reason,
                "deleted_record": deleted_record,
                "engine_used": engine_used,
                "deleted_at": _now_iso(),
            }
            # PersistentDict: dict-style write + persist; fall back to .set()
            try:
                store[tombstone_id] = tomb
                if hasattr(store, "persist"):
                    store.persist(tombstone_id)
            except (TypeError, AttributeError):
                if hasattr(store, "set"):
                    store.set(tombstone_id, tomb)
    except Exception as exc:  # noqa: BLE001
        _logger.debug("hooks_router: tombstone persist failed: %s", exc)

    return {
        "status": "ok",
        "deleted": deleted_count,
        "deleted_record": deleted_record,
        "tombstone_id": tombstone_id,
        "engine_used": engine_used,
        "uninstalled_at": _now_iso(),
    }
