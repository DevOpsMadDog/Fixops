"""GitHub App + .fixops/hooks.yaml Router — ALDECI (GAP-015 + GAP-068).

Endpoints (api_key_auth on all):
  POST /api/v1/github-app/register        — register_github_app (idempotent)
  POST /api/v1/github-app/webhook         — receive + HMAC-verify webhook
  GET  /api/v1/github-app/installations   — list installations for org_id
  POST /api/v1/hooks-yaml/parse           — parse .fixops/hooks.yaml
  POST /api/v1/hooks-yaml/apply           — parse + persist hook policy

The router mounts TWO prefixes (/github-app and /hooks-yaml) on the same
APIRouter instance by exposing two router objects — FastAPI requires one
prefix per router — so we define two: `router` (github-app) and
`router_hooks` (hooks-yaml). app.py must include both.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/github-app",
    tags=["GitHub App"],
)

router_hooks = APIRouter(
    prefix="/api/v1/hooks-yaml",
    tags=["Fixops Hooks YAML"],
)


def _get_engine():
    from core.devsecops_engine import get_devsecops_engine
    return get_devsecops_engine()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class GitHubAppRegisterRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    app_id: str = Field(..., min_length=1, max_length=128)
    installation_id: str = Field(..., min_length=1, max_length=128)
    webhook_secret: str = Field(
        ...,
        min_length=8,
        max_length=4096,
        description=(
            "Raw webhook secret. Stored hashed (SHA-256). GitHub's "
            "X-Hub-Signature-256 must be computed using this secret as the HMAC key."
        ),
    )
    app_slug: Optional[str] = Field(default="", max_length=256)


class HooksYamlParseRequest(BaseModel):
    yaml_text: str = Field(..., min_length=1, max_length=65536)


class HooksYamlApplyRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    yaml_text: str = Field(..., min_length=1, max_length=65536)


# ---------------------------------------------------------------------------
# GitHub App endpoints
# ---------------------------------------------------------------------------


@router.post("/register", dependencies=[Depends(api_key_auth)], status_code=201)
def register_github_app(body: GitHubAppRegisterRequest) -> Dict[str, Any]:
    """Register (or refresh) a GitHub App installation. Idempotent."""
    engine = _get_engine()
    try:
        secret_hash = hashlib.sha256(body.webhook_secret.encode("utf-8")).hexdigest()
        record = engine.register_github_app(
            org_id=body.org_id,
            app_id=body.app_id,
            installation_id=body.installation_id,
            webhook_secret_hash=secret_hash,
            app_slug=body.app_slug or "",
        )
        # Strip the stored hash from the response — never leak.
        safe = {k: v for k, v in record.items() if k != "webhook_secret_hash"}
        return {"status": "ok", "installation": safe}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        _logger.exception("register_github_app failed")
        raise HTTPException(status_code=500, detail=f"internal error: {exc}")


@router.post("/webhook", dependencies=[Depends(api_key_auth)])
async def receive_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_installation_id: Optional[str] = Header(default=None),
    installation_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Receive and HMAC-verify a GitHub webhook."""
    inst = x_installation_id or installation_id
    if not inst:
        raise HTTPException(status_code=400, detail="installation_id required (header or query)")
    if not x_hub_signature_256:
        raise HTTPException(status_code=400, detail="X-Hub-Signature-256 header required")

    payload_bytes = await request.body()
    engine = _get_engine()
    ok = engine.verify_webhook(
        payload_bytes=payload_bytes,
        signature_header=x_hub_signature_256,
        installation_id=inst,
    )
    if not ok:
        raise HTTPException(status_code=401, detail="webhook signature verification failed")
    return {"status": "ok", "verified": True, "installation_id": inst, "bytes": len(payload_bytes)}


@router.get("/installations", dependencies=[Depends(api_key_auth)])
def list_installations(org_id: str = Query(..., min_length=1)) -> Dict[str, Any]:
    """List GitHub App installations for an org."""
    engine = _get_engine()
    rows = engine.list_github_app_installations(org_id=org_id)
    safe_rows = [
        {k: v for k, v in r.items() if k != "webhook_secret_hash"} for r in rows
    ]
    return {"status": "ok", "org_id": org_id, "count": len(safe_rows), "installations": safe_rows}


# ---------------------------------------------------------------------------
# .fixops/hooks.yaml endpoints
# ---------------------------------------------------------------------------


@router_hooks.post("/parse", dependencies=[Depends(api_key_auth)])
def parse_hooks(body: HooksYamlParseRequest) -> Dict[str, Any]:
    """Parse and validate a .fixops/hooks.yaml document (YAML or JSON)."""
    engine = _get_engine()
    try:
        result = engine.parse_hooks_yaml(body.yaml_text)
    except Exception as exc:  # noqa: BLE001
        _logger.exception("parse_hooks failed")
        raise HTTPException(status_code=500, detail=f"parse failure: {exc}")
    return {"status": "ok", **result}


@router_hooks.post("/apply", dependencies=[Depends(api_key_auth)], status_code=201)
def apply_hooks(body: HooksYamlApplyRequest) -> Dict[str, Any]:
    """Parse a hooks.yaml, persist it if valid. Idempotent on policy hash."""
    engine = _get_engine()
    try:
        parsed = engine.parse_hooks_yaml(body.yaml_text)
    except Exception as exc:  # noqa: BLE001
        _logger.exception("apply_hooks parse failed")
        raise HTTPException(status_code=500, detail=f"parse failure: {exc}")

    if not parsed.get("valid"):
        raise HTTPException(
            status_code=400,
            detail={
                "message": "invalid hooks policy",
                "errors": parsed.get("errors", []),
                "source": parsed.get("source"),
            },
        )
    try:
        applied = engine.apply_hook_policy(body.org_id, parsed["policy"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        _logger.exception("apply_hooks persist failed")
        raise HTTPException(status_code=500, detail=f"persist failure: {exc}")
    return {"status": "ok", "applied": applied, "source": parsed.get("source")}
