"""Webhook Verifier Router — incoming webhook signature verification endpoints.

4 endpoints at /api/v1/webhooks/verify/*:
    POST   /api/v1/webhooks/verify/                 -- auto-detect provider and verify
    POST   /api/v1/webhooks/verify/{provider}       -- verify against a specific provider
    GET    /api/v1/webhooks/verify/stats            -- pass/fail rates per provider (org-scoped)
    POST   /api/v1/webhooks/verify/detect           -- detect provider from headers (dry-run)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.dependencies import get_org_id
from core.webhook_verifier import VerificationResult, WebhookProvider, WebhookVerifier
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks/verify", tags=["webhook-verifier"])

_verifier = WebhookVerifier()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class VerifyRequest(BaseModel):
    """Payload for manual (non-auto-detect) verification requests."""

    payload: str = Field(..., description="Raw webhook payload (UTF-8 string or hex-encoded bytes)")
    signature: str = Field(..., description="Signature header value sent by the provider")
    secret: str = Field(..., description="Shared secret configured for this integration")
    # Provider-specific optional fields
    timestamp: Optional[str] = Field(
        default=None,
        description="Timestamp header value (required for Slack / Stripe)",
    )
    algorithm: Optional[str] = Field(
        default="sha256",
        description="HMAC algorithm for CUSTOM provider (sha256, sha1, sha512, md5)",
    )
    ip_address: Optional[str] = Field(default=None, description="Source IP for audit log")


class DetectRequest(BaseModel):
    """Headers sent to the detect endpoint for provider identification."""

    headers: Dict[str, str] = Field(..., description="HTTP headers from the incoming webhook")


def _result_to_dict(result: VerificationResult) -> Dict[str, Any]:
    data = result.model_dump()
    if data.get("timestamp") is not None:
        ts = data["timestamp"]
        data["timestamp"] = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
    return data


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/")
async def auto_verify(
    request: Request,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Auto-detect the webhook provider from request headers and verify the signature.

    Reads the raw request body and all headers.  The ``X-Webhook-Secret-<Provider>``
    header (e.g. ``X-Webhook-Secret-Github``) is used to pass the shared secret
    without exposing it in the JSON body.  Alternatively, callers can supply secrets
    via the ``X-Webhook-Secrets`` JSON header: ``{"github": "s3cr3t"}``.

    Returns a VerificationResult JSON object.
    """
    import json as _json

    raw_payload: bytes = await request.body()
    headers: Dict[str, str] = dict(request.headers)

    # Resolve secrets: try X-Webhook-Secrets JSON header first, then
    # individual X-Webhook-Secret-<Provider> headers.
    secrets: Dict[str, str] = {}
    raw_secrets_hdr = headers.get("x-webhook-secrets") or headers.get("X-Webhook-Secrets")
    if raw_secrets_hdr:
        try:
            secrets = _json.loads(raw_secrets_hdr)
        except Exception:
            raise HTTPException(400, "X-Webhook-Secrets header must be valid JSON")
    else:
        for provider in WebhookProvider:
            key = f"x-webhook-secret-{provider.value}"
            if key in {k.lower() for k in headers}:
                # Case-insensitive lookup
                for hk, hv in headers.items():
                    if hk.lower() == key:
                        secrets[provider.value] = hv
                        break

    client = request.client
    ip_address = client.host if client else None

    result = _verifier.verify(headers=headers, payload=raw_payload, secrets=secrets, ip_address=ip_address)
    _verifier.log_verification(result, org_id=org_id)

    if not result.valid:
        # Return 401 with the result body so callers can inspect the error
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content=_result_to_dict(result))

    return _result_to_dict(result)


# NOTE: /stats and /detect MUST be defined before /{provider} so FastAPI
# resolves them as literal paths rather than capturing them as the {provider}
# path parameter.

@router.get("/stats")
async def verification_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return webhook verification pass/fail rates per provider for the current org."""
    try:
        return _verifier.get_verification_stats(org_id=org_id)
    except RuntimeError as exc:
        logger.error("get_verification_stats failed: %s", exc)
        raise HTTPException(500, "Failed to retrieve verification stats") from exc


@router.post("/detect")
async def detect_provider(
    req: DetectRequest,
    org_id: str = Depends(get_org_id),  # noqa: ARG001
) -> Dict[str, Any]:
    """Detect the webhook provider from a set of HTTP headers (dry-run, no verification).

    Returns ``{"provider": "<name>"}`` or ``{"provider": null}`` if unrecognised.
    """
    provider = _verifier.auto_detect_provider(req.headers)
    return {
        "provider": provider.value if provider else None,
        "detected": provider is not None,
    }


@router.post("/{provider}")
async def verify_provider(
    provider: str,
    req: VerifyRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Verify a webhook against a specific named provider.

    ``provider`` must be one of: github, gitlab, jira, servicenow, slack,
    pagerduty, stripe, custom.
    """
    try:
        prov = WebhookProvider(provider.lower())
    except ValueError:
        valid = [p.value for p in WebhookProvider]
        raise HTTPException(422, f"Unknown provider '{provider}'. Valid: {valid}")

    raw_payload = req.payload.encode("utf-8")
    ip = req.ip_address

    if prov == WebhookProvider.GITHUB:
        result = _verifier.verify_github(raw_payload, req.signature, req.secret, ip)

    elif prov == WebhookProvider.GITLAB:
        result = _verifier.verify_gitlab(raw_payload, req.signature, req.secret, ip)

    elif prov == WebhookProvider.JIRA:
        result = _verifier.verify_jira(raw_payload, req.signature, req.secret, ip)

    elif prov == WebhookProvider.SLACK:
        if not req.timestamp:
            raise HTTPException(422, "Slack verification requires 'timestamp' field")
        result = _verifier.verify_slack(raw_payload, req.signature, req.timestamp, req.secret, ip)

    elif prov == WebhookProvider.PAGERDUTY:
        result = _verifier.verify_pagerduty(raw_payload, req.signature, req.secret, ip)

    elif prov == WebhookProvider.STRIPE:
        if not req.timestamp:
            raise HTTPException(422, "Stripe verification requires 'timestamp' field")
        # Re-build the Stripe-Signature header from components
        stripe_sig = f"t={req.timestamp},v1={req.signature}"
        result = _verifier.verify_stripe(raw_payload, stripe_sig, req.secret, ip)

    elif prov == WebhookProvider.SERVICENOW:
        result = _verifier.verify_custom(
            raw_payload, req.signature, req.secret, req.algorithm or "sha256", ip
        )
        result = VerificationResult(
            valid=result.valid,
            provider=WebhookProvider.SERVICENOW,
            timestamp=result.timestamp,
            ip_address=result.ip_address,
            error=result.error,
        )

    else:  # CUSTOM
        result = _verifier.verify_custom(
            raw_payload, req.signature, req.secret, req.algorithm or "sha256", ip
        )

    _verifier.log_verification(result, org_id=org_id)

    if not result.valid:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content=_result_to_dict(result))

    return _result_to_dict(result)
