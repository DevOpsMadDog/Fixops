"""CI/CD signature verification endpoint helpers.

Provides verify_signature() used by pipeline integrity checks to confirm
that evidence payloads have not been tampered with between signing and
consumption.  The function uses the configured KeyProvider from
core.utils.enterprise.crypto and is intentionally decoupled from any
FastAPI router so it can be called directly in tests.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict

from core.utils.enterprise import crypto
from fastapi import HTTPException


async def verify_signature(request: Any) -> Dict[str, Any]:
    """Verify a CI/CD pipeline evidence signature.

    Parameters
    ----------
    request:
        An object (or SimpleNamespace) with the following attributes:

        - ``evidence_id`` (str): Identifier of the evidence record.
        - ``payload`` (dict): The original evidence payload that was signed.
        - ``signature`` (str): Base64-encoded RSA-SHA256 signature.
        - ``fingerprint`` (str): Public key fingerprint used during signing.

    Returns
    -------
    dict
        ``{"verified": True, "evidence_id": <evidence_id>}`` when the
        signature is valid.

    Raises
    ------
    fastapi.HTTPException
        HTTP 400 with a detail string containing "signature" when
        verification fails.
    """

    provider = crypto._KEY_PROVIDER or crypto.get_key_provider()

    payload_bytes = json.dumps(request.payload, sort_keys=True).encode()

    try:
        sig_bytes = base64.b64decode(request.signature)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        raise HTTPException(
            status_code=400,
            detail=f"Invalid signature encoding: {exc}",
        ) from exc

    verified = provider.verify(payload_bytes, sig_bytes, request.fingerprint)

    if not verified:
        raise HTTPException(
            status_code=400,
            detail="Signature verification failed: signature does not match payload",
        )

    return {
        "verified": True,
        "evidence_id": request.evidence_id,
    }
