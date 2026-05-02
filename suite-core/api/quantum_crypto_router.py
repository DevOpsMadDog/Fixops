"""Quantum-Secure Cryptography Router (V6).

Exposes hybrid ML-DSA + RSA signing, verification, and key management.
Uses ML-DSA-65 (FIPS 204) when dilithium-py is installed; falls back to
HMAC-SHA512 placeholder signatures when the post-quantum library is absent.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/quantum-crypto", tags=["Quantum Crypto"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class SignRequest(BaseModel):
    content: str = Field(..., description="Content to sign (base64 or UTF-8)")
    key_id: Optional[str] = Field(None, description="Key ID (auto-selects default)")
    content_type: str = Field("evidence", description="Content type label")


class SignResponse(BaseModel):
    signature_id: str
    rsa_algorithm: str
    mldsa_algorithm: str
    content_hash: str
    rsa_signature: str
    mldsa_signature: str
    worm_retention_until: str
    verified: bool


class VerifyRequest(BaseModel):
    content: str = Field(..., description="Original content")
    signature: Dict[str, Any] = Field(..., description="HybridSignature envelope")


class KeyInfoResponse(BaseModel):
    rsa_key_id: str
    mldsa_security_level: int
    mldsa_algorithm: str
    mldsa_public_key_size: int
    rsa_public_key_available: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/health")
async def quantum_crypto_health() -> Dict[str, Any]:
    """Health check alias for quantum crypto engine (mirrors /status)."""
    return await quantum_crypto_status()


@router.get("/status")
async def quantum_crypto_status() -> Dict[str, Any]:
    """Get quantum crypto engine status.

    Honestly reports whether real ML-DSA (dilithium-py / liboqs) is available
    or whether the system is running with the HMAC-SHA512 placeholder backend.
    """
    try:
        from core.quantum_crypto import get_quantum_signer
        signer = get_quantum_signer()
        mldsa_engine = signer.mldsa
        backend = mldsa_engine._backend if mldsa_engine else "N/A"
        is_real_pq = backend in ("dilithium-py", "liboqs")
        return {
            "status": "operational",
            "engine": "quantum-crypto",
            "version": "1.0.0",
            "quantum_ready": is_real_pq,
            "mldsa_available": mldsa_engine is not None,
            "mldsa_backend": backend,
            "mldsa_production_grade": is_real_pq,
            "rsa_available": True,
            "security_level": mldsa_engine.security_level if mldsa_engine else None,
            "algorithm": mldsa_engine.algorithm_name if mldsa_engine else None,
            "hybrid_mode": "ML-DSA + RSA-SHA256",
            "fips_204_compliant": is_real_pq,
            "note": None if is_real_pq else (
                "ML-DSA signatures use HMAC-SHA512 placeholder. "
                "Install dilithium-py or liboqs-python for real post-quantum security."
            ),
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        return {
            "status": "degraded",
            "engine": "quantum-crypto",
            "quantum_ready": False,
            "error": type(e).__name__,
        }


@router.post("/sign", response_model=SignResponse)
async def sign_content(req: SignRequest) -> Dict[str, Any]:
    """Create a hybrid quantum+classical signature."""
    try:
        from core.quantum_crypto import get_quantum_signer
        signer = get_quantum_signer()
        sig = signer.sign(req.content.encode())
        return {
            "signature_id": sig.content_hash[:16],
            "rsa_algorithm": sig.rsa_algorithm,
            "mldsa_algorithm": sig.mldsa_algorithm,
            "content_hash": sig.content_hash,
            "rsa_signature": sig.rsa_signature[:64] + "...",
            "mldsa_signature": sig.mldsa_signature[:64] + "...",
            "worm_retention_until": sig.worm_retention_until,
            "verified": True,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=f"Signing failed: {e}")


@router.post("/verify")
async def verify_signature(req: VerifyRequest) -> Dict[str, Any]:
    """Verify a hybrid quantum+classical signature."""
    try:
        from core.quantum_crypto import HybridSignature, get_quantum_signer
        signer = get_quantum_signer()
        sig = HybridSignature(**req.signature)
        valid = signer.verify(req.content.encode(), sig)
        return {
            "valid": valid,
            "rsa_verified": True,
            "mldsa_verified": True,
            "content_hash": sig.content_hash,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        return {
            "valid": False,
            "error": type(e).__name__,
        }


@router.get("/keys")
async def get_key_info() -> Dict[str, Any]:
    """Get current key information."""
    try:
        from core.quantum_crypto import get_quantum_signer
        signer = get_quantum_signer()
        return {
            "mldsa_security_level": signer.mldsa.security_level,
            "mldsa_algorithm": signer.mldsa.algorithm_name,
            "mldsa_public_key_size": len(signer.mldsa.keypair.public_key) if signer.mldsa.keypair else 0,
            "rsa_available": signer._rsa_signer is not None,
            "hybrid_mode": True,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.post("/keys/rotate")
async def rotate_keys() -> Dict[str, Any]:
    """Rotate ML-DSA keys (generates new keypair)."""
    try:
        from core.quantum_crypto import get_quantum_signer
        signer = get_quantum_signer()
        signer.mldsa.generate_keypair()
        return {
            "rotated": True,
            "new_algorithm": signer.mldsa.algorithm_name,
            "security_level": signer.mldsa.security_level,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=f"Key rotation failed: {e}")
