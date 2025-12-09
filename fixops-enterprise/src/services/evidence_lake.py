"""Minimal evidence lake facade for integrity checks."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Optional

import structlog
from src.db.session import DatabaseManager
from src.utils.crypto import rsa_verify

logger = structlog.get_logger()


class EvidenceLake:
    """Immutable evidence retrieval with integrity verification."""

    @staticmethod
    async def retrieve_evidence(evidence_id: str) -> Optional[Dict[str, Any]]:
        """Fetch an evidence record and verify hashes/signatures."""

        try:
            async with DatabaseManager.get_session_context() as session:
                result = await session.execute(
                    "FETCH_EVIDENCE", {"evidence_id": evidence_id}
                )
                row = result.fetchone() if hasattr(result, "fetchone") else None
                if not row:
                    return None

                payload = row[0] if isinstance(row, (list, tuple)) else row
                evidence_record: Dict[str, Any] = json.loads(payload)

                stored_hash = evidence_record.get("immutable_hash", "").replace(
                    "SHA256:", ""
                )
                working_copy = dict(evidence_record)
                for field in [
                    "immutable_hash",
                    "stored_timestamp",
                    "integrity_verified",
                    "evidence_lake_version",
                ]:
                    working_copy.pop(field, None)

                calculated_hash = hashlib.sha256(
                    json.dumps(working_copy, sort_keys=True).encode()
                ).hexdigest()
                integrity_ok = stored_hash == calculated_hash

                signature_valid = False
                signature_b64 = working_copy.get("signature")
                fingerprint = working_copy.get("pubkey_fp")
                if signature_b64 and fingerprint:
                    try:
                        signature_bytes = base64.b64decode(signature_b64.encode())
                        to_verify = working_copy.copy()
                        for meta_field in ["signature", "signature_alg", "pubkey_fp"]:
                            to_verify.pop(meta_field, None)
                        signature_valid = rsa_verify(
                            json.dumps(to_verify, sort_keys=True).encode(),
                            signature_bytes,
                            fingerprint,
                        )
                    except Exception as exc:  # pragma: no cover - defensive logging
                        logger.error(
                            "Failed to verify evidence signature",
                            evidence_id=evidence_id,
                            error=str(exc),
                        )

                evidence_record["integrity_verified"] = integrity_ok
                evidence_record["signature_verified"] = signature_valid
                return evidence_record

        except Exception as exc:
            logger.error(
                "Failed to retrieve evidence",
                evidence_id=evidence_id,
                error=str(exc),
            )
            return None
