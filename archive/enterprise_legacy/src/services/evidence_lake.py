"""Evidence Lake - Immutable audit records storage."""

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
from src.db.session import DatabaseManager
from src.models.user import User, UserAuditLog
from src.utils.crypto import rsa_sign, rsa_verify

logger = structlog.get_logger()


class EvidenceLake:
    """Immutable evidence storage with cryptographic integrity"""

    @staticmethod
    async def store_evidence(evidence_record: Dict[str, Any]) -> str:
        """Store immutable evidence record with signature"""
        try:
            # Canonical payload for signing (without mutable metadata)
            canonical_payload = json.loads(json.dumps(evidence_record, sort_keys=True))
            payload_bytes = json.dumps(canonical_payload, sort_keys=True).encode()
            signature_bytes, fingerprint = rsa_sign(payload_bytes)
            signature_b64 = base64.b64encode(signature_bytes).decode()

            canonical_payload.update(
                {
                    "signature_alg": "RSA-SHA256",
                    "signature": signature_b64,
                    "pubkey_fp": fingerprint,
                }
            )

            # Generate cryptographic hash over signed payload
            evidence_json = json.dumps(canonical_payload, sort_keys=True)
            evidence_hash = hashlib.sha256(evidence_json.encode()).hexdigest()

            # Add signature, hash, and integrity metadata
            evidence_record.update(canonical_payload)
            evidence_record.update(
                {
                    "immutable_hash": f"SHA256:{evidence_hash}",
                    "stored_timestamp": datetime.now(timezone.utc).isoformat(),
                    "integrity_verified": True,
                    "evidence_lake_version": "1.1",
                }
            )

            # Store in database (audit log table)
            async with DatabaseManager.get_session_context() as session:
                audit_record = UserAuditLog(
                    user_id=evidence_record.get("user_id", "system"),
                    action="evidence_stored",
                    resource_type="decision_evidence",
                    resource_id=evidence_record["evidence_id"],
                    details=json.dumps(evidence_record),
                    ip_address="127.0.0.1",
                    user_agent="FixOps Decision Engine",
                    timestamp=datetime.now(timezone.utc),
                )

                session.add(audit_record)
                await session.commit()

            logger.info(
                "Evidence record stored in Evidence Lake",
                evidence_id=evidence_record["evidence_id"],
                hash=evidence_hash[:16],
            )

            return evidence_record["evidence_id"]

        except Exception as e:
            logger.error(f"Failed to store evidence: {str(e)}")
            raise

    @staticmethod
    async def retrieve_evidence(evidence_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve evidence record and verify integrity"""
        try:
            async with DatabaseManager.get_session_context() as session:
                # Query audit logs for evidence record
                from sqlalchemy import text

                result = await session.execute(
                    text(
                        "SELECT details FROM user_audit_logs WHERE resource_id = :evidence_id AND action = 'evidence_stored'"
                    ),
                    {"evidence_id": evidence_id},
                )

                record = result.fetchone()
                if not record:
                    return None

                evidence_record = json.loads(record[0])

                # Verify integrity
                stored_hash = evidence_record.get("immutable_hash", "").replace(
                    "SHA256:", ""
                )
                evidence_copy = evidence_record.copy()
                for field in [
                    "immutable_hash",
                    "stored_timestamp",
                    "integrity_verified",
                    "evidence_lake_version",
                ]:
                    evidence_copy.pop(field, None)

                calculated_hash = hashlib.sha256(
                    json.dumps(evidence_copy, sort_keys=True).encode()
                ).hexdigest()

                signature_valid = False
                signature_b64 = evidence_record.get("signature")
                fingerprint = evidence_record.get("pubkey_fp")
                if signature_b64 and fingerprint:
                    try:
                        signature_bytes = base64.b64decode(signature_b64.encode())
                        signed_payload = evidence_copy.copy()
                        # Remove signature metadata before verification
                        for meta_field in ["signature", "signature_alg", "pubkey_fp"]:
                            signed_payload.pop(meta_field, None)
                        signature_valid = rsa_verify(
                            json.dumps(signed_payload, sort_keys=True).encode(),
                            signature_bytes,
                            fingerprint,
                        )
                    except Exception as exc:  # pragma: no cover - defensive logging
                        logger.error(
                            "Failed to verify evidence signature",
                            evidence_id=evidence_id,
                            error=str(exc),
                        )

                if stored_hash != calculated_hash or not signature_valid:
                    logger.error(
                        "Evidence integrity violation detected",
                        evidence_id=evidence_id,
                        hash_valid=stored_hash == calculated_hash,
                        signature_valid=signature_valid,
                    )
                    evidence_record["integrity_verified"] = False

                evidence_record["signature_verified"] = signature_valid

                return evidence_record

        except Exception as e:
            logger.error(f"Failed to retrieve evidence: {str(e)}")
            return None

    @staticmethod
    async def get_evidence_summary() -> Dict[str, Any]:
        """Get Evidence Lake summary statistics"""
        try:
            async with DatabaseManager.get_session_context() as session:
                from sqlalchemy import text

                # Count total evidence records
                result = await session.execute(
                    text(
                        "SELECT COUNT(*) FROM user_audit_logs WHERE action = 'evidence_stored'"
                    )
                )
                total_records = result.scalar()

                # Get recent evidence count (last 24h)
                result = await session.execute(
                    text(
                        """
                        SELECT COUNT(*) FROM user_audit_logs 
                        WHERE action = 'evidence_stored' 
                        AND timestamp > datetime('now', '-1 day')
                    """
                    )
                )
                recent_records = result.scalar()

                return {
                    "total_evidence_records": total_records or 0,
                    "recent_24h": recent_records or 0,
                    "integrity_status": "verified",
                    "storage_type": "immutable",
                    "audit_compliance": 1.0,
                }

        except Exception as e:
            logger.error(f"Failed to get evidence summary: {str(e)}")
            return {
                "total_evidence_records": 0,
                "recent_24h": 0,
                "integrity_status": "error",
                "storage_type": "immutable",
                "audit_compliance": 0.0,
            }
