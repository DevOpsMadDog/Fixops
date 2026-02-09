"""Enterprise-grade evidence bundle store with database persistence.

This module provides production-ready evidence management with:
- Database persistence using SQLAlchemy
- Cryptographic signing and verification
- Integrity hash computation
- Audit trail and versioning
- Search and filtering capabilities
- Export to various formats
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Mapping, MutableMapping, Optional

from sqlalchemy import Column, DateTime, Float, Index, String, Text, select
from src.db.session import Base, DatabaseManager

logger = logging.getLogger(__name__)


def _canonicalize(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Canonicalize payload for consistent hashing."""
    return json.loads(json.dumps(payload, sort_keys=True))


def _compute_hash(data: Mapping[str, Any], algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of data."""
    canonical = json.dumps(data, sort_keys=True).encode("utf-8")
    if algorithm == "sha256":
        return hashlib.sha256(canonical).hexdigest()
    elif algorithm == "sha384":
        return hashlib.sha384(canonical).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(canonical).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


class EvidenceStatus(str, Enum):
    """Evidence record status."""

    PENDING = "pending"
    SIGNED = "signed"
    VERIFIED = "verified"
    REVOKED = "revoked"
    EXPIRED = "expired"


class EvidenceType(str, Enum):
    """Evidence type classification."""

    SCAN_RESULT = "scan_result"
    POLICY_DECISION = "policy_decision"
    COMPLIANCE_CHECK = "compliance_check"
    PENTEST_REPORT = "pentest_report"
    AUDIT_LOG = "audit_log"
    ATTESTATION = "attestation"
    SBOM = "sbom"
    VULNERABILITY = "vulnerability"
    REMEDIATION = "remediation"
    CUSTOM = "custom"


@dataclass
class EvidenceRecord:
    """Evidence record with full metadata."""

    evidence_id: str
    manifest: Mapping[str, Any]
    created_at: float = field(default_factory=time.time)
    signature: Mapping[str, Any] | None = None
    kid: str | None = None
    algorithm: str | None = None

    # Extended fields
    evidence_type: EvidenceType = EvidenceType.CUSTOM
    status: EvidenceStatus = EvidenceStatus.PENDING
    integrity_hash: str = ""
    hash_algorithm: str = "sha256"
    version: int = 1
    parent_id: str | None = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    expires_at: float | None = None

    def __post_init__(self) -> None:
        """Compute integrity hash after initialization."""
        if not self.integrity_hash:
            self.integrity_hash = _compute_hash(
                dict(self.manifest), self.hash_algorithm
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "manifest": dict(self.manifest),
            "created_at": self.created_at,
            "signature": dict(self.signature) if self.signature else None,
            "kid": self.kid,
            "algorithm": self.algorithm,
            "evidence_type": self.evidence_type.value,
            "status": self.status.value,
            "integrity_hash": self.integrity_hash,
            "hash_algorithm": self.hash_algorithm,
            "version": self.version,
            "parent_id": self.parent_id,
            "tags": self.tags,
            "metadata": self.metadata,
            "expires_at": self.expires_at,
        }

    def verify_integrity(self) -> bool:
        """Verify the integrity hash matches the manifest."""
        computed = _compute_hash(dict(self.manifest), self.hash_algorithm)
        return computed == self.integrity_hash


class EvidenceModel(Base):
    """SQLAlchemy model for evidence records."""

    __tablename__ = "evidence_records"

    evidence_id = Column(String(64), primary_key=True)
    manifest_json = Column(Text, nullable=False)
    created_at = Column(Float, nullable=False, default=time.time)
    signature_json = Column(Text, nullable=True)
    kid = Column(String(256), nullable=True)
    algorithm = Column(String(64), nullable=True)
    evidence_type = Column(String(64), nullable=False, default="custom")
    status = Column(String(32), nullable=False, default="pending")
    integrity_hash = Column(String(128), nullable=False)
    hash_algorithm = Column(String(32), nullable=False, default="sha256")
    version = Column(String(16), nullable=False, default="1")
    parent_id = Column(String(64), nullable=True)
    tags_json = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)
    expires_at = Column(Float, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("ix_evidence_type", "evidence_type"),
        Index("ix_evidence_status", "status"),
        Index("ix_evidence_created", "created_at"),
    )

    def to_record(self) -> EvidenceRecord:
        """Convert to EvidenceRecord dataclass."""
        return EvidenceRecord(
            evidence_id=self.evidence_id,
            manifest=json.loads(self.manifest_json),
            created_at=self.created_at,
            signature=json.loads(self.signature_json) if self.signature_json else None,
            kid=self.kid,
            algorithm=self.algorithm,
            evidence_type=EvidenceType(self.evidence_type),
            status=EvidenceStatus(self.status),
            integrity_hash=self.integrity_hash,
            hash_algorithm=self.hash_algorithm,
            version=int(self.version),
            parent_id=self.parent_id,
            tags=json.loads(self.tags_json) if self.tags_json else [],
            metadata=json.loads(self.metadata_json) if self.metadata_json else {},
            expires_at=self.expires_at,
        )


class EvidenceStore:
    """Enterprise-grade evidence store with database persistence.

    Features:
    - Database persistence with SQLAlchemy
    - In-memory caching for performance
    - Cryptographic signing support
    - Integrity verification
    - Search and filtering
    - Audit trail
    """

    def __init__(self, use_database: bool = True) -> None:
        """Initialize evidence store.

        Args:
            use_database: Whether to use database persistence (default: True)
        """
        self._store: MutableMapping[str, EvidenceRecord] = {}
        self._use_database = use_database
        self._audit_log: List[Dict[str, Any]] = []

    def _log_audit(
        self, action: str, evidence_id: str, details: Dict[str, Any]
    ) -> None:
        """Log an audit event."""
        self._audit_log.append(
            {
                "timestamp": time.time(),
                "action": action,
                "evidence_id": evidence_id,
                "details": details,
            }
        )
        # Keep only last 10000 audit entries
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-10000:]

    def create(
        self,
        manifest: Mapping[str, Any],
        evidence_type: EvidenceType = EvidenceType.CUSTOM,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        expires_at: Optional[float] = None,
    ) -> EvidenceRecord:
        """Create a new evidence record.

        Args:
            manifest: Evidence manifest data
            evidence_type: Type of evidence
            tags: Optional tags for categorization
            metadata: Optional additional metadata
            expires_at: Optional expiration timestamp

        Returns:
            Created evidence record
        """
        evidence_id = f"EVD-{uuid.uuid4().hex[:12].upper()}"
        canonical_manifest = _canonicalize(manifest)

        record = EvidenceRecord(
            evidence_id=evidence_id,
            manifest=canonical_manifest,
            evidence_type=evidence_type,
            tags=tags or [],
            metadata=metadata or {},
            expires_at=expires_at,
        )

        self._store[evidence_id] = record
        self._log_audit(
            "create",
            evidence_id,
            {
                "evidence_type": evidence_type.value,
                "tags": tags,
            },
        )

        logger.info(f"Created evidence record: {evidence_id}")
        return record

    async def create_async(
        self,
        manifest: Mapping[str, Any],
        evidence_type: EvidenceType = EvidenceType.CUSTOM,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        expires_at: Optional[float] = None,
    ) -> EvidenceRecord:
        """Create a new evidence record with database persistence.

        Args:
            manifest: Evidence manifest data
            evidence_type: Type of evidence
            tags: Optional tags for categorization
            metadata: Optional additional metadata
            expires_at: Optional expiration timestamp

        Returns:
            Created evidence record
        """
        record = self.create(manifest, evidence_type, tags, metadata, expires_at)

        if self._use_database:
            try:
                async with DatabaseManager.get_session_context() as session:
                    model = EvidenceModel(
                        evidence_id=record.evidence_id,
                        manifest_json=json.dumps(dict(record.manifest)),
                        created_at=record.created_at,
                        evidence_type=record.evidence_type.value,
                        status=record.status.value,
                        integrity_hash=record.integrity_hash,
                        hash_algorithm=record.hash_algorithm,
                        version=str(record.version),
                        tags_json=json.dumps(record.tags),
                        metadata_json=json.dumps(record.metadata),
                        expires_at=record.expires_at,
                    )
                    session.add(model)
                    await session.commit()
                    logger.debug(
                        f"Persisted evidence to database: {record.evidence_id}"
                    )
            except Exception as e:
                logger.warning(f"Failed to persist evidence to database: {e}")

        return record

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        """Get an evidence record by ID.

        Args:
            evidence_id: Evidence ID

        Returns:
            Evidence record or None if not found
        """
        return self._store.get(evidence_id)

    async def get_async(self, evidence_id: str) -> EvidenceRecord | None:
        """Get an evidence record by ID with database fallback.

        Args:
            evidence_id: Evidence ID

        Returns:
            Evidence record or None if not found
        """
        # Check in-memory cache first
        if evidence_id in self._store:
            return self._store[evidence_id]

        # Try database
        if self._use_database:
            try:
                async with DatabaseManager.get_session_context() as session:
                    result = await session.execute(
                        select(EvidenceModel).where(
                            EvidenceModel.evidence_id == evidence_id
                        )
                    )
                    model = result.scalar_one_or_none()
                    if model:
                        record = model.to_record()
                        self._store[evidence_id] = record  # Cache it
                        return record
            except Exception as e:
                logger.warning(f"Failed to fetch evidence from database: {e}")

        return None

    def attach_signature(
        self,
        evidence_id: str,
        signature: Mapping[str, Any],
        kid: str | None,
        algorithm: str,
    ) -> None:
        """Attach a cryptographic signature to evidence.

        Args:
            evidence_id: Evidence ID
            signature: Signature data
            kid: Key ID used for signing
            algorithm: Signing algorithm

        Raises:
            KeyError: If evidence not found
        """
        record = self._store.get(evidence_id)
        if not record:
            raise KeyError(evidence_id)

        record.signature = dict(signature)
        record.kid = kid
        record.algorithm = algorithm
        record.status = EvidenceStatus.SIGNED

        self._log_audit(
            "sign",
            evidence_id,
            {
                "kid": kid,
                "algorithm": algorithm,
            },
        )

        logger.info(f"Attached signature to evidence: {evidence_id}")

    async def attach_signature_async(
        self,
        evidence_id: str,
        signature: Mapping[str, Any],
        kid: str | None,
        algorithm: str,
    ) -> None:
        """Attach a cryptographic signature with database update.

        Args:
            evidence_id: Evidence ID
            signature: Signature data
            kid: Key ID used for signing
            algorithm: Signing algorithm
        """
        self.attach_signature(evidence_id, signature, kid, algorithm)

        if self._use_database:
            try:
                async with DatabaseManager.get_session_context() as session:
                    result = await session.execute(
                        select(EvidenceModel).where(
                            EvidenceModel.evidence_id == evidence_id
                        )
                    )
                    model = result.scalar_one_or_none()
                    if model:
                        model.signature_json = json.dumps(dict(signature))
                        model.kid = kid
                        model.algorithm = algorithm
                        model.status = EvidenceStatus.SIGNED.value
                        await session.commit()
            except Exception as e:
                logger.warning(f"Failed to update signature in database: {e}")

    def verify(self, evidence_id: str) -> Dict[str, Any]:
        """Verify evidence integrity and signature.

        Args:
            evidence_id: Evidence ID

        Returns:
            Verification result with status and details
        """
        record = self._store.get(evidence_id)
        if not record:
            return {"valid": False, "error": "Evidence not found"}

        # Check integrity
        integrity_valid = record.verify_integrity()

        # Check expiration
        expired = False
        if record.expires_at and time.time() > record.expires_at:
            expired = True

        # Check signature (basic check - full verification requires key)
        signature_present = record.signature is not None

        result = {
            "valid": integrity_valid and not expired,
            "integrity_valid": integrity_valid,
            "signature_present": signature_present,
            "expired": expired,
            "status": record.status.value,
            "evidence_id": evidence_id,
        }

        self._log_audit("verify", evidence_id, result)
        return result

    async def search(
        self,
        evidence_type: Optional[EvidenceType] = None,
        status: Optional[EvidenceStatus] = None,
        tags: Optional[List[str]] = None,
        created_after: Optional[float] = None,
        created_before: Optional[float] = None,
        limit: int = 100,
    ) -> List[EvidenceRecord]:
        """Search evidence records with filters.

        Args:
            evidence_type: Filter by evidence type
            status: Filter by status
            tags: Filter by tags (any match)
            created_after: Filter by creation time
            created_before: Filter by creation time
            limit: Maximum results to return

        Returns:
            List of matching evidence records
        """
        results: List[EvidenceRecord] = []

        # Search in-memory store
        for record in self._store.values():
            if evidence_type and record.evidence_type != evidence_type:
                continue
            if status and record.status != status:
                continue
            if tags and not any(t in record.tags for t in tags):
                continue
            if created_after and record.created_at < created_after:
                continue
            if created_before and record.created_at > created_before:
                continue

            results.append(record)
            if len(results) >= limit:
                break

        return results

    def export_bundle(
        self,
        evidence_id: str,
        format: str = "json",
        include_signature: bool = True,
    ) -> Optional[str]:
        """Export evidence as a bundle.

        Args:
            evidence_id: Evidence ID
            format: Export format (json, yaml)
            include_signature: Whether to include signature

        Returns:
            Exported bundle string or None if not found
        """
        record = self._store.get(evidence_id)
        if not record:
            return None

        bundle = record.to_dict()
        if not include_signature:
            bundle.pop("signature", None)
            bundle.pop("kid", None)
            bundle.pop("algorithm", None)

        if format == "json":
            return json.dumps(bundle, indent=2, sort_keys=True)
        elif format == "yaml":
            try:
                import yaml

                return yaml.dump(bundle, default_flow_style=False)
            except ImportError:
                return json.dumps(bundle, indent=2, sort_keys=True)
        else:
            return json.dumps(bundle, indent=2, sort_keys=True)

    def get_audit_log(
        self,
        evidence_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit log entries.

        Args:
            evidence_id: Filter by evidence ID
            limit: Maximum entries to return

        Returns:
            List of audit log entries
        """
        if evidence_id:
            entries = [e for e in self._audit_log if e["evidence_id"] == evidence_id]
        else:
            entries = self._audit_log

        return entries[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get evidence store statistics.

        Returns:
            Statistics dictionary
        """
        by_type: Dict[str, int] = {}
        by_status: Dict[str, int] = {}

        for record in self._store.values():
            by_type[record.evidence_type.value] = (
                by_type.get(record.evidence_type.value, 0) + 1
            )
            by_status[record.status.value] = by_status.get(record.status.value, 0) + 1

        return {
            "total_records": len(self._store),
            "by_type": by_type,
            "by_status": by_status,
            "audit_log_size": len(self._audit_log),
        }


# Global evidence store instance
_evidence_store: Optional[EvidenceStore] = None


def get_evidence_store() -> EvidenceStore:
    """Get the global evidence store instance."""
    global _evidence_store
    if _evidence_store is None:
        use_db = os.environ.get("FIXOPS_EVIDENCE_USE_DB", "true").lower() == "true"
        _evidence_store = EvidenceStore(use_database=use_db)
    return _evidence_store


__all__ = [
    "EvidenceRecord",
    "EvidenceStore",
    "EvidenceStatus",
    "EvidenceType",
    "EvidenceModel",
    "get_evidence_store",
]
