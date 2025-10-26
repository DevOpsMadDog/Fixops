"""In-memory evidence bundle store used for CI integrations."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, MutableMapping


def _canonicalize(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    return json.loads(json.dumps(payload, sort_keys=True))


@dataclass
class EvidenceRecord:
    evidence_id: str
    manifest: Mapping[str, Any]
    created_at: float = field(default_factory=time.time)
    signature: Mapping[str, Any] | None = None
    kid: str | None = None
    algorithm: str | None = None


class EvidenceStore:
    """Simple in-memory evidence registry."""

    def __init__(self) -> None:
        self._store: MutableMapping[str, EvidenceRecord] = {}

    def create(self, manifest: Mapping[str, Any]) -> EvidenceRecord:
        evidence_id = f"EVD-{uuid.uuid4().hex[:12].upper()}"
        record = EvidenceRecord(
            evidence_id=evidence_id, manifest=_canonicalize(manifest)
        )
        self._store[evidence_id] = record
        return record

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        return self._store.get(evidence_id)

    def attach_signature(
        self,
        evidence_id: str,
        signature: Mapping[str, Any],
        kid: str | None,
        algorithm: str,
    ) -> None:
        record = self._store.get(evidence_id)
        if not record:
            raise KeyError(evidence_id)
        record.signature = signature
        record.kid = kid
        record.algorithm = algorithm
