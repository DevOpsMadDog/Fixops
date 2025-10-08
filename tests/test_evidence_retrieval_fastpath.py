from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import asynccontextmanager
from typing import Any

import pytest

from src.db.session import DatabaseManager
from src.services.evidence_lake import EvidenceLake


class _FakeResult:
    def __init__(self, row: tuple[str, ...]) -> None:
        self._row = row

    def fetchone(self) -> tuple[str, ...]:
        return self._row


class _FakeSession:
    def __init__(self, payload: str) -> None:
        self._payload = payload

    async def execute(self, *args: Any, **kwargs: Any) -> _FakeResult:
        return _FakeResult((self._payload,))


def test_evidence_retrieval_validates_integrity(monkeypatch: pytest.MonkeyPatch) -> None:
    base_record = {
        "evidence_id": "EVD-123",
        "context": {"service": "payments"},
        "stored_timestamp": "2024-01-01T00:00:00Z",
        "evidence_lake_version": "1.1",
    }
    payload_to_hash = base_record.copy()
    payload_to_hash.pop("stored_timestamp")
    payload_to_hash.pop("evidence_lake_version")
    digest = hashlib.sha256(json.dumps(payload_to_hash, sort_keys=True).encode()).hexdigest()
    base_record["immutable_hash"] = f"SHA256:{digest}"
    fake_payload = json.dumps(base_record, sort_keys=True)

    @asynccontextmanager
    async def fake_context():
        yield _FakeSession(fake_payload)

    monkeypatch.setattr(DatabaseManager, "get_session_context", fake_context)

    record = asyncio.run(EvidenceLake.retrieve_evidence("EVD-123"))
    assert record is not None
    assert record["evidence_id"] == "EVD-123"
    assert record["signature_verified"] is False
    assert record.get("integrity_verified") is False
