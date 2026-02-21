from __future__ import annotations

import asyncio
import io
import json
from typing import Any, Dict
from zipfile import ZipFile

import pytest
from core.services.enterprise import evidence_export
from core.services.enterprise.evidence_export import EvidenceExportService


def test_evidence_export_creates_signed_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    sample_record: Dict[str, Any] = {
        "evidence_id": "E-123",
        "decision": "ALLOW",
        "confidence_score": 0.91,
        "context_sources": ["Vector DB"],
        "stored_timestamp": "2024-05-01T12:00:00Z",
    }

    async def fake_retrieve_evidence(evidence_id: str):
        return dict(sample_record)

    monkeypatch.setattr(
        evidence_export,
        "EvidenceLake",
        type(
            "_StubLake", (), {"retrieve_evidence": staticmethod(fake_retrieve_evidence)}
        ),
    )

    async def _run() -> None:
        service = EvidenceExportService()
        archive_bytes, metadata = await service.build_bundle("E-123")

        with ZipFile(io.BytesIO(archive_bytes)) as bundle:
            names = set(bundle.namelist())
            assert {"evidence.json", "evidence.signed.json", "evidence.pdf"}.issubset(
                names
            )
            signed_payload = json.loads(bundle.read("evidence.signed.json"))
            assert signed_payload["fingerprint"] == metadata["fingerprint"]
            assert signed_payload["signature"] == metadata["signature"]

    asyncio.run(_run())
