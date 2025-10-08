from __future__ import annotations

from pathlib import Path

import pytest

from src.services import vex_ingestion
from src.services.vex_ingestion import VEXIngestor


def test_vex_ingestion_suppresses_not_affected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CycloneDX ingestion should flag `not_affected` findings as suppressed."""

    cache_dir = tmp_path / "vex"
    monkeypatch.setattr(vex_ingestion, "_VEX_CACHE", cache_dir)
    monkeypatch.setattr(VEXIngestor, "CACHE_FILE", cache_dir / "assertions.json")

    document = {
        "vulnerabilities": [
            {
                "id": "CVE-2024-0001",
                "analysis": {"state": "not_affected", "justification": "component_not_present"},
            }
        ]
    }

    result = VEXIngestor.ingest_document(document, source="cyclonedx.json")
    assert result["count"] == 1

    findings = [
        {"cve_id": "CVE-2024-0001", "severity": "medium"},
        {"cve_id": "CVE-2024-9999", "severity": "high"},
    ]

    enriched = VEXIngestor.apply_assertions(findings)
    suppressed = [finding for finding in enriched if finding.get("suppressed")]
    assert len(suppressed) == 1
    assert suppressed[0]["vex"]["status"] == "not_affected"
