"""Regression tests for EPSS/KEV enrichment in the decision engine hot path."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Dict, List

import pytest


@pytest.mark.parametrize("existing_epss", [None, 0.1])
def test_enrich_findings_populates_epss_and_kev(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_epss: float | None
) -> None:
    monkeypatch.setenv("FIXOPS_FEEDS_DIR", str(tmp_path))

    from core.services.enterprise import feeds_service

    importlib.reload(feeds_service)

    epss_snapshot = {
        "fetched_at": "2024-10-01T00:00:00Z",
        "source": "test",
        "data": {
            "data": [
                {"cve": "CVE-2024-0001", "epss": 0.92},
                {"cveID": "CVE-2024-0002", "epssScore": "0.73"},
            ]
        },
    }
    kev_snapshot = {
        "fetched_at": "2024-10-01T00:00:00Z",
        "data": {
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001", "notes": "Exploit detected"},
                {"cveID": "CVE-2024-9999", "notes": "Irrelevant"},
            ]
        },
    }

    (feeds_service.FeedsService._path("epss")).write_text(
        json.dumps(epss_snapshot), encoding="utf-8"
    )
    (feeds_service.FeedsService._path("kev")).write_text(
        json.dumps(kev_snapshot), encoding="utf-8"
    )

    base_findings: List[Dict[str, object]] = [
        {
            "cve_id": "CVE-2024-0001",
            "severity": "high",
            **({"epss_score": existing_epss} if existing_epss is not None else {}),
        },
        {"cve": "CVE-2024-0002", "severity": "medium"},
        {"id": "random", "severity": "low"},
    ]

    enriched = feeds_service.FeedsService.enrich_findings(base_findings)

    assert len(enriched) == 3
    first = enriched[0]
    assert first["kev_flag"] is True
    assert first["kev_reference"] == "CVE-2024-0001"
    assert first["kev_metadata"]["notes"] == "Exploit detected"
    if existing_epss is None:
        assert pytest.approx(first["epss_score"], rel=1e-3) == 0.92
    else:
        assert first["epss_score"] == existing_epss

    second = enriched[1]
    assert pytest.approx(second["epss_score"], rel=1e-3) == 0.73
    assert second.get("kev_flag") is None

    third = enriched[2]
    assert "epss_score" not in third
    assert "kev_flag" not in third
