import json
from pathlib import Path

import pytest

from cli import fixops_risk
from risk.feeds.epss import load_epss_scores
from risk.feeds.kev import load_kev_catalog
from risk.scoring import compute_risk_profile


@pytest.fixture()
def sample_feeds(tmp_path: Path) -> tuple[Path, Path]:
    epss_path = tmp_path / "epss.csv"
    epss_path.write_text(
        "cve,epss\nCVE-2024-0001,0.8\nCVE-2024-0003,0.1\n",
        encoding="utf-8",
    )
    kev_path = tmp_path / "kev.json"
    kev_payload = {
        "data": {
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001"},
                {"cveID": "CVE-2024-9999"},
            ]
        }
    }
    kev_path.write_text(json.dumps(kev_payload), encoding="utf-8")
    return epss_path, kev_path


@pytest.fixture()
def sample_normalized(tmp_path: Path) -> Path:
    normalized = {
        "components": [
            {
                "name": "pkgA",
                "version": "1.0.0",
                "purl": "pkg:pypi/pkgA@1.0.0",
                "exposure_flags": ["internet"],
                "vulnerabilities": [
                    {
                        "cve": "CVE-2024-0001",
                        "version_lag_days": 90,
                        "exposure": "internet",
                    },
                    {
                        "cve": "CVE-2024-0002",
                        "version_lag_days": 45,
                        "exposure_flags": ["partner"],
                    },
                ],
            },
            {
                "name": "pkgB",
                "version": "2.0.0",
                "purl": None,
                "exposure": "internal",
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-0003",
                        "version_lag_days": 30,
                        "exposure_flags": ["internal"],
                    }
                ],
            },
        ]
    }
    path = tmp_path / "normalized.json"
    path.write_text(json.dumps(normalized), encoding="utf-8")
    return path


def test_feed_loaders(sample_feeds: tuple[Path, Path]):
    epss_path, kev_path = sample_feeds
    scores = load_epss_scores(path=epss_path)
    assert scores == {"CVE-2024-0001": 0.8, "CVE-2024-0003": 0.1}

    kev = load_kev_catalog(path=kev_path)
    assert set(kev) == {"CVE-2024-0001", "CVE-2024-9999"}


def test_compute_risk_profile(sample_feeds: tuple[Path, Path], sample_normalized: Path):
    epss_path, kev_path = sample_feeds
    scores = load_epss_scores(path=epss_path)
    kev = load_kev_catalog(path=kev_path)

    with sample_normalized.open("r", encoding="utf-8") as handle:
        normalized = json.load(handle)

    report = compute_risk_profile(normalized, scores, kev)
    assert report["summary"]["component_count"] == 2
    assert report["summary"]["cve_count"] == 3

    component_index = {entry["slug"]: entry for entry in report["components"]}
    pkga = component_index["pkg-pypi-pkga-1.0.0"]
    assert pkga["component_risk"] == pytest.approx(80.0, rel=1e-2)

    cve_index = report["cves"]
    assert cve_index["CVE-2024-0001"]["max_risk"] == pytest.approx(80.0, rel=1e-2)
    assert sorted(cve_index["CVE-2024-0001"]["components"]) == ["pkg-pypi-pkga-1.0.0"]


def test_cli_score(tmp_path: Path, sample_feeds: tuple[Path, Path], sample_normalized: Path):
    epss_path, kev_path = sample_feeds
    output_path = tmp_path / "risk.json"

    exit_code = fixops_risk.main(
        [
            "score",
            "--sbom",
            str(sample_normalized),
            "--out",
            str(output_path),
            "--epss",
            str(epss_path),
            "--kev",
            str(kev_path),
        ]
    )
    assert exit_code == 0
    assert output_path.is_file()

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["summary"]["component_count"] == 2
