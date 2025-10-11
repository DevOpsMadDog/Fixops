import json
from pathlib import Path

from lib4sbom.normalizer import (
    build_and_write_quality_outputs,
    build_quality_report,
    normalize_sboms,
    render_html_report,
    write_normalized_sbom,
)


def _write_sbom(tmp_path: Path, name: str, document: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _sample_sboms(tmp_path: Path) -> list[Path]:
    syft_doc = {
        "bomFormat": "CycloneDX",
        "metadata": {
            "tools": {
                "components": [
                    {"vendor": "Anchore", "name": "Syft", "version": "1.0.0"}
                ]
            }
        },
        "components": [
            {
                "name": "pkgA",
                "version": "1.0.0",
                "purl": "pkg:pypi/pkgA@1.0.0",
                "hashes": [{"alg": "SHA256", "content": "a" * 64}],
                "licenses": [{"license": {"name": "MIT"}}],
            },
            {
                "name": "pkgB",
                "version": "2.0.0",
                "purl": "pkg:pypi/pkgB@2.0.0",
                "hashes": [{"alg": "SHA1", "content": "b" * 40}],
            },
        ],
    }

    trivy_doc = {
        "bomFormat": "CycloneDX",
        "metadata": {
            "tools": {
                "components": [
                    {
                        "vendor": "Aqua Security",
                        "name": "Trivy",
                        "version": "0.43.1",
                    }
                ]
            }
        },
        "components": [
            {
                "name": "pkgA",
                "version": "1.0.0",
                "purl": "pkg:pypi/pkgA@1.0.0",
                "licenses": [{"expression": "Apache-2.0"}],
            },
            {
                "name": "pkgC",
                "version": "3.1.4",
                "hashes": [{"alg": "SHA256", "content": "c" * 64}],
            },
        ],
    }

    osv_doc = {
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {"creators": ["Tool: osv-scanner@1.2.3"]},
        "packages": [
            {
                "name": "pkgB",
                "versionInfo": "2.0.0",
                "purl": "pkg:pypi/pkgB@2.0.0",
                "licenseConcluded": "GPL-2.0-only",
                "checksums": [{"algorithm": "SHA256", "checksumValue": "b" * 64}],
            },
            {
                "name": "pkgD",
                "versionInfo": "4.5.6",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:deb/debian/pkgd@4.5.6",
                    }
                ],
                "licenseDeclared": "Apache-2.0",
            },
        ],
    }

    return [
        _write_sbom(tmp_path, "syft.json", syft_doc),
        _write_sbom(tmp_path, "trivy.json", trivy_doc),
        _write_sbom(tmp_path, "osv.json", osv_doc),
    ]


def test_normalize_sboms_merges_components(tmp_path):
    paths = _sample_sboms(tmp_path)

    normalized = normalize_sboms(paths)

    metadata = normalized["metadata"]
    assert metadata["total_components"] == 6
    assert metadata["unique_components"] == 4
    assert metadata["generator_count"] == 3

    components = normalized["components"]
    packages = {component["purl"]: component for component in components}
    assert "pkg:pypi/pkgA@1.0.0" in packages
    assert "pkg:pypi/pkgB@2.0.0" in packages

    pkg_a = packages["pkg:pypi/pkgA@1.0.0"]
    assert sorted(pkg_a["licenses"]) == ["Apache-2.0", "MIT"]
    assert any("Syft" in generator for generator in pkg_a["generators"])
    assert any("Trivy" in generator for generator in pkg_a["generators"])

    pkg_c = next(component for component in components if component["name"] == "pkgC")
    assert pkg_c["purl"] is None
    assert "SHA256" in pkg_c["hashes"]


def test_quality_report_metrics(tmp_path):
    normalized = normalize_sboms(_sample_sboms(tmp_path))

    report = build_quality_report(normalized)

    metrics = report["metrics"]
    assert metrics["coverage_percent"] == 66.67
    assert metrics["license_coverage_percent"] == 75.0
    assert metrics["resolvability_percent"] == 100.0
    assert metrics["generator_variance_score"] == 1.0


def test_render_html_report(tmp_path):
    normalized = normalize_sboms(_sample_sboms(tmp_path))
    report = build_quality_report(normalized)

    destination = tmp_path / "report.html"
    render_html_report(report, destination)

    html = destination.read_text(encoding="utf-8")
    assert "SBOM Quality Report" in html
    assert "66.67%" in html
    assert "Generator Variance" in html


def test_write_normalized_sbom(tmp_path: Path) -> None:
    paths = _sample_sboms(tmp_path)
    destination = tmp_path / "artifacts/sbom/normalized.json"
    normalized = write_normalized_sbom(paths, destination)
    assert destination.is_file()

    persisted = json.loads(destination.read_text(encoding="utf-8"))
    assert (
        persisted["metadata"]["unique_components"]
        == normalized["metadata"]["unique_components"]
    )


def test_build_and_write_quality_outputs(tmp_path: Path) -> None:
    normalized = normalize_sboms(_sample_sboms(tmp_path))
    json_destination = tmp_path / "analysis/report.json"
    html_destination = tmp_path / "reports/report.html"

    report = build_and_write_quality_outputs(
        normalized, json_destination, html_destination
    )
    assert json_destination.is_file()
    assert html_destination.is_file()

    html = html_destination.read_text(encoding="utf-8")
    assert report["metrics"]["coverage_percent"] > 0
    assert "SBOM Quality Report" in html
