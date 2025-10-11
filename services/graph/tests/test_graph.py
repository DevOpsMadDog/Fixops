import json
from pathlib import Path

from services.graph.graph import ProvenanceGraph
from services.provenance.attestation import generate_attestation


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_graph_queries(tmp_path: Path) -> None:
    artefact = tmp_path / "demo-artifact.tar.gz"
    artefact.write_bytes(b"demo")

    attestation = generate_attestation(
        artefact,
        builder_id="builder://ci/demo",
        source_uri="git+https://example.com/demo.git",
        build_type="https://example.com/schema/build",
    )
    attestation.metadata["buildInvocationID"] = "job-42"

    graph = ProvenanceGraph()
    graph.ingest_commits(
        [
            {
                "sha": "abc123",
                "parents": [],
                "author": "Dev One",
                "timestamp": "2024-01-01T00:00:00Z",
                "message": "Initial",
            },
            {
                "sha": "def456",
                "parents": ["abc123"],
                "author": "Dev Two",
                "timestamp": "2024-01-02T00:00:00Z",
                "message": "Build",
            },
        ]
    )
    graph.ingest_attestations([attestation])

    normalized = {
        "metadata": {"total_components": 1},
        "components": [
            {
                "name": "pkgA",
                "version": "1.2.0",
                "purl": "pkg:pypi/pkgA@1.2.0",
                "licenses": ["MIT"],
                "hashes": {"SHA256": "a" * 64},
                "generators": ["Syft"],
                "slug": "pkg-a",
            }
        ],
    }
    normalized_path = _write_json(tmp_path / "normalized.json", normalized)
    graph.ingest_normalized_sbom(normalized_path)

    risk_report = {
        "components": [
            {
                "id": "pkgA@1.2.0",
                "slug": "pkg-a",
                "name": "pkgA",
                "version": "1.2.0",
                "purl": "pkg:pypi/pkgA@1.2.0",
                "component_risk": 88.0,
                "vulnerabilities": [
                    {
                        "cve": "CVE-2024-0001",
                        "epss": 0.9,
                        "kev": True,
                        "fixops_risk": 88.0,
                    }
                ],
            }
        ],
        "cves": {
            "CVE-2024-0001": {
                "cve": "CVE-2024-0001",
                "max_risk": 88.0,
                "components": ["pkg-a"],
            }
        },
    }
    risk_path = _write_json(tmp_path / "risk.json", risk_report)
    graph.ingest_risk_report(risk_path)

    releases = [
        {
            "tag": "v1.2.0",
            "date": "2024-01-05T00:00:00Z",
            "artifacts": [artefact.name],
            "components": [
                {"slug": "pkg-a", "name": "pkgA", "version": "1.2.0"}
            ],
        },
        {
            "tag": "v1.0.0",
            "date": "2024-02-05T00:00:00Z",
            "components": [
                {"slug": "pkg-a", "name": "pkgA", "version": "1.0.0"}
            ],
        },
    ]
    graph.ingest_releases(releases)

    lineage = graph.lineage(artefact.name)
    assert lineage["nodes"]
    assert any(edge["relation"] == "produced" for edge in lineage["edges"])

    kev_components = graph.components_with_kev(last_releases=2)
    assert kev_components
    assert any(entry["components"] for entry in kev_components)

    anomalies = graph.detect_version_anomalies()
    assert anomalies
    assert any(item["release"] == "v1.0.0" for item in anomalies)

    graph.close()
