"""Periodic provenance graph builder for the demo stack."""

from __future__ import annotations

import os
import time
from pathlib import Path

from services.graph.graph import GraphSources, build_graph_from_sources
from telemetry import configure as configure_telemetry, get_tracer

configure_telemetry(service_name="fixops-graph-worker")
_TRACER = get_tracer("fixops.graph.worker")


def _optional_path(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    return path if path.exists() else None


def main() -> None:
    repo_path = Path(os.getenv("FIXOPS_REPO", ".")).resolve()
    attest_dir = Path(os.getenv("FIXOPS_ATTESTATIONS", "artifacts/attestations")).resolve()
    sbom_path = _optional_path(os.getenv("FIXOPS_NORMALIZED_SBOM", "artifacts/sbom/normalized.json"))
    risk_path = _optional_path(os.getenv("FIXOPS_RISK_REPORT", "artifacts/risk.json"))
    releases_path = _optional_path(os.getenv("FIXOPS_RELEASES", "analysis/releases.json"))
    interval = int(os.getenv("FIXOPS_GRAPH_INTERVAL", "300"))

    sources = GraphSources(
        repo_path=repo_path,
        attestation_dir=attest_dir,
        normalized_sbom=sbom_path,
        risk_report=risk_path,
        releases_path=releases_path,
    )

    while True:
        with _TRACER.start_as_current_span("graph_worker.cycle"):
            graph = build_graph_from_sources(sources)
            graph.close()
        time.sleep(max(interval, 60))


if __name__ == "__main__":
    main()
