import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_optional_path(tmp_path):
    from scripts import graph_worker

    existing = tmp_path / "existing.json"
    existing.write_text("{}", encoding="utf-8")

    assert graph_worker._optional_path(str(existing)) == existing
    assert graph_worker._optional_path(str(tmp_path / "missing.json")) is None
    assert graph_worker._optional_path(None) is None


def test_graph_worker_main_single_cycle(monkeypatch, tmp_path):
    monkeypatch.setenv("FIXOPS_REPO", str(tmp_path))
    attestations = tmp_path / "attest"
    attestations.mkdir()
    monkeypatch.setenv("FIXOPS_ATTESTATIONS", str(attestations))

    sbom_path = tmp_path / "artifacts/sbom/normalized.json"
    sbom_path.parent.mkdir(parents=True, exist_ok=True)
    sbom_path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("FIXOPS_NORMALIZED_SBOM", str(sbom_path))

    risk_path = tmp_path / "artifacts/risk.json"
    risk_path.parent.mkdir(parents=True, exist_ok=True)
    risk_path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("FIXOPS_RISK_REPORT", str(risk_path))

    monkeypatch.setenv("FIXOPS_RELEASES", str(tmp_path / "analysis/releases.json"))
    monkeypatch.setenv("FIXOPS_GRAPH_INTERVAL", "0")

    module = importlib.reload(importlib.import_module("scripts.graph_worker"))

    calls: list[str] = []

    class DummyGraph:
        def close(self) -> None:
            calls.append("closed")

    def fake_build_graph_from_sources(sources):
        calls.append("build")
        assert isinstance(sources.repo_path, Path)
        assert sources.attestation_dir == attestations.resolve()
        return DummyGraph()

    class DummySpan:
        def __enter__(self):
            calls.append("enter")
            return self

        def __exit__(self, exc_type, exc, tb):
            calls.append("exit")
            return False

    class DummyTracer:
        def start_as_current_span(self, name):
            calls.append(name)
            return DummySpan()

    def raise_system_exit(*_args, **_kwargs):
        raise SystemExit(0)

    monkeypatch.setattr(
        module, "build_graph_from_sources", fake_build_graph_from_sources
    )
    monkeypatch.setattr(module, "_TRACER", DummyTracer())
    monkeypatch.setattr(module, "time", SimpleNamespace(sleep=raise_system_exit))

    with pytest.raises(SystemExit):
        module.main()

    assert "build" in calls
    assert "closed" in calls
    assert "graph_worker.cycle" in calls
    assert "enter" in calls
    assert "exit" in calls
