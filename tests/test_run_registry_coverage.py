"""Tests for RunRegistry — stage run lifecycle, directory management, artefact storage."""
from pathlib import Path


from core.services.enterprise.run_registry import (
    RunContext,
    RunRegistry,
    _resolve_root,
)


class TestResolveRoot:
    def test_default_path(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_ARTEFACTS_ROOT", raising=False)
        monkeypatch.delenv("FIXOPS_DATA_DIR", raising=False)
        root = _resolve_root()
        assert root == Path(".fixops_data") / "runs"

    def test_custom_artefacts_root(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_ARTEFACTS_ROOT", "/tmp/custom_artefacts")
        root = _resolve_root()
        assert root == Path("/tmp/custom_artefacts")

    def test_custom_data_dir(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_ARTEFACTS_ROOT", raising=False)
        monkeypatch.setenv("FIXOPS_DATA_DIR", "/tmp/fixops")
        root = _resolve_root()
        assert root == Path("/tmp/fixops") / "runs"


class TestRunContext:
    def test_create(self, tmp_path):
        ctx = RunContext(
            run_id="run-001",
            app_id="APP-123",
            stage="requirements",
            run_dir=tmp_path / "run-001",
        )
        assert ctx.run_id == "run-001"
        assert ctx.app_id == "APP-123"
        assert ctx.stage == "requirements"

    def test_run_path_alias(self, tmp_path):
        ctx = RunContext(
            run_id="run-001",
            app_id="APP-123",
            stage="design",
            run_dir=tmp_path / "run-001",
        )
        assert ctx.run_path == ctx.run_dir

    def test_inputs_dir(self, tmp_path):
        ctx = RunContext(
            run_id="run-001",
            app_id="APP-123",
            stage="build",
            run_dir=tmp_path / "run-001",
        )
        assert ctx.inputs_dir == tmp_path / "run-001" / "inputs"

    def test_outputs_dir(self, tmp_path):
        ctx = RunContext(
            run_id="run-001",
            app_id="APP-123",
            stage="test",
            run_dir=tmp_path / "run-001",
        )
        assert ctx.outputs_dir == tmp_path / "run-001" / "outputs"

    def test_signatures_dir(self, tmp_path):
        ctx = RunContext(
            run_id="run-001",
            app_id="APP-123",
            stage="deploy",
            run_dir=tmp_path / "run-001",
        )
        assert ctx.signatures_dir == tmp_path / "run-001" / "signatures"

    def test_started_at_auto_set(self, tmp_path):
        ctx = RunContext(
            run_id="run-001",
            app_id="APP-123",
            stage="requirements",
            run_dir=tmp_path / "run-001",
        )
        assert ctx.started_at is not None
        assert "T" in ctx.started_at  # ISO format


class TestRunRegistry:
    def test_init_creates_root(self, tmp_path):
        root = tmp_path / "runs"
        RunRegistry(data_dir=root)
        assert root.exists()

    def test_ensure_run_creates_dirs(self, tmp_path):
        root = tmp_path / "runs"
        registry = RunRegistry(data_dir=root)
        ctx = registry.ensure_run(app_id="APP-001", stage="requirements")
        assert isinstance(ctx, RunContext)
        assert ctx.app_id == "APP-001"
        assert ctx.run_dir.exists()

    def test_ensure_run_different_stages(self, tmp_path):
        root = tmp_path / "runs"
        registry = RunRegistry(data_dir=root)
        ctx1 = registry.ensure_run(app_id="APP-001", stage="requirements")
        ctx2 = registry.ensure_run(app_id="APP-001", stage="build")
        assert ctx1.app_id == ctx2.app_id

    def test_new_run_stages(self, tmp_path):
        root = tmp_path / "runs"
        RunRegistry(data_dir=root)
        # "requirements" and "design" should create new runs
        assert "requirements" in RunRegistry._NEW_RUN_STAGES
        assert "design" in RunRegistry._NEW_RUN_STAGES

    def test_multiple_apps(self, tmp_path):
        root = tmp_path / "runs"
        registry = RunRegistry(data_dir=root)
        ctx1 = registry.ensure_run(app_id="APP-001", stage="requirements")
        ctx2 = registry.ensure_run(app_id="APP-002", stage="requirements")
        assert ctx1.app_id != ctx2.app_id
        assert ctx1.run_dir != ctx2.run_dir
