"""Tests for the run registry service."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.services import run_registry, signing


def _prepare(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> run_registry.RunContext:
    monkeypatch.setattr(run_registry, "ARTEFACTS_ROOT", tmp_path)
    return run_registry.resolve_run("APP-1234")


def test_resolve_run_creates_expected_structure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _prepare(monkeypatch, tmp_path)
    assert ctx.app_id == "APP-1234"
    assert ctx.run_path.exists()
    assert ctx.inputs_dir.exists()
    assert ctx.outputs_dir.exists()
    assert ctx.signed_outputs_dir.exists()


def test_save_input_and_write_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _prepare(monkeypatch, tmp_path)
    raw_path = ctx.save_input("requirements-input.csv", b"feature,enabled\nfoo,true\n")
    assert raw_path.read_text() == "feature,enabled\nfoo,true\n"

    json_path = ctx.save_input("requirements.json", {"hello": "world"})
    assert json.loads(json_path.read_text())["hello"] == "world"

    output_doc = {"requirements": []}
    output_path = ctx.write_output("requirements.json", output_doc)
    assert json.loads(output_path.read_text()) == output_doc

    with pytest.raises(ValueError):
        ctx.write_output("unexpected.json", {})


def test_save_input_rejects_parent_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _prepare(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        ctx.save_input("..", b"nope")

    safe_path = ctx.save_input("../../escape.txt", b"safe")
    assert safe_path.parent == ctx.inputs_dir
    assert safe_path.name == "escape.txt"


def test_reopen_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _prepare(monkeypatch, tmp_path)
    reopened = run_registry.reopen_run(ctx.app_id, ctx.run_id)
    assert reopened.app_id == ctx.app_id
    assert reopened.run_id == ctx.run_id
    assert reopened.inputs_dir.exists()


def test_signed_outputs_create_transparency_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signing_env: None
) -> None:
    ctx = _prepare(monkeypatch, tmp_path)
    manifest = {"stage": "requirements", "items": []}
    output_path = ctx.write_output("requirements.json", manifest)
    signed_path = ctx.signed_outputs_dir / "requirements.json.manifest.json"
    assert signed_path.exists()
    envelope = json.loads(signed_path.read_text())
    assert envelope["alg"] == "RS256"
    assert signing.verify_manifest(json.loads(output_path.read_text()), envelope)
    index = ctx.transparency_index
    assert index.exists()
    contents = index.read_text().strip()
    assert "requirements.json" in contents
