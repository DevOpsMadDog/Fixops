from pathlib import Path

from pathlib import Path

import pytest

from fixops.configuration import OverlayConfig, load_overlay


@pytest.fixture
def overlay_file(tmp_path: Path) -> Path:
    path = tmp_path / "fixops.overlay.yml"
    path.write_text(
        (
            "{"\
            "\"mode\": \"enterprise\","
            "\"profiles\": {\"enterprise\": {\"toggles\": {\"require_design_input\": true}}},"
            "\"jira\": {\"project_key\": \"SEC\"},"
            "\"toggles\": {\"enforce_ticket_sync\": true}"
            "}"
        ),
        encoding="utf-8",
    )
    return path


def test_load_overlay_merges_profile_and_defaults(overlay_file: Path) -> None:
    config = load_overlay(overlay_file)
    assert isinstance(config, OverlayConfig)
    assert config.mode == "enterprise"
    assert config.toggles["require_design_input"] is True
    assert config.toggles["auto_attach_overlay_metadata"] is True
    assert config.required_inputs[0] == "design"
    exported = config.to_sanitised_dict()
    assert exported["jira"]["project_key"] == "SEC"
    assert exported["auth"] == {}


def test_environment_variable_override(monkeypatch: pytest.MonkeyPatch, overlay_file: Path) -> None:
    monkeypatch.setenv("FIXOPS_OVERLAY_PATH", str(overlay_file))
    config = load_overlay()
    assert config.metadata["source_path"] == str(overlay_file)
    monkeypatch.delenv("FIXOPS_OVERLAY_PATH", raising=False)
