import json
from pathlib import Path

import pytest

from fixops.configuration import OverlayConfig, load_overlay


@pytest.fixture
def overlay_file(tmp_path: Path) -> Path:
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "mode": "enterprise",
        "profiles": {
            "enterprise": {
                "toggles": {"require_design_input": True},
                "guardrails": {"maturity": "advanced"},
            }
        },
        "jira": {"project_key": "SEC"},
        "toggles": {"enforce_ticket_sync": True},
        "guardrails": {"maturity": "foundational"},
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
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
    assert exported["guardrails"]["maturity"] == "advanced"
    assert exported["guardrails"]["fail_on"] in {"medium", "high", "critical"}


def test_environment_variable_override(monkeypatch: pytest.MonkeyPatch, overlay_file: Path) -> None:
    monkeypatch.setenv("FIXOPS_OVERLAY_PATH", str(overlay_file))
    config = load_overlay()
    assert config.metadata["source_path"] == str(overlay_file)
    assert config.metadata["guardrail_maturity"] == "advanced"
    assert config.guardrail_policy["warn_on"] in {"medium", "high"}
    monkeypatch.delenv("FIXOPS_OVERLAY_PATH", raising=False)


def test_guardrail_defaults_when_missing() -> None:
    config = OverlayConfig()
    policy = config.guardrail_policy
    assert policy["maturity"] == "scaling"
    assert policy["fail_on"] == "high"
    assert policy["warn_on"] == "medium"
