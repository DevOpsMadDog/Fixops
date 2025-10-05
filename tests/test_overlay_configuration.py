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
    assert "ssdlc" in exported
    assert "modules" in exported
    assert "analytics" in exported
    assert "tenancy" in exported
    assert "performance" in exported
    assert exported["modules"]["guardrails"]["enabled"] is True


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
    assert config.is_module_enabled("guardrails") is True
    assert config.is_module_enabled("probabilistic") is True


def test_module_defaults_and_custom_specs() -> None:
    overlay = OverlayConfig(
        modules={
            "guardrails": {"enabled": False},
            "probabilistic": {"enabled": False},
            "custom": [
                {
                    "name": "demo",
                    "entrypoint": "tests.sample_modules:record_outcome",
                    "enabled": False,
                }
            ],
        }
    )
    assert overlay.is_module_enabled("guardrails") is False
    assert overlay.is_module_enabled("probabilistic") is False
    assert overlay.custom_module_specs[0]["name"] == "demo"
    assert overlay.enabled_modules and "custom:demo" not in overlay.enabled_modules


def test_overlay_rejects_unknown_keys(tmp_path: Path) -> None:
    path = tmp_path / "fixops.overlay.yml"
    path.write_text(json.dumps({"mode": "demo", "unknown": 1}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_overlay(path)


def test_overlay_rejects_outside_data_directory(tmp_path: Path) -> None:
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "mode": "demo",
        "data": {"evidence_dir": "/tmp/forbidden"},
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
    with pytest.raises(ValueError):
        load_overlay(path)


def test_token_strategy_requires_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "mode": "demo",
        "auth": {"strategy": "token", "token_env": "FIXOPS_API_TOKEN"},
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
    with pytest.raises(RuntimeError):
        load_overlay(path)


def test_compliance_controls_reject_unknown_fields(tmp_path: Path) -> None:
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "compliance": {
            "frameworks": [
                {
                    "name": "SOC 2",
                    "controls": [
                        {
                            "id": "CC8.1",
                            "requires": ["design"],
                            "unexpected": True,
                        }
                    ],
                }
            ]
        }
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
    with pytest.raises(ValueError):
        load_overlay(path)


def test_policy_actions_reject_unknown_fields(tmp_path: Path) -> None:
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "policy_automation": {
            "actions": [
                {
                    "trigger": "guardrail:fail",
                    "type": "jira_issue",
                    "unknown": "value",
                }
            ]
        }
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
    with pytest.raises(ValueError):
        load_overlay(path)


def test_policy_action_triggers_normalised(tmp_path: Path) -> None:
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "policy_automation": {
            "actions": [
                {
                    "trigger": "Guardrail:Fail",
                    "type": "JIRA_Issue",
                }
            ]
        }
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
    config = load_overlay(path)
    actions = config.policy_settings["actions"]
    assert actions and actions[0]["trigger"] == "guardrail:fail"
    assert actions[0]["type"] == "jira_issue"
