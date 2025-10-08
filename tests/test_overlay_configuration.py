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
    assert exported["signing"]["provider"] == "env"
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


def test_policy_engine_overlay_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "policy_engine": {
            "opa": {
                "enabled": False,
                "url": "https://opa.example.com",
                "policy_package": "fixops.security",
                "health_path": "/healthz",
                "bundle_status_path": "/bundles/status",
                "auth_token_env": "OPA_TOKEN",
                "request_timeout_seconds": 12,
            }
        }
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
    config = load_overlay(path)
    opa_config = config.policy_engine.get("opa")
    assert opa_config is not None
    assert opa_config["enabled"] is False
    assert opa_config["url"] == "https://opa.example.com"
    exported = config.to_sanitised_dict()["policy_engine"]["opa"]
    assert exported["auth_token_env"] == "OPA_TOKEN"


def test_overlay_toggles_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "toggles": {
            "enable_rl_experiments": True,
            "enable_shap_experiments": True,
            "signing_provider": "aws_kms",
            "opa_server_url": "https://opa.internal:8181",
        },
        "signing": {"provider": "aws_kms", "key_id": "alias/app"},
        "policy_engine": {"opa": {"enabled": True, "url": "https://opa.internal:8181"}},
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
    config = load_overlay(path)

    assert config.toggles["enable_rl_experiments"] is True
    assert config.toggles["enable_shap_experiments"] is True
    assert config.toggles["signing_provider"] == "aws_kms"
    assert config.toggles["opa_server_url"] == "https://opa.internal:8181"

    exported = config.to_sanitised_dict()
    opa_export = exported["policy_engine"]["opa"]
    assert exported["toggles"]["signing_provider"] == "aws_kms"
    assert exported["toggles"]["opa_server_url"] == "https://opa.internal:8181"
    assert exported["signing"]["provider"] == "aws_kms"
    assert opa_export["url"] == "https://opa.internal:8181"


def test_policy_engine_rejects_invalid_timeout(tmp_path: Path) -> None:
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "policy_engine": {
            "opa": {
                "url": "https://opa.example.com",
                "request_timeout_seconds": 0,
            }
        }
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
    with pytest.raises(ValueError):
        load_overlay(path)


def test_policy_engine_rejects_unknown_fields(tmp_path: Path) -> None:
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "policy_engine": {
            "opa": {
                "url": "https://opa.example.com",
                "unexpected": True,
            },
            "other": {},
        }
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
    with pytest.raises(ValueError):
        load_overlay(path)


def test_signing_configuration_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "fixops.overlay.yml"
    overlay_content = {
        "signing": {
            "provider": "aws_kms",
            "key_id": "alias/decision",
            "aws_region": "us-west-2",
            "rotation_sla_days": 14,
        }
    }
    path.write_text(json.dumps(overlay_content), encoding="utf-8")
    config = load_overlay(path)
    assert config.signing["provider"] == "aws_kms"
    assert config.signing["key_id"] == "alias/decision"
    assert config.signing["aws_region"] == "us-west-2"
    assert config.signing["rotation_sla_days"] == 14

    exported = config.to_sanitised_dict()["signing"]
    assert exported["provider"] == "aws_kms"
    assert exported["rotation_sla_days"] == 14
