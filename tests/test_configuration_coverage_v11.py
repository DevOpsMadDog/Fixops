"""Comprehensive coverage tests for core.configuration — v11 swarm coverage push.

Targets: _read_text_cached, _parse_overlay, _deep_merge, _require_mapping,
         _require_string, _optional_string, _string_list, _validate_signing_config,
         _validate_compliance_frameworks, _validate_compliance_controls,
         _validate_compliance_config, _validate_policy_actions, _validate_policy_config,
         guardrail profiles, FixOpsConfig.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.configuration import (
    _deep_merge,
    _optional_string,
    _parse_overlay,
    _require_mapping,
    _require_string,
    _string_list,
    _validate_signing_config,
)


# ---------------------------------------------------------------------------
# _parse_overlay
# ---------------------------------------------------------------------------


class TestParseOverlay:
    def test_empty_string(self):
        assert _parse_overlay("") == {}

    def test_whitespace_only(self):
        assert _parse_overlay("   \n  ") == {}

    def test_valid_json(self):
        text = '{"mode": "enterprise", "signing": {"provider": "env"}}'
        result = _parse_overlay(text)
        assert result["mode"] == "enterprise"
        assert result["signing"]["provider"] == "env"

    def test_valid_yaml(self):
        text = "mode: enterprise\nsigning:\n  provider: env\n"
        result = _parse_overlay(text)
        assert result["mode"] == "enterprise"

    def test_yaml_null_returns_empty(self):
        # YAML null parses to None
        result = _parse_overlay("null")
        assert result == {}

    def test_yaml_non_mapping_raises(self):
        with pytest.raises(TypeError, match="mapping"):
            _parse_overlay("- item1\n- item2\n")


# ---------------------------------------------------------------------------
# _deep_merge
# ---------------------------------------------------------------------------


class TestDeepMerge:
    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        overrides = {"b": 3, "c": 4}
        result = _deep_merge(base, overrides)
        assert result == {"a": 1, "b": 3, "c": 4}
        # Original should NOT be mutated
        assert base == {"a": 1, "b": 2}

    def test_nested_merge(self):
        base = {"a": {"x": 1, "y": 2}, "b": 3}
        overrides = {"a": {"y": 99, "z": 100}}
        result = _deep_merge(base, overrides)
        assert result["a"]["x"] == 1
        assert result["a"]["y"] == 99
        assert result["a"]["z"] == 100
        assert result["b"] == 3

    def test_override_replaces_non_dict(self):
        base = {"a": "string"}
        overrides = {"a": {"nested": True}}
        result = _deep_merge(base, overrides)
        assert result["a"] == {"nested": True}

    def test_empty_overrides(self):
        base = {"a": 1}
        result = _deep_merge(base, {})
        assert result == {"a": 1}

    def test_empty_base(self):
        result = _deep_merge({}, {"a": 1})
        assert result == {"a": 1}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


class TestRequireMapping:
    def test_valid_mapping(self):
        result = _require_mapping({"key": "value"}, "test")
        assert result == {"key": "value"}

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="must be a mapping"):
            _require_mapping("not a dict", "test_field")

    def test_list_raises(self):
        with pytest.raises(ValueError, match="must be a mapping"):
            _require_mapping([1, 2, 3], "test_field")


class TestRequireString:
    def test_valid_string(self):
        assert _require_string("hello", "field") == "hello"

    def test_strips_whitespace(self):
        assert _require_string("  hello  ", "field") == "hello"

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            _require_string("   ", "field")

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _require_string(42, "field")


class TestOptionalString:
    def test_none_returns_none(self):
        assert _optional_string(None, "field") is None

    def test_valid_string(self):
        assert _optional_string("hello", "field") == "hello"

    def test_empty_string_returns_none(self):
        assert _optional_string("   ", "field") is None

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _optional_string(42, "field")


class TestStringList:
    def test_none_returns_empty(self):
        assert _string_list(None, "field") == []

    def test_valid_list(self):
        assert _string_list(["a", "b", "c"], "field") == ["a", "b", "c"]

    def test_non_list_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            _string_list("not a list", "field")

    def test_non_string_item_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _string_list(["a", 42, "c"], "field")

    def test_empty_item_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            _string_list(["a", "   ", "c"], "field")

    def test_strips_whitespace(self):
        assert _string_list(["  a  ", " b "], "field") == ["a", "b"]


# ---------------------------------------------------------------------------
# _validate_signing_config
# ---------------------------------------------------------------------------


class TestValidateSigningConfig:
    def test_none_returns_defaults(self):
        result = _validate_signing_config(None)
        assert result["provider"] == "env"
        assert result["rotation_sla_days"] == 30

    def test_env_provider(self):
        result = _validate_signing_config({"provider": "env"})
        assert result["provider"] == "env"

    def test_aws_kms_provider(self):
        result = _validate_signing_config({
            "provider": "aws_kms",
            "key_id": "arn:aws:kms:us-east-1:123456789:key/abc",
            "aws_region": "us-east-1",
        })
        assert result["provider"] == "aws_kms"
        assert "key_id" in result
        assert result["aws_region"] == "us-east-1"

    def test_azure_key_vault_provider(self):
        result = _validate_signing_config({
            "provider": "azure_key_vault",
            "azure_vault_url": "https://myvault.vault.azure.net/",
        })
        assert result["provider"] == "azure_key_vault"
        assert "azure_vault_url" in result

    def test_invalid_provider_raises(self):
        with pytest.raises(ValueError, match="provider"):
            _validate_signing_config({"provider": "invalid_provider"})

    def test_unexpected_keys_raises(self):
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_signing_config({"provider": "env", "extra_key": "bad"})

    def test_rotation_sla_positive(self):
        result = _validate_signing_config({"rotation_sla_days": 90})
        assert result["rotation_sla_days"] == 90

    def test_rotation_sla_zero_raises(self):
        with pytest.raises(ValueError, match="positive integer"):
            _validate_signing_config({"rotation_sla_days": 0})

    def test_rotation_sla_negative_raises(self):
        with pytest.raises(ValueError, match="positive integer"):
            _validate_signing_config({"rotation_sla_days": -1})


# ---------------------------------------------------------------------------
# Guardrail profiles
# ---------------------------------------------------------------------------


class TestGuardrailProfiles:
    def test_default_profiles_exist(self):
        from core.configuration import _DEFAULT_GUARDRAIL_PROFILES
        assert "foundational" in _DEFAULT_GUARDRAIL_PROFILES
        assert "scaling" in _DEFAULT_GUARDRAIL_PROFILES
        assert "advanced" in _DEFAULT_GUARDRAIL_PROFILES

    def test_foundational_profile(self):
        from core.configuration import _DEFAULT_GUARDRAIL_PROFILES
        p = _DEFAULT_GUARDRAIL_PROFILES["foundational"]
        assert p["fail_on"] == "critical"
        assert p["warn_on"] == "high"

    def test_scaling_profile(self):
        from core.configuration import _DEFAULT_GUARDRAIL_PROFILES
        p = _DEFAULT_GUARDRAIL_PROFILES["scaling"]
        assert p["fail_on"] == "high"
        assert p["warn_on"] == "medium"

    def test_advanced_profile(self):
        from core.configuration import _DEFAULT_GUARDRAIL_PROFILES
        p = _DEFAULT_GUARDRAIL_PROFILES["advanced"]
        assert p["fail_on"] == "medium"

    def test_default_maturity(self):
        from core.configuration import _DEFAULT_GUARDRAIL_MATURITY
        assert _DEFAULT_GUARDRAIL_MATURITY == "scaling"

    def test_allowed_overlay_keys(self):
        from core.configuration import _ALLOWED_OVERLAY_KEYS
        assert "mode" in _ALLOWED_OVERLAY_KEYS
        assert "jira" in _ALLOWED_OVERLAY_KEYS
        assert "signing" in _ALLOWED_OVERLAY_KEYS
        assert "guardrails" in _ALLOWED_OVERLAY_KEYS
        assert "compliance" in _ALLOWED_OVERLAY_KEYS
        assert "modules" in _ALLOWED_OVERLAY_KEYS


# ---------------------------------------------------------------------------
# _validate_compliance_frameworks and controls
# ---------------------------------------------------------------------------


class TestValidateComplianceFrameworks:
    def test_none_returns_empty(self):
        from core.configuration import _validate_compliance_frameworks
        assert _validate_compliance_frameworks(None, "loc") == []

    def test_valid_framework(self):
        from core.configuration import _validate_compliance_frameworks
        result = _validate_compliance_frameworks([
            {
                "name": "SOC2",
                "version": "2024",
                "description": "SOC 2 Type II",
                "controls": [
                    {"id": "CC1.1", "title": "Control 1", "requires": ["evidence_signing"]},
                ],
            }
        ], "compliance.frameworks")
        assert len(result) == 1
        assert result[0]["name"] == "SOC2"
        assert len(result[0]["controls"]) == 1

    def test_non_list_raises(self):
        from core.configuration import _validate_compliance_frameworks
        with pytest.raises(ValueError, match="must be a list"):
            _validate_compliance_frameworks("not a list", "loc")

    def test_non_mapping_item_raises(self):
        from core.configuration import _validate_compliance_frameworks
        with pytest.raises(ValueError, match="must be a mapping"):
            _validate_compliance_frameworks(["not a dict"], "loc")

    def test_unexpected_keys_raises(self):
        from core.configuration import _validate_compliance_frameworks
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_compliance_frameworks([
                {"name": "SOC2", "extra": "bad"}
            ], "loc")


class TestValidateComplianceControls:
    def test_none_returns_empty(self):
        from core.configuration import _validate_compliance_controls
        assert _validate_compliance_controls(None, "loc") == []

    def test_valid_control(self):
        from core.configuration import _validate_compliance_controls
        result = _validate_compliance_controls([
            {"id": "CC1.1", "title": "Control Env", "requires": ["signing"]},
        ], "loc")
        assert len(result) == 1
        assert result[0]["id"] == "CC1.1"

    def test_control_with_tags_and_metadata(self):
        from core.configuration import _validate_compliance_controls
        result = _validate_compliance_controls([
            {
                "id": "CC1.1",
                "tags": ["critical", "auth"],
                "metadata": {"owner": "security-team"},
                "requires": [],
            },
        ], "loc")
        assert result[0]["tags"] == ["critical", "auth"]
        assert result[0]["metadata"]["owner"] == "security-team"


# ---------------------------------------------------------------------------
# _validate_policy_actions
# ---------------------------------------------------------------------------


class TestValidatePolicyActions:
    def test_none_returns_empty(self):
        from core.configuration import _validate_policy_actions
        assert _validate_policy_actions(None, "loc") == []

    def test_valid_jira_action(self):
        from core.configuration import _validate_policy_actions
        result = _validate_policy_actions([
            {
                "trigger": "guardrail:fail",
                "type": "jira_issue",
                "summary": "Security violation",
                "project_key": "SEC",
            }
        ], "loc")
        assert len(result) == 1
        assert result[0]["trigger"] == "guardrail:fail"
        assert result[0]["type"] == "jira_issue"

    def test_valid_slack_action(self):
        from core.configuration import _validate_policy_actions
        result = _validate_policy_actions([
            {
                "trigger": "guardrail:warn",
                "type": "slack",
                "webhook_url": "https://hooks.slack.com/xxx",
                "channel": "#security",
                "text": "Warning!",
            }
        ], "loc")
        assert result[0]["type"] == "slack"

    def test_invalid_trigger_raises(self):
        from core.configuration import _validate_policy_actions
        with pytest.raises(ValueError, match="trigger"):
            _validate_policy_actions([
                {"trigger": "invalid:trigger", "type": "slack"}
            ], "loc")

    def test_invalid_type_raises(self):
        from core.configuration import _validate_policy_actions
        with pytest.raises(ValueError, match="type"):
            _validate_policy_actions([
                {"trigger": "guardrail:fail", "type": "email"}
            ], "loc")

    def test_non_list_raises(self):
        from core.configuration import _validate_policy_actions
        with pytest.raises(ValueError, match="must be a list"):
            _validate_policy_actions("not a list", "loc")

    def test_force_delivery_bool(self):
        from core.configuration import _validate_policy_actions
        result = _validate_policy_actions([
            {"trigger": "guardrail:fail", "type": "jira_issue", "force_delivery": True}
        ], "loc")
        assert result[0]["force_delivery"] is True

    def test_force_delivery_non_bool_raises(self):
        from core.configuration import _validate_policy_actions
        with pytest.raises(ValueError, match="boolean"):
            _validate_policy_actions([
                {"trigger": "guardrail:fail", "type": "jira_issue", "force_delivery": "yes"}
            ], "loc")

    def test_parent_page_id_numeric(self):
        from core.configuration import _validate_policy_actions
        result = _validate_policy_actions([
            {
                "trigger": "guardrail:fail",
                "type": "confluence_page",
                "parent_page_id": 12345,
                "space": "DEV",
                "title": "Security Report",
            }
        ], "loc")
        assert result[0]["parent_page_id"] == "12345"

    def test_unexpected_keys_raises(self):
        from core.configuration import _validate_policy_actions
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_policy_actions([
                {"trigger": "guardrail:fail", "type": "slack", "bad_key": "val"}
            ], "loc")


# ---------------------------------------------------------------------------
# _validate_policy_config
# ---------------------------------------------------------------------------


class TestValidatePolicyConfig:
    def test_none_returns_empty(self):
        from core.configuration import _validate_policy_config
        assert _validate_policy_config(None) == {}

    def test_empty_returns_empty(self):
        from core.configuration import _validate_policy_config
        assert _validate_policy_config({}) == {}

    def test_valid_config(self):
        from core.configuration import _validate_policy_config
        result = _validate_policy_config({
            "slack_webhook_env": "SLACK_WEBHOOK_URL",
            "context_high_threshold": 80,
            "actions": [
                {"trigger": "guardrail:fail", "type": "slack", "text": "Alert!"},
            ],
        })
        assert result["slack_webhook_env"] == "SLACK_WEBHOOK_URL"
        assert result["context_high_threshold"] == 80

    def test_unexpected_keys_raises(self):
        from core.configuration import _validate_policy_config
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_policy_config({"bad_key": "value"})


# ---------------------------------------------------------------------------
# _validate_compliance_config
# ---------------------------------------------------------------------------


class TestValidateComplianceConfig:
    def test_none_returns_empty(self):
        from core.configuration import _validate_compliance_config
        assert _validate_compliance_config(None) == {}

    def test_valid_config(self):
        from core.configuration import _validate_compliance_config
        result = _validate_compliance_config({
            "frameworks": [
                {"name": "SOC2", "controls": [{"id": "CC1.1", "requires": []}]},
            ],
        })
        assert len(result["frameworks"]) == 1

    def test_unexpected_keys_raises(self):
        from core.configuration import _validate_compliance_config
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_compliance_config({"frameworks": [], "extra": "bad"})
