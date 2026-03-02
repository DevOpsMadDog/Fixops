"""
Comprehensive unit tests for suite-core/core/configuration.py.

Covers:
  - _mask utility
  - _read_text_cached / _read_text
  - _parse_overlay: empty, JSON, YAML, invalid
  - _deep_merge: nested, non-overlapping, overwrite
  - _require_mapping / _require_string / _optional_string / _string_list
  - _validate_signing_config: provider validation, unexpected keys, rotation SLA
  - _validate_compliance_frameworks / _validate_compliance_controls
  - _validate_compliance_config
  - _validate_policy_actions: triggers, types, optional fields, force_delivery
  - _validate_policy_config
  - _validate_policy_engine_config: OPA sub-config
  - _OverlayDocument: pydantic validation, extra fields forbidden
  - _resolve_allowlisted_roots
  - _ensure_within_allowlist
  - OverlayConfig dataclass: defaults, guardrail_maturity, guardrail_policy,
    required_inputs, signing_settings, to_sanitised_dict, _mask method,
    data_directories
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.configuration import (
    _read_text,
    _read_text_cached,
    _parse_overlay,
    _deep_merge,
    _require_mapping,
    _require_string,
    _optional_string,
    _string_list,
    _validate_signing_config,
    _validate_compliance_frameworks,
    _validate_compliance_controls,
    _validate_compliance_config,
    _validate_policy_actions,
    _validate_policy_config,
    _validate_policy_engine_config,
    _OverlayDocument,
    _resolve_allowlisted_roots,
    _ensure_within_allowlist,
    OverlayConfig,
    _ALLOWED_OVERLAY_KEYS,
    _DEFAULT_GUARDRAIL_MATURITY,
    _DEFAULT_GUARDRAIL_PROFILES,
)


# ===========================================================================
# _parse_overlay
# ===========================================================================


class TestParseOverlay:
    def test_empty_string(self):
        assert _parse_overlay("") == {}

    def test_whitespace_only(self):
        assert _parse_overlay("   \n  ") == {}

    def test_json_valid(self):
        result = _parse_overlay('{"mode": "enterprise"}')
        assert result == {"mode": "enterprise"}

    def test_yaml_valid(self):
        result = _parse_overlay("mode: enterprise\ntoggle: true\n")
        assert result["mode"] == "enterprise"

    def test_yaml_null_returns_empty(self):
        result = _parse_overlay("---\n")
        assert result == {}

    def test_yaml_non_mapping_raises(self):
        with pytest.raises(TypeError, match="mapping at the root"):
            _parse_overlay("- item1\n- item2\n")


# ===========================================================================
# _deep_merge
# ===========================================================================


class TestDeepMerge:
    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        overrides = {"b": 3, "c": 4}
        result = _deep_merge(base, overrides)
        assert result == {"a": 1, "b": 3, "c": 4}
        # Base should not be mutated
        assert base == {"a": 1, "b": 2}

    def test_nested_merge(self):
        base = {"a": {"x": 1, "y": 2}, "b": 3}
        overrides = {"a": {"y": 99, "z": 100}}
        result = _deep_merge(base, overrides)
        assert result == {"a": {"x": 1, "y": 99, "z": 100}, "b": 3}

    def test_override_non_mapping_with_value(self):
        base = {"a": "string"}
        overrides = {"a": {"nested": True}}
        result = _deep_merge(base, overrides)
        assert result == {"a": {"nested": True}}

    def test_empty_overrides(self):
        base = {"a": 1}
        result = _deep_merge(base, {})
        assert result == {"a": 1}

    def test_empty_base(self):
        result = _deep_merge({}, {"a": 1})
        assert result == {"a": 1}


# ===========================================================================
# Validators
# ===========================================================================


class TestRequireMapping:
    def test_valid_mapping(self):
        result = _require_mapping({"key": "value"}, "test")
        assert result == {"key": "value"}

    def test_non_mapping_raises(self):
        with pytest.raises(ValueError, match="test must be a mapping"):
            _require_mapping("string", "test")

    def test_none_raises(self):
        with pytest.raises(ValueError):
            _require_mapping(None, "test")


class TestRequireString:
    def test_valid_string(self):
        assert _require_string("hello", "test") == "hello"

    def test_strips_whitespace(self):
        assert _require_string("  hello  ", "test") == "hello"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            _require_string("", "test")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            _require_string("   ", "test")

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _require_string(123, "test")


class TestOptionalString:
    def test_none_returns_none(self):
        assert _optional_string(None, "test") is None

    def test_valid_string(self):
        assert _optional_string("hello", "test") == "hello"

    def test_empty_returns_none(self):
        assert _optional_string("", "test") is None

    def test_whitespace_returns_none(self):
        assert _optional_string("   ", "test") is None

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _optional_string(123, "test")


class TestStringList:
    def test_none_returns_empty(self):
        assert _string_list(None, "test") == []

    def test_valid_list(self):
        assert _string_list(["a", "b"], "test") == ["a", "b"]

    def test_strips_whitespace(self):
        assert _string_list(["  hello  "], "test") == ["hello"]

    def test_non_list_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            _string_list("string", "test")

    def test_non_string_item_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _string_list([123], "test")

    def test_empty_string_item_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            _string_list([""], "test")


# ===========================================================================
# _validate_signing_config
# ===========================================================================


class TestValidateSigningConfig:
    def test_none_returns_defaults(self):
        result = _validate_signing_config(None)
        assert result["provider"] == "env"
        assert result["rotation_sla_days"] == 30

    def test_valid_provider_env(self):
        result = _validate_signing_config({"provider": "env"})
        assert result["provider"] == "env"

    def test_valid_provider_aws_kms(self):
        result = _validate_signing_config({"provider": "AWS_KMS"})
        assert result["provider"] == "aws_kms"

    def test_valid_provider_azure(self):
        result = _validate_signing_config({"provider": "Azure_Key_Vault"})
        assert result["provider"] == "azure_key_vault"

    def test_invalid_provider_raises(self):
        with pytest.raises(ValueError, match="must be one of"):
            _validate_signing_config({"provider": "gcp_kms"})

    def test_unexpected_keys_raises(self):
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_signing_config({"provider": "env", "extra_key": True})

    def test_rotation_sla_valid(self):
        result = _validate_signing_config({"rotation_sla_days": 90})
        assert result["rotation_sla_days"] == 90

    def test_rotation_sla_zero_raises(self):
        with pytest.raises(ValueError, match="positive integer"):
            _validate_signing_config({"rotation_sla_days": 0})

    def test_rotation_sla_negative_raises(self):
        with pytest.raises(ValueError, match="positive integer"):
            _validate_signing_config({"rotation_sla_days": -1})

    def test_key_id_and_aws_region(self):
        result = _validate_signing_config({
            "provider": "aws_kms",
            "key_id": "my-key-id",
            "aws_region": "us-west-2",
        })
        assert result["key_id"] == "my-key-id"
        assert result["aws_region"] == "us-west-2"


# ===========================================================================
# _validate_compliance_controls / _validate_compliance_frameworks
# ===========================================================================


class TestValidateComplianceControls:
    def test_none_returns_empty(self):
        assert _validate_compliance_controls(None, "test") == []

    def test_valid_control(self):
        result = _validate_compliance_controls(
            [{"id": "CC-1.1", "title": "Access Control"}], "test"
        )
        assert len(result) == 1
        assert result[0]["id"] == "CC-1.1"

    def test_non_list_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            _validate_compliance_controls("not a list", "test")

    def test_non_mapping_item_raises(self):
        with pytest.raises(ValueError, match="must be a mapping"):
            _validate_compliance_controls(["string"], "test")

    def test_unexpected_keys(self):
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_compliance_controls(
                [{"id": "CC-1", "extra": True}], "test"
            )


class TestValidateComplianceFrameworks:
    def test_none_returns_empty(self):
        assert _validate_compliance_frameworks(None, "test") == []

    def test_valid_framework(self):
        result = _validate_compliance_frameworks(
            [{"name": "SOC2", "version": "2023", "controls": []}], "test"
        )
        assert len(result) == 1
        assert result[0]["name"] == "SOC2"

    def test_non_list_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            _validate_compliance_frameworks("not a list", "test")

    def test_non_mapping_item_raises(self):
        with pytest.raises(ValueError, match="must be a mapping"):
            _validate_compliance_frameworks(["string"], "test")


class TestValidateComplianceConfig:
    def test_none_returns_empty(self):
        assert _validate_compliance_config(None) == {}

    def test_empty_returns_empty(self):
        assert _validate_compliance_config({}) == {}

    def test_valid_config(self):
        result = _validate_compliance_config({
            "frameworks": [{"name": "SOC2", "controls": []}],
        })
        assert "frameworks" in result
        assert len(result["frameworks"]) == 1

    def test_unexpected_keys(self):
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_compliance_config({"frameworks": [], "extra": True})


# ===========================================================================
# _validate_policy_actions / _validate_policy_config
# ===========================================================================


class TestValidatePolicyActions:
    def test_none_returns_empty(self):
        assert _validate_policy_actions(None, "test") == []

    def test_valid_action(self):
        result = _validate_policy_actions(
            [{"trigger": "guardrail:fail", "type": "jira_issue", "summary": "Alert"}],
            "test",
        )
        assert len(result) == 1
        assert result[0]["trigger"] == "guardrail:fail"

    def test_non_list_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            _validate_policy_actions("not a list", "test")

    def test_invalid_trigger_raises(self):
        with pytest.raises(ValueError, match="trigger must be one of"):
            _validate_policy_actions(
                [{"trigger": "invalid", "type": "jira_issue"}], "test"
            )

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="type must be one of"):
            _validate_policy_actions(
                [{"trigger": "guardrail:fail", "type": "invalid"}], "test"
            )

    def test_force_delivery_boolean(self):
        result = _validate_policy_actions(
            [{"trigger": "guardrail:fail", "type": "jira_issue", "force_delivery": True}],
            "test",
        )
        assert result[0]["force_delivery"] is True

    def test_force_delivery_non_boolean_raises(self):
        with pytest.raises(ValueError, match="must be a boolean"):
            _validate_policy_actions(
                [{"trigger": "guardrail:fail", "type": "jira_issue", "force_delivery": "yes"}],
                "test",
            )

    def test_parent_page_id_numeric(self):
        result = _validate_policy_actions(
            [{"trigger": "guardrail:fail", "type": "confluence_page", "parent_page_id": 12345}],
            "test",
        )
        assert result[0]["parent_page_id"] == "12345"


class TestValidatePolicyConfig:
    def test_none_returns_empty(self):
        assert _validate_policy_config(None) == {}

    def test_empty_returns_empty(self):
        assert _validate_policy_config({}) == {}

    def test_unexpected_keys_raises(self):
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_policy_config({"actions": [], "bad_key": True})


# ===========================================================================
# _validate_policy_engine_config
# ===========================================================================


class TestValidatePolicyEngineConfig:
    def test_none_returns_empty(self):
        assert _validate_policy_engine_config(None) == {}

    def test_empty_returns_empty(self):
        assert _validate_policy_engine_config({}) == {}

    def test_valid_opa_config(self):
        result = _validate_policy_engine_config({
            "opa": {
                "enabled": True,
                "url": "http://localhost:8181",
                "policy_package": "fixops.guardrails",
                "request_timeout_seconds": 5,
            }
        })
        assert result["opa"]["enabled"] is True
        assert result["opa"]["url"] == "http://localhost:8181"

    def test_opa_unexpected_keys_raises(self):
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_policy_engine_config({"opa": {"extra_key": True}})

    def test_unexpected_top_keys_raises(self):
        with pytest.raises(ValueError, match="unexpected keys"):
            _validate_policy_engine_config({"bad_key": True})

    def test_opa_invalid_timeout_raises(self):
        with pytest.raises(ValueError, match="positive integer"):
            _validate_policy_engine_config({
                "opa": {"request_timeout_seconds": -1}
            })


# ===========================================================================
# _OverlayDocument (Pydantic)
# ===========================================================================


class TestOverlayDocument:
    def test_default_values(self):
        doc = _OverlayDocument()
        assert doc.mode == "enterprise"
        assert doc.jira is None

    def test_valid_document(self):
        doc = _OverlayDocument(mode="oss", jira={"url": "https://jira.example.com"})
        assert doc.mode == "oss"

    def test_extra_field_forbidden(self):
        from pydantic import ValidationError as PydanticValidationError
        with pytest.raises(PydanticValidationError):
            _OverlayDocument(unknown_field="bad")


# ===========================================================================
# _resolve_allowlisted_roots / _ensure_within_allowlist
# ===========================================================================


class TestResolveAllowlistedRoots:
    def test_default_without_env(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_DATA_ROOT_ALLOWLIST", raising=False)
        roots = _resolve_allowlisted_roots()
        assert len(roots) >= 1
        assert all(isinstance(r, Path) for r in roots)

    def test_with_env_set(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FIXOPS_DATA_ROOT_ALLOWLIST", str(tmp_path))
        roots = _resolve_allowlisted_roots()
        assert tmp_path.resolve() in roots


class TestEnsureWithinAllowlist:
    def test_within_allowed_root(self, tmp_path):
        child = tmp_path / "sub" / "file.txt"
        result = _ensure_within_allowlist(child, [tmp_path])
        assert str(result).startswith(str(tmp_path.resolve()))

    def test_outside_allowed_root_raises(self, tmp_path):
        outside = Path("/tmp/totally_outside")
        with pytest.raises(ValueError, match="not within the allowed roots"):
            _ensure_within_allowlist(outside, [tmp_path])


# ===========================================================================
# OverlayConfig
# ===========================================================================


class TestOverlayConfig:
    def test_default_values(self):
        config = OverlayConfig()
        assert config.mode == "enterprise"
        assert config.jira == {}
        assert config.toggles == {}

    def test_guardrail_maturity_default(self):
        config = OverlayConfig()
        assert config.guardrail_maturity == _DEFAULT_GUARDRAIL_MATURITY

    def test_guardrail_maturity_from_guardrails(self):
        config = OverlayConfig(guardrails={"maturity": "advanced"})
        assert config.guardrail_maturity == "advanced"

    def test_guardrail_maturity_from_metadata(self):
        config = OverlayConfig(metadata={"guardrail_maturity": "foundational"})
        assert config.guardrail_maturity == "foundational"

    def test_guardrail_policy_defaults(self):
        config = OverlayConfig()
        policy = config.guardrail_policy
        assert "maturity" in policy
        assert "fail_on" in policy
        assert "warn_on" in policy

    def test_guardrail_policy_scaling(self):
        config = OverlayConfig(guardrails={"maturity": "scaling"})
        policy = config.guardrail_policy
        assert policy["fail_on"] == "high"
        assert policy["warn_on"] == "medium"

    def test_guardrail_policy_foundational(self):
        config = OverlayConfig(guardrails={"maturity": "foundational"})
        policy = config.guardrail_policy
        assert policy["fail_on"] == "critical"
        assert policy["warn_on"] == "high"

    def test_guardrail_policy_advanced(self):
        config = OverlayConfig(guardrails={"maturity": "advanced"})
        policy = config.guardrail_policy
        assert policy["fail_on"] == "medium"

    def test_guardrail_policy_custom_override(self):
        config = OverlayConfig(guardrails={
            "maturity": "scaling",
            "fail_on": "critical",
            "warn_on": "high",
        })
        policy = config.guardrail_policy
        assert policy["fail_on"] == "critical"
        assert policy["warn_on"] == "high"

    def test_required_inputs_with_design(self):
        config = OverlayConfig(toggles={"require_design_input": True})
        assert "design" in config.required_inputs
        assert "sbom" in config.required_inputs

    def test_required_inputs_without_design(self):
        config = OverlayConfig(toggles={"require_design_input": False})
        assert "design" not in config.required_inputs
        assert "sbom" in config.required_inputs

    def test_signing_settings_defaults(self):
        config = OverlayConfig()
        settings = config.signing_settings
        assert settings["provider"] == "env"

    def test_signing_settings_with_values(self):
        config = OverlayConfig(signing={
            "provider": "aws_kms",
            "key_id": "my-key",
            "aws_region": "us-west-2",
            "rotation_sla_days": 90,
        })
        settings = config.signing_settings
        assert settings["provider"] == "aws_kms"
        assert settings["key_id"] == "my-key"
        assert settings["aws_region"] == "us-west-2"
        assert settings["rotation_sla_days"] == 90

    def test_mask_sensitive_fields(self):
        result = OverlayConfig._mask({
            "url": "https://jira.com",
            "token": "secret-value",
            "api_key": "key-123",
            "password": "pass",
        })
        assert result["url"] == "https://jira.com"
        assert result["token"] == "***"
        assert result["api_key"] == "***"
        assert result["password"] == "***"

    def test_mask_non_sensitive_fields(self):
        result = OverlayConfig._mask({"project_key": "TEST", "user": "admin"})
        assert result["project_key"] == "TEST"
        assert result["user"] == "admin"

    def test_to_sanitised_dict(self):
        config = OverlayConfig(
            mode="enterprise",
            jira={"url": "https://j.com", "token": "secret"},
        )
        d = config.to_sanitised_dict()
        assert d["mode"] == "enterprise"
        assert d["jira"]["token"] == "***"

    def test_allowed_overlay_keys_non_empty(self):
        assert len(_ALLOWED_OVERLAY_KEYS) > 10
        assert "mode" in _ALLOWED_OVERLAY_KEYS
        assert "jira" in _ALLOWED_OVERLAY_KEYS

    def test_guardrail_profiles_known_maturities(self):
        assert "foundational" in _DEFAULT_GUARDRAIL_PROFILES
        assert "scaling" in _DEFAULT_GUARDRAIL_PROFILES
        assert "advanced" in _DEFAULT_GUARDRAIL_PROFILES


# ===========================================================================
# _read_text helpers
# ===========================================================================


class TestReadText:
    def test_read_existing_file(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("mode: enterprise\n")
        # Clear cache before test
        _read_text_cached.cache_clear()
        result = _read_text(f)
        assert "enterprise" in result

    def test_read_missing_file(self, tmp_path):
        _read_text_cached.cache_clear()
        result = _read_text(tmp_path / "nonexistent.yaml")
        assert result == ""
